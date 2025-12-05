#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <windows.h>
#ifndef ALLOW_CONSOLE_PRINTS
#define printf(...) ((void)0)
#define fprintf(...) ((void)0)
#define puts(...) ((void)0)
#define putchar(...) ((void)0)
#define perror(...) ((void)0)
#endif

// Simple micro-benchmark that measures section copy time from a provided PE file
int main(int argc, char **argv) {
    if (argc < 2) { printf("Usage: %s <exe/dll> [iterations]\n", argv[0]); return 1; }
    const char *path = argv[1];
    int iterations = argc >= 3 ? atoi(argv[2]) : 100;
    FILE *f = fopen(path, "rb"); if (!f) { perror("fopen"); return 1; }
    fseek(f, 0, SEEK_END); long size = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char *buf = malloc(size); if (!buf) { fclose(f); return 1; }
    fread(buf, 1, size, f); fclose(f);

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)buf;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { printf("Not a PE\n"); free(buf); return 1; }
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(buf + dos->e_lfanew);
    SIZE_T image_size = nt->OptionalHeader.SizeOfImage;
    SIZE_T headers = nt->OptionalHeader.SizeOfHeaders;

    clock_t t0 = clock();
    for (int it = 0; it < iterations; ++it) {
        LPVOID imageBase = VirtualAlloc(NULL, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!imageBase) { break; }
        memcpy(imageBase, buf, headers);
        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
        for (DWORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            SIZE_T raw_size = section[i].SizeOfRawData;
            SIZE_T raw_ptr = section[i].PointerToRawData;
            SIZE_T virt_addr = section[i].VirtualAddress;
            if (raw_size == 0) continue;
            memcpy((BYTE *)imageBase + virt_addr, buf + raw_ptr, raw_size);
        }
        VirtualFree(imageBase, 0, MEM_RELEASE);
    }
    clock_t t1 = clock();
    double elapsed = (double)(t1 - t0) / CLOCKS_PER_SEC;
    // printf("PE load bench: file=%s, size=%ld, iterations=%d, total_time=%.3fs\n", path, size, iterations, elapsed);
    free(buf);
    return 0;
}
