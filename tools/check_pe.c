#include <stdio.h>
#include <stdint.h>
#include <windows.h>
#ifndef ALLOW_CONSOLE_PRINTS
#define printf(...) ((void)0)
#define fprintf(...) ((void)0)
#define puts(...) ((void)0)
#define putchar(...) ((void)0)
#define perror(...) ((void)0)
#endif
int main(int argc, char **argv) {
    if (argc < 2) { printf("usage: check_pe <file>\n"); return 1; }
    const char *path = argv[1];
    FILE *f = fopen(path, "rb");
    if (!f) { perror("fopen"); return 2; }
    IMAGE_DOS_HEADER dos;
    if (fread(&dos, 1, sizeof(dos), f) != sizeof(dos)) { printf("read dos failed\n"); fclose(f); return 3; }
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) { printf("Not PE (no MZ)\n"); fclose(f); return 4; }
    if (fseek(f, dos.e_lfanew, SEEK_SET) != 0) { perror("fseek"); fclose(f); return 5; }
    IMAGE_NT_HEADERS nt;
    if (fread(&nt, 1, sizeof(nt), f) != sizeof(nt)) { printf("read nt failed\n"); fclose(f); return 6; }
    if (nt.Signature != IMAGE_NT_SIGNATURE) { printf("Not PE (no NT)\n"); fclose(f); return 7; }
    printf("Subsystem: %u\n", nt.OptionalHeader.Subsystem);
    printf("ImageBase: 0x%llx\n", (unsigned long long)nt.OptionalHeader.ImageBase);
    printf("AddressOfEntryPoint: 0x%x\n", nt.OptionalHeader.AddressOfEntryPoint);
    fclose(f);
    return 0;
}
