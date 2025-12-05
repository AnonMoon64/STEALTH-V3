#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <windows.h>
#ifndef ALLOW_CONSOLE_PRINTS
#define printf(...) ((void)0)
#define fprintf(...) ((void)0)
#define puts(...) ((void)0)
#define putchar(...) ((void)0)
#define perror(...) ((void)0)
#endif
#include "../plugin.h"

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <exe-path>\n", argv[0]);
        return 1;
    }
    const char *path = argv[1];
    FILE *f = fopen(path, "rb+");
    if (!f) { perror("fopen"); return 1; }
    if (fseek(f, 0, SEEK_END) != 0) { perror("fseek"); fclose(f); return 1; }
    long sz = ftell(f);
    if (sz < (long)sizeof(PluginOverlayHeader)) { fprintf(stderr, "File too small to contain overlay\n"); fclose(f); return 1; }
    // Read header at end
    if (fseek(f, sz - (long)sizeof(PluginOverlayHeader), SEEK_SET) != 0) { perror("fseek2"); fclose(f); return 1; }
    PluginOverlayHeader hdr;
    if (fread(&hdr, 1, sizeof(hdr), f) != sizeof(hdr)) { perror("fread"); fclose(f); return 1; }
    if (memcmp(hdr.magic, PLUGIN_MAGIC, 8) != 0) {
        fprintf(stderr, "No plugin overlay found (magic mismatch).\n"); fclose(f); return 2;
    }
    uint32_t table_offset = hdr.table_offset;
    uint32_t plugin_count = hdr.plugin_count;
    // compute overlay size = table_offset + sizeof(header)
    uint64_t overlay_size = (uint64_t)table_offset + sizeof(PluginOverlayHeader);
    if ((uint64_t)sz < overlay_size) { fprintf(stderr, "Overlay size larger than file — aborting\n"); fclose(f); return 1; }
    uint64_t new_size = (uint64_t)sz - overlay_size;
    // Truncate file
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) { perror("CreateFile"); fclose(f); return 1; }
    LARGE_INTEGER li; li.QuadPart = (LONGLONG)new_size;
    if (!SetFilePointerEx(h, li, NULL, FILE_BEGIN)) { fprintf(stderr, "SetFilePointerEx failed: %lu\n", GetLastError()); CloseHandle(h); fclose(f); return 1; }
    if (!SetEndOfFile(h)) { fprintf(stderr, "SetEndOfFile failed: %lu\n", GetLastError()); CloseHandle(h); fclose(f); return 1; }
    CloseHandle(h);
    fclose(f);
    printf("Stripped plugin overlay: removed %llu bytes; plugin_count=%u\n", (unsigned long long)overlay_size, plugin_count);
    return 0;
}
