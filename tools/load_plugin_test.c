#include <windows.h>
#include <stdio.h>

int main(int argc, char **argv) {
    #ifndef ALLOW_CONSOLE_PRINTS
    #define printf(...) ((void)0)
    #define fprintf(...) ((void)0)
    #define puts(...) ((void)0)
    #define putchar(...) ((void)0)
    #define perror(...) ((void)0)
    #endif
    if (argc < 2) {
        printf("Usage: load_plugin_test.exe <plugin_path>\n");
        return 1;
    }
    const char *path = argv[1];
    HMODULE h = LoadLibraryA(path);
    if (!h) {
        printf("LoadLibrary failed: %lu\n", GetLastError());
        return 1;
    }
    printf("Loaded %s -> module %p\n", path, (void*)h);
    Sleep(1000);
    FreeLibrary(h);
    return 0;
}
