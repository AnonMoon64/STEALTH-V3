// test_plugin_loader.c
// Simple loader to test STEALTH plugins without triggering WD on rundll32

#include <windows.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <plugin.dll>\n", argv[0]);
        return 1;
    }
    
    const char *dllPath = argv[1];
    printf("[*] Loading plugin: %s\n", dllPath);
    
    // Load DLL (will trigger DllMain with DLL_PROCESS_ATTACH)
    HMODULE hModule = LoadLibraryA(dllPath);
    if (!hModule) {
        printf("[-] LoadLibrary failed: %lu\n", GetLastError());
        return 1;
    }
    
    printf("[+] Plugin loaded successfully\n");
    printf("[*] DllMain executed (DLL_PROCESS_ATTACH)\n");
    
    // Small delay to let plugin execute
    Sleep(1000);
    
    // Unload
    FreeLibrary(hModule);
    printf("[+] Plugin unloaded\n");
    
    return 0;
}
