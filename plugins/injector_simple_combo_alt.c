#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "advapi32.lib")

DWORD WINAPI SimpleWorker(LPVOID p) {
    // Phase 1: File
    FILE* f = fopen("C:\\Windows\\Temp\\simple_combo_test.txt", "w");
    if (f) {
        fprintf(f, "Simple combo test executed\n");
        fclose(f);
    }
    
    // Phase 2: Registry
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "SimplComboTest", 0, REG_SZ, (const BYTE*)"test", 5);
        RegCloseKey(hKey);
    }
    
    // Phase 3: Memory alloc
    LPVOID mem = VirtualAlloc(NULL, 1024, MEM_COMMIT, PAGE_READWRITE);
    if (mem) {
        DWORD old;
        VirtualProtect(mem, 1024, PAGE_EXECUTE_READ, &old);
        VirtualFree(mem, 0, MEM_RELEASE);
    }
    
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
    if (reason == DLL_PROCESS_ATTACH) {
        HANDLE hThread = CreateThread(NULL, 0, SimpleWorker, NULL, 0, NULL);
        if (hThread) {
            WaitForSingleObject(hThread, 3000);
            CloseHandle(hThread);
        }
    }
    return TRUE;
}
