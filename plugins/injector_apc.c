// ATT-013: APC (Asynchronous Procedure Call) Injection Plugin
// Uses QueueUserAPC for thread hijacking/callback execution
// Target stage: POSTLAUNCH

#include <windows.h>
#include <stdio.h>

#ifndef ALLOW_CONSOLE_PRINTS
#define printf(...) ((void)0)
#define fprintf(...) ((void)0)
#define puts(...) ((void)0)
#define putchar(...) ((void)0)
#define perror(...) ((void)0)
#endif

static void write_plugin_log(const char *msg) {
    char tmp[MAX_PATH];
    if (!GetTempPathA(MAX_PATH, tmp)) return;
    char path[MAX_PATH];
    snprintf(path, MAX_PATH, "%sstealth_plugin.log", tmp);
    FILE *fp = fopen(path, "a");
    if (fp) {
        fprintf(fp, "[ATT-013] %s\n", msg);
        fclose(fp);
    }
}

static volatile int apc_executed = 0;

// APC callback
static VOID CALLBACK apc_callback(ULONG_PTR dwParam) {
    write_plugin_log("APC callback executed");
    apc_executed = 1;
}

static DWORD WINAPI worker_thread(LPVOID lpParam) {
    write_plugin_log("Worker thread started");
    
    // Enter alertable wait state
    SleepEx(500, TRUE); // TRUE = alertable
    
    if (apc_executed) {
        write_plugin_log("APC execution confirmed");
    } else {
        write_plugin_log("APC did not execute");
    }
    
    return 0;
}

static void execute_apc(void) {
    HANDLE hThread = CreateThread(NULL, 0, worker_thread, NULL, 0, NULL);
    if (!hThread) {
        write_plugin_log("CreateThread failed");
        return;
    }
    
    write_plugin_log("Worker thread created");
    
    // Queue APC to worker thread
    if (QueueUserAPC(apc_callback, hThread, 0)) {
        write_plugin_log("APC queued successfully");
    } else {
        write_plugin_log("QueueUserAPC failed");
    }
    
    // Wait for thread completion
    WaitForSingleObject(hThread, 2000);
    CloseHandle(hThread);
    
    write_plugin_log("APC injection completed");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        write_plugin_log("Plugin loaded");
        execute_apc();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
