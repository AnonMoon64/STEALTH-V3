// ATT-014: Fiber Injection Plugin
// Uses Windows Fibers for cooperative multitasking and execution
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
        fprintf(fp, "[ATT-014] %s\n", msg);
        fclose(fp);
    }
}

static LPVOID mainFiber = NULL;
static volatile int fiber_executed = 0;

// Fiber callback
static VOID CALLBACK fiber_routine(LPVOID lpParameter) {
    write_plugin_log("Fiber callback executed");
    fiber_executed = 1;
    
    // Switch back to main fiber
    SwitchToFiber(mainFiber);
}

static void execute_fiber(void) {
    // Convert thread to fiber
    mainFiber = ConvertThreadToFiber(NULL);
    if (!mainFiber) {
        write_plugin_log("ConvertThreadToFiber failed");
        return;
    }
    
    write_plugin_log("Thread converted to fiber");
    
    // Create new fiber
    LPVOID newFiber = CreateFiber(0, fiber_routine, NULL);
    if (!newFiber) {
        write_plugin_log("CreateFiber failed");
        ConvertFiberToThread();
        return;
    }
    
    write_plugin_log("New fiber created");
    
    // Switch to new fiber
    SwitchToFiber(newFiber);
    
    // Control returns here after fiber switches back
    if (fiber_executed) {
        write_plugin_log("Fiber execution confirmed");
    } else {
        write_plugin_log("Fiber did not execute");
    }
    
    DeleteFiber(newFiber);
    ConvertFiberToThread();
    write_plugin_log("Fiber injection completed");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        write_plugin_log("Plugin loaded");
        execute_fiber();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
