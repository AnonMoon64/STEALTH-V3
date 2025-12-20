// INJ-007: VEH (Vectored Exception Handler) Execution Plugin
// Uses VEH for stealthy execution flow control
// Target stage: PREINJECT

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
        fprintf(fp, "[INJ-007] %s\n", msg);
        fclose(fp);
    }
}

static volatile int veh_triggered = 0;

// VEH handler
static LONG WINAPI exception_handler(EXCEPTION_POINTERS *ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_INT_DIVIDE_BY_ZERO) {
        write_plugin_log("VEH handler triggered successfully");
        veh_triggered = 1;
        #ifdef _WIN64
        ExceptionInfo->ContextRecord->Rip += 3;
        #else
        ExceptionInfo->ContextRecord->Eip += 3;
        #endif
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static void execute_veh_test(void) {
    PVOID handler = AddVectoredExceptionHandler(1, exception_handler);
    if (!handler) {
        write_plugin_log("Failed to register VEH handler");
        return;
    }
    
    write_plugin_log("VEH handler registered");
    
    volatile int x = 0;
    volatile int y = 10;
    volatile int z = y / x;
    
    if (veh_triggered) {
        write_plugin_log("VEH execution flow control successful");
    } else {
        write_plugin_log("VEH handler was not triggered");
    }
    
    RemoveVectoredExceptionHandler(handler);
    write_plugin_log("VEH handler removed");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        write_plugin_log("Plugin loaded");
        execute_veh_test();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
