// INJ-008: TLS Callbacks Plugin
// Uses Thread Local Storage callbacks for early execution
// Target stage: PRELAUNCH (executes before main)

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
        fprintf(fp, "[INJ-008] %s\n", msg);
        fclose(fp);
    }
}

// TLS callback - executed before DllMain
static void NTAPI tls_callback(PVOID DllHandle, DWORD Reason, PVOID Reserved) {
    if (Reason == DLL_PROCESS_ATTACH) {
        write_plugin_log("TLS callback executed before DllMain");
    }
}

// TLS callback array (must be in .CRT$XL* section)
#ifdef _WIN64
#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:tls_callback_array")
#pragma const_seg(".CRT$XLB")
const PIMAGE_TLS_CALLBACK tls_callback_array[] = { tls_callback, 0 };
#pragma const_seg()
#else
#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:_tls_callback_array")
#pragma data_seg(".CRT$XLB")
PIMAGE_TLS_CALLBACK tls_callback_array[] = { tls_callback, 0 };
#pragma data_seg()
#endif

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        write_plugin_log("DllMain executed (after TLS callback)");
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
