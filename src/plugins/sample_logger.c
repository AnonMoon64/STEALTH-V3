// sample_logger.c — inert sample plugin (build as DLL)
#include <windows.h>
#include <stdio.h>
#ifndef ALLOW_CONSOLE_PRINTS
#define printf(...) ((void)0)
#define fprintf(...) ((void)0)
#define puts(...) ((void)0)
#define putchar(...) ((void)0)
#define perror(...) ((void)0)
#endif

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH: {
        char tmp[MAX_PATH];
        if (GetTempPathA(MAX_PATH, tmp)) {
            char f[MAX_PATH];
            snprintf(f, MAX_PATH, "%sstealth_plugin.log", tmp);
            FILE *fp = fopen(f, "a");
            if (fp) {
                fprintf(fp, "sample_logger plugin loaded.\n");
                fclose(fp);
            }
        }
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
