// ATT-012: IOCP (I/O Completion Port) Injection Plugin
// Uses IOCP for asynchronous callback execution
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
        fprintf(fp, "[ATT-012] %s\n", msg);
        fclose(fp);
    }
}

static void execute_iocp(void) {
    // Create IOCP
    HANDLE iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    if (!iocp) {
        write_plugin_log("CreateIoCompletionPort failed");
        return;
    }
    
    write_plugin_log("IOCP created");
    
    // Post completion packet
    if (!PostQueuedCompletionStatus(iocp, 1337, (ULONG_PTR)0xDEADBEEF, NULL)) {
        write_plugin_log("PostQueuedCompletionStatus failed");
        CloseHandle(iocp);
        return;
    }
    
    write_plugin_log("Completion packet posted");
    
    // Retrieve completion packet
    DWORD bytesTransferred = 0;
    ULONG_PTR completionKey = 0;
    LPOVERLAPPED overlapped = NULL;
    
    if (GetQueuedCompletionStatus(iocp, &bytesTransferred, &completionKey, &overlapped, 1000)) {
        char logbuf[256];
        snprintf(logbuf, sizeof(logbuf), "Retrieved packet: bytes=%lu, key=0x%llX", 
                 bytesTransferred, (unsigned long long)completionKey);
        write_plugin_log(logbuf);
    } else {
        write_plugin_log("GetQueuedCompletionStatus failed or timed out");
    }
    
    CloseHandle(iocp);
    write_plugin_log("IOCP cleanup completed");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        write_plugin_log("Plugin loaded");
        execute_iocp();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
