// INJ-004: Direct Syscalls Plugin
// Demonstrates NT API direct syscalls with minimal overhead
// Target stage: PREINJECT (runs before main payload injection)

#include <windows.h>
#include <stdio.h>

#ifndef ALLOW_CONSOLE_PRINTS
#define printf(...) ((void)0)
#define fprintf(...) ((void)0)
#define puts(...) ((void)0)
#define putchar(...) ((void)0)
#define perror(...) ((void)0)
#endif

// NT API structures
typedef NTSTATUS (NTAPI *NtAllocateVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS (NTAPI *NtProtectVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

typedef NTSTATUS (NTAPI *NtFreeVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
);

static void write_plugin_log(const char *msg) {
    char tmp[MAX_PATH];
    if (!GetTempPathA(MAX_PATH, tmp)) return;
    char path[MAX_PATH];
    snprintf(path, MAX_PATH, "%sstealth_plugin.log", tmp);
    FILE *fp = fopen(path, "a");
    if (fp) {
        fprintf(fp, "[INJ-004] %s\n", msg);
        fclose(fp);
    }
}

// Demonstrate direct NT API usage for memory operations
static void execute_direct_syscalls(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        write_plugin_log("Failed to get ntdll.dll handle");
        return;
    }
    
    NtAllocateVirtualMemory_t NtAllocateVirtualMemory = 
        (NtAllocateVirtualMemory_t)GetProcAddress(ntdll, "NtAllocateVirtualMemory");
    NtProtectVirtualMemory_t NtProtectVirtualMemory = 
        (NtProtectVirtualMemory_t)GetProcAddress(ntdll, "NtProtectVirtualMemory");
    NtFreeVirtualMemory_t NtFreeVirtualMemory = 
        (NtFreeVirtualMemory_t)GetProcAddress(ntdll, "NtFreeVirtualMemory");
    
    if (!NtAllocateVirtualMemory || !NtProtectVirtualMemory || !NtFreeVirtualMemory) {
        write_plugin_log("Failed to resolve NT APIs");
        return;
    }
    
    // Allocate RW memory
    PVOID baseAddress = NULL;
    SIZE_T regionSize = 4096;
    NTSTATUS status = NtAllocateVirtualMemory(
        GetCurrentProcess(),
        &baseAddress,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    
    if (status != 0 || !baseAddress) {
        write_plugin_log("NtAllocateVirtualMemory failed");
        return;
    }
    
    char logbuf[256];
    snprintf(logbuf, sizeof(logbuf), "Allocated RW memory at 0x%p", baseAddress);
    write_plugin_log(logbuf);
    
    // Change to RWX
    ULONG oldProtect = 0;
    status = NtProtectVirtualMemory(
        GetCurrentProcess(),
        &baseAddress,
        &regionSize,
        PAGE_EXECUTE_READWRITE,
        &oldProtect
    );
    
    if (status == 0) {
        write_plugin_log("Changed protection to RWX using NtProtectVirtualMemory");
    } else {
        write_plugin_log("NtProtectVirtualMemory failed");
    }
    
    // Free memory
    regionSize = 0;
    status = NtFreeVirtualMemory(
        GetCurrentProcess(),
        &baseAddress,
        &regionSize,
        MEM_RELEASE
    );
    
    if (status == 0) {
        write_plugin_log("Memory freed using NtFreeVirtualMemory");
    }
    
    write_plugin_log("Direct syscalls completed successfully");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        write_plugin_log("Plugin loaded");
        execute_direct_syscalls();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
