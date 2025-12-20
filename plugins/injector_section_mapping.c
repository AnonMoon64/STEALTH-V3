// INJ-005: Section View Mapping Plugin
// Uses NtCreateSection + NtMapViewOfSection for memory mapping
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

typedef NTSTATUS (NTAPI *NtCreateSection_t)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
);

typedef NTSTATUS (NTAPI *NtMapViewOfSection_t)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
);

typedef NTSTATUS (NTAPI *NtUnmapViewOfSection_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress
);

typedef NTSTATUS (NTAPI *NtClose_t)(HANDLE Handle);

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define SECTION_MAP_WRITE 0x0002
#define SECTION_MAP_READ 0x0004
#define SECTION_MAP_EXECUTE 0x0008
#define SEC_COMMIT 0x8000000
#define ViewUnmap 2

static void write_plugin_log(const char *msg) {
    char tmp[MAX_PATH];
    if (!GetTempPathA(MAX_PATH, tmp)) return;
    char path[MAX_PATH];
    snprintf(path, MAX_PATH, "%sstealth_plugin.log", tmp);
    FILE *fp = fopen(path, "a");
    if (fp) {
        fprintf(fp, "[INJ-005] %s\n", msg);
        fclose(fp);
    }
}

static void execute_section_mapping(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        write_plugin_log("Failed to get ntdll.dll handle");
        return;
    }
    
    NtCreateSection_t NtCreateSection = (NtCreateSection_t)GetProcAddress(ntdll, "NtCreateSection");
    NtMapViewOfSection_t NtMapViewOfSection = (NtMapViewOfSection_t)GetProcAddress(ntdll, "NtMapViewOfSection");
    NtUnmapViewOfSection_t NtUnmapViewOfSection = (NtUnmapViewOfSection_t)GetProcAddress(ntdll, "NtUnmapViewOfSection");
    NtClose_t NtClose = (NtClose_t)GetProcAddress(ntdll, "NtClose");
    
    if (!NtCreateSection || !NtMapViewOfSection || !NtUnmapViewOfSection || !NtClose) {
        write_plugin_log("Failed to resolve NT APIs");
        return;
    }
    
    HANDLE sectionHandle = NULL;
    LARGE_INTEGER maxSize;
    maxSize.QuadPart = 4096;
    
    // Create section object
    NTSTATUS status = NtCreateSection(
        &sectionHandle,
        SECTION_MAP_WRITE | SECTION_MAP_READ | SECTION_MAP_EXECUTE,
        NULL,
        &maxSize,
        PAGE_EXECUTE_READWRITE,
        SEC_COMMIT,
        NULL
    );
    
    if (status != STATUS_SUCCESS || !sectionHandle) {
        write_plugin_log("NtCreateSection failed");
        return;
    }
    
    write_plugin_log("Section object created");
    
    // Map view into current process
    PVOID baseAddress = NULL;
    SIZE_T viewSize = 4096;
    
    status = NtMapViewOfSection(
        sectionHandle,
        GetCurrentProcess(),
        &baseAddress,
        0,
        0,
        NULL,
        &viewSize,
        ViewUnmap,
        0,
        PAGE_EXECUTE_READWRITE
    );
    
    if (status == STATUS_SUCCESS && baseAddress) {
        char logbuf[256];
        snprintf(logbuf, sizeof(logbuf), "View mapped at 0x%p (size: %zu bytes)", baseAddress, viewSize);
        write_plugin_log(logbuf);
        
        // Unmap view
        NtUnmapViewOfSection(GetCurrentProcess(), baseAddress);
        write_plugin_log("View unmapped");
    } else {
        write_plugin_log("NtMapViewOfSection failed");
    }
    
    NtClose(sectionHandle);
    write_plugin_log("Section view mapping completed");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        write_plugin_log("Plugin loaded");
        execute_section_mapping();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
