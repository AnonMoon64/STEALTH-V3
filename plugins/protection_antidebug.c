// STEALTH Anti-Debug Plugin (Simplified)
// Stage: PRELAUNCH
// Purpose: Detect debuggers and terminate if found
//
// Set STEALTH_ANTIDEBUG_DEBUG=1 for logging

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>


#pragma comment(lib, "kernel32.lib")

static int g_debug = 0;

static void init_config() {
  char *debug = getenv("STEALTH_ANTIDEBUG_DEBUG");
  g_debug = (debug && debug[0]);
}

static void log_msg(const char *msg) {
  if (!g_debug)
    return;

  char path[MAX_PATH];
  GetTempPathA(sizeof(path), path);
  strcat(path, "stealth_antidebug.log");

  FILE *f = fopen(path, "a");
  if (f) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(f, "[%02d:%02d:%02d] %s\n", st.wHour, st.wMinute, st.wSecond, msg);
    fclose(f);
  }
}

// Check for debugger using multiple methods
static BOOL IsDebuggerActive() {
  // Method 1: IsDebuggerPresent
  if (IsDebuggerPresent()) {
    log_msg("THREAT: IsDebuggerPresent() = TRUE");
    return TRUE;
  }

  // Method 2: CheckRemoteDebuggerPresent
  BOOL remoteDebugger = FALSE;
  if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugger)) {
    if (remoteDebugger) {
      log_msg("THREAT: Remote debugger present");
      return TRUE;
    }
  }

  // Method 3: Timing check (debuggers slow execution)
  LARGE_INTEGER freq, start, end;
  QueryPerformanceFrequency(&freq);
  QueryPerformanceCounter(&start);

  // Simple loop - should complete very fast
  volatile int x = 0;
  for (int i = 0; i < 100000; i++)
    x++;

  QueryPerformanceCounter(&end);
  double elapsed = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;

  // If loop took more than 1 second, likely being debugged/traced
  if (elapsed > 1.0) {
    log_msg("THREAT: Timing anomaly (possible debugger)");
    return TRUE;
  }

  return FALSE;
}

// Run anti-debug checks
static BOOL RunAntiDebugChecks() {
  log_msg("=== ANTI-DEBUG CHECKS ===");

  if (IsDebuggerActive()) {
    log_msg("RESULT: Debugger detected - BLOCKING");
    return FALSE;
  }

  log_msg("RESULT: Environment is SAFE");
  return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
  if (fdwReason == DLL_PROCESS_ATTACH) {
    DisableThreadLibraryCalls(hinstDLL);

    init_config();
    log_msg("Anti-Debug plugin loaded");

    BOOL safe = RunAntiDebugChecks();

    if (!safe) {
      log_msg("CRITICAL: Debugger detected - terminating");
      ExitProcess(0);
    }

    log_msg("Anti-Debug checks passed");
  }

  return TRUE;
}
