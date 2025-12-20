#include <windows.h>

// Safer popup plugin: spawn a thread on PROCESS_ATTACH to show a MessageBox
// This avoids doing potentially blocking UI work inside DllMain loader lock.

DWORD WINAPI popup_thread(LPVOID lpParam) {
    // Show a topmost informational dialog so it's visible during tests
    // Detach from any console (if present) so the UI appears without a console window.
    FreeConsole();
    MessageBoxA(NULL, "Popup test plugin loaded successfully.", "STEALTH Plugin Test", MB_OK | MB_ICONINFORMATION | MB_SETFOREGROUND | MB_TOPMOST);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // create a thread to show the message box outside the loader lock
        {
            HANDLE h = CreateThread(NULL, 0, popup_thread, NULL, 0, NULL);
            if (h) CloseHandle(h);
        }
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
