// persistence.h - cross-platform persistence API
#pragma once

#include <stdint.h>

typedef enum {
    PERSIST_NONE = 0,
    PERSIST_STARTUP_FOLDER = 1,
    PERSIST_REGISTRY_RUN = 2,
    PERSIST_SCHEDULED_TASK = 3,
    // future: systemd, crontab, launchd, etc.
} PersistenceType;

typedef struct {
    PersistenceType type;
    uint8_t option;    // variant for a method if needed
    uint32_t reserved; // reserved for future flags
    char human[64];    // optional debug description
} PersistenceOpts;

// Create persistence according to opts. Return 0 on success, non-zero on failure.
int create_persistence(const PersistenceOpts *opts);
