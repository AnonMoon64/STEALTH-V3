// For the test harness we enable file logs and console prints so test output is visible
#define ENABLE_FILE_LOGS 1
#define ALLOW_CONSOLE_PRINTS 1
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include "plugin.h"

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <plugin_dir>\n", argv[0]);
        return 1;
    }
    // Set environment variable to tell plugin_loader to load from this dir
    // Use CRT _putenv_s so that getenv() within this process sees the change.
    _putenv_s("PLUGIN_TEST_DIR", argv[1]);
    printf("PLUGIN_TEST_DIR=%s\n", argv[1]);
    const char *got = getenv("PLUGIN_TEST_DIR");
    printf("getenv(PLUGIN_TEST_DIR) -> %s\n", got ? got : "(null)");
    (void)got;

    // Initialize loader (key_hex NULL -> plaintext test mode)
    int r = plugin_loader_init(NULL);
    printf("plugin_loader_init -> %d\n", r);
    (void)r;

    int fired = plugin_fire_stage(PLUGIN_STAGE_PRELAUNCH);
    printf("Fired PRELAUNCH plugins: %d\n", fired);
    fired = plugin_fire_stage(PLUGIN_STAGE_POSTLAUNCH);
    printf("Fired POSTLAUNCH plugins: %d\n", fired);
    fired = plugin_fire_stage(PLUGIN_STAGE_PREINJECT);
    printf("Fired PREINJECT plugins: %d\n", fired);
    fired = plugin_fire_stage(PLUGIN_STAGE_ONFAIL);
    printf("Fired ONFAIL plugins: %d\n", fired);
    fired = plugin_fire_stage(PLUGIN_STAGE_ONEXIT);
    printf("Fired ONEXIT plugins: %d\n", fired);
    (void)fired;

    return 0;
}
