#include <windows.h>
#include <stdio.h>
 #ifndef ALLOW_CONSOLE_PRINTS
 #define printf(...) ((void)0)
 #define fprintf(...) ((void)0)
 #define puts(...) ((void)0)
 #define putchar(...) ((void)0)
 #define perror(...) ((void)0)
 #endif
int main(void){
    char tmp[MAX_PATH];
    if (!GetTempPathA(MAX_PATH,tmp)) return 1;
    char f[MAX_PATH];
    sprintf(f, "%slogtest.tmp", tmp);
    HANDLE h = CreateFileA(f, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h==INVALID_HANDLE_VALUE) return 2;
    const char *s = "hello\n";
    DWORD w; WriteFile(h, s, (DWORD)strlen(s), &w, NULL);
    CloseHandle(h);
    return 0;
}
