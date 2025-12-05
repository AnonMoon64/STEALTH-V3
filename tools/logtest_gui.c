#include <windows.h>
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrev, LPSTR lpCmdLine, int nShowCmd) {
    char tmp[MAX_PATH];
    if (!GetTempPathA(MAX_PATH,tmp)) return 1;
    char f[MAX_PATH];
    wsprintfA(f, "%slogtest_gui.tmp", tmp);
    HANDLE h = CreateFileA(f, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h==INVALID_HANDLE_VALUE) return 2;
    const char *s = "hello_gui\n";
    DWORD w; WriteFile(h, s, (DWORD)strlen(s), &w, NULL);
    CloseHandle(h);
    return 0;
}
