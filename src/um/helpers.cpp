#include "helpers.h"

DWORD Helpers::GetPIDFromProcessName(const char* processName) {
    DWORD pid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnap, &pe32)) {
            do {
                if (strcmp(pe32.szExeFile, processName) == 0) {
                    pid = pe32.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &pe32));
        }
        CloseHandle(hSnap);
    }

    return pid;
}

BOOL Helpers::IsProcessRunning(DWORD pid) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnap, &pe32)) {
            do {
                if (pe32.th32ProcessID == pid) {
                    CloseHandle(hSnap);
                    return TRUE;
                }
            } while (Process32Next(hSnap, &pe32));
        }
        CloseHandle(hSnap);
    }

    return FALSE;
}

BOOL Helpers::ReadFileToBuffer(const char* filePath, BYTE** ppBuffer, DWORD* pSize) {
    HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    DWORD dwFileSize = GetFileSize(hFile, NULL);
    if (dwFileSize == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return FALSE;
    }

    BYTE* pBuffer = (BYTE*)malloc(dwFileSize);
    if (!pBuffer) {
        CloseHandle(hFile);
        return FALSE;
    }

    DWORD dwBytesRead = 0;
    if (!ReadFile(hFile, pBuffer, dwFileSize, &dwBytesRead, NULL)) {
        free(pBuffer);
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);

    *ppBuffer = pBuffer;
    *pSize = dwFileSize;

    return TRUE;
}

BOOL Helpers::LoadConfigINI(const char* filePath, char* processName, char* dllPath) {
    char absPath[MAX_PATH];
    if (GetFullPathNameA(filePath, MAX_PATH, absPath, NULL) == 0)
        return FALSE;

    if (!IsFileExists(absPath))
        return FALSE;

    const int bufferSize = 256;
    char processBuffer[bufferSize];
    char dllBuffer[bufferSize];

    DWORD processLen = GetPrivateProfileStringA("Settings", "ProcessName", "", processBuffer, bufferSize, absPath);
    if (processLen > 0 && processLen < bufferSize)
        strcpy_s(processName, bufferSize, processBuffer);
    else
        return FALSE;

    DWORD dllLen = GetPrivateProfileStringA("Settings", "DllPath", "", dllBuffer, bufferSize, absPath);
    if (dllLen > 0 && dllLen < bufferSize)
        strcpy_s(dllPath, bufferSize, dllBuffer);
    else
        return FALSE;

    return TRUE;
}

BOOL Helpers::SaveConfigINI(const char* filePath, const char* processName, const char* dllPath) {
    char absPath[MAX_PATH];
    if (GetFullPathNameA(filePath, MAX_PATH, absPath, NULL) == 0)
        return FALSE;

    if (!IsFileExists(absPath)) {
        HANDLE hFile = CreateFileA(absPath, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE)
            return FALSE;

        CloseHandle(hFile);
    }

    BOOL status = WritePrivateProfileStringA("Settings", "ProcessName", processName, absPath);
    if (!status)
        return FALSE;

    status = WritePrivateProfileStringA("Settings", "DllPath", dllPath, absPath);
    if (!status)
        return FALSE;

    return TRUE;
}

BOOL Helpers::IsFileExists(const char* filePath) {
    DWORD dwAttrib = GetFileAttributesA(filePath);
    return (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

BOOL Helpers::IsValidDLL(const char* filePath) {
    HANDLE hFile = CreateFileA(filePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;

    BYTE buffer[4];
    DWORD dwBytesRead = 0;

    if (!ReadFile(hFile, buffer, 4, &dwBytesRead, NULL) || dwBytesRead < 4) {
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);

    if (buffer[0] == 0x4D || buffer[1] == 0x5A)
        return TRUE;

    return FALSE;
}

VOID Helpers::TerminalInit() {
    SetConsoleTitle(CONSOLE_TITLE);

    HANDLE hcons = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hcons == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Error getting console handle. Error code: %lu\n", GetLastError());
        return;
    }

    DWORD dw_mode = 0;
    if (GetConsoleMode(hcons, &dw_mode)) {
        dw_mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(hcons, dw_mode);
    }

    HWND hwnd_console = GetConsoleWindow();
    if (hwnd_console == NULL) {
        fprintf(stderr, "Error getting console window handle. Error code: %lu\n", GetLastError());
        return;
    }

    RECT rect;
    GetWindowRect(hwnd_console, &rect);
    int console_width = rect.right - rect.left;
    int console_height = rect.bottom - rect.top;
    
    int display_width = GetSystemMetrics(SM_CXSCREEN);
    int display_height = GetSystemMetrics(SM_CYSCREEN);

    int c_x = (display_width - console_width) / 2;
    int c_y = (display_height - console_height) / 2;

    SetWindowPos(hwnd_console, HWND_TOPMOST, c_x, c_y, 0, 0, SWP_NOSIZE | SWP_NOACTIVATE | SWP_FRAMECHANGED);

    LONG style = GetWindowLong(hwnd_console, GWL_STYLE);
    SetWindowLong(hwnd_console, GWL_STYLE, style & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX & ~WS_MINIMIZEBOX);

    style = GetWindowLong(hwnd_console, GWL_EXSTYLE);
    SetWindowLong(hwnd_console, GWL_EXSTYLE, style | WS_EX_LAYERED);
    SetLayeredWindowAttributes(hwnd_console, 0, (BYTE)(255 * CONSOLE_OPACITY), LWA_ALPHA);
}

inline static int BoundColor(int c) {
    return (c < 0) ? 0 : (c > 255) ? 255 : c;
}

VOID Helpers::FadedPrint(int r, int g, int b, int dr, int dg, int db, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);

    size_t fmtd_size = vsnprintf(NULL, 0, fmt, args) + 1;
    char* fmtd = (char*)malloc(fmtd_size);
    if (!fmtd) {
        va_end(args);
        return;
    }

    vsnprintf(fmtd, fmtd_size, fmt, args);

    va_end(args);

    size_t buffer_size = 1024;
    char* buffer = (char*)malloc(buffer_size);
    if (!buffer)
        return;

    int tr = r, tg = g, tb = b;

    char* p = buffer;
    const char* s = fmtd;
    while (*s) {
        if (*s == '\n') {
            p += sprintf(p, "\n");
            s++;
            tr = r;
            tg = g;
            tb = b;
            continue;
        }
        
        if (p - buffer + 64  >= buffer_size) {
            int written = p - buffer;

            buffer_size *= 2;
            buffer = (char*)realloc(buffer, buffer_size);
            if (!buffer)
                return;

            p = buffer + written;
        }

        p += sprintf(p, "\033[38;2;%d;%d;%dm%c", tr, tg, tb, *s);

        if (dr != 0)
            tr = BoundColor(tr + dr);
        if (dg != 0)
            tg = BoundColor(tg + dg);
        if (db != 0)
            tb = BoundColor(tb + db);

        s++;
    }

    p += sprintf(p, "\033[0m");
    *p = '\0';

    printf("%s", buffer);
    free(buffer);
    free(fmtd);

    return;
}

VOID Helpers::FadedBanner(int r, int g, int b, int dr, int dg, int db, const char* fmtd) {
    int tr = r, tg = g, tb = b;

    const char* s = fmtd;
    while (*s) {
        const char* eol = strchr(s, '\n');
        if (!eol)
            eol = s + strlen(s);
        
        printf("\033[38;2;%d;%d;%dm", tr, tg, tb);
        while (s < eol) {
            putchar(*s);
            s++;
        }
        printf("\033[0m\n");

        if (dr != 0)
            tr = BoundColor(tr + dr);
        if (dg != 0)
            tg = BoundColor(tg + dg);
        if (db != 0)
            tb = BoundColor(tb + db);

        if (*eol == '\n')
            eol++;

        s = eol;
    }

    printf("\033[0m\n");

    return;
}