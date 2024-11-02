#ifndef __HELPERS_H
#define __HELPERS_H

#include <Windows.h>
#include <TlHelp32.h>
#include <cstdio>

#define FADED_RED(fmt, ...) Helpers::FadedPrint(255, 255, 0, 0, -4, 0, fmt, ##__VA_ARGS__)
#define FADED_GREEN(fmt, ...) Helpers::FadedPrint(100, 75, 200, -4, 8, -4, fmt, ##__VA_ARGS__)
#define FADED_BLUE(fmt, ...) Helpers::FadedPrint(0, 255, 255, 0, 0, 8, fmt, ##__VA_ARGS__)

#define BANNER_RED(fmtd) Helpers::FadedBanner(255, 255, 0, 0, -32, 0, fmtd)
#define BANNER_GREEN(fmtd) Helpers::FadedBanner(255, 0, 255, 0, 32, 0, fmtd)
#define BANNER_BLUE(fmtd) Helpers::FadedBanner(0, 255, 160, 0, 0, 32, fmtd)

#define CONSOLE_TITLE "[~] github.com/rft0/km-dll-mapper"
#define CONSOLE_OPACITY 0.9f

namespace Helpers {
    DWORD GetPIDFromProcessName(const char* processName);

    BOOL IsProcessRunning(DWORD pid);
    BOOL ReadFileToBuffer(const char* filePath, BYTE** ppBuffer, DWORD* pSize);

    BOOL LoadConfigINI(const char* filePath, char* processName, char* dllPath);
    BOOL SaveConfigINI(const char* filePath, const char* processName, const char* dllPath);

    BOOL IsFileExists(const char* filePath);
    BOOL IsValidDLL(const char* filePath);

    VOID TerminalInit();

    VOID FadedPrint(int r, int g, int b, int dr, int dg, int db, const char* fmt, ...);
    VOID FadedBanner(int r, int g, int b, int dr, int dg, int db, const char* fmtd);
}

#endif