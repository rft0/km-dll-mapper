#include <conio.h>

#include "helpers.h"
#include "mmap.h"
#define _WINTERNL_
#include "loader.h"
#include "com.h"

static const char* ascii_art = 
" __  __     __    __     _____     __    __     __    __    \n"
"/\\ \\/ /    /\\ \"-./  \\   /\\  __-.  /\\ \"-./  \\   /\\ \"-./  \\   \n"
"\\ \\  _\"-.  \\ \\ \\-./\\ \\  \\ \\ \\/\\ \\ \\ \\ \\-./\\ \\  \\ \\ \\-./\\ \\  \n"
" \\ \\_\\ \\_\\  \\ \\_\\ \\ \\_\\  \\ \\____-  \\ \\_\\ \\ \\_\\  \\ \\_\\ \\ \\_\\ \n"
"  \\/_/\\/_/   \\/_/  \\/_/   \\/____/   \\/_/  \\/_/   \\/_/  \\/_/ \n";

                                                            

int main(int argc, char* argv[]) {
    Helpers::TerminalInit();

    printf("\n");
    BANNER_BLUE(ascii_art);
    printf("\n");

    BOOL loaded = Com::LoadDeviceHandle(DEVICE_NAME);
    if (!loaded) {
        Loader::EnableCrashHandler();
        Loader::LoadDriver();

        FADED_RED("[+] Vulnerable Driver loaded successfully for mapping custom driver.\n");

        Sleep(1000);

        if (!Com::LoadDeviceHandle(DEVICE_NAME)) {
            FADED_RED("[-] Failed to load custom driver.\n");
            FADED_RED("[+] Terminating...\n");
            Sleep(2000);
            return 1;    
        }

        FADED_RED("[+] Custom driver loaded successfully.\n\n");
    } else {
        FADED_RED("[+] Custom Driver is already loaded.\n");
    }

    char processName[256];
    char dllPath[256];

    if (argc >= 3) {
        strcpy_s(processName, argv[1]);
        strcpy_s(dllPath, argv[2]);

        FADED_BLUE("[+] Process name: %s\n", processName);
        FADED_BLUE("[+] DLL path: %s\n\n", dllPath);
    } else {
        BOOL exists = Helpers::LoadConfigINI("config.ini", processName, dllPath);
        if (!exists) {
            FADED_RED("[-] No configuration file found.\n\n");
            FADED_BLUE("[+] Enter the process name: ");
            scanf_s("%255s", processName, (unsigned)sizeof(processName));

            FADED_BLUE("[+] Enter the DLL path: ");
            scanf_s("%255s", dllPath, (unsigned)sizeof(dllPath));
            if (!Helpers::IsValidDLL(dllPath)) {
                FADED_RED("[-] DLL file not found.\n");
                FADED_RED("[+] Terminating...\n\n");
                Sleep(2000);
                return 1;
            }

            FADED_RED("\n[+] Do you want to save the configuration file? (Y/n): ");
            char saveConfig = _getch();
            FADED_RED("\n\n");
            scanf_s("%c", &saveConfig, (unsigned)sizeof(saveConfig));
            if (saveConfig == '\r' || saveConfig == '\n' || saveConfig == 'y' || saveConfig == 'Y') {
                if (Helpers::SaveConfigINI("config.ini", processName, dllPath))
                    FADED_BLUE("[+] Configuration file saved.\n\n");
                else
                    FADED_BLUE("[-] Failed to save the configuration file.\n");
            }
        } else {
            FADED_BLUE("[+] Configuration file loaded.\n");
            FADED_BLUE("[+] Process name: %s\n", processName);
            FADED_BLUE("[+] DLL path: %s\n\n", dllPath);
        }
    }


    DWORD pid = Helpers::GetPIDFromProcessName(processName);
    if (!pid) {
        FADED_RED("[-] Process \"%s\" not found.\n", processName);
        FADED_RED("[+] Terminating...\n");
        Sleep(2000);
        return 1;
    }

    FADED_RED("[+] Process \"%s\" found. (ID: %lu)\n\n", processName, pid);

    BYTE* pSrcData = NULL;
    DWORD dwSize = 0;
    if (!Helpers::ReadFileToBuffer(dllPath, &pSrcData, &dwSize)) {
        FADED_RED("[-] Failed to read the DLL file.\n");
        FADED_RED("[+] Terminating...\n");
        Sleep(2000);
        return 1;
    }
    
    BOOL status = mmap(pid, pSrcData, dwSize);
    if (!status) {
        FADED_RED("[-] DLL injection failed.\n");
        FADED_RED("[+] Terminating...\n");
        Sleep(2000);
        return 1;
    }

    free(pSrcData);

    FADED_RED("\n[+] DLL mapped into the memory of process successfully.\n");
    FADED_RED("[+] Terminating...\n");

    Sleep(3000);

    return 0;
}