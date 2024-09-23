#ifndef __DEF_H
#define __DEF_H

#include <Windows.h>

typedef struct __declspec(align(8)) _CUSTOM_PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
	char pad[44];
} CUSTOM_PROCESS_BASIC_INFORMATION,*PCUSTOM_PROCESS_BASIC_INFORMATION;

#endif