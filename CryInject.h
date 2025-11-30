#pragma once
#include <Windows.h>

PVOID CryShellInject(HANDLE hProcess, unsigned char* shellcode, SIZE_T shellsize);
PVOID CryEntryPatch(HANDLE hProcess, LPVOID BaseAddress, PVOID shellcodeaddress);