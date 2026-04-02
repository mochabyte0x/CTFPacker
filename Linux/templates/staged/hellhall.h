/*
 * hellhall.h
 *
 * Hell's Hall: indirect syscalls via SSN discovery + ntdll syscall-instruction
 * trampoline. Adapted from Hell's Hall (MalDevAcademy).
 *
 * Drop-in replacement for SysWhispers3.
 * Exports NTAVM / NTPVM / NTWVM / NTQAT with the same signatures.
 */
#pragma once

#include <windows.h>

/* -------------------------------------------------------------------------- */
/* Primitive types used internally                                             */
/* -------------------------------------------------------------------------- */
typedef unsigned char      hh_u8;
typedef unsigned int       hh_u32;

/* -------------------------------------------------------------------------- */
/* CRC32b hash (Castagnoli, SEED = 0xEDB88320)                                */
/* -------------------------------------------------------------------------- */
#define HH_SEED  0xEDB88320u
#define HH_RANGE 0x1E           /* max bytes to search forward for syscall    */

hh_u32 HH_Crc32b(const hh_u8 *str);
#define HASH(s) HH_Crc32b((const hh_u8 *)(s))

/* Precomputed CRC32b hashes — verified: HASH("NtXxx") == constant below     */
#define HH_HASH_NtAllocateVirtualMemory  0xE0762FEBu
#define HH_HASH_NtProtectVirtualMemory   0x5C2D1A97u
#define HH_HASH_NtWriteVirtualMemory     0xE4879939u
#define HH_HASH_NtQueueApcThread         0x235B0390u

/* -------------------------------------------------------------------------- */
/* SysFunc — one instance per syscall                                          */
/* -------------------------------------------------------------------------- */
typedef struct _SysFunc {
    PVOID   pInst;      /* address of a 'syscall' instruction inside ntdll   */
    PBYTE   pAddress;   /* address of the NT stub in ntdll                   */
    WORD    wSSN;       /* syscall service number                             */
    hh_u32  uHash;      /* CRC32b of the function name                       */
} SysFunc, *PSysFunc;

/* -------------------------------------------------------------------------- */
/* Assembly stubs (whispers-asm.x64.asm)                                       */
/* -------------------------------------------------------------------------- */
EXTERN_C VOID SetConfig(WORD wSSN, PVOID pSyscallInst);
#define SYSCALL(sf) (SetConfig((sf).wSSN, (sf).pInst))

/* -------------------------------------------------------------------------- */
/* NTSTATUS / KNORMAL_ROUTINE (guard against redefinition)                    */
/* -------------------------------------------------------------------------- */
#ifndef _NTDEF_
typedef _Return_type_success_(return >= 0) LONG NTSTATUS;
typedef NTSTATUS *PNTSTATUS;
#endif

#ifndef _KNORMAL_ROUTINE_DEFINED
#define _KNORMAL_ROUTINE_DEFINED
typedef VOID(KNORMAL_ROUTINE)(IN PVOID NormalContext,
                               IN PVOID SystemArgument1,
                               IN PVOID SystemArgument2);
typedef KNORMAL_ROUTINE *PKNORMAL_ROUTINE;
#endif

/* -------------------------------------------------------------------------- */
/* Typed HellHall dispatch stubs (all share the same ASM body)                */
/* -------------------------------------------------------------------------- */
EXTERN_C NTSTATUS HellHall_NtAVM(
    HANDLE ProcessHandle, PVOID *BaseAddress,
    ULONG ZeroBits, PSIZE_T RegionSize,
    ULONG AllocationType, ULONG Protect);

EXTERN_C NTSTATUS HellHall_NtPVM(
    HANDLE ProcessHandle, PVOID *BaseAddress,
    PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);

EXTERN_C NTSTATUS HellHall_NtWVM(
    HANDLE ProcessHandle, PVOID BaseAddress,
    PVOID Buffer, SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten);

EXTERN_C NTSTATUS HellHall_NtQAT(
    HANDLE ThreadHandle, PKNORMAL_ROUTINE ApcRoutine,
    PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3);

/* -------------------------------------------------------------------------- */
/* Hell's Hall C API                                                           */
/* -------------------------------------------------------------------------- */
BOOL HH_InitNtdll(VOID);
BOOL HH_InitSysFunc(IN hh_u32 uHash, OUT PSysFunc psF);
BOOL HH_Initialize(VOID);       /* resolve all 4 syscalls once at startup     */

/* -------------------------------------------------------------------------- */
/* Public wrappers — same signatures as the old SysWhispers3 stubs            */
/* -------------------------------------------------------------------------- */
NTSTATUS NTAVM(
    IN HANDLE ProcessHandle, IN OUT PVOID *BaseAddress,
    IN ULONG ZeroBits, IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType, IN ULONG Protect);

NTSTATUS NTPVM(
    IN HANDLE ProcessHandle, IN OUT PVOID *BaseAddress,
    IN OUT PSIZE_T RegionSize, IN ULONG NewProtect, OUT PULONG OldProtect);

NTSTATUS NTWVM(
    IN HANDLE ProcessHandle, IN PVOID BaseAddress,
    IN PVOID Buffer, IN SIZE_T NumberOfBytesToWrite,
    OUT PSIZE_T NumberOfBytesWritten);

NTSTATUS NTQAT(
    IN HANDLE ThreadHandle, IN PKNORMAL_ROUTINE ApcRoutine,
    IN PVOID ApcArgument1 OPTIONAL,
    IN PVOID ApcArgument2 OPTIONAL,
    IN PVOID ApcArgument3 OPTIONAL);
