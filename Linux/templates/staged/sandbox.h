#pragma once
#include <windows.h>

/*
 * RunSandboxChecks — returns TRUE if the environment looks legitimate.
 * Call this early in the entry point; bail out if it returns FALSE.
 */
BOOL RunSandboxChecks(void);
