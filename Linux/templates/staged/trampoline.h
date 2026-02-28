#pragma once
#include <windows.h>

/*
 * trampoline.h
 *
 * AMSI & ETW bypass via x64 trampoline hooks.
 * Adapted from TrampoLatté (github.com/MochaByte/TrampoLatte).
 *
 * InstallTrampolines
 *   bypassAmsi  – hook AmsiScanBuffer -> always return AMSI_RESULT_CLEAN
 *   bypassEtw   – hook EtwpEventWriteFull -> silent no-op return
 *
 * Returns TRUE on success (or when both flags are FALSE).
 */
BOOL InstallTrampolines(BOOL bypassAmsi, BOOL bypassEtw);
