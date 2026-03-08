# -*- coding: utf-8 -*-
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class BuildConfig:
    """All parameters needed for a CTFPacker build."""

    # Core
    mode: str = "staged"                    # "staged" or "stageless"
    payload_path: str = ""                  # Path to .bin shellcode
    format: str = "EXE"                     # "EXE" or "DLL"
    inject_method: str = "apc"              # "apc", "copyfile2", "tp_direct", "wf_overwrite", "timerqueue"
    target_process: str = "RuntimeBroker.exe"  # APC target process
    output: str = "ctfloader"               # Output base name

    # Options
    encrypt: bool = False
    scramble: bool = False
    unhook: bool = True              # NTDLL unhooking via Known DLLs
    entropy_reduction: bool = False
    sandbox_checks: bool = False     # pre-flight uptime/RAM/CPU checks
    sandbox_min_uptime_s: int = 300   # minimum system uptime in seconds
    sandbox_min_ram_gb: int = 4       # minimum physical RAM in GB
    sandbox_min_cpu: int = 2          # minimum logical CPU count

    # Trampoline hooks (TrampoLatté)
    bypass_amsi: bool = False    # hook AmsiScanBuffer -> AMSI_RESULT_CLEAN
    bypass_etw: bool  = False    # hook EtwpEventWriteFull -> no-op RET

    # Debug
    debug_mode: bool = False     # enable OutputDebugString prints in trampoline.c

    # Staged-only: network
    ip_address: str = ""
    port: int = 8080
    path: str = ""
    https: bool = False
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )

    # Code signing
    pfx: Optional[str] = None
    pfx_password: Optional[str] = None
    sign_description: str = ""   # authenticode program name (-n in osslsigncode)
    sign_url: str = ""           # authenticode program URL  (-i in osslsigncode)

    def to_dict(self) -> dict:
        return asdict(self)

    def to_safe_dict(self) -> dict:
        """Like to_dict but strips sensitive fields that should never be persisted."""
        d = asdict(self)
        d.pop("pfx_password", None)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "BuildConfig":
        # Filter out unknown keys for forward-compat
        valid = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{k: v for k, v in d.items() if k in valid})
