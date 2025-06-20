###############################################################################
# Makefile for Clang (MinGW) on Windows or cross-compiling from Linux
# DO NOT MODIFY THIS FILE UNLESS YOU KNOW WHAT YOU ARE DOING
###############################################################################

# ───────────────────────────────────────────────────────────────────────────────
# 1. Toolchain – Clang/LLD cross‑targeting MinGW‑w64
# ───────────────────────────────────────────────────────────────────────────────
.SUFFIXES:


TARGET_TRIPLE ?= x86_64-w64-mingw32
CLANG ?= clang --target=$(TARGET_TRIPLE) -fuse-ld=lld

# MinGW‑w64 include / lib helper paths (auto‑detect the GCC win32 subtree)
GCC_WIN32_PATH := $(shell find /usr/lib/gcc/$(TARGET_TRIPLE)/ -type d -name "*win32" | head -n 1)
INCLUDE_DIR     := /usr/$(TARGET_TRIPLE)/include
INCLUDE         := -I$(INCLUDE_DIR)
LIBPATH         := -L$(GCC_WIN32_PATH)

# ───────────────────────────────────────────────────────────────────────────────
# 2. Build format selector (EXE is default)
# ───────────────────────────────────────────────────────────────────────────────
FORMAT ?= EXE                  # { EXE | DLL }

# ───────────────────────────────────────────────────────────────────────────────
# 3. Source files
# ───────────────────────────────────────────────────────────────────────────────
COMMON_SRCS := \
	api_hashing.c \
	download.c     \
	inject.c       \
	unhook.c       \
	whispers.c

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
CFLAGS_BASE  := -O0 -Wall -w -fms-extensions -fdeclspec -static
LDFLAGS_BASE := -Wl,--disable-auto-import -s
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
.PHONY: all exe dll clean

all: $(TARGET)

exe:
	$(MAKE) FORMAT=EXE

dll:
	$(MAKE) FORMAT=DLL

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