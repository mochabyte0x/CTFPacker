###############################################################################
# Makefile for Clang (MinGW) on Windows 
# DO NOT MODIFY THIS FILE UNLESS YOU KNOW WHAT YOU ARE DOING
###############################################################################

# If on Windows/MSYS2, you might have "x86_64-w64-mingw32-clang" 
CLANG    := C:\msys64\mingw64\bin\clang

# Build format selector
# EXE is the default so existing scripts continue to work unchanged.
# -----------------------------------------------------------------------------
FORMAT ?= EXE            # { EXE | DLL }

# -----------------------------------------------------------------------------
# 3. Source files
# -----------------------------------------------------------------------------
COMMON_SRCS := \
    api_hashing.c \
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

# -----------------------------------------------------------------------------
# 4. Assembly helper (Whispers)
# -----------------------------------------------------------------------------
ASM_SRC := whispers-asm.x64.asm
ASM_OBJ := whispers-asm.o
ASFLAGS := -f win64

# -----------------------------------------------------------------------------
# 5. Flags
# -----------------------------------------------------------------------------
CFLAGS_BASE := -O2 -Wall -w -static
LDFLAGS     := -Wl,--disable-auto-import -s
LIBS        := -lwinhttp -lntdll

# DLL nuances: strip -static and add /shared linker options
ifeq ($(FORMAT),DLL)
    CFLAGS := $(filter-out -static,$(CFLAGS_BASE)) -DCTF_AS_DLL
    LDFLAGS += -shared -Wl,--out-implib,libctfloader.a
else
    CFLAGS := $(CFLAGS_BASE)
endif

# -----------------------------------------------------------------------------
# 6. Phony targets
# -----------------------------------------------------------------------------
.PHONY: all exe dll clean

all: $(TARGET)

exe:
	$(MAKE) FORMAT=EXE

dll:
	$(MAKE) FORMAT=DLL

# -----------------------------------------------------------------------------
# 7. Linking & compilation rules
# -----------------------------------------------------------------------------
$(TARGET): $(C_OBJS) $(ASM_OBJ)
	$(CLANG) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

%.o: %.c
	$(CLANG) $(CFLAGS) -c $< -o $@

$(ASM_OBJ): $(ASM_SRC)
	nasm $(ASFLAGS) $< -o $@

# -----------------------------------------------------------------------------
# 8. House‑keeping
# -----------------------------------------------------------------------------
clean:
	rm -f *.o *.obj $(TARGET) libctfloader.a