###############################################################################
# Makefile for Clang (MinGW) on Windows or cross-compiling from Linux
# DO NOT MODIFY THIS FILE UNLESS YOU KNOW WHAT YOU ARE DOING
###############################################################################

TARGET_TRIPLE := x86_64-w64-mingw32

# If on Windows/MSYS2, you might have "x86_64-w64-mingw32-clang" 
CLANG    := clang --target=$(TARGET_TRIPLE) -fuse-ld=lld

# Compile flags for C source
CFLAGS   := -static -O0 -Wall -w -fms-extensions -fdeclspec

LDFLAGS  := -Wl,--disable-auto-import -s

# MinGW-w64 include/lib paths
GCC_WIN32_PATH := $(shell find /usr/lib/gcc/$(TARGET_TRIPLE)/ -type d -name "*win32" | head -n 1)
INCLUDE  := -I/usr/$(TARGET_TRIPLE)/include
LIBPATH := -L$(GCC_WIN32_PATH)

# Libraries needed:
LIBS     := -lwinhttp -lntdll

# NASM flags
ASFLAGS  := -f win64  # produce 64-bit COFF objects

# List all your C source files here:
C_SRCS := \
	api_hashing.c \
	download.c \
	inject.c \
	main.c \
	unhook.c \
	whispers.c

# Corresponding .o object files
C_OBJS := $(C_SRCS:.c=.o)

# Assembly source and its object
ASM_SRC := whispers-asm.x64.asm
ASM_OBJ := whispers-asm.o

# Final executable name
TARGET  := ctfloader.exe

###############################################################################
# Default rule: build the final .exe
###############################################################################
all: $(TARGET)

# Link rule: combine all object files into final .exe
$(TARGET): $(C_OBJS) $(ASM_OBJ)
	$(CLANG) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBPATH) $(LIBS)

###############################################################################
# Compile each .c -> .o
###############################################################################
%.o: %.c
	$(CLANG) $(CFLAGS) $(INCLUDE) -c $< -o $@

###############################################################################
# Assemble NASM .asm -> .o
###############################################################################
$(ASM_OBJ): $(ASM_SRC)
	nasm $(ASFLAGS) $< -o $@

###############################################################################
# Housekeeping
###############################################################################
.PHONY: clean
clean:
	rm -f *.o *.obj $(TARGET)