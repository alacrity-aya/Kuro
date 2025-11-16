ARCH        := x86_64
KHEAD       := $(CURDIR)/kernel-headers/include

CC          := clang
BPF_CFLAGS  := -O2 -g -target bpf -Wno-unknown-attributes
PKG_CFLAGS  := $(shell pkg-config --cflags libbpf)

INCLUDES    := \
	-I$(KHEAD) \
	-I/usr/include \
	-I$(CURDIR)/include \
	-I$(CURDIR)/build   # vmlinux.h 所在目录

SRCS        := $(wildcard src/tc_*.c)
BUILD_DIR   := build
SKEL_DIR    := skel
OBJS        := $(patsubst src/%.c,$(BUILD_DIR)/%.o,$(SRCS))
SKELS       := $(patsubst src/%.c,$(SKEL_DIR)/%.skel.h,$(SRCS))
VMLINUX     := $(BUILD_DIR)/vmlinux.h

.PHONY: all clean

all: $(BUILD_DIR) $(SKEL_DIR) $(VMLINUX) $(OBJS) $(SKELS)

# Create build and skel directories
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(SKEL_DIR):
	mkdir -p $(SKEL_DIR)

# Auto-generate vmlinux.h into build/
$(VMLINUX):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

# Compile .c -> .o into build/
$(BUILD_DIR)/%.o: src/%.c $(BUILD_DIR)/vmlinux.h include/common.h
	$(CC) $(BPF_CFLAGS) $(PKG_CFLAGS) $(INCLUDES) -c $< -o $@

# Generate skeleton headers from .o files into skel/
$(SKEL_DIR)/%.skel.h: $(BUILD_DIR)/%.o
	bpftool gen skeleton $< > $@

# Clean all build artifacts
clean:
	rm -rf $(BUILD_DIR) $(SKEL_DIR)
