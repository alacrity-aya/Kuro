ARCH        := x86_64
KHEAD       := $(CURDIR)/kernel-headers/include

CC          := clang
BPF_CFLAGS  := -O2 -g -target bpf -Wno-unknown-attributes
PKG_CFLAGS  := $(shell pkg-config --cflags libbpf)

INCLUDES    := \
	-I$(KHEAD) \
	-I/usr/include \
	-I/usr/include/$(shell dpkg-architecture -q DEB_HOST_MULTIARCH)

SRCS        := $(wildcard tc_*.c)
BUILD_DIR   := build
SKEL_DIR    := skel
OBJS        := $(patsubst %.c,$(BUILD_DIR)/%.o,$(SRCS))
SKELS       := $(patsubst %.c,$(SKEL_DIR)/%.skel.h,$(SRCS))

.PHONY: all clean

all: $(BUILD_DIR) $(SKEL_DIR) vmlinux.h $(OBJS) $(SKELS)

# Create build directory for object files
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Create skel directory for skeleton headers
$(SKEL_DIR):
	mkdir -p $(SKEL_DIR)

# Auto-generate vmlinux.h from kernel BTF
vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Compile .c -> .o into build/
$(BUILD_DIR)/%.o: %.c vmlinux.h common.h
	$(CC) $(BPF_CFLAGS) $(PKG_CFLAGS) $(INCLUDES) -c $< -o $@

# Generate skeleton headers from .o files into skel/
$(SKEL_DIR)/%.skel.h: $(BUILD_DIR)/%.o
	bpftool gen skeleton $< > $@

# Clean all build artifacts
clean:
	rm -rf $(BUILD_DIR) $(SKEL_DIR) vmlinux.h
