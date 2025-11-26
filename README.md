<div align="center">
    <h2>kuro: the project is still in progress...</h2>
</div>


## TODO:

- bps <---> Bps is chaotic
- using smoothrate to improve flow limit
- adding eth port module
- making the volume of token bucket configurable
- `libbpf: Kernel error message: Exclusivity flag on, cannot modify`


---

<div align="center">          
    <img src="assert/kuro.png" alt="kuro CG" width="70%">
</div>


---

# **Kuro**

Kuro is a userspace application built on top of eBPF.
This project uses **CMake** and **vcpkg** for dependency management and **Ninja** as the build generator.

---

# Prerequisites

This project uses a **hybrid dependency management model**:

* **vcpkg** → application-level C++ libraries
* **System package manager** → low-level system libraries & tools (eBPF ecosystem)

Before compiling, ensure your system satisfies the following requirements.

---

# **1. System-level Dependencies (Manual Installation)**

The following libraries/tools **are NOT managed by vcpkg** and must be installed via your system package manager:

| Component        | Description                | Usage                                     |
| ---------------- | -------------------------- | ----------------------------------------- |
| **libbpf**       | eBPF core library          | Loading and interacting with BPF programs |
| **libelf**       | ELF handling library       | Parsing ELF files (dependency of libbpf)  |
| **libsystemd**   | Systemd library            | System service integration                |
| **Clang / LLVM** | Compiler suite             | Compiling BPF C code                      |
| **bpftool**      | BPF tool                   | Generating `.skel.h` skeleton headers     |
| **Bear**         | compile_commands.json tool | Recording compilation for BPF Makefile    |
| **Ninja**        | Build backend for CMake    | Faster parallel builds                    |
| **PkgConfig**    | Package discovery          | Let CMake locate system libraries         |

---

## Installation Commands

### **Ubuntu / Debian**

```bash
sudo apt update
sudo apt install -y \
    build-essential cmake ninja-build pkg-config \
    clang llvm \
    libbpf-dev libelf-dev libsystemd-dev \
    linux-tools-$(uname -r) linux-tools-common \
    bear
```

> Note: `bpftool` is included in the `linux-tools` packages.

---

### **Fedora / RHEL**

```bash
sudo dnf install -y \
    cmake ninja-build pkgconf \
    clang llvm bpftool \
    libbpf-devel elfutils-libelf-devel systemd-devel \
    bear
```

---

### **Arch Linux**

```bash
sudo pacman -S --needed \
    base-devel cmake ninja pkgconf \
    clang llvm bpftool \
    libbpf libelf systemd \
    bear
```

---

# **2. vcpkg Dependencies (Automated)**

These dependencies are automatically installed via `vcpkg.json`:

* **tomlplusplus** – Configuration parsing
* **cpptrace** – Stack traces
* **zlib** – Compression support

Before building, ensure `vcpkg` is installed and the root path is set:

```bash
export VCPKG_ROOT=/path/to/your/vcpkg
```

---

# Build Instructions

This project uses **CMake Presets**, providing a fully reproducible build environment.

> A **custom vcpkg triplet** (`triplets/x64-linux-kuro.cmake`) is used
> to ensure all dependencies respect `TOML_EXCEPTIONS=0`.

---

## **1. Configure**

```bash
cmake --preset debug
```

This will automatically:

* Boot vcpkg
* Build dependencies using the custom triplet
* Generate the build tree

---

## **2. Build**

```bash
cmake --build --preset debug
```

Artifacts will be located in:

```
build/debug/
```

---

# Technical Notes

### **1. Exception Handling Synchronization**

The project uses:

```
TOML_EXCEPTIONS=0
```

To avoid ABI inconsistencies, the custom triplet forces:

* `toml++`
* `cpptrace`
* other C++ dependencies

to compile with the *exact same flags*.

---

### **2. BPF Build Pipeline**

BPF programs live under:

```
bpf/
```

During the build:

1. `make` compiles `.bpf.c` programs
2. `bpftool gen skeleton <obj>` creates the `.skel.h` headers
3. CMake links everything into the final executable

This process is fully automated through the `bpf_skel` custom CMake target.

---
