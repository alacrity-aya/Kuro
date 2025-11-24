cmake_minimum_required(VERSION 3.26)
project(kuro)

# --- Config.h Generation ---
configure_file(
  config.h.in
  ${CMAKE_CURRENT_BINARY_DIR}/config.h
  @ONLY
)

# --- 1. Vcpkg Managed Dependencies ---
# vcpkg automatically handles these paths via the toolchain file
find_package(tomlplusplus CONFIG REQUIRED)
find_package(cpptrace CONFIG REQUIRED)
find_package(ZLIB REQUIRED) # Vcpkg provides ZLIB compatible wrapper

# --- 2. System Dependencies (Original Method) ---

# Libbpf (System)
find_library(LIBBPF_LIB NAMES bpf REQUIRED)

# LibElf (System - Reverted per request)
find_library(ELF_LIB names elf REQUIRED)

# Systemd (System - via PkgConfig is safer than raw find_library)
find_package(PkgConfig REQUIRED)
pkg_check_modules(Systemd REQUIRED libsystemd)

# --- Target Definition ---

add_executable(kuro main.cpp modules/cgroup.cpp modules/ip.cpp)

# --- Custom BPF Target ---
set(BPF_DIR ${CMAKE_SOURCE_DIR}/bpf)
add_custom_target(bpf_skel ALL
    COMMAND make clean && bear --append --output ${CMAKE_BINARY_DIR}/compile_commands.json -- make -B
    WORKING_DIRECTORY ${BPF_DIR}
    COMMENT "Building BPF programs via bpf/Makefile"
    VERBATIM
)

add_dependencies(kuro bpf_skel)

# --- Compile Definitions & Includes ---

# --- Compile Definitions ---
target_compile_definitions(kuro PRIVATE TOML_EXCEPTIONS=0)

target_include_directories(kuro PRIVATE
    ${BPF_INCLUDE_DIRS}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_SOURCE_DIR}
    ${BPF_DIR}/skel
)

# --- Link Libraries ---

target_link_libraries(kuro PRIVATE
    ${LIBBPF_LIB}               # System libbpf
    ${ELF_LIB}                  # System libelf (Original method)
    ZLIB::ZLIB                  # Vcpkg zlib
    tomlplusplus::tomlplusplus  # Vcpkg tomlplusplus
    cpptrace::cpptrace          # Vcpkg cpptrace
    ${Systemd_LIBRARIES}        # System systemd
)
