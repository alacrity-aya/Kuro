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
find_package(Protobuf REQUIRED) 
find_package(gRPC CONFIG REQUIRED)

# --- 2. System Dependencies (Original Method) ---

# Libbpf (System)
find_library(LIBBPF_LIB NAMES bpf REQUIRED)

# LibElf (System - Reverted per request)
find_library(ELF_LIB names elf REQUIRED)

# Systemd (System - via PkgConfig is safer than raw find_library)
find_package(PkgConfig REQUIRED)
pkg_check_modules(Systemd REQUIRED libsystemd)


# ---------------------------------------------------------
# --- RPC Generation (C++ + Python)
# ---------------------------------------------------------

set(PROTO_FILE ${CMAKE_SOURCE_DIR}/kuro.proto)
set(GENERATED_DIR ${CMAKE_CURRENT_BINARY_DIR})
set(GRPC_GEN_SH ${CMAKE_SOURCE_DIR}/scripts/generate_cc_grpc.sh)
set(PY_GEN_SH   ${CMAKE_SOURCE_DIR}/scripts/generate_python_rpc.sh)

set(RPC_GENERATED_SOURCES
    ${GENERATED_DIR}/${CMAKE_PROJECT_NAME}.pb.cc
    ${GENERATED_DIR}/${CMAKE_PROJECT_NAME}.grpc.pb.cc
    ${GENERATED_DIR}/${CMAKE_PROJECT_NAME}.pb.h
    ${GENERATED_DIR}/${CMAKE_PROJECT_NAME}.grpc.pb.h
)

set_source_files_properties(${RPC_GENERATED_SOURCES} PROPERTIES GENERATED TRUE)

add_custom_command(
    OUTPUT ${RPC_GENERATED_SOURCES}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${GENERATED_DIR}
    COMMAND ${GRPC_GEN_SH} ${PROTO_FILE} ${GENERATED_DIR}
    COMMAND ${PY_GEN_SH}
    DEPENDS ${PROTO_FILE} ${GRPC_GEN_SH} ${PY_GEN_SH} 
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Generating RPC code (C++ + Python)"
    VERBATIM
)

add_custom_target(rpc_gen DEPENDS ${RPC_GENERATED_SOURCES})

# ---------------------------------------------------------
# --- Collect generated C++ RPC .cc files
# ---------------------------------------------------------

set(RPC_GENERATED_SOURCES
    ${GENERATED_DIR}/kuro.pb.cc
    ${GENERATED_DIR}/kuro.grpc.pb.cc
)

# --- Target Definition ---
add_executable(kuro
    main.cpp
    modules/cgroup.cpp
    modules/ip.cpp
    server/server.cpp
    ${RPC_GENERATED_SOURCES}   
)

add_dependencies(kuro rpc_gen bpf_skel)

# --- Custom BPF Target ---
set(BPF_DIR ${CMAKE_SOURCE_DIR}/bpf)
add_custom_target(bpf_skel ALL
    COMMAND make clean && bear --append --output ${CMAKE_BINARY_DIR}/compile_commands.json -- make -B
    WORKING_DIRECTORY ${BPF_DIR}
    COMMENT "Building BPF programs via bpf/Makefile"
    VERBATIM
)

# --- Compile Definitions ---
target_compile_definitions(kuro PRIVATE TOML_EXCEPTIONS=0)

target_include_directories(kuro PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR} # For config.h
    ${CMAKE_SOURCE_DIR}         # Source file
    ${BPF_DIR}/skel             # BPF skel
    ${GENERATED_DIR}            # Rpc
)

# --- Link Libraries ---

target_link_libraries(kuro PRIVATE
    ${LIBBPF_LIB}               # System libbpf
    ${ELF_LIB}                  # System libelf (Original method)
    ZLIB::ZLIB                  # Vcpkg zlib
    tomlplusplus::tomlplusplus  # Vcpkg tomlplusplus
    cpptrace::cpptrace          # Vcpkg cpptrace
    ${Systemd_LIBRARIES}        # System systemd
    gRPC::grpc++                # Vcpkg rpc
    protobuf::libprotobuf       # Vcpkg protobuf
)
