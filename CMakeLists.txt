cmake_minimum_required(VERSION 3.26)
project(kuro)

# configuration

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fdiagnostics-color=always")
set(CMAKE_C_FLAGS_DEBUG   "${CMAKE_C_FLAGS_DEBUG} -fdiagnostics-color=always")
set(CMAKE_GENERATOR "Ninja" CACHE STRING "Generator" FORCE)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -O0 -Wall -Wextra")
set(CMAKE_C_FLAGS_DEBUG   "${CMAKE_C_FLAGS_DEBUG} -g -O0 -Wall -Wextra")

# Configure config.h
configure_file(
  config.h.in
  ${CMAKE_CURRENT_BINARY_DIR}/config.h
  @ONLY
)


# User-space executable
add_executable(kuro main.cpp modules/cgroup.cpp)
add_dependencies(kuro bpf_skel)

# Include BPF include directories
target_include_directories(kuro PRIVATE
    ${BPF_INCLUDE_DIRS}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_SOURCE_DIR}
)

# Link libraries: libbpf, elf, zlib, toml++, cpptrace
find_library(LIBBPF_LIB bpf REQUIRED)
find_library(ELF_LIB elf REQUIRED)
find_library(ZLIB_LIB z REQUIRED)

add_compile_definitions(TOML_EXCEPTIONS=0)
include(FetchContent)
FetchContent_Declare(
    tomlplusplus
    GIT_REPOSITORY https://github.com/marzer/tomlplusplus.git
    GIT_TAG v3.4.0
)
FetchContent_MakeAvailable(tomlplusplus)

FetchContent_Declare(
  cpptrace
  GIT_REPOSITORY https://github.com/jeremy-rifkin/cpptrace.git
  GIT_TAG        v1.0.4 # <HASH or TAG>
)
FetchContent_MakeAvailable(cpptrace)

target_link_libraries(kuro PRIVATE
    ${LIBBPF_LIB}
    ${ELF_LIB}
    ${ZLIB_LIB}
    tomlplusplus::tomlplusplus
    cpptrace::cpptrace
)

# BPF Build using Make
set(BPF_DIR ${CMAKE_SOURCE_DIR}/bpf)
add_custom_target(bpf_skel ALL
    COMMAND bear --append --output ../build/compile_commands.json -- make -B
    WORKING_DIRECTORY ${BPF_DIR}
    COMMENT "Building BPF programs via bpf/Makefile"
    VERBATIM
)

target_include_directories(kuro PRIVATE
    ${BPF_DIR}/skel
)
