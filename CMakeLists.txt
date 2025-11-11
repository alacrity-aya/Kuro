cmake_minimum_required(VERSION 3.10)
project(wirefisher)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_compile_definitions(TOML_EXCEPTIONS=0)

include(FetchContent)
FetchContent_Declare(
    tomlplusplus
    GIT_REPOSITORY https://github.com/marzer/tomlplusplus.git
    GIT_TAG v3.4.0
)
FetchContent_MakeAvailable(tomlplusplus)

find_library(LIBBPF_LIB   bpf   REQUIRED)
find_library(ELF_LIB      elf   REQUIRED)
find_library(ZLIB_LIB     z     REQUIRED)

find_path(LIBBPF_INCLUDE_DIR NAMES bpf/libbpf.h REQUIRED)


add_executable(wirefisher
  main.cpp
)

target_include_directories(
  wirefisher
  PRIVATE
  ${LIBBPF_INCLUDE_DIR}   # libbpf
  ${CMAKE_SOURCE_DIR}
  ${CMAKE_SOURCE_DIR}/bpf/skel # skel
)

target_compile_definitions(wirefisher PRIVATE TOML_EXCEPTIONS=0)

# 链接所需库
target_link_libraries(wirefisher
    PRIVATE
    tomlplusplus::tomlplusplus
    ${LIBBPF_LIB}
    ${ELF_LIB}
    ${ZLIB_LIB}
)

find_package(PkgConfig REQUIRED)
pkg_check_modules(RDKAFKA REQUIRED rdkafka)
target_link_libraries(wirefisher PRIVATE ${RDKAFKA_LIBRARIES})
target_include_directories(wirefisher PRIVATE ${RDKAFKA_INCLUDE_DIRS})

