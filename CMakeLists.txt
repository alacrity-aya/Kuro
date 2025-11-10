cmake_minimum_required(VERSION 3.10)
project(wirefisher)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# 查找 yaml-cpp
find_package(yaml-cpp REQUIRED)

include(FetchContent)
FetchContent_Declare(
    tomlplusplus
    GIT_REPOSITORY https://github.com/marzer/tomlplusplus.git
    GIT_TAG v3.4.0
)
FetchContent_MakeAvailable(tomlplusplus)

# 查找 libbpf、libelf、zlib
find_library(LIBBPF_LIB   bpf   REQUIRED)
find_library(ELF_LIB      elf   REQUIRED)
find_library(ZLIB_LIB     z     REQUIRED)

# 查找 libbpf 头文件（bpf/libbpf.h）
find_path(LIBBPF_INCLUDE_DIR NAMES bpf/libbpf.h REQUIRED)


# 添加可执行文件，按目录组织源文件
add_executable(wirefisher
  # src/main.cpp
  # src/kafka_producer.cpp
  modules/process_module.cpp
  # modules/ip_pro_port_module.cpp
  # modules/eth_module.cpp
  # modules/cgroup_module.cpp
  main.cpp
)

target_include_directories(
  wirefisher
  PRIVATE
  ${LIBBPF_INCLUDE_DIR}   # libbpf
  ${CMAKE_SOURCE_DIR}
)


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

