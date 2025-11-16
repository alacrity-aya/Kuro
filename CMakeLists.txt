cmake_minimum_required(VERSION 3.26)
project(kuro)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
add_compile_definitions(TOML_EXCEPTIONS=0)

configure_file(
  config.h.in
  ${CMAKE_CURRENT_BINARY_DIR}/config.h
  @ONLY
)

# -----------------------------
# 1️⃣ BPF 配置
# -----------------------------
set(BPF_DIR ${CMAKE_SOURCE_DIR}/bpf)
set(BPF_SRC_DIR ${BPF_DIR}/src)
set(BPF_INCLUDE_DIRS ${BPF_DIR}/include ${BPF_DIR}/build)
set(BPF_BUILD_DIR ${BPF_DIR}/build)
set(BPF_SKEL_DIR ${BPF_DIR}/skel)

file(GLOB BPF_SRCS "${BPF_SRC_DIR}/tc_*.c")

# 创建输出目录
file(MAKE_DIRECTORY ${BPF_BUILD_DIR})
file(MAKE_DIRECTORY ${BPF_SKEL_DIR})

# -----------------------------
# 2️⃣ 生成 vmlinux.h
# -----------------------------
set(VMLINUX_H ${BPF_BUILD_DIR}/vmlinux.h)
add_custom_command(
    OUTPUT ${VMLINUX_H}
    COMMAND bpftool btf dump file /sys/kernel/btf/vmlinux format c > ${VMLINUX_H}
    COMMENT "Generating vmlinux.h"
    VERBATIM
)

# -----------------------------
# 3️⃣ 为每个 BPF 源文件生成 .o + skeleton
# -----------------------------
set(BPF_OBJS)
set(BPF_SKELS)

foreach(BPF_FILE IN LISTS BPF_SRCS)
    get_filename_component(BPF_NAME ${BPF_FILE} NAME_WE)
    set(OBJ_FILE ${BPF_BUILD_DIR}/${BPF_NAME}.o)
    set(SKEL_FILE ${BPF_SKEL_DIR}/${BPF_NAME}.skel.h)

    # 编译 .c -> .o
    add_custom_command(
        OUTPUT ${OBJ_FILE}
        COMMAND clang -O2 -g -target bpf -Wno-unknown-attributes
                -I/usr/include
                -I${BPF_DIR}/include
                -I${BPF_BUILD_DIR}
                -c ${BPF_FILE} -o ${OBJ_FILE}
        DEPENDS ${BPF_FILE} ${VMLINUX_H}
        COMMENT "Compiling BPF object ${BPF_NAME}.o"
        VERBATIM
    )

    # 生成 skeleton
    add_custom_command(
        OUTPUT ${SKEL_FILE}
        COMMAND bpftool gen skeleton ${OBJ_FILE} > ${SKEL_FILE}
        DEPENDS ${OBJ_FILE}
        COMMENT "Generating BPF skeleton ${BPF_NAME}.skel.h"
        VERBATIM
    )

    list(APPEND BPF_OBJS ${OBJ_FILE})
    list(APPEND BPF_SKELS ${SKEL_FILE})
endforeach()

# -----------------------------
# 4️⃣ BPF 总 target
# -----------------------------
add_custom_target(bpf_skel ALL
    DEPENDS ${BPF_OBJS} ${BPF_SKELS}
)

# -----------------------------
# 5️⃣ 用户态可执行文件
# -----------------------------
add_executable(kuro main.cpp)
add_dependencies(kuro bpf_skel)

# 包含 skeleton 头和 BPF include
target_include_directories(kuro PRIVATE
    ${BPF_SKEL_DIR}
    ${BPF_INCLUDE_DIRS}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_SOURCE_DIR}
)

# 链接 libbpf、zlib、elf、toml++
find_library(LIBBPF_LIB bpf REQUIRED)
find_library(ELF_LIB elf REQUIRED)
find_library(ZLIB_LIB z REQUIRED)

include(FetchContent)
FetchContent_Declare(
    tomlplusplus
    GIT_REPOSITORY https://github.com/marzer/tomlplusplus.git
    GIT_TAG v3.4.0
)
FetchContent_MakeAvailable(tomlplusplus)

target_link_libraries(kuro PRIVATE
    ${LIBBPF_LIB}
    ${ELF_LIB}
    ${ZLIB_LIB}
    tomlplusplus::tomlplusplus
)
