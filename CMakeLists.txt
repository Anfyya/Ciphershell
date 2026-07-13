# CipherShell CMakeLists.txt
# 自研高强度代码保护壳

cmake_minimum_required(VERSION 3.16)
project(CipherShell VERSION 0.1.0 LANGUAGES C CXX)

include(CTest)
option(CS_BUILD_LEGACY_DECRYPTOR
    "Build the unsupported legacy decryptor diagnostic tool" OFF)

# ============================================================================
# 编译选项
# ============================================================================

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Zydis v4.1.0 (569320ad3c4856da13b9dbf1f0d9e20bda63870e) is vendored with
# Zycore v1.5.0 (74620eefd233bec20daeb66e78e744ff06e273b7).  The production
# decoder is always built from these pinned sources and never resolved from a
# machine-wide installation.
set(ZYDIS_BUILD_SHARED_LIB OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_MAN OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_DOXYGEN OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(ZYAN_SYSTEM_ZYCORE OFF CACHE BOOL "" FORCE)
add_subdirectory(third_party/zydis EXCLUDE_FROM_ALL)

# VM runtime 由 packer 在每次保护构建时按 seed 现场合成。这里不再编译、
# 链接或嵌入任何参考解释器 PE，避免产物共享逐字节相同的 runtime blob。

# MSVC 特定选项
if(MSVC)
    add_compile_options(/W4 /WX /utf-8 /w14244 /wd4100)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
    add_compile_definitions(WIN32_LEAN_AND_MEAN)
    add_compile_definitions(NOMINMAX)
elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    # GCC/Clang — 用于 Linux 编译验证
    add_compile_options(-Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers)
    add_compile_definitions(CS_LINUX_COMPAT)
endif()

# ============================================================================
# 跨平台兼容头
# ============================================================================

# 非 Windows 时使用兼容层
if(NOT WIN32)
    include_directories(BEFORE ${CMAKE_SOURCE_DIR}/compat)
    message(STATUS "Non-Windows build: using compat/windows_compat.h")
endif()

# ============================================================================
# NASM 汇编支持（仅在可用时启用）
# ============================================================================

include(CheckLanguage)
check_language(ASM_NASM)
if(CMAKE_ASM_NASM_COMPILER)
    enable_language(ASM_NASM)
    message(STATUS "NASM found: ${CMAKE_ASM_NASM_COMPILER}")
    set(HAVE_NASM TRUE)
else()
    message(WARNING "NASM not found. Assembly stub will not be compiled.")
    set(HAVE_NASM FALSE)
endif()

# ============================================================================
# 输出目录
# ============================================================================

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# ============================================================================
# 子目录
# ============================================================================

add_subdirectory(packer)

if(WIN32 OR HAVE_NASM)
    add_subdirectory(stub)
else()
    message(STATUS "Skipping stub (requires NASM or Windows)")
endif()

# 测试仅在可链接时构建
if(WIN32 AND BUILD_TESTING)
    add_subdirectory(tests)
endif()
if(WIN32 AND CS_BUILD_LEGACY_DECRYPTOR)
    add_subdirectory(tools)
endif()
if(NOT WIN32)
    message(STATUS "Skipping tests (Windows-only)")
endif()

# ============================================================================
# 安装规则
# ============================================================================

if(TARGET ciphershell)
    install(TARGETS ciphershell RUNTIME DESTINATION bin)
endif()
