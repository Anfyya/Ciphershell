# CipherShell CMakeLists.txt
# 自研高强度代码保护壳

cmake_minimum_required(VERSION 3.16)
project(CipherShell VERSION 0.1.0 LANGUAGES CXX)

# ============================================================================
# 编译选项
# ============================================================================

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# MSVC 特定选项
if(MSVC)
    add_compile_options(/W4 /WX /utf-8)
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
if(WIN32)
    add_subdirectory(tests)
else()
    message(STATUS "Skipping tests (Windows-only)")
endif()

# ============================================================================
# 安装规则
# ============================================================================

if(TARGET ciphershell)
    install(TARGETS ciphershell RUNTIME DESTINATION bin)
endif()
