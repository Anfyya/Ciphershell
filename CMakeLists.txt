# CipherShell CMakeLists.txt
# 自研高强度代码保护壳

cmake_minimum_required(VERSION 3.16)
project(CipherShell VERSION 0.1.0 LANGUAGES C CXX)

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

if(WIN32)
    find_program(CS_NASM_EXECUTABLE NAMES nasm nasm.exe)
    if(NOT CS_NASM_EXECUTABLE)
        message(FATAL_ERROR "NASM is required for the production VM native bridge")
    endif()
    set(CMAKE_ASM_NASM_COMPILER "${CS_NASM_EXECUTABLE}" CACHE FILEPATH
        "Pinned NASM executable" FORCE)
endif()

# Build the freestanding x86/x64 VM interpreter images with the pinned MSVC
# toolset and NASM already present in the project environment.  The resulting
# PE files are embedded as byte arrays; VMRuntimeBuilder maps and relocates them
# into the protected image without requiring runtime files at deployment.
if(WIN32)
    # Resolve the active Visual Studio toolset selected by CMake.  No developer-
    # machine paths or fixed SDK versions are allowed in the production build.
    set(CS_MSVC_ROOT "" CACHE PATH "Optional MSVC toolset root override")
    if(NOT CS_MSVC_ROOT)
        if(NOT MSVC OR NOT CMAKE_C_COMPILER)
            message(FATAL_ERROR "The VM runtime blobs require the Visual Studio 2022 MSVC toolchain")
        endif()
        get_filename_component(_cs_compiler_arch_dir "${CMAKE_C_COMPILER}" DIRECTORY)
        get_filename_component(_cs_compiler_host_dir "${_cs_compiler_arch_dir}" DIRECTORY)
        get_filename_component(_cs_compiler_bin_dir "${_cs_compiler_host_dir}" DIRECTORY)
        get_filename_component(CS_MSVC_ROOT "${_cs_compiler_bin_dir}" DIRECTORY)
    endif()

    set(CS_WINDOWS_KITS_ROOT "" CACHE PATH "Optional Windows Kits root override")
    if(NOT CS_WINDOWS_KITS_ROOT)
        if(DEFINED ENV{WindowsSdkDir} AND IS_DIRECTORY "$ENV{WindowsSdkDir}")
            file(TO_CMAKE_PATH "$ENV{WindowsSdkDir}" CS_WINDOWS_KITS_ROOT)
        elseif(IS_DIRECTORY "C:/Program Files (x86)/Windows Kits/10")
            set(CS_WINDOWS_KITS_ROOT "C:/Program Files (x86)/Windows Kits/10")
        elseif(IS_DIRECTORY "C:/Program Files/Windows Kits/10")
            set(CS_WINDOWS_KITS_ROOT "C:/Program Files/Windows Kits/10")
        else()
            message(FATAL_ERROR "Windows 10/11 SDK was not found; set CS_WINDOWS_KITS_ROOT")
        endif()
    endif()

    set(CS_WINDOWS_SDK_VERSION "${CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION}" CACHE STRING
        "Optional Windows SDK version override")
    if(NOT CS_WINDOWS_SDK_VERSION)
        file(GLOB _cs_sdk_candidates LIST_DIRECTORIES true
            "${CS_WINDOWS_KITS_ROOT}/Include/10.*")
        list(SORT _cs_sdk_candidates COMPARE NATURAL ORDER DESCENDING)
        foreach(_cs_sdk_dir IN LISTS _cs_sdk_candidates)
            if(IS_DIRECTORY "${_cs_sdk_dir}/ucrt" AND IS_DIRECTORY "${_cs_sdk_dir}/um")
                get_filename_component(CS_WINDOWS_SDK_VERSION "${_cs_sdk_dir}" NAME)
                break()
            endif()
        endforeach()
    endif()
    if(NOT CS_WINDOWS_SDK_VERSION)
        message(FATAL_ERROR "No usable Windows SDK version was found under ${CS_WINDOWS_KITS_ROOT}/Include")
    endif()

    set(CS_RUNTIME_GENERATED_DIR "${CMAKE_BINARY_DIR}/generated/runtime")
    set(CS_RUNTIME_COMMON "${CMAKE_SOURCE_DIR}/runtime/common")
    set(CS_MSVC_INCLUDE "${CS_MSVC_ROOT}/include")
    set(CS_UCRT_INCLUDE "${CS_WINDOWS_KITS_ROOT}/Include/${CS_WINDOWS_SDK_VERSION}/ucrt")

    # Prefer a native x64 host compiler and fall back to Hostx86 when CMake was
    # launched from a 32-bit developer environment.
    set(_cs_host_candidates Hostx64 Hostx86)
    foreach(_cs_host IN LISTS _cs_host_candidates)
        if(NOT CS_CL_X64 AND EXISTS "${CS_MSVC_ROOT}/bin/${_cs_host}/x64/cl.exe")
            set(CS_CL_X64 "${CS_MSVC_ROOT}/bin/${_cs_host}/x64/cl.exe")
            set(CS_LINK_X64 "${CS_MSVC_ROOT}/bin/${_cs_host}/x64/link.exe")
        endif()
        if(NOT CS_CL_X86 AND EXISTS "${CS_MSVC_ROOT}/bin/${_cs_host}/x86/cl.exe")
            set(CS_CL_X86 "${CS_MSVC_ROOT}/bin/${_cs_host}/x86/cl.exe")
            set(CS_LINK_X86 "${CS_MSVC_ROOT}/bin/${_cs_host}/x86/link.exe")
        endif()
    endforeach()
    foreach(required_path IN ITEMS
        "${CS_CL_X64}" "${CS_LINK_X64}" "${CS_CL_X86}" "${CS_LINK_X86}"
        "${CS_MSVC_INCLUDE}/stdint.h" "${CS_UCRT_INCLUDE}/stddef.h")
        if(NOT required_path OR NOT EXISTS "${required_path}")
            message(FATAL_ERROR "Required runtime build dependency is missing: ${required_path}")
        endif()
    endforeach()
    message(STATUS "VM runtime MSVC root: ${CS_MSVC_ROOT}")
    message(STATUS "VM runtime Windows SDK: ${CS_WINDOWS_KITS_ROOT} (${CS_WINDOWS_SDK_VERSION})")
    set(_cs_runtime_c_flags
        /nologo /c /TC /O1 /GS- /GR- /Oi- /Zl /W3
        "/I${CMAKE_SOURCE_DIR}" "/I${CS_MSVC_INCLUDE}" "/I${CS_UCRT_INCLUDE}")

    set(CS_RUNTIME_X64_DIR "${CS_RUNTIME_GENERATED_DIR}/x64")
    set(CS_RUNTIME_X64_PE "${CS_RUNTIME_X64_DIR}/vm_runtime_x64.exe")
    set(CS_RUNTIME_X64_HEADER "${CS_RUNTIME_GENERATED_DIR}/vm_runtime_x64_image.h")
    add_custom_command(
        OUTPUT "${CS_RUNTIME_X64_HEADER}"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${CS_RUNTIME_X64_DIR}"
        COMMAND "${CS_CL_X64}" ${_cs_runtime_c_flags}
            "/Fo${CS_RUNTIME_X64_DIR}/core.obj" "${CS_RUNTIME_COMMON}/vm_runtime_core.c"
        COMMAND "${CS_CL_X64}" ${_cs_runtime_c_flags}
            "/Fo${CS_RUNTIME_X64_DIR}/crypto.obj" "${CS_RUNTIME_COMMON}/vm_crypto.c"
        COMMAND "${CS_NASM_EXECUTABLE}" -f win64
            "${CMAKE_SOURCE_DIR}/runtime/x64/native_bridge.asm"
            -o "${CS_RUNTIME_X64_DIR}/bridge.obj"
        COMMAND "${CS_LINK_X64}" /NOLOGO /NODEFAULTLIB /SUBSYSTEM:CONSOLE /MACHINE:X64
            /DYNAMICBASE /NXCOMPAT /BASE:0x180000000 /ENTRY:vm_runtime_interpret
            "/OUT:${CS_RUNTIME_X64_PE}"
            "${CS_RUNTIME_X64_DIR}/core.obj" "${CS_RUNTIME_X64_DIR}/crypto.obj"
            "${CS_RUNTIME_X64_DIR}/bridge.obj"
        COMMAND ${CMAKE_COMMAND}
            "-DINPUT_FILE=${CS_RUNTIME_X64_PE}"
            "-DOUTPUT_FILE=${CS_RUNTIME_X64_HEADER}"
            -DSYMBOL_NAME=kVMRuntimeX64Image
            -P "${CMAKE_SOURCE_DIR}/cmake/EmbedBinary.cmake"
        DEPENDS
            "${CS_RUNTIME_COMMON}/vm_runtime_core.c"
            "${CS_RUNTIME_COMMON}/vm_runtime_core.h"
            "${CS_RUNTIME_COMMON}/vm_crypto.c"
            "${CS_RUNTIME_COMMON}/vm_crypto.h"
            "${CS_RUNTIME_COMMON}/vm_metadata.h"
            "${CS_RUNTIME_COMMON}/vm_isa.h"
            "${CS_RUNTIME_COMMON}/vm_schema_contract.h"
            "${CMAKE_SOURCE_DIR}/runtime/x64/native_bridge.asm"
            "${CMAKE_SOURCE_DIR}/cmake/EmbedBinary.cmake"
        VERBATIM)

    set(CS_RUNTIME_X86_DIR "${CS_RUNTIME_GENERATED_DIR}/x86")
    set(CS_RUNTIME_X86_PE "${CS_RUNTIME_X86_DIR}/vm_runtime_x86.exe")
    set(CS_RUNTIME_X86_HEADER "${CS_RUNTIME_GENERATED_DIR}/vm_runtime_x86_image.h")
    add_custom_command(
        OUTPUT "${CS_RUNTIME_X86_HEADER}"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${CS_RUNTIME_X86_DIR}"
        COMMAND "${CS_CL_X86}" ${_cs_runtime_c_flags}
            "/Fo${CS_RUNTIME_X86_DIR}/core.obj" "${CS_RUNTIME_COMMON}/vm_runtime_core.c"
        COMMAND "${CS_CL_X86}" ${_cs_runtime_c_flags}
            "/Fo${CS_RUNTIME_X86_DIR}/crypto.obj" "${CS_RUNTIME_COMMON}/vm_crypto.c"
        COMMAND "${CS_NASM_EXECUTABLE}" -f win32
            "${CMAKE_SOURCE_DIR}/runtime/x86/native_bridge.asm"
            -o "${CS_RUNTIME_X86_DIR}/bridge.obj"
        COMMAND "${CS_LINK_X86}" /NOLOGO /NODEFAULTLIB /SUBSYSTEM:CONSOLE /MACHINE:X86
            /DYNAMICBASE /NXCOMPAT /BASE:0x10000000 /ENTRY:vm_runtime_interpret /SAFESEH:NO
            "/OUT:${CS_RUNTIME_X86_PE}"
            "${CS_RUNTIME_X86_DIR}/core.obj" "${CS_RUNTIME_X86_DIR}/crypto.obj"
            "${CS_RUNTIME_X86_DIR}/bridge.obj"
        COMMAND ${CMAKE_COMMAND}
            "-DINPUT_FILE=${CS_RUNTIME_X86_PE}"
            "-DOUTPUT_FILE=${CS_RUNTIME_X86_HEADER}"
            -DSYMBOL_NAME=kVMRuntimeX86Image
            -P "${CMAKE_SOURCE_DIR}/cmake/EmbedBinary.cmake"
        DEPENDS
            "${CS_RUNTIME_COMMON}/vm_runtime_core.c"
            "${CS_RUNTIME_COMMON}/vm_runtime_core.h"
            "${CS_RUNTIME_COMMON}/vm_crypto.c"
            "${CS_RUNTIME_COMMON}/vm_crypto.h"
            "${CS_RUNTIME_COMMON}/vm_metadata.h"
            "${CS_RUNTIME_COMMON}/vm_isa.h"
            "${CS_RUNTIME_COMMON}/vm_schema_contract.h"
            "${CMAKE_SOURCE_DIR}/runtime/x86/native_bridge.asm"
            "${CMAKE_SOURCE_DIR}/cmake/EmbedBinary.cmake"
        VERBATIM)

    add_custom_target(vm_runtime_blobs DEPENDS
        "${CS_RUNTIME_X64_HEADER}" "${CS_RUNTIME_X86_HEADER}")
endif()

# MSVC 特定选项
if(MSVC)
    add_compile_options(/W3 /utf-8 /w14244 /wd4100)
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
    add_subdirectory(tools)
else()
    message(STATUS "Skipping tests (Windows-only)")
endif()

# ============================================================================
# 安装规则
# ============================================================================

if(TARGET ciphershell)
    install(TARGETS ciphershell RUNTIME DESTINATION bin)
endif()
