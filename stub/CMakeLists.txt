# CipherShell Stub CMakeLists.txt

# ============================================================================
# Stage0 汇编对象
# ============================================================================

# x86 版本
add_library(stage0_x86 OBJECT
    stage0/stage0_x86.asm
)
set_target_properties(stage0_x86 PROPERTIES
    NASM_FORMAT win32
)

# x64 版本
add_library(stage0_x64 OBJECT
    stage0/stage0_x64.asm
)
set_target_properties(stage0_x64 PROPERTIES
    NASM_FORMAT win64
)

# ============================================================================
# Stage1 运行时引擎
# ============================================================================

add_library(stage1_runtime STATIC
    stage1/api_resolver.cpp
)

# 包含目录
target_include_directories(stage1_runtime PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/..
)

# 编译选项（无 CRT）
if(MSVC)
    target_compile_options(stage1_runtime PRIVATE
        /GS-          # 禁用栈保护
        /Zl           # 不嵌入默认库名
        /O1           # 优化大小
    )
    target_compile_definitions(stage1_runtime PRIVATE
        _NO_CRT
        WIN32_LEAN_AND_MEAN
    )
endif()

# ============================================================================
# VM 引擎 (Mirage)
# ============================================================================

add_library(mirage_vm STATIC
    vm/dispatcher.c
    vm/flags_emu.c
)

# 包含目录
target_include_directories(mirage_vm PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/..
)
