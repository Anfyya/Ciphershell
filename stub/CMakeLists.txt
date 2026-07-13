# CipherShell Stub CMakeLists.txt

# ============================================================================
# Stage0 汇编对象（需要 NASM，如果不可用则跳过）
# ============================================================================

# Stage0 汇编由外部手动编译（NASM 参数与 CMake 不兼容）
# stub/build/stage0_x86.obj
# stub/build/stage0_x64.obj

# ============================================================================
# Stage1 运行时引擎
# ============================================================================

add_library(stage1_runtime STATIC
    stage1/api_resolver.cpp
    stage1/anti_debug.cpp
    stage1/anti_debug_advanced.cpp
    stage1/implicit_response.cpp
    stage1/runtime_stub.cpp
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

# VM 内核不再由 stub 静态链接固定 dispatcher。所有微操作 handler 与
# direct-threaded 分发尾均由 packer 按本次 build seed 现场发射。
