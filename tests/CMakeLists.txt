# CipherShell Tests CMakeLists.txt

# ============================================================================
# 测试程序
# ============================================================================

# PE Parser 测试
add_executable(test_pe_parser
    test_pe_parser.cpp
)

target_link_libraries(test_pe_parser PRIVATE
    ciphershell_packer
)

target_include_directories(test_pe_parser PRIVATE ${CMAKE_SOURCE_DIR})

# VM 正确性测试
add_executable(test_vm_correctness
    test_vm_correctness.cpp
)

target_link_libraries(test_vm_correctness PRIVATE
    ciphershell_packer
)

# 性能基准测试
add_executable(benchmark
    benchmark.cpp
)

target_link_libraries(benchmark PRIVATE
    ciphershell_packer
    psapi
)

# ============================================================================
# 测试辅助程序
# ============================================================================

# Hello World 测试样本
add_executable(hello_world_sample
    samples/hello_world.cpp
)

# 设置测试样本输出目录
set_target_properties(hello_world_sample PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests/samples
)

add_executable(test_e2e_packaging
    test_e2e_packaging.cpp
)

target_link_libraries(test_e2e_packaging PRIVATE
    ciphershell_packer
)

add_executable(test_cli_options
    test_cli_options.cpp
    ../packer/cli_options.cpp
)

target_include_directories(test_cli_options PRIVATE ${CMAKE_SOURCE_DIR})

# Fail-closed 基线测试（仅编译，不运行）
add_executable(test_fail_closed
    test_fail_closed.cpp
)

target_link_libraries(test_fail_closed PRIVATE
    ciphershell_packer
)

target_include_directories(test_fail_closed PRIVATE ${CMAKE_SOURCE_DIR})

# PE 解析/发射加固回归测试（仅编译，不运行）
add_executable(test_pe_hardening
    test_pe_hardening.cpp
)

target_link_libraries(test_pe_hardening PRIVATE
    ciphershell_packer
)

target_include_directories(test_pe_hardening PRIVATE ${CMAKE_SOURCE_DIR})

add_test(NAME cli_options COMMAND test_cli_options)
add_test(NAME pe_parser_bounds COMMAND test_pe_parser)
