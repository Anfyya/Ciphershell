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

# VM 正确性测试
add_executable(test_vm_correctness
    test_vm_correctness.cpp
)

target_link_libraries(test_vm_correctness PRIVATE
    ciphershell_packer
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
