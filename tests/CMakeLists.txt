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

# Pack-time handler 合成：检查机器码/密文/差异度，并在主机架构执行
# direct-threaded 语义与 #DE 门禁；不加载或运行任何样例/原始/加壳 PE。
add_executable(test_vm_handler_synthesis
    test_vm_handler_synthesis.cpp
)

target_link_libraries(test_vm_handler_synthesis PRIVATE
    ciphershell_packer
)

target_include_directories(test_vm_handler_synthesis PRIVATE ${CMAKE_SOURCE_DIR})

# 公开五参数入口：在匿名内存中构造最小合法 PE/metadata/record，执行
# crypto/auth/ABI/W^X 闭环；不加载或运行任何样例/原始/加壳 PE。
add_executable(test_vm_public_entry
    test_vm_public_entry.cpp
)

target_link_libraries(test_vm_public_entry PRIVATE
    ciphershell_packer
)

target_include_directories(test_vm_public_entry PRIVATE ${CMAKE_SOURCE_DIR})

# 微操作紧凑流、生产语义 executor 与差分等价硬门禁。
add_executable(test_vm_micro_core
    test_vm_micro_core.cpp
)

target_link_libraries(test_vm_micro_core PRIVATE
    ciphershell_packer
)

target_include_directories(test_vm_micro_core PRIVATE ${CMAKE_SOURCE_DIR})

# 最终 PE runtime/handler 内容硬校验：覆盖 section 原始偏移移动、完整
# synth image、handler 密文、dispatch 表和关键 digest 的篡改拒绝。
add_executable(test_vm_runtime_integrity
    test_vm_runtime_integrity.cpp
)

target_link_libraries(test_vm_runtime_integrity PRIVATE
    ciphershell_packer
)

target_include_directories(test_vm_runtime_integrity PRIVATE ${CMAKE_SOURCE_DIR})

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
add_test(NAME fail_closed_baseline COMMAND test_fail_closed)
add_test(NAME pe_hardening_regression COMMAND test_pe_hardening)
add_test(NAME vm_handler_synthesis COMMAND test_vm_handler_synthesis)
set_tests_properties(vm_handler_synthesis PROPERTIES LABELS "vm;hard-gate")
add_test(NAME vm_public_entry COMMAND test_vm_public_entry)
set_tests_properties(vm_public_entry PROPERTIES
    LABELS "vm;hard-gate"
    TIMEOUT 30
)
add_test(NAME vm_micro_core COMMAND test_vm_micro_core)
set_tests_properties(vm_micro_core PROPERTIES LABELS "vm;hard-gate")
add_test(NAME vm_runtime_integrity COMMAND test_vm_runtime_integrity)
set_tests_properties(vm_runtime_integrity PROPERTIES LABELS "vm;hard-gate")

# 微操作内核源码硬门禁：只读源码，不运行原始/加壳/样例 PE。
find_package(Python3 COMPONENTS Interpreter REQUIRED)
add_test(
    NAME vm_kernel_static_gate
    COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/scripts/vm_kernel_static_gate.py"
        --source-root "${CMAKE_SOURCE_DIR}"
)
set_tests_properties(vm_kernel_static_gate PROPERTIES LABELS "vm;hard-gate")
