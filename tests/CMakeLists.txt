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

# 隔离原生差分证据源：真实 CPU 执行一小段原生字节，与本次 build 合成的
# handler 链在隔离 worker 进程里逐位比较，并验证蓄意语义分歧真的会被拒绝。
# 依赖 vm_native_differential_worker 与本可执行文件同目录。
add_executable(test_vm_native_differential
    test_vm_native_differential.cpp
)

target_link_libraries(test_vm_native_differential PRIVATE
    ciphershell_packer
)

target_include_directories(test_vm_native_differential PRIVATE ${CMAKE_SOURCE_DIR})

if(WIN32 AND HAVE_NASM)
    add_dependencies(test_vm_native_differential vm_native_differential_worker)
endif()

# 独立 CFG-only 闭环：在 RX 内存中分别执行原始函数字节和
# 平坦化后的真实分发器/块体，对边界语料逐值比较返回结果。
add_executable(test_cfg_flattener_differential
    test_cfg_flattener_differential.cpp
)

target_link_libraries(test_cfg_flattener_differential PRIVATE
    ciphershell_packer
)

target_include_directories(test_cfg_flattener_differential PRIVATE ${CMAKE_SOURCE_DIR})
target_compile_definitions(test_cfg_flattener_differential PRIVATE
    CS_CFG_FULL_PE_TEST=1)

# Per-build decryptor 真实覆盖：8 组 xorshift * 48 个等价但字节不同的
# 指令布局，每个组合都生成、逐字节验证并在真实 CPU 上解密。
add_executable(test_vm_decryptor_coverage
    test_vm_decryptor_coverage.cpp
)

target_link_libraries(test_vm_decryptor_coverage PRIVATE
    ciphershell_packer
)

target_include_directories(test_vm_decryptor_coverage PRIVATE ${CMAKE_SOURCE_DIR})

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

# 手动 VM 测试样本：5 个 extern "C" noinline 函数，全部从 main 直接调用，
# 不会被内联/消除。vm_per_build_similarity_gate 用它做两次独立构建对比。
add_executable(vm_manual_x64_sample
    samples/vm_manual_x64_sample.cpp
)

set_target_properties(vm_manual_x64_sample PROPERTIES
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
add_test(NAME vm_native_differential COMMAND test_vm_native_differential)
set_tests_properties(vm_native_differential PROPERTIES
    LABELS "vm;hard-gate"
    TIMEOUT 120
)
add_test(NAME cfg_flattener_differential COMMAND test_cfg_flattener_differential)
set_tests_properties(cfg_flattener_differential PROPERTIES
    LABELS "cfg;hard-gate"
    TIMEOUT 30
)
add_test(NAME vm_decryptor_coverage COMMAND test_vm_decryptor_coverage)
set_tests_properties(vm_decryptor_coverage PROPERTIES
    LABELS "vm;decryptor;hard-gate"
    TIMEOUT 120
)

# 微操作内核源码硬门禁：只读源码，不运行原始/加壳/样例 PE。
find_package(Python3 COMPONENTS Interpreter REQUIRED)
add_test(
    NAME vm_kernel_static_gate
    COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/scripts/vm_kernel_static_gate.py"
        --source-root "${CMAKE_SOURCE_DIR}"
)
set_tests_properties(vm_kernel_static_gate PROPERTIES LABELS "vm;hard-gate")

# ciphershellpro.md §8 "Per-build 差异度":同一份输入用两次真实、独立
# seed 的完整构建，比较 handler 密文字节相似度必须 < 15%，且 opcode map/
# 分发键/微操作选择四个自检摘要两两不同。ciphershell.exe 只处理 PE，
# 这条门禁只在这个 Windows-only 的 tests/CMakeLists.txt 里注册，不会在
# Linux 静态门禁 job 里出现。
add_test(
    NAME vm_per_build_similarity_gate
    COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/scripts/vm_per_build_similarity_gate.py"
        --ciphershell "$<TARGET_FILE:ciphershell>"
        --sample "$<TARGET_FILE:vm_manual_x64_sample>"
        --workdir "${CMAKE_BINARY_DIR}/tests/per_build_similarity_gate"
)
set_tests_properties(vm_per_build_similarity_gate PROPERTIES
    LABELS "vm;hard-gate"
    TIMEOUT 300
)
