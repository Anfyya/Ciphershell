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
    Zydis
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

if(MSVC)
    # Explicitly off (redundant with the project default, since CMake never
    # turns CFG on here) so this target's x64 IMAGE_LOAD_CONFIG_DIRECTORY64
    # stays close to the legacy/security-cookie-only shape PEParser::
    # ParseLoadConfig was written and regression-tested against
    # (TestLoadConfigDeclaredSizeExceedsAvailable in test_pe_hardening.cpp),
    # rather than picking up whatever newer Guard CF/XFG fields the current
    # toolset's default IMAGE_LOAD_CONFIG_DIRECTORY64 layout happens to add.
    target_compile_options(vm_manual_x64_sample PRIVATE /guard:cf-)
    target_link_options(vm_manual_x64_sample PRIVATE /GUARD:NO)
endif()

# per-build 门禁同时打包并执行真实 MSVC DLL 与 EXE。两种样本都显式导出
# 八个 noinline VM 目标，使 PE32/PE32+ 的函数边界来源稳定一致；这不是跳过
# EXE 入口，而是让同一组被 main/runner 实际调用的函数在 DLL/EXE 两种容器
# 中都经过正式 discovery、packer、trampoline、bytecode 与 runtime 路径。
if(HAVE_NASM)
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(CS_VM_FLAGS_PROBE_ASM samples/vm_flags_probe_x64.asm)
        set(CS_VM_ABI_PROBE_ASM samples/vm_abi_probe_x64.asm)
    else()
        set(CS_VM_FLAGS_PROBE_ASM samples/vm_flags_probe_x86.asm)
        set(CS_VM_ABI_PROBE_ASM samples/vm_abi_probe_x86.asm)
    endif()
else()
    message(FATAL_ERROR
        "The real PE VM runtime gate requires NASM for its flags and ABI probes")
endif()

add_library(vm_similarity_gate_sample SHARED
    samples/vm_similarity_gate_sample.cpp
)

add_executable(vm_similarity_gate_runner
    samples/vm_similarity_gate_runner.cpp
    samples/vm_abi_unwind_gate.cpp
    ${CS_VM_FLAGS_PROBE_ASM}
    ${CS_VM_ABI_PROBE_ASM}
)

add_executable(vm_runtime_gate_exe
    samples/vm_runtime_gate_exe.cpp
    samples/vm_abi_unwind_gate.cpp
    ${CS_VM_FLAGS_PROBE_ASM}
    ${CS_VM_ABI_PROBE_ASM}
)

add_executable(function_discovery_fixture
    samples/function_discovery_fixture.cpp
)

set_target_properties(vm_similarity_gate_sample PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests/samples
)

set_target_properties(vm_similarity_gate_runner PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests/samples
)

set_target_properties(vm_runtime_gate_exe PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests/samples
)

set_target_properties(function_discovery_fixture PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests/samples
)

if(MSVC)
    # Keep every named export large enough for the production five-byte entry
    # trampoline in both PE32 and PE32+. The functions and ABI remain ordinary
    # MSVC code; /Od only prevents Release from collapsing add/local1 into
    # unpatchable 3-byte bodies.
    target_compile_options(vm_similarity_gate_sample PRIVATE /guard:cf- /Od /Ob0)
    target_link_options(vm_similarity_gate_sample PRIVATE /GUARD:NO)
    target_compile_options(vm_runtime_gate_exe PRIVATE
        $<$<COMPILE_LANGUAGE:C,CXX>:/guard:cf->
        $<$<COMPILE_LANGUAGE:C,CXX>:/Od>
        $<$<COMPILE_LANGUAGE:C,CXX>:/Ob0>)
    target_link_options(vm_runtime_gate_exe PRIVATE /GUARD:NO /DYNAMICBASE /FIXED:NO)
    target_compile_options(function_discovery_fixture PRIVATE /guard:cf- /Od /Ob0)
    target_link_options(function_discovery_fixture PRIVATE /GUARD:NO /OPT:NOICF)
endif()

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
add_dependencies(test_pe_hardening vm_runtime_gate_exe)

# 只读取同一 CMake 配置由 MSVC 实际编译链接的 PE。Win32 覆盖 CRT OEP
# direct-tail、真实 .text 间隙候选和派生 direct-call root；x64 覆盖真实 .pdata。
add_executable(test_function_discovery
    test_function_discovery.cpp
)

target_link_libraries(test_function_discovery PRIVATE
    ciphershell_packer
)

target_include_directories(test_function_discovery PRIVATE ${CMAKE_SOURCE_DIR})
add_dependencies(test_function_discovery function_discovery_fixture)

add_test(NAME cli_options COMMAND test_cli_options)
add_test(NAME pe_parser_bounds COMMAND test_pe_parser)
add_test(NAME fail_closed_baseline COMMAND test_fail_closed)
add_test(NAME pe_hardening_regression
    COMMAND test_pe_hardening "$<TARGET_FILE:vm_runtime_gate_exe>")
add_test(NAME function_discovery_regression
    COMMAND test_function_discovery "$<TARGET_FILE:function_discovery_fixture>")
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
add_test(NAME vm_flags_boundary_native_differential
    COMMAND test_vm_native_differential --flags-boundary-only)
set_tests_properties(vm_flags_boundary_native_differential PROPERTIES
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

# ciphershellpro.md §8 "跨 seed 字节多样性防回退门禁":同一份输入用两次
# 真实、独立 seed 的完整构建，比较 handler 密文字节相似度必须低于按架构
# 分别校准的阈值，且 opcode map/分发键/微操作选择四个自检摘要两两不同。
# business_core 与 codec 两条聚合阈值都按架构分别设置，是各自实测当前值
# 加余量的防回退基线，不是已验证的攻击者分析难度下限（见 ciphershellpro.md
# §8 与 codex_change.log v2.7.3/v2.7.4）。business_core 两个架构都落在
# 0.32（各自独立测量、巧合数字相同，见 v2.7.3）；codec 则两个架构明显不同
# （x64 0.32、Win32 0.15）——v2.7.4 排查过 codec 是否有真实"随机性没用满"
# 的bug（确认 value-codec 的 build-wide keyed-permutation 计划只用了8种
# 操作里的4种，其中被排除的 XorShift 确认数学上不自逆），但两次尝试扩大
# 熵源（加宽操作词表、翻倍轮数）经真实数据验证后都让 codec 相似度变得更差
# 而不是更好，均已回退，因此改为按 x64 12 个、Win32 8 个独立真实种子样本
# 的均值+6倍标准差重新校准阈值，不做代码层面的多样性修复。ciphershell.exe
# 只处理 PE，这条门禁只在这个 Windows-only 的 tests/CMakeLists.txt 里注册，
# 不会在 Linux 静态门禁 job 里出现。
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(CS_BUSINESS_CORE_SIMILARITY_THRESHOLD 0.32)
    set(CS_CODEC_SIMILARITY_THRESHOLD 0.32)
else()
    set(CS_BUSINESS_CORE_SIMILARITY_THRESHOLD 0.32)
    set(CS_CODEC_SIMILARITY_THRESHOLD 0.15)
endif()
add_test(
    NAME vm_per_build_similarity_gate
    COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/scripts/vm_per_build_similarity_gate.py"
        --ciphershell "$<TARGET_FILE:ciphershell>"
        --sample "$<TARGET_FILE:vm_similarity_gate_sample>"
        --runner "$<TARGET_FILE:vm_similarity_gate_runner>"
        --exe-sample "$<TARGET_FILE:vm_runtime_gate_exe>"
        --config "${CMAKE_CURRENT_SOURCE_DIR}/samples/vm_similarity_gate_sample.toml"
        --workdir "${CMAKE_BINARY_DIR}/tests/per_build_similarity_gate"
        --business-core-similarity-threshold ${CS_BUSINESS_CORE_SIMILARITY_THRESHOLD}
        --codec-similarity-threshold ${CS_CODEC_SIMILARITY_THRESHOLD}
)
set_tests_properties(vm_per_build_similarity_gate PROPERTIES
    LABELS "vm;hard-gate"
    # Four full pack-and-run builds take 6-8 minutes on the slower Win32
    # builders.  Keep the CTest wrapper above the script's own per-case
    # deadlines so it cannot strand a runner that still owns an output PE.
    TIMEOUT 900
)
