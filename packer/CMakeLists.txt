# CipherShell Packer CMakeLists.txt

# ============================================================================
# Packer 库
# ============================================================================

add_library(ciphershell_packer STATIC
    ../runtime/common/vm_crypto.c
    # PE 解析器
    pe_parser/pe_parser.cpp
    pe_parser/pe_emitter.cpp
    pe_parser/pe_rebuilder.cpp
    pe_parser/dll_packer.cpp

    # 变换引擎 — Phase 1
    transforms/section_encryptor.cpp
    transforms/string_encryptor.cpp
    transforms/string_encryptor_advanced.cpp
    transforms/import_obfuscator.cpp
    transforms/reloc_fixer.cpp

    # 分析引擎 — Phase 3
    analysis/instruction_ir.cpp
    analysis/function_discovery.cpp
    analysis/disassembler.cpp
    analysis/cfg_builder.cpp
    analysis/capability_checker.cpp
    analysis/hotspot_analyzer.cpp

    # 变换引擎 — Phase 3
    transforms/cfg_flattener.cpp
    transforms/opaque_predicates.cpp
    transforms/bogus_flow.cpp

    # Stub 构建器
    transforms/stub_builder.cpp
    transforms/loader_import_builder.cpp

    # 转译器 — Phase 4
    vm/vm_schema.cpp
    vm/vm_verifier.cpp
    transforms/translator.cpp
    transforms/vm_section_emitter.cpp
    transforms/vm_runtime_builder.cpp
    transforms/vm_instruction_bridge_builder.cpp
    transforms/function_trampoline_patcher.cpp

    # 变异引擎 — Phase 4
    mutation/mutation_engine.cpp

    # 配置解析
    config/config_parser.cpp
    config/protection_build_context.cpp

    # 签名消除
    signature/signature_eliminator.cpp

    # API Resolver (从 stub 引入，编译验证用)
    ../stub/stage1/api_resolver.cpp

    # GUI
    gui/console_gui.cpp
)

# 包含目录
target_include_directories(ciphershell_packer PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/..
)

if(WIN32)
    add_dependencies(ciphershell_packer vm_runtime_blobs)
    target_include_directories(ciphershell_packer PRIVATE "${CS_RUNTIME_GENERATED_DIR}")
endif()

# 链接依赖
if(WIN32)
    target_sources(ciphershell_packer PRIVATE
        transforms/nanomite.cpp
    )
endif()

target_link_libraries(ciphershell_packer PRIVATE Zydis)
if(WIN32)
    target_link_libraries(ciphershell_packer PRIVATE bcrypt)
endif()

# ============================================================================
# Packer 可执行文件
# ============================================================================

add_executable(ciphershell
    main.cpp
)

target_link_libraries(ciphershell PRIVATE
    ciphershell_packer
)
