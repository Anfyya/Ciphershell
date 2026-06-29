# CipherShell Packer CMakeLists.txt

# ============================================================================
# Packer 库
# ============================================================================

add_library(ciphershell_packer STATIC
    # PE 解析器
    pe_parser/pe_parser.cpp
    pe_parser/pe_rebuilder.cpp

    # 变换引擎 — Phase 1
    transforms/section_encryptor.cpp
    transforms/string_encryptor.cpp
    transforms/import_obfuscator.cpp
    transforms/reloc_fixer.cpp

    # 分析引擎 — Phase 3
    analysis/disassembler.cpp
    analysis/cfg_builder.cpp

    # 变换引擎 — Phase 3
    transforms/cfg_flattener.cpp
    transforms/opaque_predicates.cpp
    transforms/bogus_flow.cpp

    # Stub 构建器
    transforms/stub_builder.cpp

    # 转译器 — Phase 4
    transforms/translator.cpp
    transforms/vm_nester.cpp

    # 变异引擎 — Phase 4
    mutation/bytecode_encryptor.cpp
    mutation/mutation_engine.cpp

    # 配置解析
    config/config_parser.cpp

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

# 链接依赖
target_link_libraries(ciphershell_packer PRIVATE
    # Windows API
)

# ============================================================================
# Packer 可执行文件
# ============================================================================

add_executable(ciphershell
    main.cpp
)

target_link_libraries(ciphershell PRIVATE
    ciphershell_packer
)
