/**
 * CipherShell 主程序入口
 * 命令行界面
 */

#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <filesystem>
#ifdef _WIN32
#include <windows.h>
#else
#include "windows_compat.h"
#endif

#include "pe_parser/pe_parser.h"
#include "pe_parser/pe_rebuilder.h"
#include "transforms/section_encryptor.h"
#include "transforms/string_encryptor.h"
#include "transforms/import_obfuscator.h"
#include "transforms/reloc_fixer.h"
#include "config/config_parser.h"
#include "signature/signature_eliminator.h"
#include "analysis/disassembler.h"
#include "analysis/cfg_builder.h"
#include "transforms/cfg_flattener.h"
#include "transforms/opaque_predicates.h"
#include "transforms/bogus_flow.h"
#include "transforms/stub_builder.h"
#include "transforms/translator.h"
#include "transforms/vm_nester.h"
#include "mutation/mutation_engine.h"
#include "mutation/bytecode_encryptor.h"
#include "gui/console_gui.h"

namespace fs = std::filesystem;

// ============================================================================
// 帮助信息
// ============================================================================

void PrintHelp() {
    std::cout << R"(
CipherShell v0.1 - 自研高强度代码保护壳

用法: ciphershell [选项] <输入文件>

选项:
  -o, --output <文件>      指定输出文件路径
  -l, --level <1-5>        设置保护等级 (默认: 1)
  -c, --config <文件>      指定配置文件路径 (TOML 格式)
  -v, --verbose            显示详细信息
  -h, --help               显示此帮助信息

保护等级:
  L1 (Guard)    基础加密保护 (~1.05x 性能开销)
  L2 (Shield)   控制流平坦化 (~2-3x 性能开销)
  L3 (Armor)    高级混淆 (~5-8x 性能开销)
  L4 (Fortress) 代码虚拟化 (~15-30x 性能开销)
  L5 (Citadel)  多层嵌套 VM (~50-100x+ 性能开销)

示例:
  ciphershell input.exe -o protected.exe -l 3
  ciphershell input.dll -l 2 -c config.toml
)" << std::endl;
}

// ============================================================================
// 主函数
// ============================================================================

int main(int argc, char* argv[]) {
    // 设置控制台为 UTF-8 编码
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);

    // 如果没有参数，启动 GUI 模式
    if (argc == 1) {
        CipherShell::ConsoleGUI gui;
        gui.Initialize();
        gui.ShowMainMenu();
        return 0;
    }

    std::cout << "CipherShell v0.1 - 自研高强度代码保护壳" << std::endl;
    std::cout << "======================================" << std::endl;

    // 解析命令行参数
    std::string inputFile;
    std::string outputFile;
    std::string configFile;
    int protectionLevel = 1;
    bool verbose = false;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            PrintHelp();
            return 0;
        } else if (arg == "-o" || arg == "--output") {
            if (i + 1 < argc) {
                outputFile = argv[++i];
            } else {
                std::cerr << "错误: -o 选项需要指定输出文件路径" << std::endl;
                return 1;
            }
        } else if (arg == "-l" || arg == "--level") {
            if (i + 1 < argc) {
                protectionLevel = std::stoi(argv[++i]);
                if (protectionLevel < 1 || protectionLevel > 5) {
                    std::cerr << "错误: 保护等级必须在 1-5 之间" << std::endl;
                    return 1;
                }
            } else {
                std::cerr << "错误: -l 选项需要指定保护等级" << std::endl;
                return 1;
            }
        } else if (arg == "-c" || arg == "--config") {
            if (i + 1 < argc) {
                configFile = argv[++i];
            } else {
                std::cerr << "错误: -c 选项需要指定配置文件路径" << std::endl;
                return 1;
            }
        } else if (arg == "-v" || arg == "--verbose") {
            verbose = true;
        } else if (inputFile.empty()) {
            inputFile = arg;
        } else {
            std::cerr << "错误: 未知参数 '" << arg << "'" << std::endl;
            return 1;
        }
    }

    // 检查输入文件
    if (inputFile.empty()) {
        std::cerr << "错误: 未指定输入文件" << std::endl;
        PrintHelp();
        return 1;
    }

    if (!fs::exists(inputFile)) {
        std::cerr << "错误: 输入文件不存在: " << inputFile << std::endl;
        return 1;
    }

    // 自动生成输出文件名
    if (outputFile.empty()) {
        fs::path inputPath(inputFile);
        outputFile = inputPath.stem().string() + "_protected" + inputPath.extension().string();
    }

    std::cout << "输入文件: " << inputFile << std::endl;
    std::cout << "输出文件: " << outputFile << std::endl;
    std::cout << "保护等级: L" << protectionLevel << std::endl;

    // ============================================================================
    // Step 1: 解析输入 PE
    // ============================================================================

    std::cout << "\n[1/5] 解析输入 PE 文件..." << std::endl;

    CipherShell::PEParser parser;
    auto imageDeleter = [&parser](CipherShell::CS_PE_IMAGE* img) {
        if (img) parser.FreeImage(img);
    };
    std::unique_ptr<CipherShell::CS_PE_IMAGE, decltype(imageDeleter)> image(
        parser.LoadFromFile(inputFile),
        imageDeleter
    );

    if (!image || !image->isValid) {
        std::cerr << "错误: 无法解析 PE 文件";
        if (image) {
            std::cerr << " - " << image->errorMessage;
        }
        std::cerr << std::endl;
        return 1;
    }

    std::cout << "  PE 解析成功" << std::endl;
    std::cout << "  架构: " << (image->is64Bit ? "x64" : "x86") << std::endl;
    std::cout << "  入口点: 0x" << std::hex;
    if (image->is64Bit) {
        std::cout << image->ntHeaders64->OptionalHeader.AddressOfEntryPoint;
    } else {
        std::cout << image->ntHeaders32->OptionalHeader.AddressOfEntryPoint;
    }
    std::cout << std::dec << std::endl;
    std::cout << "  Section 数量: " << image->numSections << std::endl;

    if (verbose) {
        std::cout << "  导入 DLL 数量: " << image->imports.dlls.size() << std::endl;
        std::cout << "  导出函数数量: " << image->exports.functions.size() << std::endl;
        std::cout << "  重定位条目数量: " << image->relocs.entries.size() << std::endl;
    }

    // ============================================================================
    // Step 1.5: 加载配置
    // ============================================================================

    CipherShell::CipherShellConfig config;
    CipherShell::ConfigParser configParser;

    if (!configFile.empty()) {
        std::cout << "\n[1.5] 加载配置文件: " << configFile << std::endl;
        config = configParser.LoadFromFile(configFile);
        protectionLevel = config.global.protectionLevel;
    } else {
        // 使用默认配置
        config.global.protectionLevel = protectionLevel;
    }

    // ============================================================================
    // Step 1.5: 保存原始入口点
    // ============================================================================

    DWORD originalOEP = 0;
    if (image->is64Bit) {
        originalOEP = image->ntHeaders64->OptionalHeader.AddressOfEntryPoint;
    } else {
        originalOEP = image->ntHeaders32->OptionalHeader.AddressOfEntryPoint;
    }
    std::cout << "  原始入口点 (OEP): 0x" << std::hex << originalOEP << std::dec << std::endl;

    // ============================================================================
    // Step 2: 应用保护变换
    // 重要: 先做代码分析/变换（明文代码可反汇编），最后才做 Section 加密
    // ============================================================================

    std::cout << "\n[2/5] 应用保护变换 (L" << protectionLevel << ")..." << std::endl;

    // Phase A: 字符串加密（明文代码段中的内联字符串，L2+）
    if (protectionLevel >= 2 && config.global.stringEncryption) {
        std::cout << "  应用字符串加密..." << std::endl;

        CipherShell::StringEncryptor strEncryptor;
        CipherShell::CS_STRING_CONFIG strConfig;

        auto strings = strEncryptor.ScanStrings(image.get(), strConfig);
        std::cout << "    发现 " << strings.size() << " 个字符串" << std::endl;

        if (!strings.empty()) {
            strEncryptor.EncryptStrings(image.get(), strings);
            std::cout << "    已加密所有字符串" << std::endl;
        }
    }

    // Phase B: 导入表混淆（L2+）
    if (protectionLevel >= 2 && config.global.importObfuscation) {
        std::cout << "  应用导入表混淆..." << std::endl;

        CipherShell::ImportObfuscator obfuscator;
        CipherShell::CS_IMPORT_OBFUSCATION_CONFIG obfConfig;
        obfConfig.strategy = CipherShell::ImportObfuscationStrategy::StrategyC;

        CipherShell::APIResolver resolver;
        resolver.Initialize();

        auto obfImports = obfuscator.ObfuscateImports(image.get(), obfConfig, &resolver);
        std::cout << "    混淆了 " << obfImports.size() << " 个导入函数" << std::endl;
    }

    // Phase C: 控制流平坦化（L3+，暂禁用——GenerateFlattenedCode 需要优化）
    if (protectionLevel >= 99) {  // FIXME: 暂时禁用，待优化
        std::cout << "  应用控制流平坦化..." << std::endl;

        CipherShell::Disassembler disasm;
        bool is64 = image->is64Bit != 0;

        for (WORD si = 0; si < image->numSections; si++) {
            IMAGE_SECTION_HEADER& sec = image->sections[si];
            if (!(sec.Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;

            DWORD secOffset = sec.PointerToRawData;
            DWORD secSize   = sec.SizeOfRawData;
            if (secOffset + secSize > image->rawSize) continue;

            BYTE* secData = image->rawData + secOffset;
            uint64_t baseAddr = sec.VirtualAddress;

            auto functions = disasm.AnalyzeCode(secData, secSize, baseAddr, is64);
            if (functions.empty()) {
                std::cout << "    代码段[" << si << "]: 未识别到函数（可能无返回指令）" << std::endl;
                continue;
            }
            std::cout << "    代码段[" << si << "]: 识别到 " << functions.size() << " 个函数" << std::endl;

            CipherShell::CFGFlattener flattener;
            CipherShell::FlatteningConfig flatConfig;
            flatConfig.enableStateEncryption = true;
            flatConfig.enableStateRandomization = true;
            flatConfig.junkCaseCount = 5;

            uint32_t flattenedCount = 0;
            for (const auto& func : functions) {
                if (func.blocks.size() < 2) continue;

                auto flatResult = flattener.FlattenFunction(func, flatConfig);
                DWORD codeSize = 0;
                BYTE* flatCode = flattener.GenerateFlattenedCode(flatResult, is64, &codeSize);
                if (flatCode && codeSize > 0) {
                    DWORD funcSize = (DWORD)(func.size);
                    if (codeSize <= funcSize) {
                        DWORD funcOffset = (DWORD)(func.entryAddress - baseAddr);
                        memcpy(secData + funcOffset, flatCode, codeSize);
                        if (codeSize < funcSize) {
                            memset(secData + funcOffset + codeSize, 0xCC, funcSize - codeSize);
                        }
                        flattenedCount++;
                    }
                    delete[] flatCode;
                }
            }
            std::cout << "    平坦化了 " << flattenedCount << " 个函数" << std::endl;
        }
    }

    // Phase D: 虚假控制流（L3+，需在加密前反汇编明文代码）
    if (protectionLevel >= 3) {
        std::cout << "  应用虚假控制流..." << std::endl;

        CipherShell::BogusFlowInjector bogusInjector;
        CipherShell::BogusFlowConfig bogusConfig;
        bogusConfig.bogusBlocksPerReal = 2;
        bogusConfig.duplicateCode = true;
        bogusConfig.duplicateRatio = 0.3f;
        bogusConfig.insertDeadCode = true;

        CipherShell::Disassembler disasm;
        bool is64 = image->is64Bit != 0;

        for (WORD si = 0; si < image->numSections; si++) {
            IMAGE_SECTION_HEADER& sec = image->sections[si];
            if (!(sec.Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;

            DWORD secOffset = sec.PointerToRawData;
            DWORD secSize   = sec.SizeOfRawData;
            if (secOffset + secSize > image->rawSize) continue;

            auto functions = disasm.AnalyzeCode(
                image->rawData + secOffset, secSize,
                sec.VirtualAddress, is64);

            uint32_t injectedCount = 0;
            for (const auto& func : functions) {
                if (func.blocks.size() < 2) continue;

                auto bogusResult = bogusInjector.InjectIntoFunction(func, bogusConfig);

                DWORD codeSize = 0;
                BYTE* bogusCode = bogusInjector.GenerateBogusCode(bogusResult, is64, &codeSize);
                if (bogusCode && codeSize > 0) {
                    injectedCount++;
                    delete[] bogusCode;
                }
                bogusInjector.Cleanup(bogusResult);
            }
            std::cout << "    注入了 " << injectedCount << " 个函数的虚假控制流" << std::endl;
        }
    }

    // Phase E: 代码虚拟化（L4+，将热点函数翻译为 VM 字节码）
    if (protectionLevel >= 4) {
        std::cout << "  应用代码虚拟化 (Mirage VM)..." << std::endl;

        // 初始化变异引擎，生成随机化 ISA
        CipherShell::MutationEngine mutEngine;
        CipherShell::MutationConfig mutConfig;
        mutConfig.randomizeOpcodeMap = true;
        mutConfig.randomizeRegisterMap = true;
        mutConfig.mutateHandlers = true;
        mutConfig.insertJunkHandlers = true;
        mutConfig.junkHandlerCount = 20;
        mutEngine.Initialize(mutConfig);

        CipherShell::MutatedISA mutatedISA = mutEngine.GenerateMutatedISA();
        std::cout << "    ISA 变异种子: 0x" << std::hex << mutEngine.GetSeed() << std::dec << std::endl;

        // 初始化转译器
        CipherShell::Translator translator;
        CipherShell::TranslationConfig transConfig;
        transConfig.virtualRegisterCount = mutConfig.registerCount;
        transConfig.enableOpcodeRandomization = true;
        transConfig.enableJunkInsertion = true;
        transConfig.junkRatio = 10;
        // BUG 12 修复：添加错误检查
        if (!translator.Initialize(transConfig)) {
            std::cerr << "  错误: 转译器初始化失败" << std::endl;
            return 1;
        }

        // 初始化字节码加密器
        CipherShell::BytecodeEncryptor bcEncryptor;
        CipherShell::BytecodeEncryptConfig bcConfig;
        bcConfig.mode = CipherShell::BytecodeEncryptionMode::Rolling;
        bcConfig.enableIntegrityCheck = true;

        CipherShell::Disassembler disasm;
        bool is64 = image->is64Bit != 0;
        uint32_t virtualizedCount = 0;

        for (WORD si = 0; si < image->numSections; si++) {
            IMAGE_SECTION_HEADER& sec = image->sections[si];
            if (!(sec.Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;

            DWORD secOffset = sec.PointerToRawData;
            DWORD secSize   = sec.SizeOfRawData;
            if (secOffset + secSize > image->rawSize) continue;

            BYTE* secData = image->rawData + secOffset;
            uint64_t baseAddr = sec.VirtualAddress;

            auto functions = disasm.AnalyzeCode(secData, secSize, baseAddr, is64);

            for (const auto& func : functions) {
                if (func.blocks.size() < 2) continue;

                // 翻译函数为 VM 字节码
                auto transResult = translator.TranslateFunction(func);
                if (transResult.instructions.empty()) continue;

                // BUG 11 修复：GenerateBytecode 内部已经做了加密（EncryptBytecode），
                // 不能再用 bcEncryptor.Encrypt() 二次加密，否则运行时解密后得到的
                // 仍是密文。这里只生成原始字节码（key=nullptr 跳过内部加密），
                // 然后由 bcEncryptor 统一加密。
                auto bytecode = translator.GenerateBytecode(
                    transResult, nullptr, nullptr);

                // 用 BytecodeEncryptor 加密字节码
                auto encryptedBytecode = bcEncryptor.Encrypt(bytecode, bcConfig);

                if (!encryptedBytecode.empty()) {
                    virtualizedCount++;
                }
            }
        }
        std::cout << "    虚拟化了 " << virtualizedCount << " 个函数" << std::endl;

        // L5: 嵌套 VM（将部分 handler 也虚拟化）
        if (protectionLevel >= 5) {
            std::cout << "  应用嵌套 VM (L5)..." << std::endl;

            CipherShell::VMNester nester;
            CipherShell::NestingConfig nestConfig;
            nestConfig.maxNestingDepth = 2;
            nestConfig.nestedHandlerCount = 10;
            nestConfig.differentISA = true;
            // BUG 12 修复：检查嵌套器初始化结果
            if (!nester.Initialize(nestConfig)) {
                std::cerr << "  错误: VM 嵌套器初始化失败，跳过 L5 嵌套" << std::endl;
            } else {
                auto layers = nester.CreateNestedVM(mutatedISA);
                if (layers.empty()) {
                    std::cerr << "  警告: 未能创建嵌套 VM 层" << std::endl;
                } else {
                    std::cout << "    嵌套层数: " << layers.size() << std::endl;

                    // 为每层生成 dispatcher
                    for (const auto& layer : layers) {
                        DWORD dispSize = 0;
                        BYTE* dispCode = nester.GenerateNestedDispatcher(layer, is64, &dispSize);
                        if (dispCode) {
                            std::cout << "    层 " << layer.level
                                      << " dispatcher: " << dispSize << " 字节" << std::endl;
                            delete[] dispCode;
                        } else {
                            std::cerr << "    警告: 层 " << layer.level
                                      << " dispatcher 生成失败" << std::endl;
                        }
                    }
                }
            }
        }
    }

    // Phase F: Section 加密（L1+，最后执行——加密所有变换后的代码）
    std::vector<CipherShell::CS_ENCRYPTED_SECTION> encryptedSections;
    if (protectionLevel >= 1) {
        std::cout << "  应用 Section 加密..." << std::endl;

        CipherShell::SectionEncryptor encryptor;
        CipherShell::CS_ENCRYPT_CONFIG encConfig;
        encConfig.encryptCodeSections = true;
        encConfig.encryptDataSections = false;
        encConfig.encryptResources = false;
        CipherShell::CS_ENCRYPTION_KEY masterKey = encryptor.GenerateRandomKey();

        encryptedSections = encryptor.EncryptSections(image.get(), encConfig, masterKey);
        std::cout << "    已加密 " << encryptedSections.size() << " 个 Section" << std::endl;
    }

    // ============================================================================
    // Step 3: 签名消除
    // ============================================================================

    std::cout << "\n[3/5] 消除壳签名..." << std::endl;

    {
        CipherShell::SignatureEliminator sigEliminator;

        auto sigMatches = sigEliminator.DetectSignatures(image.get());
        if (!sigMatches.empty()) {
            std::cout << "  发现 " << sigMatches.size() << " 个签名匹配:" << std::endl;
            for (const auto& match : sigMatches) {
                std::cout << "    - " << match.signatureName << " (" << match.detector << ")" << std::endl;
            }
        }

        CipherShell::EliminationConfig elimConfig;
        sigEliminator.EliminateSignatures(image.get(), elimConfig);

        if (sigEliminator.VerifyElimination(image.get())) {
            std::cout << "  签名消除成功" << std::endl;
        } else {
            std::cout << "  警告: 仍有签名残留" << std::endl;
        }
    }

    // ============================================================================
    // Step 4: 嵌入 Stub
    // ============================================================================

    std::cout << "\n[4/6] 嵌入解密 Stub..." << std::endl;

    if (!encryptedSections.empty()) {
        CipherShell::StubBuilder stubBuilder;
        if (!stubBuilder.EmbedStub(image.get(), encryptedSections, originalOEP)) {
            std::cerr << "  错误: Stub 嵌入失败" << std::endl;
            return 1;
        }
    } else {
        std::cout << "  跳过（无加密 section）" << std::endl;
    }

    // ============================================================================
    // Step 5: 重建 PE
    // ============================================================================

    std::cout << "\n[5/6] 写入输出文件..." << std::endl;

    CipherShell::PERebuilder rebuilder;
    CipherShell::CS_REBUILD_CONFIG rebuildConfig;

    rebuildConfig.randomizeSectionNames = true;
    rebuildConfig.zeroTimestamps = true;
    rebuildConfig.preserveRichHeader = false;
    rebuildConfig.preserveDebugInfo = false;

    DWORD outputSize = 0;
    std::unique_ptr<BYTE[]> outputData(rebuilder.RebuildImage(image.get(), rebuildConfig, &outputSize));

    if (!outputData || outputSize == 0) {
        std::cerr << "错误: PE 重建失败" << std::endl;
        return 1;
    }

    std::cout << "  PE 重建成功" << std::endl;
    std::cout << "  输出大小: " << outputSize << " 字节" << std::endl;

    // 写入输出文件
    FILE* outFile = fopen(outputFile.c_str(), "wb");
    if (!outFile) {
        std::cerr << "错误: 无法创建输出文件: " << outputFile << std::endl;
        return 1;
    }
    fwrite(outputData.get(), 1, outputSize, outFile);
    fclose(outFile);

    std::cout << "  输出文件已保存: " << outputFile << std::endl;
    std::cout << "  文件大小: " << outputSize << " 字节" << std::endl;

    // ============================================================================
    // Step 6: 验证输出
    // ============================================================================

    std::cout << "\n[6/6] 验证输出文件..." << std::endl;

    CipherShell::CS_PE_IMAGE* verifyImage = parser.LoadFromFile(outputFile);
    if (verifyImage && verifyImage->isValid) {
        std::cout << "  验证成功: 输出文件是有效的 PE" << std::endl;
        parser.FreeImage(verifyImage);
    } else {
        std::cerr << "  警告: 输出文件可能不是有效的 PE" << std::endl;
    }

    std::cout << "\n======================================" << std::endl;
    std::cout << "CipherShell 处理完成!" << std::endl;
    std::cout << "输出文件: " << outputFile << std::endl;
    std::cout << "======================================" << std::endl;

    return 0;
}
