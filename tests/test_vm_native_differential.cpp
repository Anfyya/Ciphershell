#include "packer/analysis/disassembler.h"
#include "packer/differential/vm_native_differential_provider.h"
#include "packer/mutation/mutation_engine.h"
#include "packer/transforms/translator.h"
#include "packer/transforms/vm_handler_semantic_codegen.h"
#include "packer/vm/vm_schema.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

using namespace CipherShell;

class TestFailure final : public std::runtime_error {
public:
    explicit TestFailure(const std::string& message) : std::runtime_error(message) {}
};

void Require(bool condition, const std::string& message) {
    if (!condition) throw TestFailure(message);
}

std::array<uint8_t, 32> MakeSeed(uint8_t domain) {
    std::array<uint8_t, 32> seed{};
    uint32_t state = 0x9E3779B9u ^ (static_cast<uint32_t>(domain) * 0x85EBCA6Bu);
    for (size_t index = 0; index < seed.size(); ++index) {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        seed[index] = static_cast<uint8_t>((state >> ((index & 3u) * 8u)) ^ index);
    }
    return seed;
}

#if defined(_M_X64) || defined(_M_IX86)

#if defined(_M_X64)
constexpr bool kIs64 = true;
#else
constexpr bool kIs64 = false;
#endif

struct HarnessBuild {
    MutatedISA isa;
    uint64_t translatorSeed = 0;
};

HarnessBuild SetUpMutatedIsa(const std::array<uint8_t, 32>& seed) {
    MutationConfig mutation{};
    mutation.seed = seed;
    mutation.registerCount = 24;
    mutation.randomizeOpcodeMap = true;
    mutation.randomizeRegisterMap = true;
    mutation.mutateHandlers = true;
    mutation.embedJunkHandlers = true;
    mutation.requestedJunkHandlerCount = 12;
    for (const auto& descriptor : VMSchema::Opcodes()) {
        const bool supported = kIs64
            ? descriptor.runtimeSupportedX64 : descriptor.runtimeSupportedX86;
        if (supported) mutation.validOpcodes.push_back(static_cast<uint8_t>(descriptor.opcode));
    }
    MutationEngine engine;
    Require(engine.Initialize(mutation), "MutationEngine 拒绝固定测试 seed");
    HarnessBuild build{};
    build.isa = engine.GenerateMutatedISA();
    build.translatorSeed = engine.GetSeedFingerprint();
    return build;
}

Function DecodeStandaloneFunction(
    Disassembler& disassembler,
    const std::vector<uint8_t>& bytes,
    uint64_t entryAddress)
{
    Function function{};
    Require(disassembler.AnalyzeFunctionRange(bytes.data(),
            static_cast<uint32_t>(bytes.size()), entryAddress,
            static_cast<uint32_t>(bytes.size()), kIs64, function),
        "无法解码测试函数: " + disassembler.GetLastError());
    function.boundaryTrusted = true;
    return function;
}

TranslationResult TranslateStandaloneFunction(
    const Function& standaloneFunction,
    const HarnessBuild& build,
    Translator& translator)
{
    TranslationConfig transConfig{};
    transConfig.virtualRegisterCount = 24;
    transConfig.buildSeed = build.translatorSeed;
    transConfig.density = VMMicroDensity::Light;
    transConfig.handlerVariantCount = VM_HANDLER_VARIANT_COUNT;
    Require(translator.Initialize(transConfig), "Translator 初始化失败");
    translator.SetOpcodeMap(build.isa.opcodeMap);
    translator.SetRegisterMap(build.isa.registerMap);
    TranslationResult result = translator.TranslateFunction(standaloneFunction);
    for (const auto& failure : result.failures) {
        std::cerr << "[translate-fail] addr=" << failure.address
                  << " mnemonic=" << failure.mnemonic
                  << " bytes=" << failure.bytes
                  << " reason=" << failure.reason << '\n';
    }
    Require(result.success && !result.instructions.empty(),
        "测试函数翻译失败");
    return result;
}

void RunDifferentialCase(
    const Function& function,
    const TranslationResult& translation,
    const HarnessBuild& build,
    uint32_t corpusCount,
    bool expectSuccess,
    const char* label,
    bool expectDivideFault = false,
    uint8_t providerSeedDomain = 0xC7u,
    bool expectBreakpointFault = false,
    uint64_t expectedNativeFaultOffset = 0)
{
    VMWindowsNativeDifferentialEvidenceProvider provider;
    const auto providerSeed = MakeSeed(providerSeedDomain);
    VMHandlerOperandCodecConfig operandCodec{};
    operandCodec.opcodeXor = static_cast<uint8_t>(providerSeed[3] | 1u);
    operandCodec.opcodeAdd = static_cast<uint8_t>(providerSeed[7] | 1u);
    operandCodec.opcodeRotate = static_cast<uint8_t>((providerSeed[11] % 7u) + 1u);

    std::string initError;
    const bool ready = provider.Initialize(
        kIs64 ? VMHandlerArchitecture::X64 : VMHandlerArchitecture::X86,
        providerSeed, build.isa.handlerSemanticToSlot, build.isa.handlerSlotToSemantic,
        build.isa.handlerVariants, operandCodec, 0x10000u, initError);
    Require(ready, std::string("provider 初始化失败(需要 vm_native_differential_worker.exe "
        "与 ciphershell 同目录): ") + initError);

    std::string prepareError;
    Require(provider.PrepareForFunction(static_cast<uint32_t>(function.entryAddress),
            translation.operandCodec, prepareError),
        "provider PrepareForFunction 失败: " + prepareError);

    VMNativeDifferentialConfig config{};
    config.corpusSeed = 0xA5A5A5A5A5A5A5A5ULL;
    config.corpusCount = corpusCount;
    config.memorySize = 0x10000u;
    config.timeoutMilliseconds = 5000;
    config.expectedHandlerImageDigest = provider.SemanticIdentityDigest();
    config.evidenceProvider = &provider;
    config.expectDivideFault = expectDivideFault;
    config.expectBreakpointFault = expectBreakpointFault;
    config.expectedNativeFaultOffset = expectedNativeFaultOffset;

    const auto result = VMNativeDifferentialVerifier::Verify(
        function, translation, build.isa.opcodeMap, build.isa.registerMap, config);
    if (expectSuccess) {
        Require(result.success && result.nativeCpuEvidenceVerified &&
                result.synthesizedHandlerEvidenceVerified &&
                result.casesVerified == corpusCount,
            std::string(label) + ": 期望通过但失败: " + result.error);
    } else {
        Require(!result.success,
            std::string(label) + ": 期望检测到真实语义分歧但通过了");
    }
    std::cout << "[" << label << "] cases=" << result.casesVerified
              << " success=" << result.success << " error=" << result.error << '\n';
}

void TestDispatchTableEncodingSchemesExecuteNatively() {
    const auto seed = MakeSeed(0x6Du);
    const HarnessBuild build = SetUpMutatedIsa(seed);
    Disassembler disassembler;
    Require(disassembler.Initialize(kIs64), "Disassembler 初始化失败");
    const std::vector<uint8_t> addBytes = {0x01,0xC8,0xC3};
    constexpr uint64_t kEntry = 0x1000;
    const Function function =
        DecodeStandaloneFunction(disassembler, addBytes, kEntry);
    Translator translator;
    const TranslationResult translation =
        TranslateStandaloneFunction(function, build, translator);

    uint8_t xorDomain = 0u;
    uint8_t addRotateDomain = 0u;
    bool haveXor = false;
    bool haveAddRotate = false;
    for (uint16_t domain = 1u; domain <= 0xFFu &&
            (!haveXor || !haveAddRotate); ++domain) {
        const auto candidateSeed = MakeSeed(static_cast<uint8_t>(domain));
        const VMDispatchTableCodec codec =
            DeriveVMDispatchTableCodec(candidateSeed);
        if (codec.encoding == VMDispatchTableEncoding::XorKeyedTable &&
            !haveXor) {
            xorDomain = static_cast<uint8_t>(domain);
            haveXor = true;
        } else if (codec.encoding ==
                VMDispatchTableEncoding::AddRotateKeyedTable &&
            !haveAddRotate) {
            addRotateDomain = static_cast<uint8_t>(domain);
            haveAddRotate = true;
        }
    }
    Require(haveXor && haveAddRotate,
        "测试 seed 未覆盖两种 dispatch table 编码方案");
    RunDifferentialCase(function, translation, build, 16, true,
        "XorKeyedTable 加密查表跳转原生执行", false, xorDomain);
    RunDifferentialCase(function, translation, build, 16, true,
        "AddRotateKeyedTable 加密查表跳转原生执行", false,
        addRotateDomain);
}

void TestRealDifferentialPassAndCatchesRealMismatch() {
    const auto seed = MakeSeed(0xC6);
    const HarnessBuild build = SetUpMutatedIsa(seed);

    Disassembler disassembler;
    Require(disassembler.Initialize(kIs64), "Disassembler 初始化失败");

    // add eax, ecx ; ret
    const std::vector<uint8_t> addBytes = {0x01, 0xC8, 0xC3};
    // sub eax, ecx ; ret  (same shape, opposite semantics)
    const std::vector<uint8_t> subBytes = {0x29, 0xC8, 0xC3};
    constexpr uint64_t kEntry = 0x1000;

    const Function addFunction = DecodeStandaloneFunction(disassembler, addBytes, kEntry);
    const Function subFunction = DecodeStandaloneFunction(disassembler, subBytes, kEntry);

    Translator translator;
    const TranslationResult addTranslation =
        TranslateStandaloneFunction(addFunction, build, translator);

    VMIRModelPreflightConfig preflightConfig{};
    preflightConfig.corpusSeed = 0x1234;
    preflightConfig.corpusCount = 8;
    const auto preflight = VMIRModelPreflightVerifier::Verify(
        addFunction, addTranslation, build.isa.opcodeMap, build.isa.registerMap, preflightConfig);
    std::cout << "[preflight] success=" << preflight.success << " cases=" << preflight.casesExecuted
              << " error=" << preflight.error << '\n';
    Require(preflight.success, "software IR 预检失败(说明是翻译本身的问题，不是原生差分新代码的问题): " +
        preflight.error);

    RunDifferentialCase(addFunction, addTranslation, build, 8, true,
        "native-vs-VM ADD 语义一致");
    RunDifferentialCase(subFunction, addTranslation, build, 8, false,
        "native=SUB vs VM-bytecode=ADD 必须被判定语义分歧");
}

void TestZydisAluPilotNativeDifferential() {
    const auto seed = MakeSeed(0xB0u);
    const HarnessBuild build = SetUpMutatedIsa(seed);
    Disassembler disassembler;
    Require(disassembler.Initialize(kIs64),
        "Zydis ALU pilot disassembler initialization failed");

    // and eax,ecx ; or eax,edx ; xor eax,ecx ; ret. The same 32-bit bytes
    // execute on both hosts and force all three migrated semantic kernels to
    // contribute to the final value. Four provider seeds independently
    // synthesize the handler chain, exercising build-seed register plans in
    // the isolated native worker rather than only inspecting emitted bytes.
    const std::vector<uint8_t> bytes = {
        0x21,0xC8, 0x09,0xD0, 0x31,0xC8, 0xC3};
    constexpr uint64_t kEntry = 0x1000;
    const Function function =
        DecodeStandaloneFunction(disassembler, bytes, kEntry);
    Translator translator;
    const TranslationResult translation =
        TranslateStandaloneFunction(function, build, translator);

    VMIRModelPreflightConfig preflightConfig{};
    preflightConfig.corpusSeed = 0xA11A11ULL;
    preflightConfig.corpusCount = 32;
    const auto preflight = VMIRModelPreflightVerifier::Verify(
        function, translation, build.isa.opcodeMap,
        build.isa.registerMap, preflightConfig);
    Require(preflight.success,
        "Zydis AND/OR/XOR pilot software IR preflight failed: " +
            preflight.error);

    constexpr std::array<uint8_t, 4> providerSeeds = {
        0xB1u, 0xB2u, 0xB3u, 0xB4u};
    for (uint8_t providerSeed : providerSeeds) {
        const std::string label =
            "native-vs-VM Zydis AND/OR/XOR seed " +
            std::to_string(providerSeed);
        RunDifferentialCase(function, translation, build, 32, true,
            label.c_str(), false, providerSeed);
    }
}

void TestZydisExplicitAluMemoryBatchNativeDifferential() {
    const auto seed = MakeSeed(0xB5u);
    const HarnessBuild build = SetUpMutatedIsa(seed);
    Disassembler disassembler;
    Require(disassembler.Initialize(kIs64),
        "Zydis explicit-ALU/memory batch disassembler initialization failed");

    // mov eax,[rcx/ecx] ; add/sub eax,edx ; not/neg eax ;
    // mov [rcx/ecx+4],eax ; mov eax,[rcx/ecx+4] ; ret.
    // These address forms are valid in the verifier's prepared corpus arena
    // on both hosts and force all six newly migrated kernels into one chain.
    const std::vector<uint8_t> bytes = {
        0x8B,0x01,
        0x01,0xD0,
        0x29,0xD0,
        0xF7,0xD0,
        0xF7,0xD8,
        0x89,0x41,0x04,
        0x8B,0x41,0x04,
        0xC3};
    constexpr uint64_t kEntry = 0x1000;
    const Function function =
        DecodeStandaloneFunction(disassembler, bytes, kEntry);
    Translator translator;
    const TranslationResult translation =
        TranslateStandaloneFunction(function, build, translator);

    VMIRModelPreflightConfig preflightConfig{};
    preflightConfig.corpusSeed = 0xA11A12ULL;
    preflightConfig.corpusCount = 32;
    const auto preflight = VMIRModelPreflightVerifier::Verify(
        function, translation, build.isa.opcodeMap,
        build.isa.registerMap, preflightConfig);
    Require(preflight.success,
        "Zydis ADD/SUB/NOT/NEG/LOAD/STORE software IR preflight failed: " +
            preflight.error);

    constexpr std::array<uint8_t, 4> providerSeeds = {
        0xB6u, 0xB7u, 0xB8u, 0xB9u};
    for (uint8_t providerSeed : providerSeeds) {
        const std::string label =
            "native-vs-VM Zydis ADD/SUB/NOT/NEG/LOAD/STORE seed " +
            std::to_string(providerSeed);
        RunDifferentialCase(function, translation, build, 32, true,
            label.c_str(), false, providerSeed);
    }
}

void TestFunctionEntryStackAndRetCleanupDifferential() {
    const auto seed = MakeSeed(0xD2);
    const HarnessBuild build = SetUpMutatedIsa(seed);
    Disassembler disassembler;
    Require(disassembler.Initialize(kIs64), "Disassembler 初始化失败");
    constexpr uint64_t kEntry = 0x1000;

#if defined(_M_IX86)
    // Function-entry ESP semantics, not a synthetic pre-CALL ESP:
    //   mov eax,[esp+4] ; add eax,[esp+8] ; ret
    const std::vector<uint8_t> cdeclBytes = {
        0x8B,0x44,0x24,0x04, 0x03,0x44,0x24,0x08, 0xC3};
    const Function cdeclFunction =
        DecodeStandaloneFunction(disassembler, cdeclBytes, kEntry);
    Translator cdeclTranslator;
    const TranslationResult cdeclTranslation =
        TranslateStandaloneFunction(cdeclFunction, build, cdeclTranslator);
    RunDifferentialCase(cdeclFunction, cdeclTranslation, build, 16, true,
        "x86 cdecl 函数入口 ESP/栈参数真实 CPU 差分");

    // Same body with callee cleanup: ret 8.  The verifier must account for
    // the physical CALL return slot and still strictly prove the +8 cleanup.
    const std::vector<uint8_t> stdcallBytes = {
        0x8B,0x44,0x24,0x04, 0x03,0x44,0x24,0x08, 0xC2,0x08,0x00};
    const Function stdcallFunction =
        DecodeStandaloneFunction(disassembler, stdcallBytes, kEntry);
    Translator stdcallTranslator;
    const TranslationResult stdcallTranslation =
        TranslateStandaloneFunction(stdcallFunction, build, stdcallTranslator);
    RunDifferentialCase(stdcallFunction, stdcallTranslation, build, 16, true,
        "x86 ret imm16 清栈/入口 ESP 真实 CPU 差分");
#else
    // Win64 fifth integer argument lives at [rsp+28h] at function entry.
    // This simultaneously verifies entry RSP (8 mod 16), shadow space, and
    // the native CALL wrapper's return-address normalization.
    const std::vector<uint8_t> stackArgumentBytes = {
        0x8B,0x44,0x24,0x28, 0x03,0xC1, 0xC3};
    const Function stackArgumentFunction =
        DecodeStandaloneFunction(disassembler, stackArgumentBytes, kEntry);
    Translator stackArgumentTranslator;
    const TranslationResult stackArgumentTranslation =
        TranslateStandaloneFunction(
            stackArgumentFunction, build, stackArgumentTranslator);
    RunDifferentialCase(stackArgumentFunction, stackArgumentTranslation,
        build, 16, true,
        "x64 函数入口 RSP/影子空间后栈参数真实 CPU 差分");
#endif
}

void TestMulNativeDifferentialMatchesRealCpu() {
    // 覆盖新加入的 VM_UOP_MUL 双策略业务核心(EmitBusinessCoreVariant 的
    // IMUL reg,reg 与 MUL reg 两条真实不同字节序列)：证明无论 build 的
    // seed/variant 选中哪一支策略，合成 handler 链的乘法结果都必须与
    // 真实 CPU LEA 的 scaled-index arithmetic 一致，而不仅仅是结构层面的
    // 字节模式检查。显式 two/three-operand IMUL 在 translator 中有意降低为
    // SMUL_WIDE；VM_UOP_MUL 的真实生产入口是地址 scale 计算。
    const auto seed = MakeSeed(0xD3);
    const HarnessBuild build = SetUpMutatedIsa(seed);

    Disassembler disassembler;
    Require(disassembler.Initialize(kIs64), "Disassembler 初始化失败");

    // lea rax/eax,[rax/eax+rcx/ecx*4] ; ret. EmitAddress chooses either a
    // real VM_UOP_MUL or repeated ADDs from translator seed and instruction
    // address. Search a small deterministic address range for the MUL arm so
    // this fixture cannot silently stop covering the migrated semantic.
    std::vector<uint8_t> mulBytes;
    if (kIs64) mulBytes.push_back(0x48);
    mulBytes.insert(mulBytes.end(), {0x8D,0x04,0x88,0xC3});
    std::vector<uint8_t> addBytes;
    if (kIs64) addBytes.push_back(0x48);
    addBytes.insert(addBytes.end(), {0x01,0xC8,0xC3});

    Function mulFunction{};
    TranslationResult mulTranslation{};
    uint64_t selectedEntry = 0u;
    for (uint64_t candidateEntry = 0x1000u;
         candidateEntry < 0x1100u; candidateEntry += 0x10u) {
        Function candidateFunction = DecodeStandaloneFunction(
            disassembler, mulBytes, candidateEntry);
        Translator candidateTranslator;
        TranslationResult candidateTranslation =
            TranslateStandaloneFunction(
                candidateFunction, build, candidateTranslator);
        const auto candidateMul = std::find_if(
            candidateTranslation.instructions.begin(),
            candidateTranslation.instructions.end(),
            [](const MicroInstruction& instruction) {
                return instruction.opcode == VM_UOP_MUL;
            });
        if (candidateMul == candidateTranslation.instructions.end()) continue;
        selectedEntry = candidateEntry;
        mulFunction = std::move(candidateFunction);
        mulTranslation = std::move(candidateTranslation);
        break;
    }
    Require(selectedEntry != 0u,
        "scaled LEA fixture could not select the VM_UOP_MUL lowering arm");
    const Function addFunction = DecodeStandaloneFunction(
        disassembler, addBytes, selectedEntry);
    const auto mulInstruction = std::find_if(
        mulTranslation.instructions.begin(), mulTranslation.instructions.end(),
        [](const MicroInstruction& instruction) {
            return instruction.opcode == VM_UOP_MUL;
        });
    Require(mulInstruction != mulTranslation.instructions.end(),
        "scaled LEA fixture emitted no VM_UOP_MUL instruction");

    VMIRModelPreflightConfig preflightConfig{};
    preflightConfig.corpusSeed = 0x5678;
    preflightConfig.corpusCount = 32;
    const auto preflight = VMIRModelPreflightVerifier::Verify(
        mulFunction, mulTranslation, build.isa.opcodeMap, build.isa.registerMap, preflightConfig);
    std::cout << "[preflight] success=" << preflight.success << " cases=" << preflight.casesExecuted
              << " error=" << preflight.error << '\n';
    Require(preflight.success, "software IR 预检失败(说明是翻译本身的问题，不是原生差分新代码的问题): " +
        preflight.error);

    std::array<std::vector<uint8_t>, 2> providerSeedsByStrategy{};
    std::array<std::set<std::array<uint8_t, 4>>, 2>
        assignmentsByStrategy{};
    for (uint16_t domain = 1u; domain <= 0xFFu; ++domain) {
        VMHandlerSemanticCodegenConfig config{};
        config.architecture = kIs64 ? VM_ARCH_X64 : VM_ARCH_X86;
        config.buildSeed = MakeSeed(static_cast<uint8_t>(domain));
        config.semantic = VM_UOP_MUL;
        config.variant = mulInstruction->handlerVariant;
        const auto generated = GenerateVMHandlerSemanticKernel(config);
        Require(generated.success,
            "MUL provider-seed selection generation failed: " +
                generated.error);
        const uint8_t strategy = generated.semanticCoreStrategy;
        if (assignmentsByStrategy[strategy].insert(
                generated.registerAssignment).second &&
                providerSeedsByStrategy[strategy].size() < 2u) {
            providerSeedsByStrategy[strategy].push_back(
                static_cast<uint8_t>(domain));
        }
        if (providerSeedsByStrategy[0].size() == 2u &&
                providerSeedsByStrategy[1].size() == 2u) break;
    }
    Require(providerSeedsByStrategy[0].size() == 2u &&
            providerSeedsByStrategy[1].size() == 2u,
        "MUL native differential did not select two register plans per K");
    for (uint8_t strategy = 0u; strategy < 2u; ++strategy) {
        for (uint8_t providerSeed : providerSeedsByStrategy[strategy]) {
            const std::string label =
                "native-vs-VM Zydis MUL K=" +
                std::to_string(strategy) + " seed " +
                std::to_string(providerSeed);
            RunDifferentialCase(mulFunction, mulTranslation, build, 32, true,
                label.c_str(), false, providerSeed);
        }
    }
    RunDifferentialCase(addFunction, mulTranslation, build, 8, false,
        "native=ADD vs VM scaled-LEA MUL 必须被判定语义分歧");
}

void TestBitOperationsNativeDifferentialMatchesRealCpu() {
    // 覆盖新加入的 VM_UOP_BIT_TEST/BIT_SET/BIT_RESET 双策略业务核心
    // (EmitBusinessCoreVariant 的手工 shift+mask 序列 与 原生 BT/BTS/BTR
    // 硬件指令两条真实不同字节序列)：证明无论 build 的 seed/variant 选中
    // 哪一支策略，合成 handler 链的位操作结果都必须与真实 CPU BT/BTS/BTR
    // 逐字节一致，而不仅仅是结构层面的字节模式检查。
    const auto seed = MakeSeed(0xF5);
    const HarnessBuild build = SetUpMutatedIsa(seed);

    Disassembler disassembler;
    Require(disassembler.Initialize(kIs64), "Disassembler 初始化失败");
    constexpr uint64_t kEntry = 0x1000;

    // bt/bts/btr eax, ecx ; add eax, 0 ; ret.  BT/BTS/BTR define CF but leave
    // OF/SF/ZF/AF/PF architecturally undefined, so (exactly like the MUL and
    // DIV/IDIV cases above) a trailing value-no-op `add eax, 0` closes that
    // undefined-flags window before the translator's terminal-RET check.
    const std::vector<uint8_t> btBytes = {
        0x0F, 0xA3, 0xC8, 0x81, 0xC0, 0x00, 0x00, 0x00, 0x00, 0xC3};
    const std::vector<uint8_t> btsBytes = {
        0x0F, 0xAB, 0xC8, 0x81, 0xC0, 0x00, 0x00, 0x00, 0x00, 0xC3};
    const std::vector<uint8_t> btrBytes = {
        0x0F, 0xB3, 0xC8, 0x81, 0xC0, 0x00, 0x00, 0x00, 0x00, 0xC3};
    // add eax, ecx ; ret  (same shape, opposite semantics; negative control)
    const std::vector<uint8_t> addBytes = {0x01, 0xC8, 0xC3};

    const struct { const std::vector<uint8_t>* bytes; uint64_t preflightSeed; const char* name; } cases[] = {
        {&btBytes, 0xB17B17ULL, "BIT_TEST(BT)"},
        {&btsBytes, 0xB17B18ULL, "BIT_SET(BTS)"},
        {&btrBytes, 0xB17B19ULL, "BIT_RESET(BTR)"},
    };

    for (const auto& testCase : cases) {
        const Function bitFunction =
            DecodeStandaloneFunction(disassembler, *testCase.bytes, kEntry);
        Translator translator;
        const TranslationResult bitTranslation =
            TranslateStandaloneFunction(bitFunction, build, translator);

        VMIRModelPreflightConfig preflightConfig{};
        preflightConfig.corpusSeed = testCase.preflightSeed;
        preflightConfig.corpusCount = 8;
        const auto preflight = VMIRModelPreflightVerifier::Verify(
            bitFunction, bitTranslation, build.isa.opcodeMap, build.isa.registerMap, preflightConfig);
        std::cout << "[preflight " << testCase.name << "] success=" << preflight.success
                  << " cases=" << preflight.casesExecuted << " error=" << preflight.error << '\n';
        Require(preflight.success, std::string(testCase.name) +
            " software IR 预检失败(说明是翻译本身的问题，不是原生差分新代码的问题): " +
            preflight.error);

        RunDifferentialCase(bitFunction, bitTranslation, build, 32, true,
            (std::string("native-vs-VM ") + testCase.name + " 语义一致").c_str());
    }

    // 单独一个跨语义负控制：native=ADD 的求值结果绝不能被误判为与
    // VM-bytecode=BIT_SET 一致，证明差分验证器确实在比较真实语义而非
    // 结构存在性。
    const Function addFunction = DecodeStandaloneFunction(disassembler, addBytes, kEntry);
    Translator btsTranslator;
    const TranslationResult btsTranslation =
        TranslateStandaloneFunction(
            DecodeStandaloneFunction(disassembler, btsBytes, kEntry), build, btsTranslator);
    RunDifferentialCase(addFunction, btsTranslation, build, 8, false,
        "native=ADD vs VM-bytecode=BIT_SET 必须被判定语义分歧");
}

void TestShiftOperationsNativeDifferentialMatchesRealCpu() {
    // 覆盖新加入的 VM_UOP_SHL/SHR 双策略业务核心(EmitBusinessCoreVariant 的
    // 原生 SHL/SHR 与 SHLD/SHRD-零源 两条真实不同字节序列)。逻辑移位的关键
    // 边界是 count 掩码:1/2/4 字节操作数把 count 掩到 5 位,8 字节掩到 6 位,
    // 而 8 位操作数还要走 shld 的 16 位提升。shl/shr 的 CL 计数被 Zydis 标成
    // implicit(只剩一个显式操作数,翻译器拒收),所以这里用立即数计数形式
    // (C0/C1 立即数是显式操作数),并刻意挑能暴露"操作数尺寸选错"的计数:
    //   width4 count=33 —— 32 位 shl 把 33 掩成 1,若错用 64 位 shld(掩到 6 位)
    //     会得到 33,结果天差地别,正好抓住策略臂里尺寸选错;
    //   width8 count=40 —— 落在 32<40<63 之间,验证 6 位掩码路径。
    // 每个用例的值(eax/rax)由差分语料随机化,故 count 固定、值随机,足以在
    // 这些边界上证明无论 build 的 seed/variant 选中哪一支策略,合成 handler 链
    // 的移位结果都与真实 CPU 逐字节一致,而非仅结构层面字节模式检查。
    //
    // 注:只覆盖 4/8 字节宽度,与既有 MUL/BIT/ADD 差分一致(差分语料按整寄存器
    // 喂随机值,8/16 位原生移位会保留寄存器高位字节,而 VM 8/16 位写回语义不
    // 与之逐字节对齐——这是 VM 执行器的既有约束,非本批变体引入;8/16 位路径
    // 由静态门禁保证双策略字节真实不同,执行级覆盖留到差分语料支持窄位写回后)。
    const auto seed = MakeSeed(0x9A);
    const HarnessBuild build = SetUpMutatedIsa(seed);

    Disassembler disassembler;
    Require(disassembler.Initialize(kIs64), "Disassembler 初始化失败");
    constexpr uint64_t kEntry = 0x1000;

    // shl/shr rAX, imm8 ; <add rAX, 0> ; ret.  SHL/SHR 在 count!=1 时把 OF 留作
    // 架构未定义,所以尾部那个值无副作用的 `add rAX, 0` 必须把六个状态位全部
    // 重新定义,关掉这扇未定义 flags 窗口,翻译器的终态 RET 检查才放行(与
    // MUL/BIT 的处理一致)。
    const std::vector<uint8_t> shl4 = {
        0xC1, 0xE0, 0x05, 0x81, 0xC0, 0x00, 0x00, 0x00, 0x00, 0xC3};  // shl eax,5
    const std::vector<uint8_t> shl4mask = {
        0xC1, 0xE0, 0x21, 0x81, 0xC0, 0x00, 0x00, 0x00, 0x00, 0xC3};  // shl eax,33
    const std::vector<uint8_t> shl8 = {
        0x48, 0xC1, 0xE0, 0x28, 0x48, 0x83, 0xC0, 0x00, 0xC3};        // shl rax,40
    const std::vector<uint8_t> shr4 = {
        0xC1, 0xE8, 0x05, 0x81, 0xC0, 0x00, 0x00, 0x00, 0x00, 0xC3};  // shr eax,5
    const std::vector<uint8_t> shr4mask = {
        0xC1, 0xE8, 0x21, 0x81, 0xC0, 0x00, 0x00, 0x00, 0x00, 0xC3};  // shr eax,33
    const std::vector<uint8_t> shr8 = {
        0x48, 0xC1, 0xE8, 0x28, 0x48, 0x83, 0xC0, 0x00, 0xC3};        // shr rax,40
    // Real D2/D3 encodings: Zydis exposes CL as an implicit read operand.
    // These cases also keep terminal undefined flags open deliberately so the
    // per-corpus path oracle, rather than a trailing flag-closing instruction,
    // decides exactly which bits native and VM must compare.
    const std::vector<uint8_t> shlCl0 = {
        0xB1,0x00, 0xD3,0xE0, 0xC3};                                  // mov cl,0; shl eax,cl
    const std::vector<uint8_t> shlCl1 = {
        0xB1,0x01, 0xD3,0xE0, 0xC3};                                  // mov cl,1; shl eax,cl
    const std::vector<uint8_t> shlCl2 = {
        0xB1,0x02, 0xD3,0xE0, 0xC3};                                  // mov cl,2; shl eax,cl
    const std::vector<uint8_t> shlAlClOverWidth = {
        0xB1,0x09, 0xD2,0xE0, 0xC3};                                  // mov cl,9; shl al,cl
    const std::vector<uint8_t> shlAlClExactWidth = {
        0xB1,0x08, 0xD2,0xE0, 0xC3};                                  // mov cl,8; shl al,cl
    const std::vector<uint8_t> rolAlClFullWidth = {
        0xB1,0x08, 0xD2,0xC0, 0xC3};                                  // mov cl,8; rol al,cl
    const std::vector<uint8_t> rorAxClFullWidth = {
        0xB1,0x10, 0x66,0xD3,0xC8, 0xC3};                             // mov cl,16; ror ax,cl

    const struct { const std::vector<uint8_t>* bytes; uint64_t preflightSeed; const char* name; } cases[] = {
        {&shl4, 0x9A04ULL, "SHL(shl eax,5) width4"},
        {&shl4mask, 0x9A14ULL, "SHL(shl eax,33) width4 count-mask"},
        {&shl8, 0x9A08ULL, "SHL(shl rax,40) width8"},
        {&shr4, 0x9A24ULL, "SHR(shr eax,5) width4"},
        {&shr4mask, 0x9A34ULL, "SHR(shr eax,33) width4 count-mask"},
        {&shr8, 0x9A18ULL, "SHR(shr rax,40) width8"},
        {&shlCl0, 0x9A40ULL, "SHL(shl eax,cl) masked count=0 preserves flags"},
        {&shlCl1, 0x9A41ULL, "SHL(shl eax,cl) count=1 defines OF"},
        {&shlCl2, 0x9A42ULL, "SHL(shl eax,cl) count>1 leaves OF undefined"},
        {&shlAlClExactWidth, 0x9A48ULL, "SHL(shl al,cl) count==width leaves CF undefined"},
        {&shlAlClOverWidth, 0x9A49ULL, "SHL(shl al,cl) count>width"},
        {&rolAlClFullWidth, 0x9A58ULL, "ROL(rol al,cl) full-width count"},
        {&rorAxClFullWidth, 0x9A60ULL, "ROR(ror ax,cl) full-width count"},
    };

    for (const auto& testCase : cases) {
        const Function shiftFunction =
            DecodeStandaloneFunction(disassembler, *testCase.bytes, kEntry);
        Translator translator;
        const TranslationResult shiftTranslation =
            TranslateStandaloneFunction(shiftFunction, build, translator);
        Require(shiftTranslation.success, std::string(testCase.name) +
            " 翻译失败:移位立即数形式意外不被翻译器支持");

        VMIRModelPreflightConfig preflightConfig{};
        preflightConfig.corpusSeed = testCase.preflightSeed;
        preflightConfig.corpusCount = 8;
        const auto preflight = VMIRModelPreflightVerifier::Verify(
            shiftFunction, shiftTranslation, build.isa.opcodeMap, build.isa.registerMap, preflightConfig);
        std::cout << "[preflight " << testCase.name << "] success=" << preflight.success
                  << " cases=" << preflight.casesExecuted << " error=" << preflight.error << '\n';
        Require(preflight.success, std::string(testCase.name) +
            " software IR 预检失败(说明是翻译本身的问题，不是原生差分新代码的问题): " +
            preflight.error);

        RunDifferentialCase(shiftFunction, shiftTranslation, build, 32, true,
            (std::string("native-vs-VM ") + testCase.name + " 语义一致").c_str());
    }

    // 跨语义负控制:native=SHL 的求值结果绝不能被误判为与 VM-bytecode=SHR 一致,
    // 证明差分验证器确实在比较真实移位语义而非结构存在性。
    const Function shl4Function = DecodeStandaloneFunction(disassembler, shl4, kEntry);
    Translator shrTranslator;
    const TranslationResult shrTranslation =
        TranslateStandaloneFunction(
            DecodeStandaloneFunction(disassembler, shr4, kEntry), build, shrTranslator);
    RunDifferentialCase(shl4Function, shrTranslation, build, 8, false,
        "native=SHL vs VM-bytecode=SHR 必须被判定语义分歧");

    // Full-width r8 rotates leave the value unchanged but still define CF.
    // ROL reports the resulting LSB while ROR reports the resulting MSB, so
    // crossing the two translations is a real-worker negative control that
    // fails if the verifier incorrectly masks full-width rotate CF.
    const Function rolFullWidthFunction = DecodeStandaloneFunction(
        disassembler, rolAlClFullWidth, kEntry);
    Translator rorFullWidthTranslator;
    const TranslationResult rorFullWidthTranslation =
        TranslateStandaloneFunction(
            DecodeStandaloneFunction(disassembler,
                std::vector<uint8_t>{0xB1,0x08,0xD2,0xC8,0xC3}, kEntry),
            build, rorFullWidthTranslator);
    RunDifferentialCase(rolFullWidthFunction, rorFullWidthTranslation,
        build, 32, false,
        "native=ROL al,8 vs VM-bytecode=ROR al,8 must expose defined CF");
}

void TestRemainingArithmeticFamiliesNativeDifferential() {
    // 将新增的进位/借位、字节翻转、算术移位/旋转、扩展以及宽乘法放进
    // 三段真实可调用机器码。每段都先过同一个 IR preflight，再交给隔离
    // native worker 与合成 handler 链逐寄存器/逐 flags 比较；这不是只看
    // EmitBusinessCoreVariant 的字节存在性。
    const auto seed = MakeSeed(0xA7);
    const HarnessBuild build = SetUpMutatedIsa(seed);
    Disassembler disassembler;
    Require(disassembler.Initialize(kIs64), "Disassembler 初始化失败");
    constexpr uint64_t kEntry = 0x1000;

    // adc eax,ecx; sbb eax,edx; bswap eax; sar eax,5;
    // rol eax,1; ror eax,1; add eax,0; ret.  Use the explicit C1 imm8
    // encodings so the translator receives a visible count operand.
    // 最后的 ADD 只关闭 SAR count>1 留下的 OF 未定义窗口，不改变值。
    const std::vector<uint8_t> carryShiftBytes = {
        0x11,0xC8, 0x19,0xD0, 0x0F,0xC8, 0xC1,0xF8,0x05,
        0xC1,0xC0,0x01, 0xC1,0xC8,0x01,
        0x81,0xC0,0x00,0x00,0x00,0x00, 0xC3};
    // movzx eax,cl; movsx edx,cl; ret. MOVZX/MOVSX 必须保持输入 flags。
    const std::vector<uint8_t> extendBytes = {
        0x0F,0xB6,0xC1, 0x0F,0xBE,0xD1, 0xC3};
    // mul ecx; imul ecx; add eax,0; ret. 两条 implicit multiply 分别落到
    // UMUL_WIDE/SMUL_WIDE；末尾 ADD 关闭 MUL/IMUL 未定义状态位。
    const std::vector<uint8_t> wideMultiplyBytes = {
        0xF7,0xE1, 0xF7,0xE9,
        0x81,0xC0,0x00,0x00,0x00,0x00, 0xC3};

    const struct {
        const std::vector<uint8_t>* bytes;
        uint64_t preflightSeed;
        const char* label;
        std::array<VM_MICRO_OPCODE, 2> migratedSemantics;
        size_t migratedSemanticCount;
    } cases[] = {
        {&carryShiftBytes, 0xA701ULL,
            "ADC/SBB/BSWAP/SAR/ROL/ROR",
            {VM_UOP_BSWAP, VM_UOP_TRAP}, 1u},
        {&extendBytes, 0xA702ULL,
            "ZERO_EXTEND/SIGN_EXTEND",
            {VM_UOP_ZERO_EXTEND, VM_UOP_SIGN_EXTEND}, 2u},
        {&wideMultiplyBytes, 0xA703ULL,
            "UMUL_WIDE/SMUL_WIDE",
            {VM_UOP_TRAP, VM_UOP_TRAP}, 0u},
    };

    for (const auto& testCase : cases) {
        const Function function = DecodeStandaloneFunction(
            disassembler, *testCase.bytes, kEntry);
        Translator translator;
        const TranslationResult translation =
            TranslateStandaloneFunction(function, build, translator);
        VMIRModelPreflightConfig preflightConfig{};
        preflightConfig.corpusSeed = testCase.preflightSeed;
        preflightConfig.corpusCount = 16;
        const auto preflight = VMIRModelPreflightVerifier::Verify(
            function, translation, build.isa.opcodeMap,
            build.isa.registerMap, preflightConfig);
        Require(preflight.success,
            std::string(testCase.label) + " software IR 预检失败: " +
                preflight.error);
        std::vector<uint8_t> providerSeeds;
        if (testCase.migratedSemanticCount != 0u) {
            struct Coverage {
                VM_MICRO_OPCODE semantic = VM_UOP_TRAP;
                uint8_t variant = 0u;
                std::array<std::set<std::array<uint8_t, 4>>, 2> assignments{};
            };
            std::vector<Coverage> coverage;
            for (size_t index = 0u;
                 index < testCase.migratedSemanticCount; ++index) {
                const VM_MICRO_OPCODE semantic =
                    testCase.migratedSemantics[index];
                const auto instruction = std::find_if(
                    translation.instructions.begin(),
                    translation.instructions.end(),
                    [&](const MicroInstruction& candidate) {
                        return candidate.opcode == semantic;
                    });
                Require(instruction != translation.instructions.end(),
                    "migrated arithmetic fixture omitted its target semantic");
                coverage.push_back({semantic, instruction->handlerVariant, {}});
            }
            const auto complete = [&] {
                for (const Coverage& item : coverage) {
                    for (const auto& plans : item.assignments) {
                        if (plans.size() < 2u) return false;
                    }
                }
                return true;
            };
            for (uint16_t domain = 1u;
                 domain <= 0xFFu && !complete(); ++domain) {
                bool addsCoverage = false;
                for (Coverage& item : coverage) {
                    VMHandlerSemanticCodegenConfig config{};
                    config.architecture = kIs64 ? VM_ARCH_X64 : VM_ARCH_X86;
                    config.buildSeed = MakeSeed(static_cast<uint8_t>(domain));
                    config.semantic = item.semantic;
                    config.variant = item.variant;
                    const auto generated =
                        GenerateVMHandlerSemanticKernel(config);
                    Require(generated.success,
                        "migrated arithmetic provider-seed selection failed: " +
                            generated.error);
                    const uint8_t strategy = generated.semanticCoreStrategy;
                    Require(strategy < item.assignments.size(),
                        "migrated arithmetic selected an unknown K strategy");
                    if (item.assignments[strategy].size() < 2u &&
                            item.assignments[strategy].insert(
                                generated.registerAssignment).second) {
                        addsCoverage = true;
                    }
                }
                if (addsCoverage)
                    providerSeeds.push_back(static_cast<uint8_t>(domain));
            }
            Require(complete(),
                "migrated arithmetic differential lacks two plans per K");
        } else {
            providerSeeds.push_back(0xC7u);
        }
        for (uint8_t providerSeed : providerSeeds) {
            const std::string label = std::string("native-vs-VM ") +
                testCase.label + " seed " + std::to_string(providerSeed);
            RunDifferentialCase(function, translation, build, 32, true,
                label.c_str(), false, providerSeed);
        }
    }
}

#if defined(_M_IX86)
void TestX86ZydisUmulWidePerKNativeDifferential() {
    const auto seed = MakeSeed(0xAAu);
    const HarnessBuild build = SetUpMutatedIsa(seed);
    Disassembler disassembler;
    Require(disassembler.Initialize(false),
        "x86 UMUL_WIDE per-K disassembler initialization failed");
    constexpr uint64_t kEntry = 0x1000;
    const std::vector<uint8_t> bytes = {
        0xF7,0xE1,
        0x81,0xC0,0x00,0x00,0x00,0x00,
        0xC3};
    const Function function =
        DecodeStandaloneFunction(disassembler, bytes, kEntry);
    Translator translator;
    const TranslationResult translation =
        TranslateStandaloneFunction(function, build, translator);

    const auto umul = std::find_if(
        translation.instructions.begin(), translation.instructions.end(),
        [](const MicroInstruction& instruction) {
            return instruction.opcode == VM_UOP_UMUL_WIDE;
        });
    Require(umul != translation.instructions.end(),
        "x86 MUL fixture emitted no UMUL_WIDE instruction");

    VMIRModelPreflightConfig preflightConfig{};
    preflightConfig.corpusSeed = 0x554D554C4B31ULL;
    preflightConfig.corpusCount = 32;
    const auto preflight = VMIRModelPreflightVerifier::Verify(
        function, translation, build.isa.opcodeMap,
        build.isa.registerMap, preflightConfig);
    Require(preflight.success,
        "x86 UMUL_WIDE per-K software IR preflight failed: " +
            preflight.error);

    std::array<std::vector<uint8_t>, 2> providerSeedsByStrategy{};
    std::array<std::set<std::array<uint8_t, 4>>, 2> plansByStrategy{};
    for (uint16_t domain = 1u; domain <= 0xFFu; ++domain) {
        VMHandlerSemanticCodegenConfig config{};
        config.architecture = VM_ARCH_X86;
        config.buildSeed = MakeSeed(static_cast<uint8_t>(domain));
        config.semantic = VM_UOP_UMUL_WIDE;
        config.variant = umul->handlerVariant;
        const auto generated = GenerateVMHandlerSemanticKernel(config);
        Require(generated.success,
            "x86 UMUL_WIDE seed selection generation failed: " +
                generated.error);
        const uint8_t strategy = generated.semanticCoreStrategy;
        Require(strategy < plansByStrategy.size(),
            "x86 UMUL_WIDE selected an unknown K strategy");
        if (plansByStrategy[strategy].insert(
                generated.registerAssignment).second) {
            providerSeedsByStrategy[strategy].push_back(
                static_cast<uint8_t>(domain));
        }
        if (plansByStrategy[0].size() == 4u &&
                plansByStrategy[1].size() == 4u) break;
    }
    Require(providerSeedsByStrategy[0].size() == 4u &&
            providerSeedsByStrategy[1].size() == 4u,
        "x86 UMUL_WIDE differential seeds did not cover four plans for both K values");

    for (uint8_t strategy = 0u; strategy < 2u; ++strategy) {
        for (uint8_t providerSeed : providerSeedsByStrategy[strategy]) {
            const std::string label =
                "native-vs-VM x86 Zydis UMUL_WIDE K=" +
                std::to_string(strategy) + " seed " +
                std::to_string(providerSeed);
            RunDifferentialCase(function, translation, build, 32, true,
                label.c_str(), false, providerSeed);
        }
    }
}
#endif

void TestWideDivideNativeDifferentialAndDivideFault() {
    // 生产级 DIV/IDIV(UDIV_WIDE/IDIV_WIDE)差分证据：直接复用 packer/differential/
    // 的隔离原生 worker，而不是另起一套验证机制。dividend 是完整的
    // 高:低寄存器对(x64 下 RDX:RAX = 128 位被除数，x86 下 EDX:EAX = 64 位)，
    // 除数取自随机语料，因此语料天然混有"商能装下"(两侧都应成功且逐寄存器
    // 一致)与"除零/商溢出"(两侧都应触发 #DE)两类样本。VMNativeDifferentialConfig
    // ::expectDivideFault 让验证器按样本实际结果分别核对，而不是把任何 fault
    // 都当成硬性失败。
    const auto seed = MakeSeed(0xE4);
    const HarnessBuild build = SetUpMutatedIsa(seed);

    Disassembler disassembler;
    Require(disassembler.Initialize(kIs64), "Disassembler 初始化失败");

    constexpr uint64_t kEntry = 0x1000;
    for (const bool signedDivide : {false, true}) {
        // {REX.W} F7 /6|/7 (DIV|IDIV ecx/rcx) ; {REX.W} ADD eax/rax, 0 ; RET.
        // DIV/IDIV leaves every status flag architecturally undefined, so the
        // trailing ADD-immediate-0 (a value no-op) closes that undefined-flags
        // window for the translator's flow analysis, exactly like the MUL
        // case above. On a faulting sample the CPU never reaches it: the #DE
        // fires at the DIV/IDIV itself.
        std::vector<uint8_t> divideBytes;
        if (kIs64) divideBytes.push_back(0x48);
        divideBytes.push_back(0xF7);
        divideBytes.push_back(signedDivide ? 0xF9 : 0xF1);
        if (kIs64) divideBytes.push_back(0x48);
        divideBytes.insert(divideBytes.end(), {0x81, 0xC0, 0x00, 0x00, 0x00, 0x00});
        divideBytes.push_back(0xC3);

        const Function divideFunction =
            DecodeStandaloneFunction(disassembler, divideBytes, kEntry);
        Translator translator;
        const TranslationResult divideTranslation =
            TranslateStandaloneFunction(divideFunction, build, translator);

        VMIRModelPreflightConfig preflightConfig{};
        preflightConfig.corpusSeed = signedDivide ? 0x1D19ULL : 0xD19D19ULL;
        preflightConfig.corpusCount = 8;
        const auto preflight = VMIRModelPreflightVerifier::Verify(
            divideFunction, divideTranslation, build.isa.opcodeMap,
            build.isa.registerMap, preflightConfig);
        std::cout << "[preflight " << (signedDivide ? "IDIV" : "DIV") << "] success="
                  << preflight.success << " cases=" << preflight.casesExecuted
                  << " error=" << preflight.error << '\n';
        Require(preflight.success,
            std::string(signedDivide ? "IDIV" : "DIV") +
                " software IR 预检失败(说明是翻译本身的问题，不是原生差分新代码的问题): " +
                preflight.error);

        RunDifferentialCase(divideFunction, divideTranslation, build, 64, true,
            signedDivide ? "native-vs-VM IDIV_WIDE(128-bit dividend)/#DE 一致"
                         : "native-vs-VM UDIV_WIDE(128-bit dividend)/#DE 一致",
            /*expectDivideFault=*/true, /*providerSeedDomain=*/0xC7u,
            /*expectBreakpointFault=*/false, /*expectedNativeFaultOffset=*/0);
    }
}

void TestInt3NativeDifferentialAndBreakpointFault() {
    // INT3(0xCC)/INT 3(CD 03) 两种编码语义相同(都会触发真实的
    // STATUS_BREAKPOINT，向量都是 3)，但 Windows 报告的故障 EIP/RIP 不同。
    // 实测(而不是凭经验假设)得到的真实规律是：Windows 的向量 3 陷阱处理是
    // "无条件按 1 字节指令回退"，不管真正触发的是 1 字节的 0xCC 还是 2
    // 字节的 CD 03，报告的 Eip/Rip 都是"指令结束地址 - 1"：0xCC(1 字节)因此
    // 落在偏移 0(指令自身起始地址)；CD 03(2 字节)落在偏移 1(两个字节中间，
    // 不是指令末尾的偏移 2)。VM_UOP_INT3 的合成 handler
    // (EmitBusinessCoreVariant 的两个 strategy，见
    // vm_handler_semantic_codegen.cpp)直接内联执行真实的 0xCC 或 CD 03，而
    // 不是软件模拟这个 trap，所以"两种编码方式的等价性"必须用真实 CPU 差分
    // 证明：这里对每种编码分别构造一个只含该编码的 guest 函数，验证真实
    // CPU 执行它时确实表现出上述规律(RunDifferentialCase 里的
    // expectedNativeFaultOffset)，并且不管这次构建的 seed 让 VM_UOP_INT3 的
    // 哪个 strategy 生效，两侧故障时的寄存器/FLAGS 现场都必须和故障前的
    // 语料初始值完全一致，而不仅仅是异常码相同。
    //
    // 软件 IR 模型预检(VMIRModelPreflightVerifier)背后的 ExecuteOracle 现在
    // 会把 INT3 分类为 OracleFault::Breakpoint(参见 ExecuteOracle 的
    // InstructionMnemonic::Int3 分支)，但该预检自身的等价性折叠逻辑目前
    // 只认 DivideError；这里和 TestDispatchTableEncodingSchemesExecuteNatively
    // 一样，直接跑真实差分，不经过预检这一步。
    const auto seed = MakeSeed(0xE5);
    const HarnessBuild build = SetUpMutatedIsa(seed);

    Disassembler disassembler;
    Require(disassembler.Initialize(kIs64), "Disassembler 初始化失败");

    constexpr uint64_t kEntry = 0x1000;
    struct Int3Case {
        std::vector<uint8_t> bytes;
        const char* label;
        uint8_t seedDomain;
        uint64_t expectedNativeFaultOffset;
    };
    // No trailing RET: AnalyzeFunctionRange (disassembler.cpp) treats any
    // Interrupt-category instruction as a function boundary exactly like
    // RET/an indirect branch and never decodes past it, so the trap byte(s)
    // are the entire function.
    const Int3Case cases[] = {
        {{0xCC}, "native-vs-VM INT3(0xCC 单字节编码)/#BP 一致", 0xE6u, 0u},
        {{0xCD, 0x03}, "native-vs-VM INT 3(CD 03 双字节编码)/#BP 一致", 0xE7u, 1u},
    };

    for (const auto& testCase : cases) {
        const Function int3Function =
            DecodeStandaloneFunction(disassembler, testCase.bytes, kEntry);
        Translator translator;
        const TranslationResult int3Translation =
            TranslateStandaloneFunction(int3Function, build, translator);

        RunDifferentialCase(int3Function, int3Translation, build, 16, true,
            testCase.label,
            /*expectDivideFault=*/false, testCase.seedDomain,
            /*expectBreakpointFault=*/true,
            /*expectedNativeFaultOffset=*/testCase.expectedNativeFaultOffset);
    }
}

void TestBranchToRetMaterializesObservableFlags() {
    const auto seed = MakeSeed(0xD4);
    const HarnessBuild build = SetUpMutatedIsa(seed);
    Disassembler disassembler;
    Require(disassembler.Initialize(kIs64), "Disassembler initialization failed");
    constexpr uint64_t kEntry = 0x1000;

    // cmp ecx,edx ; jz ret ; mov eax,eax ; ret. Both paths retain exactly the
    // CMP flags, while the conditional edge targets the original RET directly.
    // Differential bytecode must rebase that edge to FLAGS_MATERIALIZE.
    const std::vector<uint8_t> bytes = {
        0x39,0xD1, 0x74,0x02, 0x89,0xC0, 0xC3};
    const Function function =
        DecodeStandaloneFunction(disassembler, bytes, kEntry);
    Translator translator;
    const TranslationResult translation =
        TranslateStandaloneFunction(function, build, translator);
    RunDifferentialCase(function, translation, build, 32, true,
        "branch-to-RET observable flags materialization");
}

void TestUndefinedFlagsReadFailsClosed() {
    const auto seed = MakeSeed(0xD5);
    const HarnessBuild build = SetUpMutatedIsa(seed);
    Disassembler disassembler;
    Require(disassembler.Initialize(kIs64), "Disassembler initialization failed");
    constexpr uint64_t kEntry = 0x1000;

    // imul eax,ecx leaves ZF undefined; JZ consumes ZF. A
    // terminal undefined flag may be excluded from observation, but reading
    // it later is nondeterministic and must remain fail-closed.
    const std::vector<uint8_t> bytes = {
        0x0F,0xAF,0xC1, 0x74,0x00, 0xC3};
    const Function function =
        DecodeStandaloneFunction(disassembler, bytes, kEntry);
    Translator translator;
    TranslationConfig config{};
    config.virtualRegisterCount = 24;
    config.buildSeed = build.translatorSeed;
    config.density = VMMicroDensity::Light;
    config.handlerVariantCount = VM_HANDLER_VARIANT_COUNT;
    Require(translator.Initialize(config), "Translator initialization failed");
    translator.SetOpcodeMap(build.isa.opcodeMap);
    translator.SetRegisterMap(build.isa.registerMap);
    const TranslationResult translation = translator.TranslateFunction(function);
    Require(!translation.success,
        "undefined ZF consumed by JZ was incorrectly accepted");
    bool foundReason = false;
    for (const auto& failure : translation.failures) {
        if (failure.reason.find(
                "instruction reads flags undefined on a reachable path") !=
                std::string::npos) {
            foundReason = true;
            break;
        }
    }
    Require(foundReason,
        "undefined-flags rejection did not identify the first flag read");

    auto requireShiftFlagReadRejected = [&](const std::vector<uint8_t>& bytes,
                                            const char* label) {
        const Function candidate =
            DecodeStandaloneFunction(disassembler, bytes, kEntry);
        Translator candidateTranslator;
        TranslationConfig candidateConfig{};
        candidateConfig.virtualRegisterCount = 24;
        candidateConfig.buildSeed = build.translatorSeed;
        candidateConfig.density = VMMicroDensity::Light;
        candidateConfig.handlerVariantCount = VM_HANDLER_VARIANT_COUNT;
        Require(candidateTranslator.Initialize(candidateConfig),
            "undefined shift-flag fixture translator initialization failed");
        candidateTranslator.SetOpcodeMap(build.isa.opcodeMap);
        candidateTranslator.SetRegisterMap(build.isa.registerMap);
        const TranslationResult candidateTranslation =
            candidateTranslator.TranslateFunction(candidate);
        bool identifiedFlagRead = false;
        for (const auto& failure : candidateTranslation.failures) {
            if (failure.reason.find(
                    "instruction reads flags undefined on a reachable path") !=
                    std::string::npos) {
                identifiedFlagRead = true;
                break;
            }
        }
        Require(!candidateTranslation.success && identifiedFlagRead,
            std::string(label) +
                " did not fail closed at the undefined flag consumer");
    };

    // shl al,8 leaves CF undefined (the equality boundary is not defined),
    // so a following ADC must never be virtualized as deterministic code.
    requireShiftFlagReadRejected(
        {0xC0,0xE0,0x08, 0x80,0xD3,0x00, 0xC3},
        "immediate exact-width SHL followed by ADC");
    // A subsequent count-zero shift preserves that undefined CF rather than
    // repairing it, so the later ADC must still be rejected.
    requireShiftFlagReadRejected(
        {0xC0,0xE0,0x08, 0xC0,0xE0,0x00,
         0x80,0xD3,0x00, 0xC3},
        "count-zero SHL preserving an undefined incoming CF");
    // With CL unknown at translation time, r8 admits counts >= 8 (undefined
    // CF) and every width admits counts > 1 (undefined OF).
    requireShiftFlagReadRejected(
        {0xD2,0xE0, 0x80,0xD3,0x00, 0xC3},
        "CL-dependent r8 SHL followed by ADC");
    requireShiftFlagReadRejected(
        {0xD3,0xE0, 0x0F,0x90,0xC3, 0xC3},
        "CL-dependent r32 SHL followed by SETO");

    // At function entry CF is defined.  An immediate zero count preserves it,
    // so the same ADC consumer is valid and must continue through the real
    // native worker instead of being rejected by an over-conservative lattice.
    const Function countZeroPreservesCf = DecodeStandaloneFunction(
        disassembler,
        {0xC0,0xE0,0x00, 0x80,0xD3,0x00, 0xC3}, kEntry);
    Translator countZeroTranslator;
    const TranslationResult countZeroTranslation =
        TranslateStandaloneFunction(
            countZeroPreservesCf, build, countZeroTranslator);
    RunDifferentialCase(countZeroPreservesCf, countZeroTranslation,
        build, 16, true,
        "count-zero SHL preserves defined incoming CF for ADC");

}

#if defined(_M_X64)
void TestCmovR32PreservesOrClearsUpperHalf() {
    const auto seed = MakeSeed(0xD6);
    const HarnessBuild build = SetUpMutatedIsa(seed);
    Disassembler disassembler;
    Require(disassembler.Initialize(true), "Disassembler initialization failed");
    constexpr uint64_t kEntry = 0x1000;

    // cmp ecx,ecx sets ZF. In 64-bit mode CMOV r32 clears RAX[63:32]
    // regardless of whether the low-32 destination assignment is taken.
    const std::vector<uint8_t> notTakenBytes = {
        0x39,0xC9, 0x0F,0x45,0xC2, 0xC3};
    const std::vector<uint8_t> takenBytes = {
        0x39,0xC9, 0x0F,0x44,0xC2, 0xC3};
    const struct {
        const std::vector<uint8_t>* bytes;
        const char* label;
    } cases[] = {
        {&notTakenBytes, "x64 CMOV r32 not-taken clears upper RAX"},
        {&takenBytes, "x64 CMOV r32 taken zero-extends RAX"},
    };
    for (const auto& testCase : cases) {
        const Function function =
            DecodeStandaloneFunction(disassembler, *testCase.bytes, kEntry);
        Translator translator;
        const TranslationResult translation =
            TranslateStandaloneFunction(function, build, translator);
        RunDifferentialCase(function, translation, build, 32, true,
            testCase.label);
    }
}
#endif

#endif // _M_X64 || _M_IX86

void Run(const char* name, void (*test)(), int& failures) {
    try {
        test();
        std::cout << "[PASS] " << name << '\n';
    } catch (const std::exception& error) {
        ++failures;
        std::cerr << "[FAIL] " << name << ": " << error.what() << '\n';
    }
}

} // namespace

int main() {
    std::cout.setf(std::ios::unitbuf);
    std::cerr.setf(std::ios::unitbuf);
    int failures = 0;
#if defined(_M_X64) || defined(_M_IX86)
    Run("隔离原生差分证据: 真实 CPU 与合成 handler 链一致性/分歧检测",
        &TestRealDifferentialPassAndCatchesRealMismatch, failures);
    Run("Zydis AND/OR/XOR build-seed register native differential",
        &TestZydisAluPilotNativeDifferential, failures);
    Run("Zydis ADD/SUB/NOT/NEG/LOAD/STORE build-seed native differential",
        &TestZydisExplicitAluMemoryBatchNativeDifferential, failures);
    Run("函数入口 SP/栈参数/RET 清栈真实 CPU 差分",
        &TestFunctionEntryStackAndRetCleanupDifferential, failures);
    Run("branch-to-RET flags materialization",
        &TestBranchToRetMaterializesObservableFlags, failures);
    Run("undefined flags consumed later fail closed",
        &TestUndefinedFlagsReadFailsClosed, failures);
#if defined(_M_X64)
    Run("x64 CMOV r32 upper-half semantics",
        &TestCmovR32PreservesOrClearsUpperHalf, failures);
#endif
    Run("分发表编码分化: 两套加密查表路径均由隔离原生 CPU 执行",
        &TestDispatchTableEncodingSchemesExecuteNatively, failures);
    Run("MUL 真 K 变体: 真实 CPU scaled LEA 与合成 handler 链一致性/分歧检测",
        &TestMulNativeDifferentialMatchesRealCpu, failures);
    Run("BIT_TEST/BIT_SET/BIT_RESET 真 K 变体: 真实 CPU BT/BTS/BTR 与合成 handler 链一致性/分歧检测",
        &TestBitOperationsNativeDifferentialMatchesRealCpu, failures);
    Run("SHL/SHR 真 K 变体: 真实 CPU 移位与合成 handler 链一致性/分歧检测",
        &TestShiftOperationsNativeDifferentialMatchesRealCpu, failures);
    Run("剩余算术家族真 K 变体: 真实 CPU 与合成 handler 链一致性检测",
        &TestRemainingArithmeticFamiliesNativeDifferential, failures);
#if defined(_M_IX86)
    Run("x86 Zydis UMUL_WIDE per-K/multi-seed native differential",
        &TestX86ZydisUmulWidePerKNativeDifferential, failures);
#endif
    Run("DIV/IDIV 128-bit 被除数与 #DE: 真实 CPU 与合成 handler 链一致性检测",
        &TestWideDivideNativeDifferentialAndDivideFault, failures);
    Run("INT3 两种编码与 #BP: 真实 CPU 与合成 handler 链故障 EIP/寄存器上下文一致性检测",
        &TestInt3NativeDifferentialAndBreakpointFault, failures);
#else
    std::cout << "[SKIP] non-x86/x64 host: native differential evidence provider is Windows x86/x64 only\n";
#endif
    return failures == 0 ? 0 : 1;
}
