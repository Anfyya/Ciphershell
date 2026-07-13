#include "packer/analysis/disassembler.h"
#include "packer/differential/vm_native_differential_provider.h"
#include "packer/mutation/mutation_engine.h"
#include "packer/transforms/translator.h"
#include "packer/vm/vm_schema.h"

#include <array>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
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
    bool expectDivideFault = false)
{
    VMWindowsNativeDifferentialEvidenceProvider provider;
    const auto providerSeed = MakeSeed(0xC7);
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

void TestMulNativeDifferentialMatchesRealCpu() {
    // 覆盖新加入的 VM_UOP_MUL 双策略业务核心(EmitBusinessCoreVariant 的
    // IMUL reg,reg 与 MUL reg 两条真实不同字节序列)：证明无论 build 的
    // seed/variant 选中哪一支策略，合成 handler 链的乘法结果都必须与
    // 真实 CPU IMUL 逐字节一致，而不仅仅是结构层面的字节模式检查。
    const auto seed = MakeSeed(0xD3);
    const HarnessBuild build = SetUpMutatedIsa(seed);

    Disassembler disassembler;
    Require(disassembler.Initialize(kIs64), "Disassembler 初始化失败");

    // imul eax, ecx ; add eax, 0 ; ret  (two-operand signed multiply).
    // IMUL only defines CF/OF and leaves SF/ZF/AF/PF architecturally
    // undefined, so the translator's flags-flow analysis correctly refuses
    // to translate a terminal RET immediately after it (it cannot know
    // what a real CPU would leave in those bits). The trailing `add eax, 0`
    // is a value no-op that fully redefines all six status flags, closing
    // that undefined-flags window without touching the product in eax.
    const std::vector<uint8_t> mulBytes = {
        0x0F, 0xAF, 0xC1, 0x81, 0xC0, 0x00, 0x00, 0x00, 0x00, 0xC3};
    // add eax, ecx ; ret  (same shape, opposite semantics; negative control)
    const std::vector<uint8_t> addBytes = {0x01, 0xC8, 0xC3};
    constexpr uint64_t kEntry = 0x1000;

    const Function mulFunction = DecodeStandaloneFunction(disassembler, mulBytes, kEntry);
    const Function addFunction = DecodeStandaloneFunction(disassembler, addBytes, kEntry);

    Translator translator;
    const TranslationResult mulTranslation =
        TranslateStandaloneFunction(mulFunction, build, translator);

    VMIRModelPreflightConfig preflightConfig{};
    preflightConfig.corpusSeed = 0x5678;
    preflightConfig.corpusCount = 8;
    const auto preflight = VMIRModelPreflightVerifier::Verify(
        mulFunction, mulTranslation, build.isa.opcodeMap, build.isa.registerMap, preflightConfig);
    std::cout << "[preflight] success=" << preflight.success << " cases=" << preflight.casesExecuted
              << " error=" << preflight.error << '\n';
    Require(preflight.success, "software IR 预检失败(说明是翻译本身的问题，不是原生差分新代码的问题): " +
        preflight.error);

    RunDifferentialCase(mulFunction, mulTranslation, build, 8, true,
        "native-vs-VM MUL(IMUL two-operand) 语义一致");
    RunDifferentialCase(addFunction, mulTranslation, build, 8, false,
        "native=ADD vs VM-bytecode=MUL 必须被判定语义分歧");
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
            /*expectDivideFault=*/true);
    }
}

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
    Run("MUL 真 K 变体: 真实 CPU IMUL 与合成 handler 链一致性/分歧检测",
        &TestMulNativeDifferentialMatchesRealCpu, failures);
    Run("BIT_TEST/BIT_SET/BIT_RESET 真 K 变体: 真实 CPU BT/BTS/BTR 与合成 handler 链一致性/分歧检测",
        &TestBitOperationsNativeDifferentialMatchesRealCpu, failures);
    Run("DIV/IDIV 128-bit 被除数与 #DE: 真实 CPU 与合成 handler 链一致性检测",
        &TestWideDivideNativeDifferentialAndDivideFault, failures);
#else
    std::cout << "[SKIP] non-x86/x64 host: native differential evidence provider is Windows x86/x64 only\n";
#endif
    return failures == 0 ? 0 : 1;
}
