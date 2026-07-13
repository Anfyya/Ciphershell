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

TranslationResult TranslateAddFunction(
    const Function& addFunction,
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
    TranslationResult result = translator.TranslateFunction(addFunction);
    Require(result.success && !result.instructions.empty(),
        "ADD;RET 测试函数翻译失败");
    return result;
}

void RunDifferentialCase(
    const Function& function,
    const TranslationResult& translation,
    const HarnessBuild& build,
    uint32_t corpusCount,
    bool expectSuccess,
    const char* label)
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
    const TranslationResult addTranslation = TranslateAddFunction(addFunction, build, translator);

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
#else
    std::cout << "[SKIP] non-x86/x64 host: native differential evidence provider is Windows x86/x64 only\n";
#endif
    return failures == 0 ? 0 : 1;
}
