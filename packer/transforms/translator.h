#ifndef CS_TRANSLATOR_H
#define CS_TRANSLATOR_H

#include "../analysis/disassembler.h"
#include "../vm/micro_semantics.h"

#include <array>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace CipherShell {

static constexpr uint8_t VM_REG_INVALID = VM_REGISTER_INVALID;

enum class VMMicroDensity : uint8_t {
    Light,
    Heavy
};

struct TranslationFailure {
    uint64_t address = 0;
    std::string mnemonic;
    std::string bytes;
    std::string reason;
};

struct VMBridgeRequest {
    uint32_t microOpIndex = 0;
    uint32_t functionRVA = 0;
    InstructionIR instruction{};
    uint8_t hiddenNativeRegister = 0xFF;
    bool usesAvx = false;
    bool usesX87 = false;
};

struct TranslationResult {
    std::vector<MicroInstruction> instructions;
    std::vector<uint8_t> bytecode;
    std::vector<uint32_t> microOffsets;
    std::unordered_map<uint64_t, uint32_t> addrMap;
    VM_OPERAND_CODEC operandCodec{};
    uint32_t totalSize = 0;
    uint32_t registerCount = 0;
    uint32_t returnStackCleanup = 0;
    // Conservative architectural flag bits defined on every terminal path.
    // Concrete model/native corpus comparisons refine this per execution path
    // with the oracle's dynamic undefined mask, so defined-path mismatches are
    // never hidden by another path where the same flag is ISA-undefined.
    uint64_t observableRflagsMask = VM_FLAG_ARCHITECTURAL_MASK;
    uint32_t nativeInstructionCount = 0;
    uint32_t microOpCount = 0;
    double microOpRatio = 0.0;
    uint64_t microSelectionDigest = 0;
    VMMicroDensity density = VMMicroDensity::Heavy;
    bool usesSimd = false;
    bool usesAvx = false;
    bool usesX87 = false;
    bool success = false;
    std::vector<VMBridgeRequest> bridgeRequests;
    std::vector<TranslationFailure> failures;

    VMMicroSemanticPlan SemanticPlan() const {
        VMMicroSemanticPlan plan{};
        plan.instructions = instructions;
        plan.encodedSize = totalSize;
        plan.encodedOffsets = microOffsets;
        return plan;
    }
};

struct TranslationConfig {
    uint32_t virtualRegisterCount = 32;
    uint64_t buildSeed = 0;
    VMMicroDensity density = VMMicroDensity::Heavy;
    uint8_t handlerVariantCount = 4;
    uint32_t heavyMinimumRatio = VM_MICRO_HEAVY_MIN_RATIO;
    bool enableSimdBridge = true;
    bool enableX87Bridge = true;
    VM_CALL_ABI x86CallAbi = VM_ABI_X86_AUTO;
    std::unordered_set<uint32_t> importThunkRVAs;
};

struct VMIRModelPreflightConfig {
    uint64_t corpusSeed = 0xD1B54A32D192ED03ULL;
    uint32_t corpusCount = 256;
    uint32_t memorySize = 0x10000;
    // File/image-relative operands must stay below this boundary. Zero uses
    // half the corpus for unit fixtures; production passes the exact rounded
    // image span and reserves the remainder for scratch/stack state.
    uint32_t imageSize = 0;
    uint32_t maxSteps = 1000000;
    // 纯粹的调用方标注：这次校验是替哪个 VM Variant Group 跑的。Verify()
    // 逐字节把它抄进 result，不参与任何校验逻辑本身——只是为了让日志/未来
    // 的多 Group 交叉校验能把证据和 Group 对上号，而不需要额外的旁路映射。
    uint32_t vmGroupId = 0;
};

struct VMIRModelPreflightResult {
    bool success = false;
    uint32_t casesExecuted = 0;
    uint32_t failingCase = 0;
    uint32_t vmGroupId = 0;
    std::string error;
};

class VMIRModelPreflightVerifier {
public:
    static VMIRModelPreflightResult Verify(
        const Function& function,
        const TranslationResult& translation,
        const std::unordered_map<uint8_t, uint8_t>& opcodeMap,
        const std::unordered_map<uint8_t, uint8_t>& registerMap,
        const VMIRModelPreflightConfig& config = {});
};

enum class VMNativeDifferentialArchitecture : uint8_t {
    Unknown = 0,
    X86 = 1,
    X64 = 2
};

struct VMNativeDifferentialSnapshot {
    std::array<uint64_t, 16> gpr{};
    uint64_t rflags = 0;
    uint64_t validRflagsMask = 0;
    std::vector<uint8_t> memory;
};

struct VMNativeDifferentialCaseRequest {
    uint32_t corpusIndex = 0;
    VMNativeDifferentialArchitecture architecture =
        VMNativeDifferentialArchitecture::Unknown;
    uint64_t functionRVA = 0;
    uint64_t translationIdentity = 0;
    uint64_t handlerImageDigest = 0;
    uint64_t inputIdentity = 0;
    uint64_t memoryBase = 0;
    uint32_t timeoutMilliseconds = 0;
    std::array<uint64_t, 16> initialGpr{};
    uint64_t initialRflags = 0;
    std::vector<uint8_t> initialMemory;
};

struct VMNativeDifferentialCaseEvidence {
    uint32_t corpusIndex = 0;
    VMNativeDifferentialArchitecture architecture =
        VMNativeDifferentialArchitecture::Unknown;
    uint64_t functionRVA = 0;
    uint64_t translationIdentity = 0;
    uint64_t handlerImageDigest = 0;
    uint64_t inputIdentity = 0;
    bool isolatedWorker = false;
    bool timeoutEnforced = false;
    bool nativeCpuExecuted = false;
    bool synthesizedHandlersExecuted = false;
    bool timedOut = false;
    bool nativeFaulted = false;
    bool vmFaulted = false;
    uint32_t nativeExceptionCode = 0;
    VMMicroFault vmFault = VMMicroFault::None;
    uint64_t nativeInstructionCount = 0;
    uint64_t handlerInstructionCount = 0;
    VMNativeDifferentialSnapshot nativeState{};
    VMNativeDifferentialSnapshot vmState{};
    // Diagnostic-only offsets of the faulting address relative to the native
    // code buffer / handler image base respectively; 0 when there was no
    // fault on that side. Verify() uses these, together with *FaultGpr/
    // *FaultRflags below, to prove the fault itself -- not just its
    // classification -- is architecturally equivalent on both sides.
    uint64_t nativeFaultOffset = 0;
    uint64_t vmFaultOffset = 0;
    // Architectural GPR/RFLAGS state at the instant of the fault; only
    // meaningful when nativeFaulted/vmFaulted is set.
    std::array<uint64_t, 16> nativeFaultGpr{};
    uint64_t nativeFaultRflags = 0;
    std::array<uint64_t, 16> vmFaultGpr{};
    uint64_t vmFaultRflags = 0;
};

class VMNativeDifferentialEvidenceProvider;

struct VMNativeDifferentialConfig {
    uint64_t corpusSeed = 0xD1B54A32D192ED03ULL;
    uint32_t corpusCount = 256;
    uint32_t memorySize = 0x10000;
    uint32_t imageSize = 0;
    uint32_t timeoutMilliseconds = 1000;
    uint64_t expectedHandlerImageDigest = 0;
    const VMNativeDifferentialEvidenceProvider* evidenceProvider = nullptr;
    // DIV/IDIV corpora deliberately include divisor=0 and quotient-overflow
    // inputs so #DE is actually exercised, not just avoided by luck.  When
    // true, a case where BOTH the native CPU and the synthesized handler
    // raise the corresponding divide fault counts as a verified match
    // instead of the default fail-closed "any fault is a mismatch" rule;
    // one side faulting without the other (or a different fault) still
    // fails the whole run.
    bool expectDivideFault = false;
    // INT3(0xCC)/INT 3(CD 03) 两种编码都会让宿主 CPU 真的产生
    // STATUS_BREAKPOINT。和 expectDivideFault 一样，双方都出现这个异常才算
    // 匹配；任一方独自异常、或异常代码不是断点，仍然按原样 fail-closed。
    bool expectBreakpointFault = false;
    // Expected value of evidence.nativeFaultOffset (offset of the faulting
    // address from the start of the native code buffer) when
    // expectDivideFault/expectBreakpointFault fires. Defaults to 0 (the
    // faulting instruction, including any prefix bytes, is the corpus's
    // first byte -- true for DIV/IDIV). Measured (not assumed) real
    // behavior for the two INT3 encodings: Windows' vector-3 trap handler
    // unconditionally reports (instruction-end-address - 1) regardless of
    // whether the trap actually came from the 1-byte 0xCC or the 2-byte
    // "CD 03" form, so callers set this to 0 for 0xCC and 1 for CD 03.
    uint64_t expectedNativeFaultOffset = 0;
    // 纯粹的调用方标注：这次差分校验用的是哪个 VM Variant Group 的
    // handler 镜像/opcode map（即 evidenceProvider 背后那个 Group）。
    // Verify() 原样抄进 result，不参与判定——是为多 Group 场景下把每条
    // 证据和它所属 Group 对应起来，给后续"验证多个 Group 互不干扰"的
    // 交叉校验提供可识别的锚点。
    uint32_t vmGroupId = 0;
};

class VMNativeDifferentialEvidenceProvider {
public:
    virtual ~VMNativeDifferentialEvidenceProvider() = default;

    // 实现必须在隔离的同架构 worker 中执行 request 指定的原生指令与本次
    // 构建的合成 handler；超时、异常、越界副作用或证据绑定失败均返回失败。
    virtual bool ExecuteCase(
        const Function& function,
        const TranslationResult& translation,
        const std::unordered_map<uint8_t, uint8_t>& opcodeMap,
        const std::unordered_map<uint8_t, uint8_t>& registerMap,
        const VMNativeDifferentialCaseRequest& request,
        VMNativeDifferentialCaseEvidence& evidence,
        std::string& error) const = 0;
};

struct VMNativeDifferentialResult {
    bool success = false;
    uint32_t casesVerified = 0;
    uint32_t failingCase = 0;
    bool nativeCpuEvidenceVerified = false;
    bool synthesizedHandlerEvidenceVerified = false;
    uint32_t vmGroupId = 0;
    std::string error;
};

class VMNativeDifferentialVerifier {
public:
    static uint64_t ComputeTranslationIdentity(
        const Function& function,
        const TranslationResult& translation,
        const std::unordered_map<uint8_t, uint8_t>& opcodeMap,
        const std::unordered_map<uint8_t, uint8_t>& registerMap);

    static VMNativeDifferentialResult Verify(
        const Function& function,
        const TranslationResult& translation,
        const std::unordered_map<uint8_t, uint8_t>& opcodeMap,
        const std::unordered_map<uint8_t, uint8_t>& registerMap,
        const VMNativeDifferentialConfig& config = {});
};

class Translator {
public:
    Translator();
    ~Translator();

    bool Initialize(const TranslationConfig& config);
    TranslationResult TranslateFunction(const Function& function);
    TranslationResult TranslateBlock(const BasicBlock& block, uint32_t baseOffset);
    std::vector<uint8_t> GenerateBytecode(const TranslationResult& result);

    std::unordered_map<uint8_t, uint8_t> GetRegisterMap() const;
    std::unordered_map<uint8_t, uint8_t> GetOpcodeMap() const;
    void SetOpcodeMap(const std::unordered_map<uint8_t, uint8_t>& opcodeMap);
    void SetRegisterMap(const std::unordered_map<uint8_t, uint8_t>& registerMap);
    const std::vector<TranslationFailure>& GetLastFailures() const;

    // Reproduces LowerExtendedBridge's own hidden-register candidate scan
    // (used-register set from the instruction's operands, then first free
    // entry in the machine-mode candidate list) as a standalone, callable
    // function. Exists so callers that need the exact register the
    // production translator would pick for a given bridged instruction --
    // tests included -- call the real selection logic instead of
    // re-deriving or hand-picking a value that happens to dodge whatever bug
    // is being tested. Returns 0xFF if no candidate is free, matching
    // LowerExtendedBridge's own failure case. See
    // docs/zydis_encoder_pilot.md batch 18.
    static uint8_t SelectBridgeHiddenRegister(const InstructionIR& instruction);

private:
    struct BranchFixup {
        size_t microOpIndex = 0;
        uint8_t operandIndex = 0;
        uint32_t targetRva = 0;
    };

    bool LowerInstruction(const InstructionIR& instruction, TranslationResult& result);
    bool LowerMove(const InstructionIR& instruction, TranslationResult& result);
    bool LowerMoveExtend(const InstructionIR& instruction, TranslationResult& result);
    bool LowerBinary(const InstructionIR& instruction, TranslationResult& result);
    bool LowerUnary(const InstructionIR& instruction, TranslationResult& result);
    bool LowerShiftRotate(const InstructionIR& instruction, TranslationResult& result);
    bool LowerMultiplyDivide(const InstructionIR& instruction, TranslationResult& result);
    bool LowerStack(const InstructionIR& instruction, TranslationResult& result);
    bool LowerBranch(const InstructionIR& instruction, TranslationResult& result);
    bool LowerCall(const InstructionIR& instruction, TranslationResult& result);
    bool LowerRet(const InstructionIR& instruction, TranslationResult& result);
    bool LowerConditionalData(const InstructionIR& instruction, TranslationResult& result);
    bool LowerBitOperation(const InstructionIR& instruction, TranslationResult& result);
    bool LowerImplicitScalar(const InstructionIR& instruction, TranslationResult& result);
    bool LowerExtendedBridge(const InstructionIR& instruction, TranslationResult& result);

    bool EmitAddress(const InstructionIR& instruction, const OperandIR& operand,
        TranslationResult& result);
    bool EmitRead(const InstructionIR& instruction, const OperandIR& operand,
        TranslationResult& result, uint8_t forcedWidth = 0);
    bool EmitWrite(const InstructionIR& instruction, const OperandIR& operand,
        TranslationResult& result, uint8_t forcedWidth = 0, uint8_t temp = 0);
    bool EmitRegisterRead(const InstructionIR& instruction, uint8_t family,
        uint8_t width, uint8_t bitOffset, TranslationResult& result);
    bool EmitRegisterWrite(const InstructionIR& instruction, uint8_t family,
        uint8_t width, uint8_t bitOffset, bool zeroExtend, TranslationResult& result);
    void Emit(TranslationResult& result, VM_MICRO_OPCODE opcode,
        std::initializer_list<uint64_t> operands, uint32_t sourceRva);
    void EmitHeavyPrefix(const InstructionIR& instruction, TranslationResult& result);
    bool FinalizeProgram(TranslationResult& result);

    std::vector<const OperandIR*> SemanticOperands(const InstructionIR& instruction) const;
    uint8_t MapRegisterFamily(uint8_t family) const;
    VM_CONDITION MapCondition(BranchKind branchKind) const;
    bool ValidateFlagDataflow(
        const Function& function,
        uint32_t& terminalReturnStackCleanup,
        uint64_t& observableRflagsMask);
    bool FailInstruction(const InstructionIR& instruction, const std::string& reason);
    static std::string FormatInstructionBytes(const InstructionIR& instruction);

    TranslationConfig m_config{};
    std::unordered_map<uint8_t, uint8_t> m_registerMap;
    std::unordered_map<uint8_t, uint8_t> m_opcodeMap;
    std::vector<TranslationFailure> m_lastFailures;
    std::vector<BranchFixup> m_branchFixups;
    uint64_t m_functionStart = 0;
    uint64_t m_functionEnd = 0;
    uint32_t m_currentFunctionRva = 0;
    bool m_initialized = false;
};

} // namespace CipherShell

#endif // CS_TRANSLATOR_H
