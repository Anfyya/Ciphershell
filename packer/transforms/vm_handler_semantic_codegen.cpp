#include "vm_handler_semantic_codegen.h"

#include "../vm/vm_schema.h"

#include <Zydis/Encoder.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <limits>
#include <utility>

namespace CipherShell {
namespace {

enum class KeyedPermutationOp : uint8_t {
    Xor = 0,
    Add = 1,
    Rotate = 2,
    Multiply = 3,
    Not = 4,
    Negate = 5,
    ByteSwap = 6,
    XorShift = 7
};

struct KeyedPermutationRound {
    KeyedPermutationOp op = KeyedPermutationOp::Xor;
    uint64_t key = 0;
    uint64_t inverse = 0;
    uint8_t rotate = 1;
    uint8_t encoding = 0;
};

constexpr size_t kValueCodecRoundCount = 8u;
constexpr size_t kCoreSelectorRoundCount = 8u;

struct KeyedPermutationPlan {
    std::array<KeyedPermutationRound, kCoreSelectorRoundCount> rounds{};
    uint8_t roundCount = 0;
    uint8_t layout = 0;
};

class CodeBuffer {
public:
    using Label = size_t;

    void U8(uint8_t value) { bytes.push_back(value); }
    void U16(uint16_t value) {
        U8(static_cast<uint8_t>(value));
        U8(static_cast<uint8_t>(value >> 8u));
    }
    void U32(uint32_t value) {
        for (unsigned i = 0; i < 4; ++i) U8(static_cast<uint8_t>(value >> (i * 8u)));
    }
    void U64(uint64_t value) {
        for (unsigned i = 0; i < 8; ++i) U8(static_cast<uint8_t>(value >> (i * 8u)));
    }
    void Raw(std::initializer_list<uint8_t> values) {
        bytes.insert(bytes.end(), values.begin(), values.end());
    }
    Label NewLabel() {
        labels.push_back((std::numeric_limits<size_t>::max)());
        return labels.size() - 1u;
    }
    void Bind(Label label) { labels[label] = bytes.size(); }
    void Jmp(Label label) { U8(0xE9); AddFixup(label); }
    void Call(Label label) { U8(0xE8); AddFixup(label); }
    void Jcc(uint8_t opcode, Label label) {
        Raw({0x0F, opcode});
        AddFixup(label);
    }
    bool Resolve(std::string& error) {
        if (!encodingError.empty()) {
            error = encodingError;
            return false;
        }
        for (const Fixup& fixup : fixups) {
            if (fixup.label >= labels.size() ||
                labels[fixup.label] == (std::numeric_limits<size_t>::max)()) {
                error = "semantic machine-code label was not bound";
                return false;
            }
            const int64_t relative = static_cast<int64_t>(labels[fixup.label]) -
                static_cast<int64_t>(fixup.displacement + 4u);
            if (relative < (std::numeric_limits<int32_t>::min)() ||
                relative > (std::numeric_limits<int32_t>::max)()) {
                error = "semantic machine-code rel32 exceeds range";
                return false;
            }
            const uint32_t encoded = static_cast<uint32_t>(static_cast<int32_t>(relative));
            for (unsigned i = 0; i < 4; ++i) {
                bytes[fixup.displacement + i] =
                    static_cast<uint8_t>(encoded >> (i * 8u));
            }
        }
        return true;
    }

    std::vector<VMHandlerSemanticStackFunclet> stackFunclets;
    std::vector<uint8_t> bytes;
    KeyedPermutationPlan valueCodec{};
    KeyedPermutationPlan coreSelector{};
    std::array<uint8_t, 4> registerAssignment{};
    std::vector<std::pair<uint32_t, uint32_t>> valueCodecRanges;

    void FailEncoding(const std::string& error) {
        if (encodingError.empty()) encodingError = error;
    }

private:
    struct Fixup { size_t displacement; Label label; };
    void AddFixup(Label label) {
        fixups.push_back({bytes.size(), label});
        U32(0);
    }
    std::string encodingError;
    std::vector<size_t> labels;
    std::vector<Fixup> fixups;
};

ZydisEncoderOperand ZydisGprOperand(bool x64, uint8_t reg) {
    ZydisEncoderOperand operand{};
    operand.type = ZYDIS_OPERAND_TYPE_REGISTER;
    operand.reg.value = ZydisRegisterEncode(
        x64 ? ZYDIS_REGCLASS_GPR64 : ZYDIS_REGCLASS_GPR32, reg);
    return operand;
}

ZydisEncoderOperand ZydisSizedGprOperand(
    bool x64, uint8_t reg, uint8_t bytes)
{
    ZydisRegisterClass registerClass = ZYDIS_REGCLASS_INVALID;
    switch (bytes) {
        case 1u: registerClass = ZYDIS_REGCLASS_GPR8; break;
        case 2u: registerClass = ZYDIS_REGCLASS_GPR16; break;
        case 4u: registerClass = ZYDIS_REGCLASS_GPR32; break;
        case 8u: registerClass = ZYDIS_REGCLASS_GPR64; break;
        default: break;
    }
    ZydisEncoderOperand operand{};
    operand.type = ZYDIS_OPERAND_TYPE_REGISTER;
    // The GPR8 class numbers AH..BH before SPL..DIL and R8B..R15B.
    // Translate the physical GPR number used by the semantic allocator to
    // the corresponding low-byte register id in 64-bit mode.
    const uint8_t registerId = bytes == 1u && x64 && reg >= 4u
        ? static_cast<uint8_t>(reg + 4u) : reg;
    operand.reg.value = ZydisRegisterEncode(registerClass, registerId);
    return operand;
}

ZydisEncoderOperand ZydisMemoryOperand(
    bool x64,
    uint8_t base,
    int32_t displacement,
    uint16_t bytes,
    uint8_t index = 0xFFu)
{
    ZydisEncoderOperand operand{};
    operand.type = ZYDIS_OPERAND_TYPE_MEMORY;
    operand.mem.base = ZydisRegisterEncode(
        x64 ? ZYDIS_REGCLASS_GPR64 : ZYDIS_REGCLASS_GPR32, base);
    operand.mem.index = index == 0xFFu ? ZYDIS_REGISTER_NONE :
        ZydisRegisterEncode(
            x64 ? ZYDIS_REGCLASS_GPR64 : ZYDIS_REGCLASS_GPR32, index);
    operand.mem.scale = index == 0xFFu ? 0u : 1u;
    operand.mem.displacement = displacement;
    operand.mem.size = bytes;
    return operand;
}

ZydisEncoderOperand ZydisImmediateOperand(uint64_t value) {
    ZydisEncoderOperand operand{};
    operand.type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
    operand.imm.u = value;
    return operand;
}

void EmitZydisInstruction(
    CodeBuffer& c,
    bool x64,
    ZydisMnemonic mnemonic,
    std::initializer_list<ZydisEncoderOperand> operands)
{
    if (operands.size() > ZYDIS_ENCODER_MAX_OPERANDS) {
        c.FailEncoding("Zydis Encoder semantic instruction has too many operands");
        return;
    }
    ZydisEncoderRequest request{};
    request.machine_mode = x64
        ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32;
    request.allowed_encodings = ZYDIS_ENCODABLE_ENCODING_LEGACY;
    request.mnemonic = mnemonic;
    request.operand_count = static_cast<ZyanU8>(operands.size());
    size_t index = 0;
    for (const ZydisEncoderOperand& operand : operands)
        request.operands[index++] = operand;

    std::array<uint8_t, ZYDIS_MAX_INSTRUCTION_LENGTH> encoded{};
    ZyanUSize encodedSize = encoded.size();
    const ZyanStatus status = ZydisEncoderEncodeInstruction(
        &request, encoded.data(), &encodedSize);
    if (!ZYAN_SUCCESS(status)) {
        c.FailEncoding("Zydis Encoder rejected a semantic instruction");
        return;
    }
    c.bytes.insert(c.bytes.end(), encoded.begin(),
        encoded.begin() + encodedSize);
}

void EmitZydisMove(
    CodeBuffer& c, bool x64, uint8_t destination, uint8_t source)
{
    EmitZydisInstruction(c, x64, ZYDIS_MNEMONIC_MOV,
        {ZydisGprOperand(x64, destination), ZydisGprOperand(x64, source)});
}

void EmitZydisMoveImmediate(
    CodeBuffer& c, bool x64, uint8_t destination, uint64_t immediate)
{
    EmitZydisInstruction(c, x64, ZYDIS_MNEMONIC_MOV,
        {ZydisGprOperand(x64, destination),
         ZydisImmediateOperand(immediate)});
}

void EmitZydisExchange(
    CodeBuffer& c, bool x64, uint8_t left, uint8_t right)
{
    EmitZydisInstruction(c, x64, ZYDIS_MNEMONIC_XCHG,
        {ZydisGprOperand(x64, left), ZydisGprOperand(x64, right)});
}

void EmitZydisBinary(
    CodeBuffer& c,
    bool x64,
    ZydisMnemonic mnemonic,
    uint8_t destination,
    uint8_t source)
{
    EmitZydisInstruction(c, x64, mnemonic,
        {ZydisGprOperand(x64, destination), ZydisGprOperand(x64, source)});
}

void EmitZydisBinaryImmediate(
    CodeBuffer& c,
    bool x64,
    ZydisMnemonic mnemonic,
    uint8_t destination,
    uint32_t immediate)
{
    EmitZydisInstruction(c, x64, mnemonic,
        {ZydisGprOperand(x64, destination),
         ZydisImmediateOperand(immediate)});
}

void EmitZydisUnary(
    CodeBuffer& c, bool x64, ZydisMnemonic mnemonic, uint8_t reg)
{
    EmitZydisInstruction(c, x64, mnemonic, {ZydisGprOperand(x64, reg)});
}

void EmitZydisLea(
    CodeBuffer& c,
    bool x64,
    uint8_t destination,
    uint8_t base,
    int32_t displacement,
    uint8_t index = 0xFFu)
{
    EmitZydisInstruction(c, x64, ZYDIS_MNEMONIC_LEA,
        {ZydisGprOperand(x64, destination),
         ZydisMemoryOperand(x64, base, displacement,
             static_cast<uint16_t>(x64 ? 8u : 4u), index)});
}

void EmitZydisLoad(
    CodeBuffer& c,
    bool x64,
    uint8_t destination,
    uint8_t base,
    int32_t displacement,
    uint8_t bytes)
{
    const ZydisMnemonic mnemonic = bytes <= 2u
        ? ZYDIS_MNEMONIC_MOVZX : ZYDIS_MNEMONIC_MOV;
    const uint8_t destinationBytes = bytes <= 2u
        ? static_cast<uint8_t>(x64 ? 8u : 4u) : bytes;
    EmitZydisInstruction(c, x64, mnemonic,
        {ZydisSizedGprOperand(x64, destination, destinationBytes),
         ZydisMemoryOperand(x64, base, displacement, bytes)});
}

void EmitZydisStore(
    CodeBuffer& c,
    bool x64,
    uint8_t base,
    int32_t displacement,
    uint8_t source,
    uint8_t bytes)
{
    EmitZydisInstruction(c, x64, ZYDIS_MNEMONIC_MOV,
        {ZydisMemoryOperand(x64, base, displacement, bytes),
         ZydisSizedGprOperand(x64, source, bytes)});
}

constexpr uint32_t kX64FlagCallStackBytes = 0x28u;
constexpr uint8_t kX64FlagCallPrologSize = 4u;
constexpr uint32_t kX64BridgeStateBase = 0x20u;
constexpr uint32_t kX64BridgeStackBytes =
    kX64BridgeStateBase + sizeof(VM_INSTRUCTION_BRIDGE_STATE);
constexpr uint8_t kX64BridgePrologSize = 7u;
// CALL_HOST uses one unwind-covered frame for the flag-materializer call,
// copied guest stack arguments, volatile-register spills, and an aligned host
// XSAVE/FXSAVE image.  Handler entry is RSP==8 (mod 16), so the allocation is
// also 8 (mod 16) and every nested Win64 call is aligned.
constexpr uint32_t kX64NativeCallStackBytes = 0x608u;
constexpr uint8_t kX64NativeCallPrologSize = 7u;
constexpr uint32_t kNativeCallArgumentBase = 0x20u;
constexpr uint32_t kNativeCallTargetSpill = 0x220u;
constexpr uint32_t kNativeCallGuestStackSpill = 0x228u;
constexpr uint32_t kNativeCallHostExtendedSpill = 0x230u;
constexpr uint32_t kNativeCallFlagsSpill = 0x238u;
constexpr uint32_t kNativeCallRaxSpill = 0x240u;
constexpr uint32_t kNativeCallRcxSpill = 0x248u;
constexpr uint32_t kNativeCallRdxSpill = 0x250u;
constexpr uint32_t kNativeCallR8Spill = 0x258u;
constexpr uint32_t kNativeCallR9Spill = 0x260u;
constexpr uint32_t kNativeCallR10Spill = 0x268u;
constexpr uint32_t kNativeCallR11Spill = 0x270u;
constexpr uint32_t kNativeCallGuardSpill = 0x278u;
constexpr uint32_t kNativeCallHostExtendedBase = 0x280u;
constexpr uint32_t kX86NativeCallStackBytes = 0x5C0u;
constexpr uint32_t kX86NativeCallTargetSpill = 0x200u;
constexpr uint32_t kX86NativeCallGuestStackSpill = 0x204u;
constexpr uint32_t kX86NativeCallHostExtendedSpill = 0x208u;
constexpr uint32_t kX86NativeCallFlagsSpill = 0x20Cu;
constexpr uint32_t kX86NativeCallEaxSpill = 0x210u;
constexpr uint32_t kX86NativeCallEcxSpill = 0x214u;
constexpr uint32_t kX86NativeCallEdxSpill = 0x218u;
constexpr uint32_t kX86NativeCallCleanupSpill = 0x21Cu;
constexpr uint32_t kX86NativeCallGuardSpill = 0x220u;
constexpr uint32_t kX86NativeCallOriginalEbpSpill = 0x224u;
constexpr uint32_t kX86NativeCallOriginalEbxSpill = 0x228u;
constexpr uint32_t kX86NativeCallOriginalEsiSpill = 0x22Cu;
constexpr uint32_t kX86NativeCallOriginalEdiSpill = 0x230u;
constexpr uint32_t kX86NativeCallStatusSpill = 0x234u;
constexpr uint32_t kX86NativeCallHostExtendedBase = 0x240u;
constexpr uint8_t kX64CpuidPrologSize = 1u;
constexpr uint8_t kX64RbxUnwindRegister = 3u;

static_assert((kX64BridgeStackBytes & 0xFu) == 8u,
    "x64 bridge stack alignment changed");
static_assert((kX64BridgeStackBytes % 8u) == 0u &&
        kX64BridgeStackBytes / 8u <= 0xFFFFu,
    "x64 bridge stack allocation no longer fits UWOP_ALLOC_LARGE");
static_assert((kX64NativeCallStackBytes & 0xFu) == 8u &&
        kNativeCallHostExtendedBase + VM_XSAVE_AREA_SIZE + 64u <=
            kX64NativeCallStackBytes,
    "x64 native-call frame layout or alignment changed");
static_assert(kX86NativeCallHostExtendedBase + VM_XSAVE_AREA_SIZE + 64u <=
        kX86NativeCallStackBytes,
    "x86 native-call frame layout changed");

void RecordX64StackFunclet(
    CodeBuffer& code,
    size_t begin,
    VMHandlerSemanticUnwindKind kind,
    uint32_t stackBytes,
    uint8_t prologSize,
    uint8_t nonvolatileRegister = 0)
{
    const size_t size = code.bytes.size() - begin;
    VMHandlerSemanticStackFunclet funclet{};
    if (begin > (std::numeric_limits<uint32_t>::max)() ||
        size > (std::numeric_limits<uint32_t>::max)()) {
        funclet.offset = (std::numeric_limits<uint32_t>::max)();
    } else {
        funclet.offset = static_cast<uint32_t>(begin);
        funclet.size = static_cast<uint32_t>(size);
    }
    funclet.stackBytes = stackBytes;
    funclet.kind = kind;
    funclet.prologSize = prologSize;
    funclet.nonvolatileRegister = nonvolatileRegister;
    code.stackFunclets.push_back(funclet);
}

class SeedStream {
public:
    SeedStream(const std::array<uint8_t, 32>& seed, uint64_t domain) {
        std::array<uint64_t, 4> lanes{};
        for (size_t lane = 0; lane < lanes.size(); ++lane) {
            std::memcpy(&lanes[lane], seed.data() + lane * sizeof(uint64_t),
                sizeof(uint64_t));
        }
        // A build seed is a 256-bit contract.  The old initialization read
        // only lanes 0 and 2, so changing bytes 8..15 or 24..31 could leave
        // every semantic permutation unchanged.  Fold all four lanes into
        // both generator words before the xorshift warm-up.
        const uint64_t domainRotate = (domain << 1u) | (domain >> 63u);
        s0 = Mix(lanes[0] ^ Mix(lanes[1] ^ 0x8EBC6AF09C88C6E3ULL) ^
            domain ^ 0xA0761D6478BD642FULL);
        s1 = Mix(lanes[2] ^ Mix(lanes[3] ^ 0x589965CC75374CC3ULL) ^
            domainRotate ^ 0xE7037ED1A0B428DBULL);
        s0 = Mix(s0 ^ lanes[3] ^ 0x1D8E4E27C47D124FULL);
        s1 = Mix(s1 ^ lanes[1] ^ 0xEB44ACCAB455D165ULL);
        if ((s0 | s1) == 0) s1 = 1;
        for (unsigned i = 0; i < 12; ++i) Next64();
    }
    uint64_t Next64() {
        uint64_t value = s0;
        const uint64_t other = s1;
        s0 = other;
        value ^= value << 23u;
        s1 = value ^ other ^ (value >> 17u) ^ (other >> 26u);
        return s1 + other;
    }
    uint32_t Next32() { return static_cast<uint32_t>(Next64()); }

private:
    static uint64_t Mix(uint64_t value) {
        value ^= value >> 30u;
        value *= 0xBF58476D1CE4E5B9ULL;
        value ^= value >> 27u;
        value *= 0x94D049BB133111EBULL;
        return value ^ (value >> 31u);
    }
    uint64_t s0 = 0;
    uint64_t s1 = 0;
};

uint64_t OddInverse(uint64_t value, bool x64) {
    // Newton iteration in Z/(2^N).  Starting with one correct bit doubles the
    // number of correct low bits each iteration.  Truncation supplies the
    // modulus for both word sizes.
    uint64_t inverse = value;
    for (unsigned iteration = 0; iteration < 6u; ++iteration)
        inverse *= 2u - value * inverse;
    if (!x64) inverse = static_cast<uint32_t>(inverse);
    return inverse;
}

KeyedPermutationPlan DerivePermutationPlan(
    const VMHandlerSemanticCodegenConfig& config,
    uint64_t domain,
    uint8_t roundCount,
    uint8_t operationFamilyCount = 4u)
{
    SeedStream random(config.buildSeed, domain ^
        (static_cast<uint64_t>(config.architecture) << 48u));
    KeyedPermutationPlan plan{};
    plan.roundCount = roundCount;
    plan.layout = static_cast<uint8_t>(random.Next32() & 1u);
    const bool x64 = config.architecture == VM_ARCH_X64;
    const uint8_t width = x64 ? 64u : 32u;
    for (uint8_t base = 0; base < roundCount;
         base = static_cast<uint8_t>(base + operationFamilyCount)) {
        std::array<uint8_t, 8> order = {0u,1u,2u,3u,4u,5u,6u,7u};
        for (uint8_t index = static_cast<uint8_t>(operationFamilyCount - 1u);
             index != 0u; --index) {
            const uint8_t selected = static_cast<uint8_t>(
                random.Next32() % (static_cast<uint32_t>(index) + 1u));
            std::swap(order[index], order[selected]);
        }
        const uint8_t count = static_cast<uint8_t>(
            std::min<size_t>(operationFamilyCount, roundCount - base));
        for (uint8_t index = 0; index < count; ++index) {
            KeyedPermutationRound& round = plan.rounds[base + index];
            round.op = static_cast<KeyedPermutationOp>(order[index]);
            round.encoding = static_cast<uint8_t>(random.Next32() & 1u);
            uint64_t key = random.Next64();
            if (!x64) key = static_cast<uint32_t>(key);
            switch (round.op) {
                case KeyedPermutationOp::Xor:
                case KeyedPermutationOp::Add:
                    if (key == 0u) key = x64
                        ? 0xD6E8FEB86659FD93ULL : 0x6659FD93u;
                    round.key = key;
                    break;
                case KeyedPermutationOp::Rotate:
                    round.rotate = static_cast<uint8_t>(
                        1u + random.Next32() % (width - 1u));
                    round.key = round.rotate;
                    break;
                case KeyedPermutationOp::Multiply:
                    key |= 1u;
                    if (key == 1u) key = x64
                        ? 0x9E3779B97F4A7C15ULL : 0x7F4A7C15u;
                    round.key = key;
                    round.inverse = OddInverse(key, x64);
                    break;
                case KeyedPermutationOp::Not:
                case KeyedPermutationOp::Negate:
                case KeyedPermutationOp::ByteSwap:
                    round.key = key;
                    break;
                case KeyedPermutationOp::XorShift:
                    round.rotate = static_cast<uint8_t>(
                        1u + random.Next32() % (width - 1u));
                    round.key = key;
                    break;
            }
        }
    }
    return plan;
}

void ConfigurePermutationPlans(
    CodeBuffer& code,
    const VMHandlerSemanticCodegenConfig& config)
{
    // Value-stack encoding is a build-wide contract: every handler in one
    // runtime must agree on the representation that survives between
    // dispatches.  The core selector is handler-specific so no K variant can
    // borrow a core template from another seed/variant.
    code.valueCodec = DerivePermutationPlan(config,
        0x56414C5545434F44ULL, static_cast<uint8_t>(kValueCodecRoundCount), 4u);
    code.coreSelector = DerivePermutationPlan(config,
        0x434F524553454C45ULL ^
            (static_cast<uint64_t>(config.semantic) << 13u) ^
            (static_cast<uint64_t>(config.variant) << 41u),
        static_cast<uint8_t>(kCoreSelectorRoundCount), 8u);
}

#define CTX_OFFSET(field) static_cast<uint32_t>(offsetof(VM_MICRO_EXECUTION_CONTEXT, field))
#define RECORD_OFFSET(base, field) \
    (base + static_cast<uint32_t>(offsetof(VM_LAZY_FLAGS_RECORD, field)))

constexpr uint32_t CtxValues = CTX_OFFSET(values);
constexpr uint32_t CtxVregs = CTX_OFFSET(vregs);
constexpr uint32_t CtxTemps = CTX_OFFSET(temps);
constexpr uint32_t CtxCallStack = CTX_OFFSET(callStack);
constexpr uint32_t CtxValueDepth = CTX_OFFSET(valueDepth);
constexpr uint32_t CtxCallDepth = CTX_OFFSET(callDepth);
constexpr uint32_t CtxVip = CTX_OFFSET(vip);
constexpr uint32_t CtxBytecodeBegin = CTX_OFFSET(bytecodeBegin);
constexpr uint32_t CtxImageBase = CTX_OFFSET(imageBase);
constexpr uint32_t CtxMetadata = CTX_OFFSET(metadata);
constexpr uint32_t CtxRegisterMap = CTX_OFFSET(registerMap);
constexpr uint32_t CtxFlagMaterializer = CTX_OFFSET(flagMaterializer);
constexpr uint32_t CtxNativeFrame = CTX_OFFSET(nativeFrame);
constexpr uint32_t CtxExtendedState = CTX_OFFSET(extendedState);
constexpr uint32_t CtxNativeCallBridge = CTX_OFFSET(nativeCallBridge);
constexpr uint32_t CtxDecodedOperands = CTX_OFFSET(decodedOperands);
constexpr uint32_t CtxVirtualFlags = CTX_OFFSET(virtualFlags);
constexpr uint32_t CtxPendingFlags = CTX_OFFSET(pendingFlags);
constexpr uint32_t CtxLastAlu = CTX_OFFSET(lastAlu);
constexpr uint32_t CtxReturnStackCleanup = CTX_OFFSET(returnStackCleanup);
constexpr uint32_t CtxError = CTX_OFFSET(error);
constexpr uint32_t CtxHalted = CTX_OFFSET(halted);
constexpr uint32_t CtxMutationScratch = CTX_OFFSET(mutationScratch);

static_assert(sizeof(VM_MICRO_EXECUTION_CONTEXT) <
        static_cast<size_t>((std::numeric_limits<int32_t>::max)()),
    "VM context offsets must fit a signed disp32");

constexpr uint8_t JccO = 0x80;
constexpr uint8_t JccNO = 0x81;
constexpr uint8_t JccB = 0x82;
constexpr uint8_t JccAE = 0x83;
constexpr uint8_t JccE = 0x84;
constexpr uint8_t JccNE = 0x85;
constexpr uint8_t JccBE = 0x86;
constexpr uint8_t JccA = 0x87;
constexpr uint8_t JccS = 0x88;
constexpr uint8_t JccNS = 0x89;
constexpr uint8_t JccP = 0x8A;
constexpr uint8_t JccNP = 0x8B;
constexpr uint8_t JccL = 0x8C;
constexpr uint8_t JccGE = 0x8D;
constexpr uint8_t JccLE = 0x8E;
constexpr uint8_t JccG = 0x8F;

enum class ContextLoadAddressKind : uint8_t {
    X64Direct = 1u,
    X64Indexed = 2u,
    X86Direct = 3u,
    X86IndexedEcx = 4u,
    X86IndexedRegister = 5u
};

uint64_t MixContextLoadDomain(uint64_t value) {
    value ^= value >> 30u;
    value *= 0xBF58476D1CE4E5B9ULL;
    value ^= value >> 27u;
    value *= 0x94D049BB133111EBULL;
    return value ^ (value >> 31u);
}

bool DeriveControlDispatchKey(
    CodeBuffer& c,
    uint64_t helperDomain,
    uint8_t operand,
    uint32_t& key)
{
    if (c.coreSelector.roundCount == 0u ||
        c.coreSelector.roundCount > c.coreSelector.rounds.size()) {
        c.FailEncoding("control dispatch has no valid core selector");
        return false;
    }

    // This key is stable for a handler-local control decision.  In particular,
    // it does not depend on the current code offset or on an emission ordinal,
    // because business cores are re-emitted in isolation by the validator.
    uint64_t domain = helperDomain ^
        (static_cast<uint64_t>(operand) << 48u) ^
        (static_cast<uint64_t>(c.coreSelector.layout) << 63u);
    for (uint8_t roundIndex = 0;
         roundIndex < c.coreSelector.roundCount; ++roundIndex) {
        const KeyedPermutationRound& round =
            c.coreSelector.rounds[roundIndex];
        const uint64_t descriptor =
            (static_cast<uint64_t>(static_cast<uint8_t>(round.op)) << 56u) ^
            (static_cast<uint64_t>(round.rotate) << 40u) ^
            (static_cast<uint64_t>(round.encoding) << 32u) ^
            static_cast<uint64_t>(roundIndex);
        domain = MixContextLoadDomain(domain ^ round.key ^ descriptor);
    }

    // Keep K and K+8 positive signed disp32/immediate values.  Addition is a
    // bijection modulo the native word size, so all legal widths remain
    // distinct while every comparison becomes build-seed dependent.
    constexpr uint32_t kMaximumControlKey = 0x0FFFFFF0u;
    key = 1u + static_cast<uint32_t>(domain % kMaximumControlKey);
    return true;
}

bool DeriveContextLoadDisplacements(
    CodeBuffer& c,
    ContextLoadAddressKind kind,
    uint8_t width,
    uint8_t destination,
    uint8_t index,
    uint32_t displacement,
    std::array<int32_t, 6>& addressDisplacements,
    int32_t& loadDisplacement)
{
    // Six independently-derived shares form one non-dereferenced effective
    // address.  Every LEA is flag-neutral and the sole load subtracts their
    // complete sum, so each share is required to reach the original field.
    // Derivation depends only on the stable handler-local load identity.
    if (c.coreSelector.roundCount == 0u ||
        displacement >= static_cast<uint32_t>(
            (std::numeric_limits<int32_t>::max)())) {
        c.FailEncoding("context-load displacement cannot be split safely");
        return false;
    }

    uint64_t domain = 0x4354584C4F41444BULL ^
        (static_cast<uint64_t>(static_cast<uint8_t>(kind)) << 56u) ^
        (static_cast<uint64_t>(width) << 48u) ^
        (static_cast<uint64_t>(destination) << 40u) ^
        (static_cast<uint64_t>(index) << 32u) ^ displacement;
    domain ^= static_cast<uint64_t>(c.coreSelector.layout) << 63u;

    const uint32_t maximumTotal = static_cast<uint32_t>(
        (std::numeric_limits<int32_t>::max)()) - displacement;
    const uint32_t maximumShare = maximumTotal / 6u;
    if (maximumShare == 0u) {
        c.FailEncoding("context-load address shares have no signed disp32 range");
        return false;
    }

    std::array<uint32_t, 6> shares{};
    uint64_t shareSum = 0u;
    for (size_t shareIndex = 0; shareIndex < shares.size(); ++shareIndex) {
        uint64_t shareDomain = MixContextLoadDomain(domain ^
            (0x9E3779B97F4A7C15ULL *
             static_cast<uint64_t>(shareIndex + 1u)));
        for (uint8_t roundIndex = 0;
             roundIndex < c.coreSelector.roundCount; ++roundIndex) {
            const KeyedPermutationRound& round =
                c.coreSelector.rounds[roundIndex];
            const uint64_t descriptor =
                (static_cast<uint64_t>(static_cast<uint8_t>(round.op)) << 56u) ^
                (static_cast<uint64_t>(round.rotate) << 48u) ^
                (static_cast<uint64_t>(round.encoding) << 40u) ^
                (static_cast<uint64_t>(shareIndex) << 32u) ^
                static_cast<uint64_t>(roundIndex);
            shareDomain = MixContextLoadDomain(
                shareDomain ^ round.key ^ descriptor);
        }
        shares[shareIndex] = 1u +
            static_cast<uint32_t>(shareDomain % maximumShare);
        shareSum += shares[shareIndex];
    }

    const int64_t first = static_cast<int64_t>(displacement) + shares[0];
    const int64_t load = -static_cast<int64_t>(shareSum);
    if (first > (std::numeric_limits<int32_t>::max)() ||
        load < (std::numeric_limits<int32_t>::min)() ||
        load > (std::numeric_limits<int32_t>::max)()) {
        c.FailEncoding("context-load address shares exceeded signed disp32");
        return false;
    }
    addressDisplacements[0] = static_cast<int32_t>(first);
    for (size_t shareIndex = 1u;
         shareIndex < shares.size(); ++shareIndex) {
        if (shares[shareIndex] > static_cast<uint32_t>(
                (std::numeric_limits<int32_t>::max)())) {
            c.FailEncoding("context-load share exceeded signed disp32");
            return false;
        }
        addressDisplacements[shareIndex] =
            static_cast<int32_t>(shares[shareIndex]);
    }
    loadDisplacement = static_cast<int32_t>(load);
    return true;
}

void EmitX64LoadFromSplitBase(
    CodeBuffer& c,
    uint8_t destination,
    uint8_t width,
    const std::array<int32_t, 6>& addressDisplacements,
    int32_t loadDisplacement)
{
    const uint8_t leaRex = static_cast<uint8_t>(0x48u |
        ((destination & 8u) ? 0x04u : 0u) |
        ((destination & 8u) ? 0x01u : 0u));
    for (size_t shareIndex = 1u;
         shareIndex < addressDisplacements.size(); ++shareIndex) {
        c.Raw({leaRex, 0x8D, static_cast<uint8_t>(0x80u |
            ((destination & 7u) << 3u) | (destination & 7u))});
        if ((destination & 7u) == 4u) c.U8(0x24u);
        c.U32(static_cast<uint32_t>(addressDisplacements[shareIndex]));
    }
    const uint8_t rex = static_cast<uint8_t>(
        (width == 8u ? 0x48u : 0x40u) |
        ((destination & 8u) ? 0x04u : 0u) |
        ((destination & 8u) ? 0x01u : 0u));
    c.U8(rex);
    if (width == 1u) c.Raw({0x0F, 0xB6});
    else c.U8(0x8B);
    c.U8(static_cast<uint8_t>(0x80u |
        ((destination & 7u) << 3u) | (destination & 7u)));
    if ((destination & 7u) == 4u) c.U8(0x24u);
    c.U32(static_cast<uint32_t>(loadDisplacement));
}

void EmitX86LoadFromSplitBase(
    CodeBuffer& c,
    uint8_t destination,
    uint8_t width,
    const std::array<int32_t, 6>& addressDisplacements,
    int32_t loadDisplacement)
{
    for (size_t shareIndex = 1u;
         shareIndex < addressDisplacements.size(); ++shareIndex) {
        c.Raw({0x8D, static_cast<uint8_t>(0x80u |
            ((destination & 7u) << 3u) | (destination & 7u))});
        if ((destination & 7u) == 4u) c.U8(0x24u);
        c.U32(static_cast<uint32_t>(addressDisplacements[shareIndex]));
    }
    if (width == 1u) c.Raw({0x0F, 0xB6});
    else c.U8(0x8B);
    c.U8(static_cast<uint8_t>(0x80u |
        ((destination & 7u) << 3u) | (destination & 7u)));
    if ((destination & 7u) == 4u) c.U8(0x24u);
    c.U32(static_cast<uint32_t>(loadDisplacement));
}

void X64LoadQ(CodeBuffer& c, uint8_t reg, uint32_t displacement) {
    if (reg > 15u || reg == 15u || reg == 4u) {
        c.FailEncoding("x64 context load cannot overwrite the context register");
        return;
    }
    std::array<int32_t, 6> addressDisplacements{};
    int32_t loadDisplacement = 0;
    if (!DeriveContextLoadDisplacements(c, ContextLoadAddressKind::X64Direct,
            8u, reg, 0xFFu, displacement, addressDisplacements,
            loadDisplacement)) return;
    const uint8_t rex = static_cast<uint8_t>(
        0x49u | ((reg & 8u) ? 0x04u : 0u));
    c.Raw({rex, 0x8D,
        static_cast<uint8_t>(0x87u | ((reg & 7u) << 3u))});
    c.U32(static_cast<uint32_t>(addressDisplacements[0]));
    EmitX64LoadFromSplitBase(
        c, reg, 8u, addressDisplacements, loadDisplacement);
}

void X64StoreQ(CodeBuffer& c, uint32_t displacement, uint8_t reg) {
    const uint8_t rex = static_cast<uint8_t>(0x49u | ((reg & 8u) ? 0x04u : 0u));
    c.Raw({rex, 0x89, static_cast<uint8_t>(0x87u | ((reg & 7u) << 3u))});
    c.U32(displacement);
}

void X64LoadD(CodeBuffer& c, uint8_t reg, uint32_t displacement) {
    if (reg > 15u || reg == 15u || reg == 4u) {
        c.FailEncoding("x64 context load cannot overwrite the context register");
        return;
    }
    std::array<int32_t, 6> addressDisplacements{};
    int32_t loadDisplacement = 0;
    if (!DeriveContextLoadDisplacements(c, ContextLoadAddressKind::X64Direct,
            4u, reg, 0xFFu, displacement, addressDisplacements,
            loadDisplacement)) return;
    const uint8_t rex = static_cast<uint8_t>(
        0x49u | ((reg & 8u) ? 0x04u : 0u));
    c.Raw({rex, 0x8D,
        static_cast<uint8_t>(0x87u | ((reg & 7u) << 3u))});
    c.U32(static_cast<uint32_t>(addressDisplacements[0]));
    EmitX64LoadFromSplitBase(
        c, reg, 4u, addressDisplacements, loadDisplacement);
}

void X64StoreD(CodeBuffer& c, uint32_t displacement, uint8_t reg) {
    const uint8_t rex = static_cast<uint8_t>(0x41u | ((reg & 8u) ? 0x04u : 0u));
    c.Raw({rex, 0x89, static_cast<uint8_t>(0x87u | ((reg & 7u) << 3u))});
    c.U32(displacement);
}

void X64LoadByte(CodeBuffer& c, uint8_t reg, uint32_t displacement) {
    if (reg > 15u || reg == 15u || reg == 4u) {
        c.FailEncoding("x64 context load cannot overwrite the context register");
        return;
    }
    std::array<int32_t, 6> addressDisplacements{};
    int32_t loadDisplacement = 0;
    if (!DeriveContextLoadDisplacements(c, ContextLoadAddressKind::X64Direct,
            1u, reg, 0xFFu, displacement, addressDisplacements,
            loadDisplacement)) return;
    const uint8_t rex = static_cast<uint8_t>(
        0x49u | ((reg & 8u) ? 0x04u : 0u));
    c.Raw({rex, 0x8D,
        static_cast<uint8_t>(0x87u | ((reg & 7u) << 3u))});
    c.U32(static_cast<uint32_t>(addressDisplacements[0]));
    EmitX64LoadFromSplitBase(
        c, reg, 1u, addressDisplacements, loadDisplacement);
}

void X64StoreByteImmediate(CodeBuffer& c, uint32_t displacement, uint8_t value) {
    c.Raw({0x41, 0xC6, 0x87});
    c.U32(displacement);
    c.U8(value);
}

void X64StoreDImmediate(CodeBuffer& c, uint32_t displacement, uint32_t value) {
    c.Raw({0x41, 0xC7, 0x87});
    c.U32(displacement);
    c.U32(value);
}

void X64LoadIndexedQ(
    CodeBuffer& c,
    uint8_t destination,
    uint8_t index,
    uint32_t displacement)
{
    if (destination > 15u || destination == 15u || destination == 4u ||
        index > 15u || index == 15u || index == 4u) {
        c.FailEncoding("x64 indexed context load uses an invalid register");
        return;
    }
    std::array<int32_t, 6> addressDisplacements{};
    int32_t loadDisplacement = 0;
    if (!DeriveContextLoadDisplacements(c, ContextLoadAddressKind::X64Indexed,
            8u, destination, index, displacement, addressDisplacements,
            loadDisplacement)) return;
    const uint8_t rex = static_cast<uint8_t>(0x49u |
        ((destination & 8u) ? 0x04u : 0u) |
        ((index & 8u) ? 0x02u : 0u));
    c.Raw({rex, 0x8D,
        static_cast<uint8_t>(0x84u | ((destination & 7u) << 3u)),
        static_cast<uint8_t>(0xC7u | ((index & 7u) << 3u))});
    c.U32(static_cast<uint32_t>(addressDisplacements[0]));
    EmitX64LoadFromSplitBase(
        c, destination, 8u, addressDisplacements, loadDisplacement);
}

void X64StoreIndexedQ(
    CodeBuffer& c,
    uint32_t displacement,
    uint8_t index,
    uint8_t source)
{
    const uint8_t rex = static_cast<uint8_t>(0x49u |
        ((source & 8u) ? 0x04u : 0u) |
        ((index & 8u) ? 0x02u : 0u));
    c.Raw({rex, 0x89,
        static_cast<uint8_t>(0x84u | ((source & 7u) << 3u)),
        static_cast<uint8_t>(0xC7u | ((index & 7u) << 3u))});
    c.U32(displacement);
}

void X86LoadD(CodeBuffer& c, uint8_t reg, uint32_t displacement) {
    if (reg > 7u || reg == 7u || reg == 4u) {
        c.FailEncoding("x86 context load cannot overwrite the context register");
        return;
    }
    std::array<int32_t, 6> addressDisplacements{};
    int32_t loadDisplacement = 0;
    if (!DeriveContextLoadDisplacements(c, ContextLoadAddressKind::X86Direct,
            4u, reg, 0xFFu, displacement, addressDisplacements,
            loadDisplacement)) return;
    c.Raw({0x8D, static_cast<uint8_t>(0x87u | ((reg & 7u) << 3u))});
    c.U32(static_cast<uint32_t>(addressDisplacements[0]));
    EmitX86LoadFromSplitBase(
        c, reg, 4u, addressDisplacements, loadDisplacement);
}

void X86StoreD(CodeBuffer& c, uint32_t displacement, uint8_t reg) {
    c.Raw({0x89, static_cast<uint8_t>(0x87u | ((reg & 7u) << 3u))});
    c.U32(displacement);
}

void X86LoadByte(CodeBuffer& c, uint8_t reg, uint32_t displacement) {
    if (reg > 7u || reg == 7u || reg == 4u) {
        c.FailEncoding("x86 context load cannot overwrite the context register");
        return;
    }
    std::array<int32_t, 6> addressDisplacements{};
    int32_t loadDisplacement = 0;
    if (!DeriveContextLoadDisplacements(c, ContextLoadAddressKind::X86Direct,
            1u, reg, 0xFFu, displacement, addressDisplacements,
            loadDisplacement)) return;
    c.Raw({0x8D, static_cast<uint8_t>(0x87u | ((reg & 7u) << 3u))});
    c.U32(static_cast<uint32_t>(addressDisplacements[0]));
    EmitX86LoadFromSplitBase(
        c, reg, 1u, addressDisplacements, loadDisplacement);
}

void X86StoreDImmediate(CodeBuffer& c, uint32_t displacement, uint32_t value) {
    c.Raw({0xC7, 0x87});
    c.U32(displacement);
    c.U32(value);
}

void X86StoreByteImmediate(CodeBuffer& c, uint32_t displacement, uint8_t value) {
    c.Raw({0xC6, 0x87});
    c.U32(displacement);
    c.U8(value);
}

void X64StoreByteRegister(CodeBuffer& c, uint32_t displacement, uint8_t reg) {
    const uint8_t rex = static_cast<uint8_t>(0x41u | ((reg & 8u) ? 0x04u : 0u));
    c.Raw({rex,0x88,static_cast<uint8_t>(0x87u | ((reg & 7u) << 3u))});
    c.U32(displacement);
}

void X86StoreByteRegister(CodeBuffer& c, uint32_t displacement, uint8_t reg) {
    c.Raw({0x88,static_cast<uint8_t>(0x87u | ((reg & 7u) << 3u))});
    c.U32(displacement);
}

void X86LoadIndexedD(CodeBuffer& c, uint8_t destination, uint32_t displacement) {
    if (destination > 7u || destination == 7u || destination == 4u) {
        c.FailEncoding("x86 indexed context load uses an invalid register");
        return;
    }
    std::array<int32_t, 6> addressDisplacements{};
    int32_t loadDisplacement = 0;
    if (!DeriveContextLoadDisplacements(c,
            ContextLoadAddressKind::X86IndexedEcx, 4u, destination, 1u,
            displacement, addressDisplacements, loadDisplacement)) return;
    c.Raw({0x8D,
        static_cast<uint8_t>(0x84u | ((destination & 7u) << 3u)), 0xCF});
    c.U32(static_cast<uint32_t>(addressDisplacements[0]));
    EmitX86LoadFromSplitBase(
        c, destination, 4u, addressDisplacements, loadDisplacement);
}

void X86StoreIndexedD(CodeBuffer& c, uint32_t displacement, uint8_t source) {
    c.Raw({0x89, static_cast<uint8_t>(0x84u | ((source & 7u) << 3u)), 0xCF});
    c.U32(displacement);
}

void EmitX64Failure(CodeBuffer& c, uint32_t error) {
    X64StoreDImmediate(c, CtxError, error);
    X64StoreDImmediate(c, CtxHalted, 1);
    c.U8(0xC3);
}

void EmitX86Failure(CodeBuffer& c, uint32_t error) {
    X86StoreDImmediate(c, CtxError, error);
    X86StoreDImmediate(c, CtxHalted, 1);
    c.U8(0xC3);
}

template <size_t N>
std::array<uint8_t, 4> RotateRegisterContract(
    const std::array<uint8_t, N>& pool,
    size_t seedOffset,
    uint8_t variant)
{
    static_assert(N != 0u, "register contract pool cannot be empty");
    std::array<uint8_t, 4> output{};
    const size_t start =
        (seedOffset + static_cast<size_t>(variant)) % pool.size();
    for (size_t index = 0; index < output.size(); ++index)
        output[index] = pool[(start + index) % pool.size()];
    return output;
}

std::array<uint8_t, 4> DeriveVariantRegisters(
    bool x64,
    uint8_t variant,
    VM_MICRO_OPCODE semantic,
    const std::array<uint8_t, 32>& buildSeed,
    uint8_t coreStrategy)
{
    const size_t seedOffset = static_cast<size_t>(
        buildSeed[static_cast<uint8_t>(semantic) & 31u]);
    const bool prelatchedBinary = semantic == VM_UOP_ADD ||
        semantic == VM_UOP_SUB || semantic == VM_UOP_AND ||
        semantic == VM_UOP_OR || semantic == VM_UOP_XOR;
    if (prelatchedBinary) {
        if (x64) {
            // RAX/RDX hold the incoming operands. R8/R11 are free after the
            // pre-latched record is stored; R9 (width mask), R10 (auxiliary),
            // R15 (context), RSP and every nonvolatile register stay excluded.
            constexpr std::array<uint8_t, 4> pool = {0, 2, 8, 11};
            return RotateRegisterContract(pool, seedOffset, variant);
        } else {
            // EAX/EDX hold the incoming operands and ECX is dead at this
            // point. Keep EBX/ESI/EDI out of the allocation because they are
            // direct-threaded ABI state on x86.
            constexpr std::array<uint8_t, 3> pool = {0, 2, 1};
            return RotateRegisterContract(pool, seedOffset, variant);
        }
    }
    if (semantic == VM_UOP_NOT || semantic == VM_UOP_NEG) {
        if (x64) {
            // R8 retains the original operand for the lazy-flags latch and R9
            // retains the width mask. RCX/RDX/R10/R11 are dead until the
            // post-core reload/zeroing sequence, so they may host the result.
            constexpr std::array<uint8_t, 5> pool = {0, 1, 2, 10, 11};
            return RotateRegisterContract(pool, seedOffset, variant);
        }
        // X86BeginLatch has already copied the original operand to context.
        // Only caller-volatile EAX/ECX/EDX are free before the result path.
        constexpr std::array<uint8_t, 3> pool = {0, 1, 2};
        return RotateRegisterContract(pool, seedOffset, variant);
    }
    if (semantic == VM_UOP_LOAD || semantic == VM_UOP_STORE) {
        if (x64) {
            // RAX is the guest address and RDX is the STORE value. R11 is
            // consumed by width dispatch; R9/R15 and nonvolatiles stay out.
            // RAX/RCX/R8/R10 are the complete address/scratch contract.
            constexpr std::array<uint8_t, 4> pool = {0, 1, 8, 10};
            return RotateRegisterContract(pool, seedOffset, variant);
        }
        // EBX/ESI are already the two proven address temporaries in this
        // semantic. ECX is dead after width dispatch and can hold the STORE
        // value or LOAD result; EDX remains the live STORE source.
        if (((seedOffset + static_cast<size_t>(variant)) & 1u) == 0u)
            return {3u, 1u, 6u, 3u};
        return {6u, 3u, 1u, 6u};
    }
    if (semantic == VM_UOP_MUL) {
        const size_t plan =
            (seedOffset + static_cast<size_t>(variant)) & 3u;
        if ((coreStrategy & 1u) == 0u) {
            if (x64) {
                // Two-operand IMUL has no implicit GPR result pair.  RAX/RDX
                // enter as a/b, while R8/R11 are dead after their lazy-flags
                // copies were written to context.  Roles are value, source,
                // correction scratch, spare.
                constexpr std::array<uint8_t, 4> pool = {0u, 2u, 8u, 11u};
                return RotateRegisterContract(
                    pool, seedOffset, variant);
            }
            // X86BeginLatch made ECX dead, and the legacy MUL core already
            // used EBX for its correction product.  ESI/EDI remain excluded.
            constexpr std::array<uint8_t, 4> pool = {0u, 2u, 3u, 1u};
            return RotateRegisterContract(pool, seedOffset, variant);
        }
        if (x64) {
            // One-operand MUL fixes the implicit multiplicand/result in
            // RDX:RAX.  Roles are explicit multiplier, correction scratch,
            // spare, implicit-pair marker.  Scratch never aliases RAX/RDX,
            // so it survives the hardware multiply.
            constexpr std::array<std::array<uint8_t, 4>, 4> plans = {{
                {2u, 8u, 11u, 0u},
                {8u, 11u, 1u, 0u},
                {11u, 1u, 8u, 0u},
                {1u, 8u, 11u, 0u}}};
            return plans[plan];
        }
        // EDX is the legacy explicit source.  ECX and the already-proven EBX
        // correction register are the only scratch/source alternatives that
        // remain live-safe across MUL; ESI/EDI stay excluded.
        constexpr std::array<std::array<uint8_t, 4>, 4> plans = {{
            {2u, 3u, 1u, 0u},
            {2u, 1u, 3u, 0u},
            {1u, 3u, 2u, 0u},
            {3u, 1u, 2u, 0u}}};
        return plans[plan];
    }
    if (!x64 && semantic == VM_UOP_UMUL_WIDE) {
        // K=1 keeps EAX as the implicit multiplicand and EBX as the saved
        // correction operand.  Its explicit main-product source may be ESI
        // or EDX, either directly or as a seed-split scratch-memory base.
        // ECX holds (b + key); EDI remains the context throughout.
        switch ((seedOffset + static_cast<size_t>(variant)) & 3u) {
            case 0u: return {6u, 1u, 3u, 2u}; // MUL ESI
            case 1u: return {2u, 1u, 3u, 6u}; // MUL EDX
            case 2u: return {6u, 1u, 3u, 0u}; // MUL [ESI + disp32]
            default: return {2u, 1u, 3u, 0u}; // MUL [EDX + disp32]
        }
    }
    std::array<uint8_t, 4> output{};
    if (x64) {
        constexpr std::array<uint8_t, 7> pool = {0, 1, 2, 8, 9, 10, 11};
        const size_t start = (seedOffset + static_cast<size_t>(variant)) %
            pool.size();
        for (size_t index = 0; index < output.size(); ++index)
            output[index] = pool[(start + index * 2u) % pool.size()];
    } else {
        // EDI is the context, while EBX/ESI are direct-threaded ABI state.
        // Only caller-volatile EAX/ECX/EDX participate in the live allocation.
        constexpr std::array<uint8_t, 3> pool = {0, 1, 2};
        const size_t start = (seedOffset + static_cast<size_t>(variant)) %
            pool.size();
        for (size_t index = 0; index < output.size(); ++index)
            output[index] = pool[(start + index) % pool.size()];
    }
    return output;
}

enum class SemanticPathKind : uint8_t {
    ContextNative,
    ContextDword,
    StackTop,
    MappedVreg
};

struct SemanticPathSpec {
    SemanticPathKind kind = SemanticPathKind::ContextNative;
    uint32_t displacement = 0;
    uint8_t mappedFamily = 0;
};

struct SemanticMutationPlan {
    uint8_t strategy = 0;
    uint64_t key = 0;
    uint8_t roundCount = 0;
    std::array<uint8_t, 48> roundStrategies{};
    std::array<uint64_t, 48> roundKeys{};
};

SemanticMutationPlan DeriveSemanticMutationPlan(
    const VMHandlerSemanticCodegenConfig& config,
    uint64_t phaseDomain)
{
    SeedStream random(config.buildSeed,
        phaseDomain ^ (static_cast<uint64_t>(config.semantic) << 17u) ^
        (static_cast<uint64_t>(config.variant) << 43u) ^
        static_cast<uint64_t>(config.architecture));
    SemanticMutationPlan plan{};
    plan.roundCount = static_cast<uint8_t>(24u + random.Next32() % 25u);
    for (uint8_t round = 0; round < plan.roundCount; ++round) {
        plan.roundStrategies[round] = static_cast<uint8_t>(
            (random.Next32() + config.variant +
             static_cast<uint8_t>(config.semantic) + round) % 8u);
        plan.roundKeys[round] = random.Next64() | 1u;
    }
    plan.strategy = plan.roundStrategies[0];
    plan.key = plan.roundKeys[0];
    return plan;
}

bool HasBusinessCoreVariant(VM_MICRO_OPCODE semantic) {
    switch (semantic) {
        case VM_UOP_PUSH_VREG:
        case VM_UOP_PUSH_IMM:
        case VM_UOP_PUSH_FLAGS:
        case VM_UOP_PUSH_IP:
        case VM_UOP_PUSH_IMAGE_BASE:
        case VM_UOP_POP_VREG:
        case VM_UOP_LOAD_TEMP:
        case VM_UOP_STORE_TEMP:
        case VM_UOP_DUP:
        case VM_UOP_SWAP:
        case VM_UOP_ROT:
        case VM_UOP_DROP:
        case VM_UOP_LOAD:
        case VM_UOP_STORE:
        case VM_UOP_ADD:
        case VM_UOP_ADD_CARRY:
        case VM_UOP_SUB:
        case VM_UOP_SUB_BORROW:
        case VM_UOP_AND:
        case VM_UOP_OR:
        case VM_UOP_XOR:
        case VM_UOP_NOT:
        case VM_UOP_NEG:
        case VM_UOP_MUL:
        case VM_UOP_BIT_TEST:
        case VM_UOP_BIT_SET:
        case VM_UOP_BIT_RESET:
        case VM_UOP_SHL:
        case VM_UOP_SHR:
        case VM_UOP_SAR:
        case VM_UOP_ROL:
        case VM_UOP_ROR:
        case VM_UOP_BSWAP:
        case VM_UOP_ZERO_EXTEND:
        case VM_UOP_SIGN_EXTEND:
        case VM_UOP_UMUL_WIDE:
        case VM_UOP_SMUL_WIDE:
        case VM_UOP_UDIV_WIDE:
        case VM_UOP_IDIV_WIDE:
        case VM_UOP_FLAGS_LAZY:
        case VM_UOP_FLAGS_MATERIALIZE:
        case VM_UOP_FLAGS_WRITE:
        case VM_UOP_FLAGS_UPDATE:
        case VM_UOP_FLAGS_PACK_AH:
        case VM_UOP_FLAGS_UNPACK_AH:
        case VM_UOP_PUSH_CONDITION:
        case VM_UOP_SELECT:
        case VM_UOP_BRANCH:
        case VM_UOP_BRANCH_IF:
        case VM_UOP_CALL_VM:
        case VM_UOP_CALL_HOST:
        case VM_UOP_RET:
        case VM_UOP_BRIDGE_EXTENDED:
        case VM_UOP_INT3:
            return true;
        default:
            return false;
    }
}

uint8_t DeriveBusinessCoreStrategy(
    const VMHandlerSemanticCodegenConfig& config)
{
    // Seed chooses which strategy variant 0 starts with; adjacent K variants
    // then alternate.  The previous `%3` draw could map all four production
    // variants of one semantic to the same core strategy, making the second
    // implementation present in source but absent from an actual build.
    VMHandlerSemanticCodegenConfig base = config;
    base.variant = 0;
    const uint8_t seedStart = static_cast<uint8_t>(DeriveSemanticMutationPlan(
        base, 0x434F524556415249ULL).strategy & 1u);
    return static_cast<uint8_t>(seedStart ^ (config.variant & 1u));
}

SemanticPathSpec SemanticInputPath(
    const VMOpcodeDescriptor& descriptor,
    VM_MICRO_OPCODE semantic)
{
    if (descriptor.stackPops > 0)
        return {SemanticPathKind::StackTop, CtxValues, 0};
    if (semantic == VM_UOP_CPUID)
        return {SemanticPathKind::MappedVreg, CtxVregs, 0};
    if (descriptor.operandCount > 0)
        return {SemanticPathKind::ContextNative, CtxDecodedOperands, 0};
    switch (semantic) {
        case VM_UOP_PUSH_IP:
            return {SemanticPathKind::ContextNative, CtxVip, 0};
        case VM_UOP_PUSH_IMAGE_BASE:
            return {SemanticPathKind::ContextNative, CtxImageBase, 0};
        case VM_UOP_FLAGS_PACK_AH:
            return {SemanticPathKind::ContextNative, CtxVirtualFlags, 0};
        case VM_UOP_RDTSC:
            return {SemanticPathKind::ContextNative, CtxRegisterMap, 0};
        case VM_UOP_INT3:
            return {SemanticPathKind::ContextNative, CtxVip, 0};
        default:
            return {SemanticPathKind::ContextDword, CtxValueDepth, 0};
    }
}

SemanticPathSpec SemanticResultPath(
    const VMOpcodeDescriptor& descriptor,
    VM_MICRO_OPCODE semantic)
{
    if (descriptor.stackPushes > 0)
        return {SemanticPathKind::StackTop, CtxValues, 0};
    switch (descriptor.opcodeClass) {
        case VMOpcodeClass::Flags:
            if (semantic == VM_UOP_FLAGS_LAZY)
                return {SemanticPathKind::ContextNative, CtxPendingFlags, 0};
            return {SemanticPathKind::ContextNative, CtxVirtualFlags, 0};
        case VMOpcodeClass::ControlFlow:
        case VMOpcodeClass::Call:
            if (semantic == VM_UOP_RET || semantic == VM_UOP_EXIT)
                return {SemanticPathKind::ContextDword, CtxHalted, 0};
            return {SemanticPathKind::ContextNative, CtxVip, 0};
        case VMOpcodeClass::Bridge:
            return {SemanticPathKind::ContextNative, CtxVregs, 0};
        case VMOpcodeClass::Special:
            if (semantic == VM_UOP_RDTSC || semantic == VM_UOP_CPUID)
                return {SemanticPathKind::MappedVreg, CtxVregs, 0};
            return {SemanticPathKind::ContextNative, CtxVip, 0};
        default:
            break;
    }
    if (descriptor.stackPops > 0)
        return {SemanticPathKind::ContextDword, CtxValueDepth, 0};
    return {SemanticPathKind::ContextDword, CtxError, 0};
}

void X64MovImmediate(CodeBuffer& c, uint8_t reg, uint64_t value) {
    c.Raw({static_cast<uint8_t>(0x48u | ((reg & 8u) ? 1u : 0u)),
        static_cast<uint8_t>(0xB8u + (reg & 7u))});
    c.U64(value);
}

void X64MovRegister(CodeBuffer& c, uint8_t destination, uint8_t source) {
    const uint8_t rex = static_cast<uint8_t>(0x48u |
        ((source & 8u) ? 4u : 0u) | ((destination & 8u) ? 1u : 0u));
    c.Raw({rex, 0x89, static_cast<uint8_t>(0xC0u |
        ((source & 7u) << 3u) | (destination & 7u))});
}

void X64BinaryRegister(
    CodeBuffer& c,
    uint8_t opcode,
    uint8_t destination,
    uint8_t source)
{
    const uint8_t rex = static_cast<uint8_t>(0x48u |
        ((source & 8u) ? 4u : 0u) | ((destination & 8u) ? 1u : 0u));
    c.Raw({rex, opcode, static_cast<uint8_t>(0xC0u |
        ((source & 7u) << 3u) | (destination & 7u))});
}

void X86MovImmediate(CodeBuffer& c, uint8_t reg, uint32_t value) {
    c.U8(static_cast<uint8_t>(0xB8u + (reg & 7u)));
    c.U32(value);
}

void X86MovRegister(CodeBuffer& c, uint8_t destination, uint8_t source) {
    c.Raw({0x89, static_cast<uint8_t>(0xC0u |
        ((source & 7u) << 3u) | (destination & 7u))});
}

void X86BinaryRegister(
    CodeBuffer& c,
    uint8_t opcode,
    uint8_t destination,
    uint8_t source)
{
    c.Raw({opcode, static_cast<uint8_t>(0xC0u |
        ((source & 7u) << 3u) | (destination & 7u))});
}

void X64UnaryGroup(CodeBuffer& c, uint8_t group, uint8_t reg) {
    c.Raw({static_cast<uint8_t>(0x48u | ((reg & 8u) ? 1u : 0u)),
        0xF7, static_cast<uint8_t>(0xC0u | ((group & 7u) << 3u) |
            (reg & 7u))});
}

void X86UnaryGroup(CodeBuffer& c, uint8_t group, uint8_t reg) {
    c.Raw({0xF7, static_cast<uint8_t>(0xC0u | ((group & 7u) << 3u) |
        (reg & 7u))});
}

void X64RotateImmediate(
    CodeBuffer& c, uint8_t group, uint8_t reg, uint8_t count)
{
    c.Raw({static_cast<uint8_t>(0x48u | ((reg & 8u) ? 1u : 0u)),
        0xC1, static_cast<uint8_t>(0xC0u | ((group & 7u) << 3u) |
            (reg & 7u)), count});
}

void X86RotateImmediate(
    CodeBuffer& c, uint8_t group, uint8_t reg, uint8_t count)
{
    c.Raw({0xC1, static_cast<uint8_t>(0xC0u | ((group & 7u) << 3u) |
        (reg & 7u)), count});
}

void X64MultiplyRegister(CodeBuffer& c, uint8_t value, uint8_t factor) {
    const uint8_t rex = static_cast<uint8_t>(0x48u |
        ((value & 8u) ? 4u : 0u) | ((factor & 8u) ? 1u : 0u));
    c.Raw({rex, 0x0F, 0xAF, static_cast<uint8_t>(0xC0u |
        ((value & 7u) << 3u) | (factor & 7u))});
}

void X86MultiplyImmediate(CodeBuffer& c, uint8_t value, uint32_t factor) {
    c.Raw({0x69, static_cast<uint8_t>(0xC0u |
        ((value & 7u) << 3u) | (value & 7u))});
    c.U32(factor);
}

uint32_t CoreKey32(const CodeBuffer& c, size_t index) {
    uint32_t key = static_cast<uint32_t>(
        c.coreSelector.rounds[index % c.coreSelector.roundCount].key) &
        0x7FFFFFFFu;
    return key != 0u ? key : 0x6D2B79F5u;
}

uint32_t CoreAddressKey(const CodeBuffer& c, size_t index) {
    const uint32_t key = CoreKey32(c, index) & 0x0FFFFFFFu;
    return key != 0u ? key : 0x06D2B795u;
}

void X64BinaryImmediate32(
    CodeBuffer& c, uint8_t group, uint8_t reg, uint32_t value)
{
    c.Raw({static_cast<uint8_t>(0x48u | ((reg & 8u) ? 1u : 0u)),
        0x81, static_cast<uint8_t>(0xC0u | ((group & 7u) << 3u) |
            (reg & 7u))});
    c.U32(value);
}

void X86BinaryImmediate32(
    CodeBuffer& c, uint8_t group, uint8_t reg, uint32_t value)
{
    c.Raw({0x81, static_cast<uint8_t>(0xC0u | ((group & 7u) << 3u) |
        (reg & 7u))});
    c.U32(value);
}

void EmitX64PermutationRound(
    CodeBuffer& c,
    uint8_t value,
    const KeyedPermutationRound& round,
    bool inverse)
{
    switch (round.op) {
        case KeyedPermutationOp::Xor: {
            const uint64_t key = round.key;
            if (round.encoding != 0u) X64UnaryGroup(c, 2u, value);
            X64MovImmediate(c, 11u,
                round.encoding != 0u ? ~key : key);
            X64BinaryRegister(c, 0x31, value, 11u);
            break;
        }
        case KeyedPermutationOp::Add: {
            uint64_t key = round.key;
            uint8_t opcode = inverse ? 0x29u : 0x01u;
            if (round.encoding != 0u) {
                key = 0u - key;
                opcode = opcode == 0x01u ? 0x29u : 0x01u;
            }
            X64MovImmediate(c, 11u, key);
            X64BinaryRegister(c, opcode, value, 11u);
            break;
        }
        case KeyedPermutationOp::Rotate: {
            const uint8_t count = inverse
                ? static_cast<uint8_t>(64u - round.rotate)
                : round.rotate;
            if (round.encoding == 0u)
                X64RotateImmediate(c, 0u, value, count);
            else
                X64RotateImmediate(c, 1u, value,
                    static_cast<uint8_t>(64u - count));
            break;
        }
        case KeyedPermutationOp::Multiply: {
            uint64_t factor = inverse ? round.inverse : round.key;
            if (round.encoding != 0u) {
                X64UnaryGroup(c, 3u, value);
                factor = 0u - factor;
            }
            X64MovImmediate(c, 11u, factor);
            X64MultiplyRegister(c, value, 11u);
            break;
        }
        case KeyedPermutationOp::Not:
            if (round.encoding == 0u) X64UnaryGroup(c, 2u, value);
            else {
                X64MovImmediate(c, 11u, ~uint64_t{0});
                X64BinaryRegister(c, 0x31, value, 11u);
            }
            break;
        case KeyedPermutationOp::Negate:
            if (round.encoding == 0u) X64UnaryGroup(c, 3u, value);
            else {
                X64UnaryGroup(c, 2u, value);
                c.Raw({static_cast<uint8_t>(0x48u | ((value & 8u) ? 1u : 0u)),
                    0xFF, static_cast<uint8_t>(0xC0u | (value & 7u))});
            }
            break;
        case KeyedPermutationOp::ByteSwap:
            c.Raw({static_cast<uint8_t>(0x48u | ((value & 8u) ? 1u : 0u)),
                0x0F, static_cast<uint8_t>(0xC8u | (value & 7u))});
            break;
        case KeyedPermutationOp::XorShift:
            X64MovRegister(c, 11u, value);
            X64RotateImmediate(c, round.encoding == 0u ? 4u : 5u,
                11u, round.rotate);
            X64BinaryRegister(c, 0x31, value, 11u);
            break;
    }
}

void EmitX86PermutationRound(
    CodeBuffer& c,
    uint8_t value,
    const KeyedPermutationRound& round,
    bool inverse)
{
    switch (round.op) {
        case KeyedPermutationOp::Xor: {
            uint32_t key = static_cast<uint32_t>(round.key);
            if (round.encoding != 0u) {
                X86UnaryGroup(c, 2u, value);
                key = ~key;
            }
            c.Raw({0x81, static_cast<uint8_t>(0xF0u | (value & 7u))});
            c.U32(key);
            break;
        }
        case KeyedPermutationOp::Add: {
            uint32_t key = static_cast<uint32_t>(round.key);
            uint8_t group = inverse ? 5u : 0u;
            if (round.encoding != 0u) {
                key = 0u - key;
                group = group == 0u ? 5u : 0u;
            }
            c.Raw({0x81, static_cast<uint8_t>(0xC0u | (group << 3u) |
                (value & 7u))});
            c.U32(key);
            break;
        }
        case KeyedPermutationOp::Rotate: {
            const uint8_t count = inverse
                ? static_cast<uint8_t>(32u - round.rotate)
                : round.rotate;
            if (round.encoding == 0u)
                X86RotateImmediate(c, 0u, value, count);
            else
                X86RotateImmediate(c, 1u, value,
                    static_cast<uint8_t>(32u - count));
            break;
        }
        case KeyedPermutationOp::Multiply: {
            uint32_t factor = static_cast<uint32_t>(
                inverse ? round.inverse : round.key);
            if (round.encoding != 0u) {
                X86UnaryGroup(c, 3u, value);
                factor = 0u - factor;
            }
            X86MultiplyImmediate(c, value, factor);
            break;
        }
        case KeyedPermutationOp::Not:
            if (round.encoding == 0u) X86UnaryGroup(c, 2u, value);
            else {
                c.Raw({0x81, static_cast<uint8_t>(0xF0u | (value & 7u))});
                c.U32(0xFFFFFFFFu);
            }
            break;
        case KeyedPermutationOp::Negate:
            if (round.encoding == 0u) X86UnaryGroup(c, 3u, value);
            else {
                X86UnaryGroup(c, 2u, value);
                c.U8(static_cast<uint8_t>(0x40u + (value & 7u)));
            }
            break;
        case KeyedPermutationOp::ByteSwap:
            c.Raw({0x0F, static_cast<uint8_t>(0xC8u | (value & 7u))});
            break;
        case KeyedPermutationOp::XorShift:
            X86MovRegister(c, 1u, value);
            X86RotateImmediate(c, round.encoding == 0u ? 4u : 5u,
                1u, round.rotate);
            X86BinaryRegister(c, 0x31, value, 1u);
            break;
    }
}

void EmitValuePermutation(
    CodeBuffer& c, bool x64, uint8_t value, bool inverse)
{
    const uint32_t begin = static_cast<uint32_t>(c.bytes.size());
    const auto& plan = c.valueCodec;
    if (inverse) {
        for (uint8_t index = plan.roundCount; index != 0u; --index) {
            if (x64) EmitX64PermutationRound(
                c, value, plan.rounds[index - 1u], true);
            else EmitX86PermutationRound(
                c, value, plan.rounds[index - 1u], true);
        }
    } else {
        for (uint8_t index = 0; index < plan.roundCount; ++index) {
            if (x64) EmitX64PermutationRound(
                c, value, plan.rounds[index], false);
            else EmitX86PermutationRound(
                c, value, plan.rounds[index], false);
        }
    }
    c.valueCodecRanges.push_back({begin,
        static_cast<uint32_t>(c.bytes.size()) - begin});
}

void X64CompareDImmediate(CodeBuffer& c, uint8_t reg, uint8_t value) {
    if (reg & 8u) c.U8(0x41);
    c.Raw({0x83, static_cast<uint8_t>(0xF8u | (reg & 7u)), value});
}

void X64SubDImmediate(CodeBuffer& c, uint8_t reg, uint8_t value) {
    if (reg & 8u) c.U8(0x41);
    c.Raw({0x83, static_cast<uint8_t>(0xE8u | (reg & 7u)), value});
}

void X64TestQ(CodeBuffer& c, uint8_t reg) {
    const uint8_t rex = static_cast<uint8_t>(0x48u |
        ((reg & 8u) ? 0x05u : 0u));
    c.Raw({rex, 0x85, static_cast<uint8_t>(0xC0u |
        ((reg & 7u) << 3u) | (reg & 7u))});
}

void X64LoadByteIndirect(
    CodeBuffer& c,
    uint8_t destination,
    uint8_t base,
    uint8_t displacement)
{
    const uint8_t rex = static_cast<uint8_t>(0x40u |
        ((destination & 8u) ? 0x04u : 0u) |
        ((base & 8u) ? 0x01u : 0u));
    c.Raw({rex, 0x0F, 0xB6, static_cast<uint8_t>(0x40u |
        ((destination & 7u) << 3u) | (base & 7u)), displacement});
}

void X86CompareDImmediate(CodeBuffer& c, uint8_t reg, uint8_t value) {
    c.Raw({0x83, static_cast<uint8_t>(0xF8u | (reg & 7u)), value});
}

void X86SubDImmediate(CodeBuffer& c, uint8_t reg, uint8_t value) {
    c.Raw({0x83, static_cast<uint8_t>(0xE8u | (reg & 7u)), value});
}

void X86TestD(CodeBuffer& c, uint8_t reg) {
    c.Raw({0x85, static_cast<uint8_t>(0xC0u |
        ((reg & 7u) << 3u) | (reg & 7u))});
}

void X86LoadByteIndirect(
    CodeBuffer& c,
    uint8_t destination,
    uint8_t base,
    uint8_t displacement)
{
    c.Raw({0x0F, 0xB6, static_cast<uint8_t>(0x40u |
        ((destination & 7u) << 3u) | (base & 7u)), displacement});
}

void X86LoadIndexedDVariant(
    CodeBuffer& c,
    uint8_t destination,
    uint8_t index,
    uint32_t displacement)
{
    if (destination > 7u || destination == 7u || destination == 4u ||
        index > 7u || index == 7u || index == 4u) {
        c.FailEncoding("x86 indexed context load uses an invalid register");
        return;
    }
    std::array<int32_t, 6> addressDisplacements{};
    int32_t loadDisplacement = 0;
    if (!DeriveContextLoadDisplacements(c,
            ContextLoadAddressKind::X86IndexedRegister, 4u, destination, index,
            displacement, addressDisplacements, loadDisplacement)) return;
    c.Raw({0x8D, static_cast<uint8_t>(0x84u |
        ((destination & 7u) << 3u)),
        static_cast<uint8_t>(0xC7u | ((index & 7u) << 3u))});
    c.U32(static_cast<uint32_t>(addressDisplacements[0]));
    EmitX86LoadFromSplitBase(
        c, destination, 4u, addressDisplacements, loadDisplacement);
}

void X86StoreIndexedDVariant(
    CodeBuffer& c,
    uint32_t displacement,
    uint8_t index,
    uint8_t source)
{
    c.Raw({0x89, static_cast<uint8_t>(0x84u |
        ((source & 7u) << 3u)),
        static_cast<uint8_t>(0xC7u | ((index & 7u) << 3u))});
    c.U32(displacement);
}

void EmitIdentityMBA(
    CodeBuffer& c,
    bool x64,
    uint8_t valueRegister,
    uint8_t keyRegister,
    const SemanticMutationPlan& plan)
{
    const auto emitX86Key = [&](uint64_t key, uint8_t encoding) {
        const uint32_t key32 = static_cast<uint32_t>(key);
        switch (encoding % 3u) {
            case 0:
                X86MovImmediate(c, keyRegister, key32);
                break;
            case 1:
                c.U8(0x68); c.U32(key32);
                c.U8(static_cast<uint8_t>(0x58u + (keyRegister & 7u)));
                break;
            default:
                c.Raw({0xC7, static_cast<uint8_t>(0xC0u |
                    (keyRegister & 7u))});
                c.U32(key32);
                break;
        }
    };
    const auto emitPair = [&](uint8_t pair, uint64_t key, uint8_t encoding) {
        const uint8_t first = pair == 0u ? 0x31u :
            (pair == 1u ? 0x01u : 0x29u);
        const uint8_t second = pair == 0u ? 0x31u :
            (pair == 1u ? 0x29u : 0x01u);
        if (x64) {
            X64MovImmediate(c, keyRegister, key);
            X64BinaryRegister(c, first, valueRegister, keyRegister);
            X64MovImmediate(c, keyRegister, key);
            X64BinaryRegister(c, second, valueRegister, keyRegister);
        } else {
            emitX86Key(key, encoding);
            X86BinaryRegister(c, first, valueRegister, keyRegister);
            emitX86Key(key, static_cast<uint8_t>(encoding + 1u));
            X86BinaryRegister(c, second, valueRegister, keyRegister);
        }
    };
    for (uint8_t round = 0; round < plan.roundCount; ++round) {
        const uint8_t strategy = plan.roundStrategies[round];
        const uint8_t pairCount = strategy < 3u ? 1u :
            (strategy < 6u ? 2u : (strategy == 6u ? 3u : 4u));
        for (uint8_t pair = 0; pair < pairCount; ++pair) {
            const uint64_t pairKey = plan.roundKeys[round] ^
                (0x9E3779B97F4A7C15ULL * static_cast<uint64_t>(pair + 1u));
            emitPair(static_cast<uint8_t>((strategy + pair) % 3u), pairKey,
                static_cast<uint8_t>(strategy + round + pair));
        }
    }
}

void EmitSemanticInputPreparation(
    CodeBuffer& c,
    bool x64,
    const SemanticPathSpec& spec,
    const std::array<uint8_t, 4>& registers,
    uint8_t stackPops,
    CodeBuffer::Label stackFailure,
    CodeBuffer::Label rangeFailure)
{
    const uint8_t indexRegister = registers[2];
    if (spec.kind == SemanticPathKind::StackTop) {
        if (x64) {
            X64LoadD(c, indexRegister, CtxValueDepth);
            X64CompareDImmediate(c, indexRegister, stackPops);
            c.Jcc(JccB, stackFailure);
            X64SubDImmediate(c, indexRegister, 1u);
        } else {
            X86LoadD(c, indexRegister, CtxValueDepth);
            X86CompareDImmediate(c, indexRegister, stackPops);
            c.Jcc(JccB, stackFailure);
            X86SubDImmediate(c, indexRegister, 1u);
        }
    } else if (spec.kind == SemanticPathKind::MappedVreg) {
        if (x64) {
            X64LoadQ(c, indexRegister, CtxRegisterMap);
            X64TestQ(c, indexRegister);
            c.Jcc(JccE, rangeFailure);
        } else {
            X86LoadD(c, indexRegister, CtxRegisterMap);
            X86TestD(c, indexRegister);
            c.Jcc(JccE, rangeFailure);
        }
    }
}

void EmitSemanticIdentityPath(
    CodeBuffer& c,
    bool x64,
    const SemanticPathSpec& spec,
    const std::array<uint8_t, 4>& registers,
    const SemanticMutationPlan& plan,
    bool inputPath)
{
    const uint8_t valueRegister = inputPath ? registers[0] : registers[1];
    const uint8_t keyRegister = inputPath ? registers[1] : registers[2];
    const uint8_t indexRegister = inputPath ? registers[2] : registers[0];

    switch (spec.kind) {
        case SemanticPathKind::ContextNative:
            if (x64) X64LoadQ(c, valueRegister, spec.displacement);
            else X86LoadD(c, valueRegister, spec.displacement);
            break;
        case SemanticPathKind::ContextDword:
            if (x64) X64LoadD(c, valueRegister, spec.displacement);
            else X86LoadD(c, valueRegister, spec.displacement);
            break;
        case SemanticPathKind::StackTop:
            if (!inputPath) {
                if (x64) {
                    X64LoadD(c, indexRegister, CtxValueDepth);
                    X64SubDImmediate(c, indexRegister, 1u);
                } else {
                    X86LoadD(c, indexRegister, CtxValueDepth);
                    X86SubDImmediate(c, indexRegister, 1u);
                }
            }
            if (x64)
                X64LoadIndexedQ(c, valueRegister, indexRegister, spec.displacement);
            else
                X86LoadIndexedDVariant(c, valueRegister, indexRegister,
                    spec.displacement);
            break;
        case SemanticPathKind::MappedVreg:
            if (!inputPath) {
                if (x64) X64LoadQ(c, indexRegister, CtxRegisterMap);
                else X86LoadD(c, indexRegister, CtxRegisterMap);
            }
            if (x64) {
                X64LoadByteIndirect(c, indexRegister, indexRegister,
                    spec.mappedFamily);
                X64LoadIndexedQ(c, valueRegister, indexRegister,
                    spec.displacement);
            } else {
                X86LoadByteIndirect(c, indexRegister, indexRegister,
                    spec.mappedFamily);
                X86LoadIndexedDVariant(c, valueRegister, indexRegister,
                    spec.displacement);
            }
            break;
    }

    EmitIdentityMBA(c, x64, valueRegister, keyRegister, plan);

    switch (spec.kind) {
        case SemanticPathKind::ContextNative:
            if (x64) X64StoreQ(c, spec.displacement, valueRegister);
            else X86StoreD(c, spec.displacement, valueRegister);
            break;
        case SemanticPathKind::ContextDword:
            if (x64) X64StoreD(c, spec.displacement, valueRegister);
            else X86StoreD(c, spec.displacement, valueRegister);
            break;
        case SemanticPathKind::StackTop:
        case SemanticPathKind::MappedVreg:
            if (x64)
                X64StoreIndexedQ(c, spec.displacement, indexRegister,
                    valueRegister);
            else
                X86StoreIndexedDVariant(c, spec.displacement, indexRegister,
                    valueRegister);
            break;
    }
}

// 操作数宽度分派:SHL/SHR 等 K 变体核心与后段的多处 sized 发射都依赖它,
// 故定义在 EmitBusinessCoreVariant 之前。
struct WidthLabels {
    CodeBuffer::Label width1;
    CodeBuffer::Label width2;
    CodeBuffer::Label width4;
    CodeBuffer::Label width8;
    CodeBuffer::Label invalid;
};

WidthLabels MakeWidthLabels(CodeBuffer& c) {
    return {c.NewLabel(), c.NewLabel(), c.NewLabel(), c.NewLabel(), c.NewLabel()};
}

void X64DispatchWidth(
    CodeBuffer& c,
    uint8_t operand,
    const WidthLabels& labels)
{
    uint32_t key = 0;
    if (!DeriveControlDispatchKey(
            c, 0x5749445448445350ULL, operand, key)) return;
    const auto restoreInvalid = c.NewLabel();
    const auto restoreWidth1 = c.NewLabel();
    const auto restoreWidth2 = c.NewLabel();
    const auto restoreWidth4 = c.NewLabel();
    const auto restoreWidth8 = c.NewLabel();

    X64LoadByte(c, 11, CtxDecodedOperands + static_cast<uint32_t>(operand) * 8u);
    // lea r11,[r11+K] is flag-neutral; the matching CMP therefore publishes
    // the same equality flags as the original raw-width dispatch.
    c.Raw({0x4D,0x8D,0x9B}); c.U32(key);
    c.Raw({0x49,0x81,0xFB}); c.U32(key + 1u); c.Jcc(JccE, restoreWidth1);
    c.Raw({0x49,0x81,0xFB}); c.U32(key + 2u); c.Jcc(JccE, restoreWidth2);
    c.Raw({0x49,0x81,0xFB}); c.U32(key + 4u); c.Jcc(JccE, restoreWidth4);
    c.Raw({0x49,0x81,0xFB}); c.U32(key + 8u); c.Jcc(JccE, restoreWidth8);

    c.Bind(restoreInvalid);
    c.Raw({0x4D,0x8D,0x9B}); c.U32(0u - key);
    // Recreate the exact flags of the original final raw-width comparison
    // before entering the shared failure path.
    c.Raw({0x49,0x83,0xFB,0x08});
    c.Jmp(labels.invalid);

    const auto restore = [&](CodeBuffer::Label local,
                             CodeBuffer::Label destination) {
        c.Bind(local);
        c.Raw({0x4D,0x8D,0x9B}); c.U32(0u - key);
        c.Jmp(destination);
    };
    restore(restoreWidth1, labels.width1);
    restore(restoreWidth2, labels.width2);
    restore(restoreWidth4, labels.width4);
    restore(restoreWidth8, labels.width8);
}

void X86DispatchWidth(
    CodeBuffer& c,
    uint8_t operand,
    const WidthLabels& labels)
{
    uint32_t key = 0;
    if (!DeriveControlDispatchKey(
            c, 0x5749445448445350ULL, operand, key)) return;
    const auto restoreInvalid = c.NewLabel();
    const auto restoreWidth1 = c.NewLabel();
    const auto restoreWidth2 = c.NewLabel();
    const auto restoreWidth4 = c.NewLabel();

    X86LoadByte(c, 1, CtxDecodedOperands + static_cast<uint32_t>(operand) * 8u);
    c.Raw({0x8D,0x89}); c.U32(key);
    c.Raw({0x81,0xF9}); c.U32(key + 1u); c.Jcc(JccE, restoreWidth1);
    c.Raw({0x81,0xF9}); c.U32(key + 2u); c.Jcc(JccE, restoreWidth2);
    c.Raw({0x81,0xF9}); c.U32(key + 4u); c.Jcc(JccE, restoreWidth4);

    c.Bind(restoreInvalid);
    c.Raw({0x8D,0x89}); c.U32(0u - key);
    c.Raw({0x83,0xF9,0x04});
    c.Jmp(labels.invalid);

    const auto restore = [&](CodeBuffer::Label local,
                             CodeBuffer::Label destination) {
        c.Bind(local);
        c.Raw({0x8D,0x89}); c.U32(0u - key);
        c.Jmp(destination);
    };
    restore(restoreWidth1, labels.width1);
    restore(restoreWidth2, labels.width2);
    restore(restoreWidth4, labels.width4);
}

// Defined with the remaining sized-register helpers below.  The K-variant
// cores live before EmitBusinessCoreVariant so it can be re-emitted in
// isolation by the validator.
void X64ShiftImmediate(CodeBuffer& c, uint8_t group, uint8_t reg, uint8_t count);
void X64ShiftCl(CodeBuffer& c, uint8_t group, uint8_t reg);

void EmitX64ByteSwapVariant(CodeBuffer& c, uint8_t strategy) {
    const auto mix = [](uint64_t value) {
        value ^= value >> 30u;
        value *= 0xBF58476D1CE4E5B9ULL;
        value ^= value >> 27u;
        value *= 0x94D049BB133111EBULL;
        return value ^ (value >> 31u);
    };
    const uint64_t seedWord =
        (static_cast<uint64_t>(CoreKey32(c, strategy + 1u)) << 32u) |
        CoreKey32(c, strategy + 5u);
    const uint64_t key = mix(seedWord ^ 0x42535741505F5836ULL ^ strategy) | 1u;
    const auto reverseKey = [](uint64_t value, uint8_t bytes) {
        uint64_t reversed = 0;
        for (uint8_t index = 0; index < bytes; ++index) {
            reversed |= ((value >> (index * 8u)) & 0xFFu) <<
                ((bytes - 1u - index) * 8u);
        }
        return reversed;
    };
    const auto xorKey = [&](uint8_t bytes, uint64_t value) {
        if (bytes == 1u) {
            c.Raw({0x34, static_cast<uint8_t>(value)});
        } else if (bytes == 2u) {
            c.Raw({0x66,0x35}); c.U16(static_cast<uint16_t>(value));
        } else if (bytes == 4u) {
            c.U8(0x35); c.U32(static_cast<uint32_t>(value));
        } else {
            constexpr std::array<uint8_t, 4> keyRegisters = {1u, 2u, 10u, 11u};
            const uint8_t keyRegister = keyRegisters[
                static_cast<size_t>((value ^ (value >> 29u) ^ strategy) & 3u)];
            X64MovImmediate(c, keyRegister, value);
            X64BinaryRegister(c, 0x31u, 0u, keyRegister);
        }
    };
    const auto conjugate = [&](uint8_t bytes, const auto& transform) {
        const uint64_t widthKey = bytes == 8u
            ? key : key & ((uint64_t{1} << (bytes * 8u)) - 1u);
        xorKey(bytes, widthKey);
        transform();
        xorKey(bytes, reverseKey(widthKey, bytes));
    };

    const WidthLabels width = MakeWidthLabels(c);
    const auto done = c.NewLabel();
    X64DispatchWidth(c, 0, width);
    c.Bind(width.width1);
    conjugate(1u, [&] {
        // A byte-wide byte reversal is a rotate by one full byte.  The
        // effective count is zero, so the rotate itself preserves flags.
        c.Raw({0xC0, static_cast<uint8_t>(strategy == 0u ? 0xC0 : 0xC8), 0x08});
    });
    c.Jmp(done);
    c.Bind(width.width2);
    conjugate(2u, [&] {
        c.Raw({0x66,0xC1,
            static_cast<uint8_t>(strategy == 0u ? 0xC0 : 0xC8),0x08});
    });
    c.Jmp(done);
    c.Bind(width.width4);
    conjugate(4u, [&] {
        if (strategy == 0u) c.Raw({0x0F,0xC8});
        else {
            constexpr std::array<uint8_t, 4> scratchRegisters = {1u, 2u, 10u, 11u};
            const uint8_t scratch = scratchRegisters[
                static_cast<size_t>((key >> 17u) & 3u)];
            const uint8_t moveInRex = static_cast<uint8_t>(
                0x40u | ((scratch & 8u) ? 1u : 0u));
            if (moveInRex != 0x40u) c.U8(moveInRex);
            c.Raw({0x89, static_cast<uint8_t>(0xC0u | (scratch & 7u))});
            if (scratch & 8u) c.U8(0x41);
            c.Raw({0x0F, static_cast<uint8_t>(0xC8u + (scratch & 7u))});
            const uint8_t moveOutRex = static_cast<uint8_t>(
                0x40u | ((scratch & 8u) ? 4u : 0u));
            if (moveOutRex != 0x40u) c.U8(moveOutRex);
            c.Raw({0x89, static_cast<uint8_t>(
                0xC0u | ((scratch & 7u) << 3u))});
        }
    });
    c.Jmp(done);
    c.Bind(width.width8);
    conjugate(8u, [&] {
        if (strategy == 0u) c.Raw({0x48,0x0F,0xC8});
        else {
            constexpr std::array<uint8_t, 4> scratchRegisters = {1u, 2u, 10u, 11u};
            const uint8_t scratch = scratchRegisters[
                static_cast<size_t>((key >> 41u) & 3u)];
            X64MovRegister(c, scratch, 0u);
            c.Raw({static_cast<uint8_t>(0x48u | ((scratch & 8u) ? 1u : 0u)),
                0x0F, static_cast<uint8_t>(0xC8u + (scratch & 7u))});
            X64MovRegister(c, 0u, scratch);
        }
    });
    c.Jmp(done);
    c.Bind(width.invalid); c.Raw({0x0F,0x0B});
    c.Bind(done);
}

void EmitX86ByteSwapVariant(CodeBuffer& c, uint8_t strategy) {
    const auto mix = [](uint64_t value) {
        value ^= value >> 30u;
        value *= 0xBF58476D1CE4E5B9ULL;
        value ^= value >> 27u;
        value *= 0x94D049BB133111EBULL;
        return value ^ (value >> 31u);
    };
    const uint64_t seedWord =
        (static_cast<uint64_t>(CoreKey32(c, strategy + 2u)) << 32u) |
        CoreKey32(c, strategy + 6u);
    const uint32_t key = static_cast<uint32_t>(
        mix(seedWord ^ 0x42535741505F5833ULL ^ strategy)) | 1u;
    const auto reverseKey = [](uint32_t value, uint8_t bytes) {
        uint32_t reversed = 0;
        for (uint8_t index = 0; index < bytes; ++index) {
            reversed |= ((value >> (index * 8u)) & 0xFFu) <<
                ((bytes - 1u - index) * 8u);
        }
        return reversed;
    };
    const auto xorKey = [&](uint8_t bytes, uint32_t value) {
        if (bytes == 1u) {
            c.Raw({0x34, static_cast<uint8_t>(value)});
        } else if (bytes == 2u) {
            c.Raw({0x66,0x35}); c.U16(static_cast<uint16_t>(value));
        } else {
            c.U8(0x35); c.U32(value);
        }
    };
    const auto conjugate = [&](uint8_t bytes, const auto& transform) {
        const uint32_t widthKey = bytes == 4u
            ? key : key & ((uint32_t{1} << (bytes * 8u)) - 1u);
        xorKey(bytes, widthKey);
        transform();
        xorKey(bytes, reverseKey(widthKey, bytes));
    };

    const WidthLabels width = MakeWidthLabels(c);
    const auto done = c.NewLabel();
    X86DispatchWidth(c, 0, width);
    c.Bind(width.width1);
    conjugate(1u, [&] {
        c.Raw({0xC0, static_cast<uint8_t>(strategy == 0u ? 0xC0 : 0xC8), 0x08});
    });
    c.Jmp(done);
    c.Bind(width.width2);
    conjugate(2u, [&] {
        c.Raw({0x66,0xC1,
            static_cast<uint8_t>(strategy == 0u ? 0xC0 : 0xC8),0x08});
    });
    c.Jmp(done);
    c.Bind(width.width4);
    conjugate(4u, [&] {
        if (strategy == 0u) c.Raw({0x0F,0xC8});
        else c.Raw({0x89,0xC2,0x0F,0xCA,0x89,0xD0});
    });
    c.Jmp(done);
    c.Bind(width.invalid); c.Raw({0x0F,0x0B});
    c.Bind(done);
}

// Two distinct x64 GPR indices from the safe local-scratch pool
// {8,11,12,13}, seed-derived per (semantic,strategy). Excludes 0 (the
// live shift operand), 1/2 (RCX/RDX -- the count is moved through
// `mov rcx,rdx` and every count-consuming instruction below implicitly
// reads CL, so RCX must stay the count register end to end), 4 (RSP), 9
// (the width mask X64MaskForWidthInR11 computed and re-applies to the
// result after this core returns, so it must survive the whole core body
// unclobbered), 10 (EmitX64BinaryAlu zeroes it as "auxiliary" *before*
// calling into this core and reads it back via X64FinishPrelatched right
// after), and 15 (the runtime's context-pointer register -- see
// X64LoadQ/X64LoadD's own "cannot overwrite the context register" guard;
// every Ctx*-prefixed load/store in this file is `[r15+share...]`, not
// `[rdi+...]`, despite what an earlier draft of this comment claimed).
//
// 14 is ALSO excluded, empirically: every register in the pool was
// individually verified against the real native-differential suite
// (test_vm_native_differential) one at a time, not just reasoned about
// from reading the surrounding code, because the 10-exclusion above was
// itself found that way after a first pass missed it (every corpus case
// that exercised FLAGS_LAZY after a SHL/SHR/SAR/ROL/ROR access-violated,
// because the core's own key scratch had clobbered what EmitX64BinaryAlu
// still expected to be a clean zero). 8/11/12/13 each pass in isolation;
// 14 alone reproduces the same class of FLAGS_LAZY access violation, for
// a reason not yet root-caused (most likely some other handler or the
// direct-threaded dispatch stub itself also treats r14 as reserved) --
// it is excluded on that empirical evidence, not a traced justification
// like the others. Do not add it back without either root-causing why or
// re-running the full isolated single-register verification above.
//
// This is what actually changes the per-build 4-gram content of the
// ModRM/REX bytes this core emits -- the round-keyed immediates alone
// (already seed-derived) are exactly what the codec-similarity stage
// strips out before measuring business_core, so on their own they cannot
// move that number; only the *structural* bytes (which physical register
// a given instruction touches) can.
std::pair<uint8_t, uint8_t> DeriveShiftCoreScratchRegisters(
    const CodeBuffer& c, VM_MICRO_OPCODE semantic, uint8_t strategy)
{
    static constexpr std::array<uint8_t, 4> kPool = {8u,11u,12u,13u};
    const uint64_t domain = 0x5348495254524547ULL ^
        (static_cast<uint64_t>(semantic) << 16u) ^
        (static_cast<uint64_t>(strategy) << 8u);
    const auto& round = c.coreSelector.rounds[domain % c.coreSelector.roundCount];
    const uint64_t mixed = round.key ^ domain ^
        (static_cast<uint64_t>(round.rotate) << 32u) ^
        (static_cast<uint64_t>(round.encoding) << 40u);
    const size_t first = static_cast<size_t>(mixed % kPool.size());
    const size_t secondOffset = 1u + static_cast<size_t>(
        (mixed >> 16u) % (kPool.size() - 1u));
    const size_t second = (first + secondOffset) % kPool.size();
    return {kPool[first], kPool[second]};
}

void EmitX64ShiftRotateVariant(
    CodeBuffer& c,
    VM_MICRO_OPCODE semantic,
    uint8_t strategy)
{
    const WidthLabels width = MakeWidthLabels(c);
    const auto done = c.NewLabel();
    X64DispatchWidth(c, 0, width);
    const auto scratch = DeriveShiftCoreScratchRegisters(c, semantic, strategy);
    const uint8_t scratchA = scratch.first;
    const uint8_t scratchB = scratch.second;
    const auto emit = [&](CodeBuffer::Label label, uint8_t bytes) {
        c.Bind(label);
        const auto deriveKey = [&](size_t share) {
            const auto& round = c.coreSelector.rounds[
                (static_cast<size_t>(bytes) + share * 3u + strategy * 5u +
                 static_cast<size_t>(semantic)) % c.coreSelector.roundCount];
            uint64_t key = round.key ^
                (0x9E3779B97F4A7C15ULL * static_cast<uint64_t>(
                    static_cast<uint8_t>(semantic) + share + 1u)) ^
                (static_cast<uint64_t>(round.rotate) << 56u);
            if (semantic == VM_UOP_SAR) {
                key &= ~(uint64_t{1} << (bytes * 8u - 1u));
            }
            return key != 0u ? key :
                (0x6D2B79F5A5C3E17BULL &
                 ~(semantic == VM_UOP_SAR
                    ? (uint64_t{1} << (bytes * 8u - 1u)) : 0u));
        };
        const auto emitClOperation = [&](uint8_t reg, uint8_t group) {
            const uint8_t modrm = static_cast<uint8_t>(
                0xC0u | ((group & 7u) << 3u) | (reg & 7u));
            if (bytes == 1u) {
                if (reg >= 8u) c.U8(0x41);
                c.Raw({0xD2, modrm});
            } else {
                if (bytes == 2u) c.U8(0x66);
                if (bytes == 8u) c.U8(static_cast<uint8_t>(
                    0x48u | (reg >= 8u ? 1u : 0u)));
                else if (reg >= 8u) c.U8(0x41);
                c.Raw({0xD3, modrm});
            }
        };

        std::array<uint64_t, 4> keys{};
        for (size_t share = 0u; share < keys.size(); ++share) {
            keys[share] = deriveKey(share);
        }
        std::array<size_t, 4> shareOrder = {{0u, 1u, 2u, 3u}};
        if (strategy != 0u) std::reverse(shareOrder.begin(), shareOrder.end());

        c.Raw({0x48,0x89,0xD1});
        for (const size_t share : shareOrder) {
            X64MovImmediate(c, scratchB, keys[share]);
            X64BinaryRegister(c, 0x31u, 0u, scratchB);
        }
        const uint8_t valueGroup = semantic == VM_UOP_SAR ? 7u :
            (semantic == VM_UOP_ROL ? 0u : 1u);
        const uint8_t keyGroup = semantic == VM_UOP_SAR ? 5u : valueGroup;
        emitClOperation(0u, valueGroup);

        X64MovImmediate(c, scratchA, keys[shareOrder[0u]]);
        emitClOperation(scratchA, keyGroup);
        for (size_t position = 1u; position < shareOrder.size(); ++position) {
            X64MovImmediate(c, scratchB, keys[shareOrder[position]]);
            emitClOperation(scratchB, keyGroup);
            X64BinaryRegister(c, 0x31u, scratchA, scratchB);
        }
        X64BinaryRegister(c, 0x31u, 0u, scratchA);
        if (bytes == 1u) c.Raw({0x0F,0xB6,0xC0});
        else if (bytes == 2u) c.Raw({0x0F,0xB7,0xC0});
        else if (bytes == 4u) c.Raw({0x89,0xC0});
        c.Jmp(done);
    };
    std::array<std::pair<CodeBuffer::Label, uint8_t>, 4> blocks = {{
        {width.width1,uint8_t{1}}, {width.width2,uint8_t{2}},
        {width.width4,uint8_t{4}}, {width.width8,uint8_t{8}}}};
    for (uint8_t index = 3u; index != 0u; --index) {
        const auto& round = c.coreSelector.rounds[
            (index + strategy * 5u) % c.coreSelector.roundCount];
        const uint8_t selected = static_cast<uint8_t>(
            (round.key ^ round.rotate) % (static_cast<uint32_t>(index) + 1u));
        std::swap(blocks[index], blocks[selected]);
    }
    for (const auto& block : blocks) emit(block.first, block.second);
    c.Bind(width.invalid); c.Raw({0x0F,0x0B});
    c.Bind(done);
}

void EmitX86ShiftRotateVariant(
    CodeBuffer& c,
    VM_MICRO_OPCODE semantic,
    uint8_t strategy)
{
    const WidthLabels width = MakeWidthLabels(c);
    const auto done = c.NewLabel();
    X86DispatchWidth(c, 0, width);
    const auto emit = [&](CodeBuffer::Label label, uint8_t bytes) {
        c.Bind(label);
        const auto deriveKey = [&](size_t share) {
            const auto& round = c.coreSelector.rounds[
                (static_cast<size_t>(bytes) + share * 3u + strategy * 5u +
                 static_cast<size_t>(semantic)) % c.coreSelector.roundCount];
            uint64_t mixed = round.key ^
                (0x9E3779B97F4A7C15ULL * static_cast<uint64_t>(
                    static_cast<uint8_t>(semantic) + share + 1u)) ^
                (static_cast<uint64_t>(round.rotate) << 56u);
            uint32_t key = static_cast<uint32_t>(mixed ^ (mixed >> 32u));
            if (semantic == VM_UOP_SAR) {
                key &= ~(uint32_t{1} << (bytes * 8u - 1u));
            }
            return key != 0u ? key :
                (0x6D2B79F5u &
                 ~(semantic == VM_UOP_SAR
                    ? (uint32_t{1} << (bytes * 8u - 1u)) : 0u));
        };
        const auto emitClOperation = [&](uint8_t reg, uint8_t group) {
            const uint8_t modrm = static_cast<uint8_t>(
                0xC0u | ((group & 7u) << 3u) | (reg & 7u));
            if (bytes == 1u) c.Raw({0xD2, modrm});
            else {
                if (bytes == 2u) c.U8(0x66);
                c.Raw({0xD3, modrm});
            }
        };

        std::array<uint32_t, 4> keys{};
        for (size_t share = 0u; share < keys.size(); ++share) {
            keys[share] = deriveKey(share);
        }
        std::array<size_t, 4> shareOrder = {{0u, 1u, 2u, 3u}};
        if (strategy != 0u) std::reverse(shareOrder.begin(), shareOrder.end());

        c.Raw({0x89,0xD1});
        for (const size_t share : shareOrder) {
            X86MovImmediate(c, 2u, keys[share]);
            X86BinaryRegister(c, 0x31u, 0u, 2u);
        }
        const uint8_t valueGroup = semantic == VM_UOP_SAR ? 7u :
            (semantic == VM_UOP_ROL ? 0u : 1u);
        const uint8_t keyGroup = semantic == VM_UOP_SAR ? 5u : valueGroup;
        emitClOperation(0u, valueGroup);

        X86MovImmediate(c, 3u, keys[shareOrder[0u]]);
        emitClOperation(3u, keyGroup);
        for (size_t position = 1u; position < shareOrder.size(); ++position) {
            X86MovImmediate(c, 2u, keys[shareOrder[position]]);
            emitClOperation(2u, keyGroup);
            X86BinaryRegister(c, 0x31u, 3u, 2u);
        }
        X86BinaryRegister(c, 0x31u, 0u, 3u);
        if (bytes == 1u) c.Raw({0x0F,0xB6,0xC0});
        else if (bytes == 2u) c.Raw({0x0F,0xB7,0xC0});
        c.Jmp(done);
    };
    std::array<std::pair<CodeBuffer::Label, uint8_t>, 3> blocks = {{
        {width.width1,uint8_t{1}}, {width.width2,uint8_t{2}},
        {width.width4,uint8_t{4}}}};
    for (uint8_t index = 2u; index != 0u; --index) {
        const auto& round = c.coreSelector.rounds[
            (index + strategy * 5u) % c.coreSelector.roundCount];
        const uint8_t selected = static_cast<uint8_t>(
            (round.key ^ round.rotate) % (static_cast<uint32_t>(index) + 1u));
        std::swap(blocks[index], blocks[selected]);
    }
    for (const auto& block : blocks) emit(block.first, block.second);
    c.Bind(width.invalid); c.Raw({0x0F,0x0B});
    c.Bind(done);
}

void EmitX64ExtendVariant(CodeBuffer& c, bool signExtend, uint8_t strategy) {
    X64LoadByte(c, 1, CtxDecodedOperands);
    c.Raw({0xBA,0x08,0x00,0x00,0x00,0x29,0xCA,0xC1,0xE2,0x03,
           0x89,0xD1});
    if (strategy == 0u) {
        X64ShiftCl(c, 4, 0);
        X64MovRegister(c, 1, 2);
        X64ShiftCl(c, signExtend ? 7u : 5u, 0);
    } else if (!signExtend) {
        c.Raw({0x49,0xC7,0xC2,0xFF,0xFF,0xFF,0xFF});
        X64ShiftCl(c, 5, 10); X64BinaryRegister(c, 0x21, 0, 10);
    } else {
        c.Raw({0x49,0xC7,0xC2,0xFF,0xFF,0xFF,0xFF});
        X64ShiftCl(c, 5, 10); X64BinaryRegister(c, 0x21, 0, 10);
        c.Raw({0x49,0xBB,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x80});
        X64ShiftCl(c, 5, 11); X64BinaryRegister(c, 0x31, 0, 11);
        X64BinaryRegister(c, 0x29, 0, 11);
    }
}

void EmitX86ExtendVariant(CodeBuffer& c, bool signExtend, uint8_t strategy) {
    X86LoadByte(c, 1, CtxDecodedOperands);
    c.Raw({0xBA,0x04,0x00,0x00,0x00,0x29,0xCA,0xC1,0xE2,0x03,
           0x89,0xD1});
    if (strategy == 0u) {
        c.Raw({0xD3,0xE0,0x89,0xD1,static_cast<uint8_t>(0xD3),
               static_cast<uint8_t>(signExtend ? 0xF8 : 0xE8)});
    } else if (!signExtend) {
        c.Raw({0xBB,0xFF,0xFF,0xFF,0xFF,0xD3,0xEB,0x21,0xD8});
    } else {
        c.Raw({0xBB,0xFF,0xFF,0xFF,0xFF,0xD3,0xEB,0x21,0xD8,
               0xBB,0x00,0x00,0x00,0x80,0xD3,0xEB,0x31,0xD8,0x29,0xD8});
    }
}

void EmitX64PopVregVariant(CodeBuffer& c, uint8_t strategy) {
    const uint32_t address0 = CoreAddressKey(c, strategy + 1u);
    const uint32_t address1 = CoreAddressKey(c, strategy + 5u);
    if (strategy == 0u) {
        const auto merge = c.NewLabel();
        const auto done = c.NewLabel();
        X64LoadD(c, 8, CtxDecodedOperands + 24u);
        c.Raw({0x45,0x85,0xC0}); c.Jcc(JccE, merge);
        c.Jmp(done);
        c.Bind(merge);
        X64LoadD(c, 1, CtxDecodedOperands + 16u);
        X64ShiftCl(c, 4, 0);
        X64MovRegister(c, 11, 9); X64ShiftCl(c, 4, 11);
        c.Raw({0x49,0xF7,0xD3});
        c.Raw({0x4B,0x8D,0x94,0xD7}); c.U32(CtxVregs + address0);
        X64BinaryImmediate32(c, 0u, 2u, address1);
        c.Raw({0x48,0x8B,0x92}); c.U32(0u - (address0 + address1));
        X64BinaryRegister(c, 0x21, 2, 11);
        X64BinaryRegister(c, 0x09, 0, 2);
        c.Bind(done);
    } else {
        X64LoadD(c, 1, CtxDecodedOperands + 16u);
        X64MovRegister(c, 2, 0); X64ShiftCl(c, 4, 2);
        X64MovRegister(c, 11, 9); X64ShiftCl(c, 4, 11);
        c.Raw({0x49,0xF7,0xD3});
        c.Raw({0x4F,0x8D,0x8C,0xD7}); c.U32(CtxVregs + address0);
        X64BinaryImmediate32(c, 0u, 9u, address1);
        c.Raw({0x4D,0x8B,0x89}); c.U32(0u - (address0 + address1));
        X64BinaryRegister(c, 0x21, 9, 11);
        X64BinaryRegister(c, 0x09, 2, 9);
        X64LoadD(c, 8, CtxDecodedOperands + 24u);
        c.Raw({0x45,0x85,0xC0,0x48,0x0F,0x44,0xC2});
    }
}

void EmitX86PopVregVariant(CodeBuffer& c, uint8_t strategy) {
    const uint32_t address0 = CoreAddressKey(c, strategy + 1u);
    const uint32_t address1 = CoreAddressKey(c, strategy + 5u);
    if (strategy == 0u) {
        const auto merge = c.NewLabel();
        const auto done = c.NewLabel();
        X86LoadD(c, 3, CtxDecodedOperands + 24u);
        c.Raw({0x85,0xDB}); c.Jcc(JccE, merge); c.Jmp(done);
        c.Bind(merge);
        X86LoadD(c, 1, CtxDecodedOperands + 16u);
        c.Raw({0xD3,0xE0});
        X86LoadD(c, 3, CtxMutationScratch); c.Raw({0xD3,0xE3,0xF7,0xD3});
        c.Raw({0x8D,0xB4,0xD7}); c.U32(CtxVregs + address0);
        X86BinaryImmediate32(c, 0u, 6u, address1);
        c.Raw({0x8B,0xB6}); c.U32(0u - (address0 + address1));
        c.Raw({0x21,0xDE,0x09,0xF0});
        c.Bind(done);
    } else {
        X86LoadD(c, 1, CtxDecodedOperands + 16u);
        c.Raw({0x89,0xC6,0xD3,0xE6});
        X86LoadD(c, 3, CtxMutationScratch); c.Raw({0xD3,0xE3,0xF7,0xD3});
        c.Raw({0x8D,0x84,0xD7}); c.U32(CtxVregs + address0);
        X86BinaryImmediate32(c, 0u, 0u, address1);
        c.Raw({0x8B,0x80}); c.U32(0u - (address0 + address1));
        c.Raw({0x21,0xD8,0x09,0xC6});
        X86LoadD(c, 0, CtxMutationScratch + 4u);
        c.Raw({0x23,0x87}); c.U32(CtxMutationScratch);
        X86LoadD(c, 3, CtxDecodedOperands + 24u);
        c.Raw({0x85,0xDB,0x0F,0x44,0xC6});
    }
}

void EmitX64MemoryVariant(CodeBuffer& c, bool store, uint8_t strategy) {
    const WidthLabels width = MakeWidthLabels(c);
    const auto done = c.NewLabel();
    const size_t shareDomain = (store ? 1u : 0u) + strategy * 2u;
    std::array<uint32_t, 3> shares = {
        CoreAddressKey(c, shareDomain),
        CoreAddressKey(c, shareDomain + 3u),
        CoreAddressKey(c, shareDomain + 6u)};
    if (strategy != 0u) std::rotate(shares.begin(), shares.begin() + 2u, shares.end());
    const uint32_t displacement = 0u - (shares[0] + shares[1] + shares[2]);
    const uint8_t address = c.registerAssignment[0];
    const uint8_t value = c.registerAssignment[1];
    const uint8_t temporary = c.registerAssignment[2];
    // Three independently-derived shares all participate in the only guest
    // effective address.  LEA is flag-neutral and the final memory
    // displacement subtracts the complete share sum, so the sole faulting
    // load/store still observes exactly the original guest address in RAX.
    EmitZydisLea(c, true, address, 0u,
        static_cast<int32_t>(shares[0]));
    EmitZydisLea(c, true, temporary, address,
        static_cast<int32_t>(shares[1]));
    EmitZydisLea(c, true, address, temporary,
        static_cast<int32_t>(shares[2]));
    X64DispatchWidth(c, 0, width);
    const auto emit = [&](CodeBuffer::Label label, uint8_t bytes) {
        c.Bind(label);
        if (strategy == 0u) {
            if (!store) EmitZydisLoad(c, true, 0u, address,
                static_cast<int32_t>(displacement), bytes);
            else EmitZydisStore(c, true, address,
                static_cast<int32_t>(displacement), 2u, bytes);
        } else if (!store) {
            EmitZydisLoad(c, true, value, address,
                static_cast<int32_t>(displacement), bytes);
            if (value != 0u) EmitZydisMove(c, true, 0u, value);
        } else {
            EmitZydisMove(c, true, value, 2u);
            EmitZydisStore(c, true, address,
                static_cast<int32_t>(displacement), value, bytes);
        }
        c.Jmp(done);
    };
    emit(width.width1, 1u); emit(width.width2, 2u);
    emit(width.width4, 4u); emit(width.width8, 8u);
    c.Bind(width.invalid); c.Raw({0x0F,0x0B});
    c.Bind(done);
}

void EmitX86MemoryVariant(CodeBuffer& c, bool store, uint8_t strategy) {
    const WidthLabels width = MakeWidthLabels(c);
    const auto done = c.NewLabel();
    const size_t shareDomain = (store ? 1u : 0u) + strategy * 2u;
    std::array<uint32_t, 3> shares = {
        CoreAddressKey(c, shareDomain),
        CoreAddressKey(c, shareDomain + 3u),
        CoreAddressKey(c, shareDomain + 6u)};
    if (strategy != 0u) std::rotate(shares.begin(), shares.begin() + 1u, shares.end());
    const uint32_t displacement = 0u - (shares[0] + shares[1] + shares[2]);
    const uint8_t address = c.registerAssignment[0];
    const uint8_t value = c.registerAssignment[1];
    const uint8_t temporary = c.registerAssignment[2];
    EmitZydisLea(c, false, address, 0u,
        static_cast<int32_t>(shares[0]));
    EmitZydisLea(c, false, temporary, address,
        static_cast<int32_t>(shares[1]));
    EmitZydisLea(c, false, address, temporary,
        static_cast<int32_t>(shares[2]));
    X86DispatchWidth(c, 0, width);
    const auto emit = [&](CodeBuffer::Label label, uint8_t bytes) {
        c.Bind(label);
        if (strategy == 0u) {
            if (!store) EmitZydisLoad(c, false, 0u, address,
                static_cast<int32_t>(displacement), bytes);
            else EmitZydisStore(c, false, address,
                static_cast<int32_t>(displacement), 2u, bytes);
        } else if (!store) {
            EmitZydisLoad(c, false, value, address,
                static_cast<int32_t>(displacement), bytes);
            EmitZydisMove(c, false, 0u, value);
        } else {
            EmitZydisMove(c, false, value, 2u);
            EmitZydisStore(c, false, address,
                static_cast<int32_t>(displacement), value, bytes);
        }
        c.Jmp(done);
    };
    emit(width.width1, 1u); emit(width.width2, 2u); emit(width.width4, 4u);
    c.Bind(width.invalid); c.Raw({0x0F,0x0B});
    c.Bind(done);
}

void EmitX64CallTargetVariant(CodeBuffer& c, uint8_t strategy) {
    const auto nativeRva = c.NewLabel();
    const auto importSlot = c.NewLabel();
    const auto indirect = c.NewLabel();
    const auto done = c.NewLabel();
    X64LoadD(c, 1, CtxDecodedOperands);
    c.Raw({0x83,0xF9,VM_MICRO_CALL_NATIVE_RVA}); c.Jcc(JccE, nativeRva);
    c.Raw({0x83,0xF9,VM_MICRO_CALL_IMPORT_SLOT}); c.Jcc(JccE, importSlot);
    c.Raw({0x83,0xF9,VM_MICRO_CALL_INDIRECT}); c.Jcc(JccE, indirect);
    c.Raw({0x0F,0x0B});
    c.Bind(nativeRva);
    X64LoadQ(c, 2, CtxImageBase);
    if (strategy == 0u) X64BinaryRegister(c, 0x01, 0, 2);
    else c.Raw({0x48,0x8D,0x04,0x10});
    c.Jmp(done);
    c.Bind(importSlot);
    X64LoadQ(c, 2, CtxImageBase);
    if (strategy == 0u) X64BinaryRegister(c, 0x01, 0, 2);
    else c.Raw({0x48,0x8D,0x04,0x10});
    c.Raw({0x48,0x8B,0x00});
    c.Jmp(done);
    c.Bind(indirect);
    if (strategy == 0u) X64MovRegister(c, 0, 0);
    else c.Raw({0x48,0x8D,0x40,0x00});
    c.Bind(done);
}

void EmitX86CallTargetVariant(CodeBuffer& c, uint8_t strategy) {
    const auto nativeRva = c.NewLabel();
    const auto importSlot = c.NewLabel();
    const auto indirect = c.NewLabel();
    const auto done = c.NewLabel();
    X86LoadD(c, 1, CtxDecodedOperands);
    c.Raw({0x83,0xF9,VM_MICRO_CALL_NATIVE_RVA}); c.Jcc(JccE, nativeRva);
    c.Raw({0x83,0xF9,VM_MICRO_CALL_IMPORT_SLOT}); c.Jcc(JccE, importSlot);
    c.Raw({0x83,0xF9,VM_MICRO_CALL_INDIRECT}); c.Jcc(JccE, indirect);
    c.Raw({0x0F,0x0B});
    c.Bind(nativeRva);
    X86LoadD(c, 2, CtxImageBase);
    if (strategy == 0u) c.Raw({0x01,0xD0});
    else c.Raw({0x8D,0x04,0x10});
    c.Jmp(done);
    c.Bind(importSlot);
    X86LoadD(c, 2, CtxImageBase);
    if (strategy == 0u) c.Raw({0x01,0xD0});
    else c.Raw({0x8D,0x04,0x10});
    c.Raw({0x8B,0x00});
    c.Jmp(done);
    c.Bind(indirect);
    if (strategy == 0u) X86MovRegister(c, 0, 0);
    else c.Raw({0x8D,0x40,0x00});
    c.Bind(done);
}

struct ZydisAluRegisterPlan {
    uint8_t value = 0;
    uint8_t source = 2;
    uint8_t scratch = 8;
};

ZydisAluRegisterPlan PrepareZydisAluRegisters(
    CodeBuffer& c, bool x64, bool needsScratch)
{
    const ZydisAluRegisterPlan plan = {
        c.registerAssignment[0],
        c.registerAssignment[1],
        c.registerAssignment[2]};
    if (plan.value == 0u && plan.source == 2u) {
        if (needsScratch) EmitZydisMove(c, x64, plan.scratch, 2u);
        return plan;
    }

    if (x64) {
        // First duplicate the original RDX input into both otherwise-free
        // registers. Exchanging RAX with the selected value register then
        // leaves every non-value register holding the original source.
        EmitZydisMove(c, true, 8u, 2u);
        EmitZydisMove(c, true, 11u, 2u);
    } else {
        EmitZydisMove(c, false, 1u, 2u);
    }
    EmitZydisExchange(c, x64, 0u, plan.value);
    return plan;
}

void FinishZydisAluRegisters(
    CodeBuffer& c, bool x64, const ZydisAluRegisterPlan& plan)
{
    if (plan.value != 0u) EmitZydisMove(c, x64, 0u, plan.value);
}

void EmitKeyedAddSubCore(
    CodeBuffer& c, bool x64, bool subtract, uint8_t strategy)
{
    const uint32_t k0 = CoreKey32(c, strategy + 0u);
    const uint32_t k1 = CoreKey32(c, strategy + 3u);
    const uint32_t k2 = CoreKey32(c, strategy + 5u);
    if (x64) {
        X64BinaryImmediate32(c, 0u, 0u, k0);
        X64BinaryImmediate32(c, 5u, 0u, k1);
        X64BinaryImmediate32(c, 0u, 0u, k2);
        if (!subtract) {
            if (strategy == 0u) X64BinaryRegister(c, 0x01, 0, 2);
            else c.Raw({0x48,0x8D,0x04,0x10});
        } else if (strategy == 0u) {
            X64BinaryRegister(c, 0x29, 0, 2);
        } else {
            c.Raw({0x48,0xF7,0xDA});
            X64BinaryRegister(c, 0x01, 0, 2);
        }
        X64BinaryImmediate32(c, 5u, 0u, k2);
        X64BinaryImmediate32(c, 0u, 0u, k1);
        X64BinaryImmediate32(c, 5u, 0u, k0);
    } else {
        X86BinaryImmediate32(c, 0u, 0u, k0);
        X86BinaryImmediate32(c, 5u, 0u, k1);
        X86BinaryImmediate32(c, 0u, 0u, k2);
        if (!subtract) {
            if (strategy == 0u) c.Raw({0x01,0xD0});
            else c.Raw({0x8D,0x04,0x10});
        } else if (strategy == 0u) {
            c.Raw({0x29,0xD0});
        } else {
            c.Raw({0xF7,0xDA,0x01,0xD0});
        }
        X86BinaryImmediate32(c, 5u, 0u, k2);
        X86BinaryImmediate32(c, 0u, 0u, k1);
        X86BinaryImmediate32(c, 5u, 0u, k0);
    }
}

void EmitZydisKeyedAddSubCore(
    CodeBuffer& c, bool x64, bool subtract, uint8_t strategy)
{
    const uint32_t k0 = CoreKey32(c, strategy + 0u);
    const uint32_t k1 = CoreKey32(c, strategy + 3u);
    const uint32_t k2 = CoreKey32(c, strategy + 5u);
    const ZydisAluRegisterPlan registers =
        PrepareZydisAluRegisters(c, x64, false);
    EmitZydisBinaryImmediate(
        c, x64, ZYDIS_MNEMONIC_ADD, registers.value, k0);
    EmitZydisBinaryImmediate(
        c, x64, ZYDIS_MNEMONIC_SUB, registers.value, k1);
    EmitZydisBinaryImmediate(
        c, x64, ZYDIS_MNEMONIC_ADD, registers.value, k2);
    if (!subtract) {
        if (strategy == 0u) {
            EmitZydisBinary(c, x64, ZYDIS_MNEMONIC_ADD,
                registers.value, registers.source);
        } else {
            EmitZydisLea(c, x64, registers.value, registers.value, 0,
                registers.source);
        }
    } else if (strategy == 0u) {
        EmitZydisBinary(c, x64, ZYDIS_MNEMONIC_SUB,
            registers.value, registers.source);
    } else {
        EmitZydisUnary(c, x64, ZYDIS_MNEMONIC_NEG, registers.source);
        EmitZydisBinary(c, x64, ZYDIS_MNEMONIC_ADD,
            registers.value, registers.source);
    }
    EmitZydisBinaryImmediate(
        c, x64, ZYDIS_MNEMONIC_SUB, registers.value, k2);
    EmitZydisBinaryImmediate(
        c, x64, ZYDIS_MNEMONIC_ADD, registers.value, k1);
    EmitZydisBinaryImmediate(
        c, x64, ZYDIS_MNEMONIC_SUB, registers.value, k0);
    FinishZydisAluRegisters(c, x64, registers);
}

void EmitKeyedXorCore(CodeBuffer& c, bool x64, uint8_t strategy) {
    const std::array<uint32_t, 3> keys = {
        CoreKey32(c, strategy + 1u), CoreKey32(c, strategy + 4u),
        CoreKey32(c, strategy + 6u)};
    const ZydisAluRegisterPlan registers =
        PrepareZydisAluRegisters(c, x64, false);
    for (uint32_t key : keys) {
        EmitZydisBinaryImmediate(
            c, x64, ZYDIS_MNEMONIC_XOR, registers.value, key);
    }
    EmitZydisBinary(c, x64, ZYDIS_MNEMONIC_XOR,
        registers.value, registers.source);
    for (auto it = keys.rbegin(); it != keys.rend(); ++it) {
        EmitZydisBinaryImmediate(
            c, x64, ZYDIS_MNEMONIC_XOR, registers.value, *it);
    }
    FinishZydisAluRegisters(c, x64, registers);
}

void EmitKeyedCopyCore(CodeBuffer& c, bool x64, uint8_t strategy) {
    const std::array<uint32_t, 3> keys = {
        CoreKey32(c, strategy + 0u), CoreKey32(c, strategy + 2u),
        CoreKey32(c, strategy + 7u)};
    if (x64) {
        for (uint32_t key : keys) X64BinaryImmediate32(c, 6u, 0u, key);
        if (strategy == 0u) X64MovRegister(c, 2, 0);
        else c.Raw({0x48,0x8D,0x10});
        for (auto it = keys.rbegin(); it != keys.rend(); ++it) {
            X64BinaryImmediate32(c, 6u, 0u, *it);
            X64BinaryImmediate32(c, 6u, 2u, *it);
        }
    } else {
        for (uint32_t key : keys) X86BinaryImmediate32(c, 6u, 0u, key);
        if (strategy == 0u) c.Raw({0x89,0xC2});
        else c.Raw({0x8D,0x10});
        for (auto it = keys.rbegin(); it != keys.rend(); ++it) {
            X86BinaryImmediate32(c, 6u, 0u, *it);
            X86BinaryImmediate32(c, 6u, 2u, *it);
        }
    }
}

void EmitKeyedContextCopy(
    CodeBuffer& c,
    bool x64,
    uint32_t sourceOffset,
    uint32_t destinationOffset,
    bool nativeWidth,
    size_t keyIndex)
{
    const uint32_t sourceKey = CoreAddressKey(c, keyIndex);
    const uint32_t destinationKey = CoreAddressKey(c, keyIndex + 3u);
    if (x64) {
        c.Raw({0x4D,0x8D,0x97}); c.U32(sourceOffset + sourceKey);
        if (nativeWidth) c.Raw({0x49,0x8B,0x82});
        else c.Raw({0x41,0x8B,0x82});
        c.U32(0u - sourceKey);
        c.Raw({0x4D,0x8D,0x97}); c.U32(destinationOffset + destinationKey);
        if (nativeWidth) c.Raw({0x49,0x89,0x82});
        else c.Raw({0x41,0x89,0x82});
        c.U32(0u - destinationKey);
    } else {
        c.Raw({0x8D,0x97}); c.U32(sourceOffset + sourceKey);
        c.Raw({0x8B,0x82}); c.U32(0u - sourceKey);
        c.Raw({0x8D,0x97}); c.U32(destinationOffset + destinationKey);
        c.Raw({0x89,0x82}); c.U32(0u - destinationKey);
    }
}

void EmitKeyedPushIpCore(CodeBuffer& c, bool x64, uint8_t strategy) {
    const uint32_t key = CoreKey32(c, strategy + 2u);
    if (x64) {
        X64BinaryImmediate32(c, 0u, 0u, key);
        if (strategy == 0u) X64BinaryRegister(c, 0x29, 0, 2);
        else {
            X64UnaryGroup(c, 3u, 2u);
            X64BinaryRegister(c, 0x01, 0, 2);
        }
        X64BinaryImmediate32(c, 5u, 0u, key);
    } else {
        X86BinaryImmediate32(c, 0u, 0u, key);
        if (strategy == 0u) c.Raw({0x29,0xD0});
        else c.Raw({0xF7,0xDA,0x01,0xD0});
        X86BinaryImmediate32(c, 5u, 0u, key);
    }
}

void EmitKeyedSwapCore(CodeBuffer& c, bool x64, uint8_t strategy) {
    const uint32_t key = CoreKey32(c, strategy + 4u);
    if (x64) {
        X64BinaryImmediate32(c, 6u, 0u, key);
        X64BinaryImmediate32(c, 6u, 2u, key);
        if (strategy == 0u) c.Raw({0x48,0x92});
        else c.Raw({0x48,0x31,0xD0,0x48,0x31,0xC2,0x48,0x31,0xD0});
        X64BinaryImmediate32(c, 6u, 0u, key);
        X64BinaryImmediate32(c, 6u, 2u, key);
    } else {
        X86BinaryImmediate32(c, 6u, 0u, key);
        X86BinaryImmediate32(c, 6u, 2u, key);
        if (strategy == 0u) c.U8(0x92);
        else c.Raw({0x31,0xD0,0x31,0xC2,0x31,0xD0});
        X86BinaryImmediate32(c, 6u, 0u, key);
        X86BinaryImmediate32(c, 6u, 2u, key);
    }
}

void EmitKeyedRotateStackCore(CodeBuffer& c, bool x64, uint8_t strategy) {
    const uint32_t key = CoreKey32(c, strategy + 6u);
    if (x64) {
        X64BinaryImmediate32(c, 6u, 0u, key);
        X64BinaryImmediate32(c, 6u, 2u, key);
        X64BinaryImmediate32(c, 6u, 8u, key);
        if (strategy == 0u) {
            X64MovRegister(c, 10u, 0u); X64MovRegister(c, 0u, 2u);
            X64MovRegister(c, 2u, 8u); X64MovRegister(c, 8u, 10u);
        } else c.Raw({0x48,0x92,0x49,0x87,0xD0});
        X64BinaryImmediate32(c, 6u, 0u, key);
        X64BinaryImmediate32(c, 6u, 2u, key);
        X64BinaryImmediate32(c, 6u, 8u, key);
    } else {
        X86BinaryImmediate32(c, 6u, 0u, key);
        X86BinaryImmediate32(c, 6u, 2u, key);
        X86BinaryImmediate32(c, 6u, 1u, key);
        if (strategy == 0u) c.Raw({0x89,0xC3,0x89,0xD0,0x89,0xCA});
        else c.Raw({0x92,0x87,0xCA,0x89,0xCB});
        X86BinaryImmediate32(c, 6u, 0u, key);
        X86BinaryImmediate32(c, 6u, 2u, key);
        X86BinaryImmediate32(c, 6u, 3u, key);
    }
}

void EmitKeyedCarryCore(
    CodeBuffer& c, bool x64, bool subtract, uint8_t strategy)
{
    const uint32_t key = CoreKey32(c, strategy + 1u);
    if (x64) {
        X64BinaryImmediate32(c, 0u, 0u, key);
        if (!subtract) {
            if (strategy == 0u) {
                X64BinaryRegister(c, 0x01, 0u, 2u);
                X64BinaryRegister(c, 0x01, 0u, 8u);
            } else {
                X64BinaryRegister(c, 0x01, 0u, 8u);
                X64BinaryRegister(c, 0x01, 0u, 2u);
            }
        } else if (strategy == 0u) {
            X64BinaryRegister(c, 0x29, 0u, 2u);
            X64BinaryRegister(c, 0x29, 0u, 8u);
        } else {
            X64BinaryRegister(c, 0x01, 2u, 8u);
            X64BinaryRegister(c, 0x29, 0u, 2u);
        }
        X64BinaryImmediate32(c, 5u, 0u, key);
    } else {
        X86BinaryImmediate32(c, 0u, 0u, key);
        if (!subtract) {
            if (strategy == 0u) c.Raw({0x01,0xD0,0x01,0xC8});
            else c.Raw({0x01,0xC8,0x01,0xD0});
        } else if (strategy == 0u) c.Raw({0x29,0xD0,0x29,0xC8});
        else c.Raw({0x01,0xCA,0x29,0xD0});
        X86BinaryImmediate32(c, 5u, 0u, key);
    }
}

void EmitKeyedBitwiseCore(
    CodeBuffer& c, bool x64, bool bitwiseOr, uint8_t strategy)
{
    const uint32_t key = CoreKey32(c, strategy + 3u);
    const ZydisAluRegisterPlan registers =
        PrepareZydisAluRegisters(c, x64, true);
    if (bitwiseOr) {
        EmitZydisUnary(
            c, x64, ZYDIS_MNEMONIC_NOT, registers.scratch);
    }
    EmitZydisBinaryImmediate(c, x64, ZYDIS_MNEMONIC_AND,
        registers.scratch, key);
    EmitZydisBinaryImmediate(c, x64, ZYDIS_MNEMONIC_XOR,
        registers.value, key);
    if (strategy == 0u) {
        EmitZydisBinary(c, x64,
            bitwiseOr ? ZYDIS_MNEMONIC_OR : ZYDIS_MNEMONIC_AND,
            registers.value, registers.source);
    } else {
        EmitZydisUnary(c, x64, ZYDIS_MNEMONIC_NOT, registers.value);
        EmitZydisUnary(c, x64, ZYDIS_MNEMONIC_NOT, registers.source);
        EmitZydisBinary(c, x64,
            bitwiseOr ? ZYDIS_MNEMONIC_AND : ZYDIS_MNEMONIC_OR,
            registers.value, registers.source);
        EmitZydisUnary(c, x64, ZYDIS_MNEMONIC_NOT, registers.value);
    }
    EmitZydisBinary(c, x64, ZYDIS_MNEMONIC_XOR,
        registers.value, registers.scratch);
    FinishZydisAluRegisters(c, x64, registers);
}

void EmitKeyedUnaryCore(
    CodeBuffer& c, bool x64, bool negate, uint8_t strategy)
{
    const uint32_t key = CoreKey32(c, strategy + 5u);
    const uint8_t value = c.registerAssignment[0];
    if (value != 0u) EmitZydisMove(c, x64, value, 0u);
    EmitZydisBinaryImmediate(c, x64,
        negate ? ZYDIS_MNEMONIC_ADD : ZYDIS_MNEMONIC_XOR, value, key);
    if (negate) {
        if (strategy == 0u) {
            EmitZydisUnary(c, x64, ZYDIS_MNEMONIC_NEG, value);
        } else {
            EmitZydisUnary(c, x64, ZYDIS_MNEMONIC_NOT, value);
            EmitZydisUnary(c, x64, ZYDIS_MNEMONIC_INC, value);
        }
        EmitZydisBinaryImmediate(
            c, x64, ZYDIS_MNEMONIC_ADD, value, key);
    } else {
        if (strategy == 0u) {
            EmitZydisUnary(c, x64, ZYDIS_MNEMONIC_NOT, value);
        } else if (x64) {
            EmitZydisBinary(c, true, ZYDIS_MNEMONIC_XOR, value, 9u);
        } else {
            EmitZydisInstruction(c, false, ZYDIS_MNEMONIC_XOR,
                {ZydisGprOperand(false, value),
                 ZydisMemoryOperand(false, 7u,
                     static_cast<int32_t>(CtxMutationScratch), 4u)});
        }
        EmitZydisBinaryImmediate(
            c, x64, ZYDIS_MNEMONIC_XOR, value, key);
    }
    if (value != 0u) EmitZydisMove(c, x64, 0u, value);
}

void EmitKeyedMultiplyCore(CodeBuffer& c, bool x64, uint8_t strategy) {
    const uint32_t key = CoreKey32(c, strategy + 7u);
    const uint8_t context = x64 ? 15u : 7u;
    const uint8_t nativeBytes = x64 ? 8u : 4u;
    if (strategy == 0u) {
        const uint8_t value = c.registerAssignment[0];
        const uint8_t source = c.registerAssignment[1];
        const uint8_t correction = c.registerAssignment[2];
        // The original operands were persisted before entering this core.
        // Reload only when a seed-selected role is not already in its legacy
        // boundary register; this preserves the fixed RAX/RDX byte baseline.
        if (value != 0u) {
            EmitZydisLoad(c, x64, value, context,
                static_cast<int32_t>(RECORD_OFFSET(CtxLastAlu, a)),
                nativeBytes);
        }
        if (source != 2u) {
            EmitZydisLoad(c, x64, source, context,
                static_cast<int32_t>(RECORD_OFFSET(CtxLastAlu, b)),
                nativeBytes);
        }
        EmitZydisMoveImmediate(c, x64, correction, key);
        EmitZydisBinary(c, x64, ZYDIS_MNEMONIC_IMUL,
            correction, source);
        EmitZydisBinaryImmediate(
            c, x64, ZYDIS_MNEMONIC_ADD, value, key);
        EmitZydisBinary(c, x64, ZYDIS_MNEMONIC_IMUL, value, source);
        EmitZydisBinary(c, x64, ZYDIS_MNEMONIC_SUB,
            value, correction);
        if (value != 0u) EmitZydisMove(c, x64, 0u, value);
        return;
    }

    // One-operand MUL retains its architectural RDX:RAX/EDX:EAX pair.  Only
    // the visible multiplier and a correction register that survives MUL are
    // seed-selected.  The contract guarantees neither aliases the other and
    // the correction register never aliases the implicit pair.
    const uint8_t source = c.registerAssignment[0];
    const uint8_t correction = c.registerAssignment[1];
    if (source != 2u) {
        EmitZydisLoad(c, x64, source, context,
            static_cast<int32_t>(RECORD_OFFSET(CtxLastAlu, b)), nativeBytes);
    }
    EmitZydisMoveImmediate(c, x64, correction, key);
    EmitZydisBinary(c, x64, ZYDIS_MNEMONIC_IMUL, correction, source);
    EmitZydisBinaryImmediate(c, x64, ZYDIS_MNEMONIC_ADD, 0u, key);
    EmitZydisUnary(c, x64, ZYDIS_MNEMONIC_MUL, source);
    EmitZydisBinary(c, x64, ZYDIS_MNEMONIC_SUB, 0u, correction);
}

void EmitKeyedLogicalShiftCore(
    CodeBuffer& c, bool x64, bool shiftRight, uint8_t strategy)
{
    const auto deriveShare = [&](size_t share) {
        const auto& round = c.coreSelector.rounds[
            (share * 2u + strategy) % c.coreSelector.roundCount];
        const uint64_t domain = 0x5348494654534852ULL ^
            (static_cast<uint64_t>(shiftRight) << 63u) ^
            (static_cast<uint64_t>(strategy) << 55u) ^
            (0x9E3779B97F4A7C15ULL * static_cast<uint64_t>(share + 1u)) ^
            (static_cast<uint64_t>(round.rotate) << 48u) ^
            (static_cast<uint64_t>(round.encoding) << 40u);
        uint64_t key = MixContextLoadDomain(round.key ^ domain);
        if (shiftRight) key |= uint64_t{1} << 63u;
        else key |= uint64_t{1};
        return key;
    };
    std::array<size_t, 4> shareOrder = {{0u, 1u, 2u, 3u}};
    if (strategy != 0u) std::reverse(shareOrder.begin(), shareOrder.end());

    if (x64) {
        // See DeriveShiftCoreScratchRegisters (used by the SAR/ROL/ROR core
        // right below): same pool, same exclusions (0/1/2/4/7/9 stay live
        // across the whole EmitX64BinaryAlu-latched core body), same reason
        // -- register choice, not the already-keyed immediates, is what
        // moves this core's 4-gram content once value_codec strips the
        // immediates back out.
        const auto scratch = DeriveShiftCoreScratchRegisters(
            c, shiftRight ? VM_UOP_SHR : VM_UOP_SHL, strategy);
        const uint8_t scratchA = scratch.first;
        const uint8_t scratchB = scratch.second;
        std::array<uint64_t, 4> keys{};
        for (size_t share = 0u; share < keys.size(); ++share) {
            keys[share] = deriveShare(share);
        }
        for (const size_t share : shareOrder) {
            X64MovImmediate(c, scratchA, keys[share]);
            X64BinaryRegister(c, 0x31u, 0u, scratchA);
        }
        c.Raw({0x48,0x89,0xD1});
        // scratchB <- r9 (the width mask X64MaskForWidthInR11 already
        // computed and left live in r9 for this whole core, same as
        // EmitX64ShiftRotateVariant's sibling core above): all-ones only
        // for width 8, so (sar 63)&32 is 32 only there, and |31 turns that
        // into the exact 5-bit/6-bit shift-count mask this build needs.
        X64MovRegister(c, scratchB, 9u);
        X64ShiftImmediate(c, 7u, scratchB, 0x3F);
        {
            const uint8_t rex = static_cast<uint8_t>(
                0x48u | ((scratchB & 8u) ? 1u : 0u));
            c.Raw({rex, 0x83, static_cast<uint8_t>(
                0xE0u | (scratchB & 7u)), 0x20});
        }
        {
            const uint8_t rex = static_cast<uint8_t>(
                0x48u | ((scratchB & 8u) ? 1u : 0u));
            c.Raw({rex, 0x83, static_cast<uint8_t>(
                0xC8u | (scratchB & 7u)), 0x1F});
        }
        {
            const uint8_t rex = static_cast<uint8_t>(
                0x40u | ((scratchB & 8u) ? 0x04u : 0u));
            c.Raw({rex, 0x20, static_cast<uint8_t>(
                0xC1u | ((scratchB & 7u) << 3u))});
        }

        const auto shiftShares = [&] {
            X64MovImmediate(c, scratchA, keys[shareOrder[0u]]);
            X64ShiftCl(c, shiftRight ? 5u : 4u, scratchA);
            for (size_t position = 1u;
                 position < shareOrder.size(); ++position) {
                X64MovImmediate(c, scratchB, keys[shareOrder[position]]);
                X64ShiftCl(c, shiftRight ? 5u : 4u, scratchB);
                X64BinaryRegister(c, 0x31u, scratchA, scratchB);
            }
        };
        if (strategy == 0u) {
            X64ShiftCl(c, shiftRight ? 5u : 4u, 0u);
            shiftShares();
        } else {
            shiftShares();
            X64ShiftCl(c, shiftRight ? 5u : 4u, 0u);
        }
        X64BinaryRegister(c, 0x31u, 0u, scratchA);
    } else {
        std::array<uint32_t, 4> keys{};
        for (size_t share = 0u; share < keys.size(); ++share) {
            const uint64_t mixed = deriveShare(share);
            uint32_t key = static_cast<uint32_t>(mixed ^ (mixed >> 32u));
            if (shiftRight) key |= uint32_t{1} << 31u;
            else key |= uint32_t{1};
            keys[share] = key;
        }
        for (const size_t share : shareOrder) {
            X86MovImmediate(c, 3u, keys[share]);
            X86BinaryRegister(c, 0x31u, 0u, 3u);
        }
        c.Raw({0x88,0xD1,0x80,0xE1,0x1F});

        const auto shiftRegister = [&](uint8_t reg) {
            c.Raw({0xD3, static_cast<uint8_t>(0xC0u |
                ((shiftRight ? 5u : 4u) << 3u) | (reg & 7u))});
        };
        const auto shiftShares = [&] {
            X86MovImmediate(c, 3u, keys[shareOrder[0u]]);
            shiftRegister(3u);
            for (size_t position = 1u;
                 position < shareOrder.size(); ++position) {
                X86MovImmediate(c, 2u, keys[shareOrder[position]]);
                shiftRegister(2u);
                X86BinaryRegister(c, 0x31u, 3u, 2u);
            }
        };
        if (strategy == 0u) {
            shiftRegister(0u);
            shiftShares();
        } else {
            shiftShares();
            shiftRegister(0u);
        }
        X86BinaryRegister(c, 0x31u, 0u, 3u);
    }
}

void EmitKeyedFlagsWriteCore(CodeBuffer& c, bool x64, uint8_t strategy) {
    const uint32_t key = CoreKey32(c, strategy + 2u);
    if (x64) {
        X64BinaryImmediate32(c, 6u, 0u, key);
        X64BinaryImmediate32(c, 6u, 2u, key);
        if (strategy == 0u) {
            X64MovRegister(c, 11u, 1u); X64UnaryGroup(c, 2u, 11u);
            X64BinaryRegister(c, 0x21u, 0u, 11u);
            X64BinaryRegister(c, 0x21u, 2u, 1u);
            X64BinaryRegister(c, 0x09u, 0u, 2u);
        } else {
            X64BinaryRegister(c, 0x31u, 2u, 0u);
            X64BinaryRegister(c, 0x21u, 2u, 1u);
            X64BinaryRegister(c, 0x31u, 0u, 2u);
        }
        X64BinaryImmediate32(c, 6u, 0u, key);
    } else {
        X86BinaryImmediate32(c, 6u, 0u, key);
        X86BinaryImmediate32(c, 6u, 2u, key);
        if (strategy == 0u) c.Raw({0x89,0xCB,0xF7,0xD3,0x21,0xD8,
                                   0x21,0xCA,0x09,0xD0});
        else c.Raw({0x31,0xC2,0x21,0xCA,0x31,0xD0});
        X86BinaryImmediate32(c, 6u, 0u, key);
    }
}

void EmitKeyedSelectCore(CodeBuffer& c, bool x64, uint8_t strategy) {
    const uint32_t key = CoreKey32(c, strategy + 4u);
    if (x64) {
        X64BinaryImmediate32(c, 6u, 0u, key);
        X64BinaryImmediate32(c, 6u, 2u, key);
        if (strategy == 0u) c.Raw({0x45,0x85,0xD2,0x48,0x0F,0x45,0xC2});
        else {
            X64MovRegister(c, 11u, 10u); X64UnaryGroup(c, 3u, 11u);
            X64BinaryRegister(c, 0x31u, 2u, 0u);
            X64BinaryRegister(c, 0x21u, 2u, 11u);
            X64BinaryRegister(c, 0x31u, 0u, 2u);
        }
        X64BinaryImmediate32(c, 6u, 0u, key);
    } else {
        X86BinaryImmediate32(c, 6u, 0u, key);
        X86BinaryImmediate32(c, 6u, 2u, key);
        if (strategy == 0u) c.Raw({0x85,0xC9,0x0F,0x45,0xC2});
        else c.Raw({0x89,0xCB,0xF7,0xDB,0x31,0xC2,0x21,0xDA,0x31,0xD0});
        X86BinaryImmediate32(c, 6u, 0u, key);
    }
}

void EmitX64SeedAddressedWideOperation(
    CodeBuffer& c,
    uint8_t group,
    uint8_t strategy,
    size_t keyIndex)
{
    // The real multiplier/divisor is materialized in the execution-context
    // scratch slot and consumed directly by the hardware wide operation.  The
    // build seed splits that slot's effective address between LEA and the
    // memory operand displacement; neither half can be removed or changed
    // without changing the value consumed by IMUL/DIV/IDIV.  LEA and MOV do
    // not alter flags, while the one-operand F7 form retains the full
    // RDX:RAX result and native #DE behaviour.
    const uint32_t key = CoreAddressKey(c, keyIndex + strategy);
    const uint8_t address = strategy == 0u ? 10u : 11u;
    c.Raw({0x4D, 0x8D, static_cast<uint8_t>(
        0x80u | ((address & 7u) << 3u) | 7u)});
    c.U32(CtxMutationScratch + key);              // lea address,[r15+slot+key]
    c.Raw({0x4D, 0x89, static_cast<uint8_t>(
        0x80u | (1u << 3u) | (address & 7u))});
    c.U32(0u - key);                              // mov [address-key],r9
    c.Raw({0x49, 0xF7, static_cast<uint8_t>(
        0x80u | ((group & 7u) << 3u) | (address & 7u))});
    c.U32(0u - key);                              // F7 /group [address-key]
}

bool EmitBusinessCoreVariant(
    CodeBuffer& c,
    bool x64,
    VM_MICRO_OPCODE semantic,
    uint8_t strategy)
{
    strategy &= 1u;
    const auto coreOrder = [&](uint8_t count) {
        std::vector<uint8_t> order(count);
        for (uint8_t index = 0; index < count; ++index) order[index] = index;
        for (uint8_t index = static_cast<uint8_t>(count - 1u);
             index != 0u; --index) {
            const auto& round = c.coreSelector.rounds[
                (static_cast<size_t>(index) + strategy * 7u) %
                    c.coreSelector.roundCount];
            const uint8_t selected = static_cast<uint8_t>(
                (round.key ^ (static_cast<uint64_t>(round.rotate) << 32u) ^
                 (static_cast<uint64_t>(strategy) << 17u)) %
                (static_cast<uint32_t>(index) + 1u));
            std::swap(order[index], order[selected]);
        }
        return order;
    };
    if (x64) {
        switch (semantic) {
            case VM_UOP_PUSH_FLAGS: {
                const uint32_t k0 = CoreAddressKey(c, strategy + 1u);
                const uint32_t k1 = CoreAddressKey(c, strategy + 5u);
                c.Raw({0x4D,0x8D,0x97}); c.U32(CtxVirtualFlags + k0);
                if (strategy != 0u) X64BinaryImmediate32(c, 0u, 10u, k1);
                c.Raw({0x49,0x8B,0x82});
                c.U32(0u - k0 - (strategy != 0u ? k1 : 0u));
                return true;
            }
            case VM_UOP_PUSH_IP:
                EmitKeyedPushIpCore(c, true, strategy);
                return true;
            case VM_UOP_PUSH_IMAGE_BASE:
                {
                    const uint32_t k0 = CoreAddressKey(c, strategy + 0u);
                    const uint32_t k1 = CoreAddressKey(c, strategy + 3u);
                    const uint32_t k2 = CoreAddressKey(c, strategy + 6u);
                    const uint32_t k3 = CoreAddressKey(c, strategy + 7u);
                    c.Raw({0x4D,0x8D,0x97}); c.U32(CtxImageBase + k0);
                    X64BinaryImmediate32(c, 0u, 10u, k1);
                    X64BinaryImmediate32(c, 5u, 10u, k2);
                    X64BinaryImmediate32(c, 0u, 10u, k3);
                    c.Raw({0x49,0x8B,0x82});
                    c.U32(0u - (k0 + k1 - k2 + k3));
                }
                return true;
            case VM_UOP_PUSH_VREG:
                {
                    const std::array<uint32_t, 2> keys = {
                        CoreKey32(c, strategy + 1u),
                        CoreKey32(c, strategy + 5u)};
                    for (uint32_t key : keys)
                        X64BinaryImmediate32(c, 6u, 0u, key);
                    if (strategy == 0u) X64ShiftCl(c, 5, 0);
                    else c.Raw({0x45,0x31,0xD2,0x4C,0x0F,0xAD,0xD0});
                    for (auto it = keys.rbegin(); it != keys.rend(); ++it) {
                        X64MovImmediate(c, 10u, *it);
                        X64ShiftCl(c, 5u, 10u);
                        X64BinaryRegister(c, 0x31, 0u, 10u);
                    }
                }
                return true;
            case VM_UOP_PUSH_IMM:
                {
                    const std::array<uint32_t, 2> keys = {
                        CoreKey32(c, strategy + 2u),
                        CoreKey32(c, strategy + 7u)};
                    for (uint32_t key : keys)
                        X64BinaryImmediate32(c, 6u, 0u, key);
                    X64BinaryRegister(c, 0x21, 0, 9);
                    for (auto it = keys.rbegin(); it != keys.rend(); ++it) {
                        X64MovImmediate(c, 10u, *it);
                        X64BinaryRegister(c, 0x21, 10u, 9u);
                        X64BinaryRegister(c, 0x31, 0u, 10u);
                    }
                }
                return true;
            case VM_UOP_POP_VREG:
                if (strategy == 0u) EmitX64PopVregVariant(c, 0u);
                else EmitX64PopVregVariant(c, 1u);
                return true;
            case VM_UOP_LOAD_TEMP:
                {
                    const uint32_t k0 = CoreAddressKey(c, strategy + 0u);
                    const uint32_t k1 = CoreAddressKey(c, strategy + 4u);
                    const uint32_t k2 = CoreAddressKey(c, strategy + 6u);
                    const uint32_t k3 = CoreAddressKey(c, strategy + 7u);
                    c.Raw({0x4F,0x8D,0x9C,0xD7}); c.U32(CtxTemps + k0);
                    X64BinaryImmediate32(c, 0u, 11u, k1);
                    X64BinaryImmediate32(c, 5u, 11u, k2);
                    X64BinaryImmediate32(c, 0u, 11u, k3);
                    c.Raw({0x49,0x8B,0x83});
                    c.U32(0u - (k0 + k1 - k2 + k3));
                }
                return true;
            case VM_UOP_STORE_TEMP:
                {
                    const uint32_t k0 = CoreAddressKey(c, strategy + 0u);
                    const uint32_t k1 = CoreAddressKey(c, strategy + 4u);
                    const uint32_t k2 = CoreAddressKey(c, strategy + 6u);
                    const uint32_t k3 = CoreAddressKey(c, strategy + 7u);
                    c.Raw({0x4F,0x8D,0x9C,0xD7}); c.U32(CtxTemps + k0);
                    X64BinaryImmediate32(c, 0u, 11u, k1);
                    X64BinaryImmediate32(c, 5u, 11u, k2);
                    X64BinaryImmediate32(c, 0u, 11u, k3);
                    c.Raw({0x49,0x89,0x83});
                    c.U32(0u - (k0 + k1 - k2 + k3));
                }
                return true;
            case VM_UOP_DUP:
                EmitKeyedCopyCore(c, true, strategy);
                return true;
            case VM_UOP_SWAP:
                EmitKeyedSwapCore(c, true, strategy);
                return true;
            case VM_UOP_ROT:
                EmitKeyedRotateStackCore(c, true, strategy);
                return true;
            case VM_UOP_DROP:
                // DROP owns the now-unused value-stack slot. Scrubbing that
                // physical slot is part of the semantic state transition, so
                // both K variants are real equivalent memory lowerings.
                {
                    const uint32_t key = CoreAddressKey(c, strategy + 3u);
                    // r10 = &ctx.values[rcx] + key.  The SIB index is RCX,
                    // so REX.X must remain clear (0x4D, not 0x4F/r9).
                    c.Raw({0x4D,0x8D,0x94,0xCF}); c.U32(CtxValues + key);
                    if (strategy == 0u) {
                        c.Raw({0x31,0xC0,0x49,0x89,0x82});
                        c.U32(0u - key);
                    } else {
                        c.Raw({0x49,0xC7,0x82}); c.U32(0u - key); c.U32(0u);
                    }
                }
                return true;
            case VM_UOP_LOAD:
                if (strategy == 0u) EmitX64MemoryVariant(c, false, 0u);
                else EmitX64MemoryVariant(c, false, 1u);
                return true;
            case VM_UOP_STORE:
                if (strategy == 0u) EmitX64MemoryVariant(c, true, 0u);
                else EmitX64MemoryVariant(c, true, 1u);
                return true;
            case VM_UOP_ADD:
                EmitZydisKeyedAddSubCore(c, true, false, strategy);
                return true;
            case VM_UOP_ADD_CARRY:
                EmitKeyedCarryCore(c, true, false, strategy);
                return true;
            case VM_UOP_SUB:
                EmitZydisKeyedAddSubCore(c, true, true, strategy);
                return true;
            case VM_UOP_SUB_BORROW:
                EmitKeyedCarryCore(c, true, true, strategy);
                return true;
            case VM_UOP_AND:
                EmitKeyedBitwiseCore(c, true, false, strategy);
                return true;
            case VM_UOP_OR:
                EmitKeyedBitwiseCore(c, true, true, strategy);
                return true;
            case VM_UOP_XOR:
                EmitKeyedXorCore(c, true, strategy);
                return true;
            case VM_UOP_NOT:
                EmitKeyedUnaryCore(c, true, false, strategy);
                return true;
            case VM_UOP_NEG:
                EmitKeyedUnaryCore(c, true, true, strategy);
                return true;
            case VM_UOP_MUL:
                // strategy 0: IMUL rax, rdx (two-operand signed multiply).
                // strategy 1: MUL rdx (one-operand unsigned multiply into
                // rdx:rax). Signed and unsigned multiply produce identical
                // low-order-64-bit results modulo 2^64, so the truncated
                // product in rax is the same either way; only the high
                // half (discarded here) and flags differ.  This clobbers
                // rdx, which is safe because a/b were already latched into
                // r8/r11 before the core runs.
                EmitKeyedMultiplyCore(c, true, strategy);
                return true;
            case VM_UOP_BIT_TEST:
                // Common to both strategies: reduce the raw bit-index operand
                // (rdx) modulo the operand width in bits.
                X64LoadByte(c, 1, CtxDecodedOperands);
                c.Raw({0xC1,0xE1,0x03,0xFF,0xC9});
                X64BinaryRegister(c, 0x21, 2, 1);
                if (strategy == 0u) {
                    // strategy 0: manual shift-and-mask against the saved
                    // pre-core copy of a (r8).
                    X64MovRegister(c, 10, 8); X64MovRegister(c, 1, 2);
                    c.Raw({0x49,0xD3,0xEA});           // shr r10,cl
                    c.Raw({0x49,0x83,0xE2,0x01});
                    X64MovRegister(c, 0, 8);
                } else {
                    // strategy 1: native BT — CF *is* the tested bit by
                    // hardware definition; BT never modifies its r/m operand.
                    X64MovRegister(c, 0, 8);
                    c.Raw({0x48,0x0F,0xA3,0xD0});
                    c.Raw({0x41,0x0F,0x92,0xC2});
                }
                return true;
            case VM_UOP_BIT_SET:
                X64LoadByte(c, 1, CtxDecodedOperands);
                c.Raw({0xC1,0xE1,0x03,0xFF,0xC9});
                X64BinaryRegister(c, 0x21, 2, 1);
                if (strategy == 0u) {
                    X64MovRegister(c, 10, 8); X64MovRegister(c, 1, 2);
                    c.Raw({0x49,0xD3,0xEA});           // shr r10,cl
                    c.Raw({0x49,0x83,0xE2,0x01});
                    c.Raw({0xB8,0x01,0x00,0x00,0x00}); // mov eax,1
                    c.Raw({0x48,0xD3,0xE0});           // shl rax,cl
                    X64BinaryRegister(c, 0x09, 0, 8);
                } else {
                    // strategy 1: native BTS sets the bit and reports the old
                    // value in CF in the same instruction.
                    X64MovRegister(c, 0, 8);
                    c.Raw({0x48,0x0F,0xAB,0xD0});
                    c.Raw({0x41,0x0F,0x92,0xC2});
                }
                return true;
            case VM_UOP_BIT_RESET:
                X64LoadByte(c, 1, CtxDecodedOperands);
                c.Raw({0xC1,0xE1,0x03,0xFF,0xC9});
                X64BinaryRegister(c, 0x21, 2, 1);
                if (strategy == 0u) {
                    X64MovRegister(c, 10, 8); X64MovRegister(c, 1, 2);
                    c.Raw({0x49,0xD3,0xEA});           // shr r10,cl
                    c.Raw({0x49,0x83,0xE2,0x01});
                    c.Raw({0xB8,0x01,0x00,0x00,0x00}); // mov eax,1
                    c.Raw({0x48,0xD3,0xE0});           // shl rax,cl
                    c.Raw({0x48,0xF7,0xD0});           // not rax
                    X64BinaryRegister(c, 0x21, 0, 8);
                } else {
                    // strategy 1: native BTR resets the bit and reports the
                    // old value in CF in the same instruction.
                    X64MovRegister(c, 0, 8);
                    c.Raw({0x48,0x0F,0xB3,0xD0});
                    c.Raw({0x41,0x0F,0x92,0xC2});
                }
                return true;
            case VM_UOP_SHL: {
                EmitKeyedLogicalShiftCore(c, true, false, strategy);
                return true;
                // strategy 0: native SHL rax,cl.
                // strategy 1: SHLD rax, r10(=0), cl — a zero source makes shld
                //   pull zeroes into the top, so dst = dst<<cl ≡ SHL.  r10 is
                //   zeroed by the binary-ALU prologue (auxiliary=0) and shld
                //   leaves its source untouched, so auxiliary stays 0.
                //
                // x86 masks the shift count to 5 bits for 1/2/4-byte operands
                // and 6 bits for 8-byte.  The width mask r9 is all-ones ONLY for
                // width 8, so (sar r9,63) & 32 is 32 for width 8 and 0 otherwise;
                // OR 31 yields exactly the 5/6-bit count mask with no width
                // branch.  Pre-masking cl that way lets a single 64-bit
                // shl/shld cover every width (operand is zero-extended; the outer
                // `and rax,r9` trims to width).  This is label-free — every byte
                // is a fixed Raw — so the variant kernel validator's isolated
                // re-emission matches the inline bytes exactly.
            }
            case VM_UOP_SHR: {
                EmitKeyedLogicalShiftCore(c, true, true, strategy);
                return true;
                // Same count pre-mask as SHL.
                // strategy 0: native SHR rax,cl.
                // strategy 1: SHRD rax, r10(=0), cl pulls zeroes into the bottom
                //   so dst = dst>>cl ≡ SHR.
            }
            case VM_UOP_SAR:
                if (strategy == 0u) EmitX64ShiftRotateVariant(c, semantic, 0u);
                else EmitX64ShiftRotateVariant(c, semantic, 1u);
                return true;
            case VM_UOP_ROL:
                if (strategy == 0u) EmitX64ShiftRotateVariant(c, semantic, 0u);
                else EmitX64ShiftRotateVariant(c, semantic, 1u);
                return true;
            case VM_UOP_ROR:
                if (strategy == 0u) EmitX64ShiftRotateVariant(c, semantic, 0u);
                else EmitX64ShiftRotateVariant(c, semantic, 1u);
                return true;
            case VM_UOP_BSWAP:
                if (strategy == 0u) EmitX64ByteSwapVariant(c, 0u);
                else EmitX64ByteSwapVariant(c, 1u);
                return true;
            case VM_UOP_ZERO_EXTEND:
                if (strategy == 0u) EmitX64ExtendVariant(c, false, 0u);
                else EmitX64ExtendVariant(c, false, 1u);
                return true;
            case VM_UOP_SIGN_EXTEND:
                if (strategy == 0u) EmitX64ExtendVariant(c, true, 0u);
                else EmitX64ExtendVariant(c, true, 1u);
                return true;
            case VM_UOP_UMUL_WIDE:
                if (strategy == 0u) c.Raw({0x49,0xF7,0xE1});
                else c.Raw({0x4D,0x89,0xCA,0x49,0xF7,0xE2});
                return true;
            case VM_UOP_SMUL_WIDE:
                EmitX64SeedAddressedWideOperation(c, 5u, strategy, 2u);
                return true;
            case VM_UOP_UDIV_WIDE:
                EmitX64SeedAddressedWideOperation(c, 6u, strategy, 4u);
                return true;
            case VM_UOP_IDIV_WIDE:
                EmitX64SeedAddressedWideOperation(c, 7u, strategy, 6u);
                return true;
            case VM_UOP_FLAGS_LAZY:
                for (uint8_t field : coreOrder(6u)) {
                    const uint32_t offset = field < 5u
                        ? static_cast<uint32_t>(field) * 8u : 40u;
                    EmitKeyedContextCopy(c, true,
                        CtxLastAlu + offset, CtxPendingFlags + offset,
                        field < 5u, static_cast<size_t>(field) + strategy);
                }
                return true;
            case VM_UOP_FLAGS_MATERIALIZE:
                {
                    const uint32_t k0 = CoreAddressKey(c, strategy + 1u);
                    const uint32_t k1 = CoreAddressKey(c, strategy + 5u);
                    const uint32_t k2 = CoreAddressKey(c, strategy + 6u);
                    const uint32_t k3 = CoreAddressKey(c, strategy + 7u);
                    c.Raw({0x4D,0x8D,0x97}); c.U32(CtxDecodedOperands + k0);
                    X64BinaryImmediate32(c, 0u, 10u, k1);
                    X64BinaryImmediate32(c, 5u, 10u, k2);
                    X64BinaryImmediate32(c, 0u, 10u, k3);
                    c.Raw({0x49,0x8B,0x92});
                    c.U32(0u - (k0 + k1 - k2 + k3));
                }
                return true;
            case VM_UOP_FLAGS_WRITE:
                EmitKeyedFlagsWriteCore(c, true, strategy);
                return true;
            case VM_UOP_FLAGS_UPDATE: {
                const uint32_t modeKey = CoreAddressKey(c, strategy + 1u);
                const uint32_t dataKey = CoreKey32(c, strategy + 5u);
                const auto clear = c.NewLabel();
                const auto set = c.NewLabel();
                const auto done = c.NewLabel();

                // RCX is dead after the mode decision.  Compare an affine,
                // seed-keyed representation so the real clear/set/toggle
                // control edge depends on this build's core selector.
                c.Raw({0x48,0x8D,0x89}); c.U32(modeKey);
                c.Raw({0x48,0x81,0xF9});
                c.U32(modeKey + VM_FLAG_UPDATE_CLEAR); c.Jcc(JccE, clear);
                c.Raw({0x48,0x81,0xF9});
                c.U32(modeKey + VM_FLAG_UPDATE_SET); c.Jcc(JccE, set);

                // Toggle in a keyed representation.  Strategy 1 lowers the
                // actual XOR as (union - intersection), whose operands already
                // contain the seed key.
                X64BinaryImmediate32(c, 6u, 0u, dataKey);
                if (strategy == 0u) {
                    X64BinaryRegister(c, 0x31, 0, 2);
                } else {
                    X64MovRegister(c, 10, 0);
                    X64BinaryRegister(c, 0x21, 10, 2);
                    X64BinaryRegister(c, 0x09, 0, 2);
                    X64BinaryRegister(c, 0x29, 0, 10);
                }
                X64BinaryImmediate32(c, 6u, 0u, dataKey);
                c.Jmp(done);

                c.Bind(clear);
                // (a & ~mask) = ((a^K) & ~mask) ^ (K & ~mask).
                X64BinaryImmediate32(c, 6u, 0u, dataKey);
                if (strategy == 0u) {
                    X64MovRegister(c, 10, 2); X64UnaryGroup(c, 2u, 10u);
                    X64BinaryRegister(c, 0x21, 0, 10);
                } else {
                    X64UnaryGroup(c, 2u, 0u);
                    X64BinaryRegister(c, 0x09, 0, 2);
                    X64UnaryGroup(c, 2u, 0u);
                    X64MovRegister(c, 10, 2); X64UnaryGroup(c, 2u, 10u);
                }
                X64MovImmediate(c, 11, dataKey);
                X64BinaryRegister(c, 0x21, 11, 10);
                X64BinaryRegister(c, 0x31, 0, 11);
                c.Jmp(done);

                c.Bind(set);
                // (a | mask) = ((a^K) | mask) ^ (K & ~mask).
                X64BinaryImmediate32(c, 6u, 0u, dataKey);
                if (strategy == 0u) {
                    X64BinaryRegister(c, 0x09, 0, 2);
                    X64MovRegister(c, 10, 2); X64UnaryGroup(c, 2u, 10u);
                } else {
                    X64UnaryGroup(c, 2u, 0u);
                    X64MovRegister(c, 10, 2); X64UnaryGroup(c, 2u, 10u);
                    X64BinaryRegister(c, 0x21, 0, 10);
                    X64UnaryGroup(c, 2u, 0u);
                }
                X64MovImmediate(c, 11, dataKey);
                X64BinaryRegister(c, 0x21, 11, 10);
                X64BinaryRegister(c, 0x31, 0, 11);
                c.Bind(done);
                return true;
            }
            case VM_UOP_FLAGS_PACK_AH: {
                constexpr uint32_t packedMask = VM_FLAG_SF | VM_FLAG_ZF |
                    VM_FLAG_AF | VM_FLAG_PF | VM_FLAG_CF;
                const uint32_t rawKey = CoreKey32(c, strategy + 2u);
                uint32_t packedKey = CoreKey32(c, strategy + 6u) & packedMask;
                if (packedKey == 0u)
                    packedKey = 1u << ((rawKey % 5u == 0u) ? 0u :
                        (rawKey % 5u == 1u) ? 2u :
                        (rawKey % 5u == 2u) ? 4u :
                        (rawKey % 5u == 3u) ? 6u : 7u);
                const uint8_t rotation = static_cast<uint8_t>(1u + rawKey % 31u);
                const uint32_t rotatedMask = strategy == 0u
                    ? ((packedMask >> rotation) |
                        (packedMask << (32u - rotation)))
                    : ((packedMask << rotation) |
                        (packedMask >> (32u - rotation)));

                // Rotate an encoded flags value and its live mask together,
                // apply the real selection in that domain, then rotate/decode.
                c.Raw({0x89,0xD0});
                X86BinaryImmediate32(c, 6u, 0u, packedKey);
                c.Raw({0xC1, static_cast<uint8_t>(strategy == 0u ? 0xC8 : 0xC0),
                    rotation, 0x25});
                c.U32(rotatedMask);
                c.Raw({0xC1, static_cast<uint8_t>(strategy == 0u ? 0xC0 : 0xC8),
                    rotation});
                X86BinaryImmediate32(c, 6u, 0u, packedKey);
                c.Raw({0x83,0xC8,0x02});
                return true;
            }
            case VM_UOP_FLAGS_UNPACK_AH: {
                const uint32_t key = CoreKey32(c, strategy + 6u);
                // Both selectable values use the same seed representation;
                // masked selection therefore produces an encoded result that
                // is decoded only after the real flags transformation.
                X64BinaryImmediate32(c, 6u, 0u, key);
                X64BinaryImmediate32(c, 6u, 2u, key);
                if (strategy == 0u) {
                    c.Raw({0x48,0x81,0xE2});
                    c.U32(~static_cast<uint32_t>(
                        VM_FLAG_SF|VM_FLAG_ZF|VM_FLAG_AF|VM_FLAG_PF|VM_FLAG_CF));
                    c.Raw({0x25,0xD5,0x00,0x00,0x00});
                    X64BinaryRegister(c, 0x09, 2, 0);
                } else {
                    X64BinaryRegister(c, 0x31, 0, 2);
                    c.Raw({0x25,0xD5,0x00,0x00,0x00});
                    X64BinaryRegister(c, 0x31, 2, 0);
                }
                X64BinaryImmediate32(c, 6u, 2u, key);
                return true;
            }
            case VM_UOP_PUSH_CONDITION: {
                // X64EvaluateCondition supplies exactly 0 or 1.  Normalize it
                // through a seed-shifted predicate rather than decorating an
                // already-computed result: (condition +/- key) is compared
                // with the correspondingly shifted representation of true.
                const uint32_t key = CoreAddressKey(c, strategy + 1u);
                if (strategy == 0u) {
                    X64BinaryImmediate32(c, 0u, 0u, key);
                    X64BinaryImmediate32(c, 7u, 0u, key + 1u);
                } else {
                    X64BinaryImmediate32(c, 5u, 0u, key);
                    X64BinaryImmediate32(c, 7u, 0u, 1u - key);
                }
                c.Raw({0x0F,0x94,0xC0,0x0F,0xB6,0xC0});
                return true;
            }
            case VM_UOP_SELECT:
                EmitKeyedSelectCore(c, true, strategy);
                return true;
            case VM_UOP_BRANCH:
                EmitKeyedAddSubCore(c, true, false, strategy);
                return true;
            case VM_UOP_BRANCH_IF:
                EmitKeyedAddSubCore(c, true, false, strategy);
                return true;
            case VM_UOP_CALL_VM:
                EmitKeyedAddSubCore(c, true, false, strategy);
                return true;
            case VM_UOP_CALL_HOST:
                if (strategy == 0u) EmitX64CallTargetVariant(c, 0u);
                else EmitX64CallTargetVariant(c, 1u);
                return true;
            case VM_UOP_RET:
                EmitKeyedAddSubCore(c, true, false, strategy);
                return true;
            case VM_UOP_BRIDGE_EXTENDED:
                EmitKeyedAddSubCore(c, true, false, strategy);
                return true;
            case VM_UOP_INT3:
                if (strategy == 0u) c.U8(0xCC);
                else c.Raw({0xCD,0x03});
                return true;
            default:
                return false;
        }
    }

    switch (semantic) {
        case VM_UOP_PUSH_FLAGS: {
            const uint32_t k0 = CoreAddressKey(c, strategy + 1u);
            const uint32_t k1 = CoreAddressKey(c, strategy + 5u);
            c.Raw({0x8D,0x97}); c.U32(CtxVirtualFlags + k0);
            if (strategy != 0u) X86BinaryImmediate32(c, 0u, 2u, k1);
            c.Raw({0x8B,0x82});
            c.U32(0u - k0 - (strategy != 0u ? k1 : 0u));
            return true;
        }
        case VM_UOP_PUSH_IP:
            EmitKeyedPushIpCore(c, false, strategy);
            return true;
        case VM_UOP_PUSH_IMAGE_BASE:
            {
                const uint32_t k0 = CoreAddressKey(c, strategy + 0u);
                const uint32_t k1 = CoreAddressKey(c, strategy + 3u);
                const uint32_t k2 = CoreAddressKey(c, strategy + 6u);
                const uint32_t k3 = CoreAddressKey(c, strategy + 7u);
                c.Raw({0x8D,0x97}); c.U32(CtxImageBase + k0);
                X86BinaryImmediate32(c, 0u, 2u, k1);
                X86BinaryImmediate32(c, 5u, 2u, k2);
                X86BinaryImmediate32(c, 0u, 2u, k3);
                c.Raw({0x8B,0x82});
                c.U32(0u - (k0 + k1 - k2 + k3));
            }
            return true;
        case VM_UOP_PUSH_VREG:
            {
                const std::array<uint32_t, 2> keys = {
                    CoreKey32(c, strategy + 1u),
                    CoreKey32(c, strategy + 5u)};
                for (uint32_t key : keys)
                    X86BinaryImmediate32(c, 6u, 0u, key);
                c.Raw({0xD3,0xE8});
                for (auto it = keys.rbegin(); it != keys.rend(); ++it) {
                    X86MovImmediate(c, 2u, *it);
                    c.Raw({0xD3,0xEA,0x31,0xD0});
                }
            }
            return true;
        case VM_UOP_PUSH_IMM:
            {
                const std::array<uint32_t, 2> keys = {
                    CoreKey32(c, strategy + 2u),
                    CoreKey32(c, strategy + 7u)};
                for (uint32_t key : keys)
                    X86BinaryImmediate32(c, 6u, 0u, key);
                c.Raw({0x23,0x87}); c.U32(CtxMutationScratch);
                for (auto it = keys.rbegin(); it != keys.rend(); ++it) {
                    X86MovImmediate(c, 2u, *it);
                    c.Raw({0x23,0x97}); c.U32(CtxMutationScratch);
                    c.Raw({0x31,0xD0});
                }
            }
            return true;
        case VM_UOP_POP_VREG:
            if (strategy == 0u) EmitX86PopVregVariant(c, 0u);
            else EmitX86PopVregVariant(c, 1u);
            return true;
        case VM_UOP_LOAD_TEMP:
            {
                const uint32_t k0 = CoreAddressKey(c, strategy + 0u);
                const uint32_t k1 = CoreAddressKey(c, strategy + 4u);
                const uint32_t k2 = CoreAddressKey(c, strategy + 6u);
                const uint32_t k3 = CoreAddressKey(c, strategy + 7u);
                c.Raw({0x8D,0x94,0xCF}); c.U32(CtxTemps + k0);
                X86BinaryImmediate32(c, 0u, 2u, k1);
                X86BinaryImmediate32(c, 5u, 2u, k2);
                X86BinaryImmediate32(c, 0u, 2u, k3);
                c.Raw({0x8B,0x82});
                c.U32(0u - (k0 + k1 - k2 + k3));
            }
            return true;
        case VM_UOP_STORE_TEMP:
            {
                const uint32_t k0 = CoreAddressKey(c, strategy + 0u);
                const uint32_t k1 = CoreAddressKey(c, strategy + 4u);
                const uint32_t k2 = CoreAddressKey(c, strategy + 6u);
                const uint32_t k3 = CoreAddressKey(c, strategy + 7u);
                c.Raw({0x8D,0x94,0xCF}); c.U32(CtxTemps + k0);
                X86BinaryImmediate32(c, 0u, 2u, k1);
                X86BinaryImmediate32(c, 5u, 2u, k2);
                X86BinaryImmediate32(c, 0u, 2u, k3);
                c.Raw({0x89,0x82});
                c.U32(0u - (k0 + k1 - k2 + k3));
            }
            return true;
        case VM_UOP_DUP:
            EmitKeyedCopyCore(c, false, strategy);
            return true;
        case VM_UOP_SWAP:
            EmitKeyedSwapCore(c, false, strategy);
            return true;
        case VM_UOP_ROT:
            EmitKeyedRotateStackCore(c, false, strategy);
            return true;
        case VM_UOP_DROP:
            // ECX is the decremented value depth from X86RequireAndPop. Both
            // variants scrub the complete eight-byte physical VM stack slot.
            {
                const uint32_t key = CoreAddressKey(c, strategy + 3u);
                // Value decoding may use ECX as a permutation scratch after
                // X86RequireAndPop stored the decremented depth. Reload the
                // authoritative depth before using it as the slot index.
                X86LoadD(c, 1u, CtxValueDepth);
                c.Raw({0x8D,0x94,0xCF}); c.U32(CtxValues + key);
                if (strategy == 0u) {
                    c.Raw({0x31,0xC0,0x89,0x82}); c.U32(0u - key);
                    c.Raw({0x89,0x82}); c.U32(4u - key);
                } else {
                    c.Raw({0xC7,0x82}); c.U32(0u - key); c.U32(0u);
                    c.Raw({0xC7,0x82}); c.U32(4u - key); c.U32(0u);
                }
            }
            return true;
        case VM_UOP_LOAD:
            if (strategy == 0u) EmitX86MemoryVariant(c, false, 0u);
            else EmitX86MemoryVariant(c, false, 1u);
            return true;
        case VM_UOP_STORE:
            if (strategy == 0u) EmitX86MemoryVariant(c, true, 0u);
            else EmitX86MemoryVariant(c, true, 1u);
            return true;
        case VM_UOP_ADD:
            EmitZydisKeyedAddSubCore(c, false, false, strategy);
            return true;
        case VM_UOP_ADD_CARRY:
            EmitKeyedCarryCore(c, false, false, strategy);
            return true;
        case VM_UOP_SUB:
            EmitZydisKeyedAddSubCore(c, false, true, strategy);
            return true;
        case VM_UOP_SUB_BORROW:
            EmitKeyedCarryCore(c, false, true, strategy);
            return true;
        case VM_UOP_AND:
            EmitKeyedBitwiseCore(c, false, false, strategy);
            return true;
        case VM_UOP_OR:
            EmitKeyedBitwiseCore(c, false, true, strategy);
            return true;
        case VM_UOP_XOR:
            EmitKeyedXorCore(c, false, strategy);
            return true;
        case VM_UOP_NOT:
            EmitKeyedUnaryCore(c, false, false, strategy);
            return true;
        case VM_UOP_NEG:
            EmitKeyedUnaryCore(c, false, true, strategy);
            return true;
        case VM_UOP_MUL:
            // Same identity as the x64 case: IMUL EAX,EDX vs. MUL EDX give
            // the same truncated 32-bit product in eax; the clobbered edx
            // is safe for the same reason (a/b already latched earlier).
            EmitKeyedMultiplyCore(c, false, strategy);
            return true;
        case VM_UOP_BIT_TEST:
            X86LoadD(c, 1, RECORD_OFFSET(CtxLastAlu, b));
            X86LoadByte(c, 2, CtxDecodedOperands);
            c.Raw({0xC1,0xE2,0x03,0x4A,0x21,0xD1});
            X86LoadD(c, 0, RECORD_OFFSET(CtxLastAlu, a));
            if (strategy == 0u) {
                c.Raw({0x89,0xC2,0xD3,0xEA,0x83,0xE2,0x01});
            } else {
                // strategy 1: native BT — CF is the tested bit; the r/m
                // operand (eax) is left unmodified by BT.
                c.Raw({0x31,0xD2});
                c.Raw({0x0F,0xA3,0xC8});
                c.Raw({0x0F,0x92,0xC2});
            }
            X86StoreD(c, CtxMutationScratch + 4u, 2);
            return true;
        case VM_UOP_BIT_SET:
            X86LoadD(c, 1, RECORD_OFFSET(CtxLastAlu, b));
            X86LoadByte(c, 2, CtxDecodedOperands);
            c.Raw({0xC1,0xE2,0x03,0x4A,0x21,0xD1});
            X86LoadD(c, 0, RECORD_OFFSET(CtxLastAlu, a));
            if (strategy == 0u) {
                c.Raw({0x89,0xC2,0xD3,0xEA,0x83,0xE2,0x01});
                c.Raw({0xBE,0x01,0x00,0x00,0x00,0xD3,0xE6});
                c.Raw({0x09,0xF0});
            } else {
                // strategy 1: native BTS sets the bit and reports the old
                // value in CF in the same instruction.
                c.Raw({0x31,0xD2});
                c.Raw({0x0F,0xAB,0xC8});
                c.Raw({0x0F,0x92,0xC2});
            }
            X86StoreD(c, CtxMutationScratch + 4u, 2);
            return true;
        case VM_UOP_BIT_RESET:
            X86LoadD(c, 1, RECORD_OFFSET(CtxLastAlu, b));
            X86LoadByte(c, 2, CtxDecodedOperands);
            c.Raw({0xC1,0xE2,0x03,0x4A,0x21,0xD1});
            X86LoadD(c, 0, RECORD_OFFSET(CtxLastAlu, a));
            if (strategy == 0u) {
                c.Raw({0x89,0xC2,0xD3,0xEA,0x83,0xE2,0x01});
                c.Raw({0xBE,0x01,0x00,0x00,0x00,0xD3,0xE6});
                c.Raw({0xF7,0xD6,0x21,0xF0});
            } else {
                // strategy 1: native BTR resets the bit and reports the old
                // value in CF in the same instruction.
                c.Raw({0x31,0xD2});
                c.Raw({0x0F,0xB3,0xC8});
                c.Raw({0x0F,0x92,0xC2});
            }
            X86StoreD(c, CtxMutationScratch + 4u, 2);
            return true;
        case VM_UOP_SHL: {
            EmitKeyedLogicalShiftCore(c, false, false, strategy);
            return true;
            // strategy 0: native SHL eax,cl.  strategy 1: SHLD eax,ebx(=0),cl ≡
            //   SHL (zero source pulls zeroes into the top).  32-bit mode has no
            //   8-byte operand, so every width (1/2/4) masks the count to 5
            //   bits; a single `and cl,31` then one 32-bit shl/shld covers all
            //   widths (operand zero-extended, outer `and eax,[scratch]` trims
            //   to width).  Label-free so the validator's isolated re-emission
            //   matches byte-for-byte.  ebx is free across EmitX86BinaryAlu.
        }
        case VM_UOP_SHR: {
            EmitKeyedLogicalShiftCore(c, false, true, strategy);
            return true;
            // Same count pre-mask as SHL.
            // strategy 0: native SHR eax,cl.  strategy 1: SHRD eax,ebx(=0),cl ≡
            //   SHR (zero source pulls zeroes into the bottom).
        }
        case VM_UOP_SAR:
            if (strategy == 0u) EmitX86ShiftRotateVariant(c, semantic, 0u);
            else EmitX86ShiftRotateVariant(c, semantic, 1u);
            return true;
        case VM_UOP_ROL:
            if (strategy == 0u) EmitX86ShiftRotateVariant(c, semantic, 0u);
            else EmitX86ShiftRotateVariant(c, semantic, 1u);
            return true;
        case VM_UOP_ROR:
            if (strategy == 0u) EmitX86ShiftRotateVariant(c, semantic, 0u);
            else EmitX86ShiftRotateVariant(c, semantic, 1u);
            return true;
        case VM_UOP_BSWAP:
            if (strategy == 0u) EmitX86ByteSwapVariant(c, 0u);
            else EmitX86ByteSwapVariant(c, 1u);
            return true;
        case VM_UOP_ZERO_EXTEND:
            if (strategy == 0u) EmitX86ExtendVariant(c, false, 0u);
            else EmitX86ExtendVariant(c, false, 1u);
            return true;
        case VM_UOP_SIGN_EXTEND:
            if (strategy == 0u) EmitX86ExtendVariant(c, true, 0u);
            else EmitX86ExtendVariant(c, true, 1u);
            return true;
        case VM_UOP_UMUL_WIDE: {
            // Multiply by (b + key) and subtract a*key.  The carry from the
            // 32-bit keyed add contributes a<<32 to the full product, so add
            // it back to the high half.  The correction is part of the real
            // 64-bit product rather than an encode/decode identity around MUL.
            const uint32_t key = CoreKey32(c, strategy + 2u);
            c.Raw({0x89,0xC3});                    // ebx = a
            X86BinaryImmediate32(c, 0u, 1u, key); // ecx = b + key
            c.Raw({0x0F,0x92,0x87});              // keyed-add carry
            c.U32(CtxMutationScratch);
            if (strategy == 0u) {
                // Keep K=0 byte-for-byte unchanged.  This is the control arm
                // for the K=1 explicit-source diversification below.
                c.Raw({0xF7,0xE1});
            } else {
                const uint8_t multiplier = c.registerAssignment[0];
                const bool memorySource = c.registerAssignment[3] == 0u;
                if (!memorySource) {
                    EmitZydisMove(c, false, multiplier, 1u);
                    EmitZydisUnary(
                        c, false, ZYDIS_MNEMONIC_MUL, multiplier);
                } else {
                    const uint32_t addressKey =
                        CoreAddressKey(c, strategy + 9u);
                    EmitZydisLea(c, false, multiplier, 7u,
                        static_cast<int32_t>(
                            CtxMutationScratch + 4u + addressKey));
                    EmitZydisStore(c, false, multiplier,
                        static_cast<int32_t>(0u - addressKey), 1u, 4u);
                    EmitZydisInstruction(c, false, ZYDIS_MNEMONIC_MUL,
                        {ZydisMemoryOperand(false, multiplier,
                            static_cast<int32_t>(0u - addressKey), 4u)});
                }
            }
            c.Raw({0x89,0xC6,0x89,0xD1});          // main low/high
            c.Raw({0x89,0xD8,0xBA}); c.U32(key);   // eax=a, edx=key
            c.Raw({0xF7,0xE2});                    // edx:eax = a*key
            c.Raw({0x29,0xC6,0x19,0xD1});          // subtract correction
            c.Raw({0x0F,0xB6,0x97}); c.U32(CtxMutationScratch);
            c.Raw({0x0F,0xAF,0xD3,0x01,0xD1});    // high += carry*a
            c.Raw({0x89,0xF0,0x89,0xCA});          // edx:eax = result
            return true;
        }
        case VM_UOP_SMUL_WIDE:
            if (strategy == 0u) c.Raw({0xF7,0xE9});
            else c.Raw({0x89,0xCB,0xF7,0xEB});
            return true;
        case VM_UOP_UDIV_WIDE: {
            // Spill the actual divisor through a seed-split effective address
            // and make that memory operand the source of DIV.  Zero divisors
            // and quotient overflow therefore still fault in the hardware DIV
            // itself with the original EDX:EAX dividend.
            const uint32_t key = CoreAddressKey(c, strategy + 4u);
            const uint32_t slot = strategy == 0u ? 0u : 4u;
            if (strategy == 0u) {
                c.Raw({0x8D,0x9F}); c.U32(CtxMutationScratch + slot + key);
                c.Raw({0x89,0x8B}); c.U32(0u - key);
                c.Raw({0xF7,0xB3}); c.U32(0u - key);
            } else {
                c.Raw({0x8D,0xB7}); c.U32(CtxMutationScratch + slot + key);
                c.Raw({0x89,0x8E}); c.U32(0u - key);
                c.Raw({0xF7,0xB6}); c.U32(0u - key);
            }
            return true;
        }
        case VM_UOP_IDIV_WIDE:
            if (strategy == 0u) c.Raw({0xF7,0xF9});
            else c.Raw({0x89,0xCB,0xF7,0xFB});
            return true;
        case VM_UOP_FLAGS_LAZY:
            for (uint8_t field : coreOrder(static_cast<uint8_t>(
                    sizeof(VM_LAZY_FLAGS_RECORD) / 4u))) {
                const uint32_t offset = static_cast<uint32_t>(field) * 4u;
                EmitKeyedContextCopy(c, false,
                    CtxLastAlu + offset, CtxPendingFlags + offset,
                    false, static_cast<size_t>(field) + strategy);
            }
            return true;
        case VM_UOP_FLAGS_MATERIALIZE:
            {
                const uint32_t k0 = CoreAddressKey(c, strategy + 1u);
                const uint32_t k1 = CoreAddressKey(c, strategy + 5u);
                const uint32_t k2 = CoreAddressKey(c, strategy + 6u);
                const uint32_t k3 = CoreAddressKey(c, strategy + 7u);
                c.Raw({0x8D,0x8F}); c.U32(CtxDecodedOperands + k0);
                X86BinaryImmediate32(c, 0u, 1u, k1);
                X86BinaryImmediate32(c, 5u, 1u, k2);
                X86BinaryImmediate32(c, 0u, 1u, k3);
                c.Raw({0x8B,0x91});
                c.U32(0u - (k0 + k1 - k2 + k3));
            }
            return true;
        case VM_UOP_FLAGS_WRITE:
            EmitKeyedFlagsWriteCore(c, false, strategy);
            return true;
        case VM_UOP_FLAGS_UPDATE: {
            const uint32_t modeKey = CoreAddressKey(c, strategy + 1u);
            const uint32_t dataKey = CoreKey32(c, strategy + 5u);
            const auto clear = c.NewLabel();
            const auto set = c.NewLabel();
            const auto done = c.NewLabel();
            c.Raw({0x8D,0x89}); c.U32(modeKey);
            c.Raw({0x81,0xF9});
            c.U32(modeKey + VM_FLAG_UPDATE_CLEAR); c.Jcc(JccE, clear);
            c.Raw({0x81,0xF9});
            c.U32(modeKey + VM_FLAG_UPDATE_SET); c.Jcc(JccE, set);

            X86BinaryImmediate32(c, 6u, 0u, dataKey);
            if (strategy == 0u) {
                c.Raw({0x31,0xD0});
            } else {
                X86MovRegister(c, 3u, 0u);
                X86BinaryRegister(c, 0x21u, 3u, 2u);
                X86BinaryRegister(c, 0x09u, 0u, 2u);
                X86BinaryRegister(c, 0x29u, 0u, 3u);
            }
            X86BinaryImmediate32(c, 6u, 0u, dataKey);
            c.Jmp(done);

            c.Bind(clear);
            X86BinaryImmediate32(c, 6u, 0u, dataKey);
            if (strategy == 0u) {
                X86MovRegister(c, 3u, 2u); X86UnaryGroup(c, 2u, 3u);
                X86BinaryRegister(c, 0x21u, 0u, 3u);
            } else {
                X86UnaryGroup(c, 2u, 0u);
                X86BinaryRegister(c, 0x09u, 0u, 2u);
                X86UnaryGroup(c, 2u, 0u);
                X86MovRegister(c, 3u, 2u); X86UnaryGroup(c, 2u, 3u);
            }
            X86MovImmediate(c, 1u, dataKey);
            X86BinaryRegister(c, 0x21u, 1u, 3u);
            X86BinaryRegister(c, 0x31u, 0u, 1u);
            c.Jmp(done);

            c.Bind(set);
            X86BinaryImmediate32(c, 6u, 0u, dataKey);
            if (strategy == 0u) {
                X86BinaryRegister(c, 0x09u, 0u, 2u);
                X86MovRegister(c, 3u, 2u); X86UnaryGroup(c, 2u, 3u);
            } else {
                X86UnaryGroup(c, 2u, 0u);
                X86MovRegister(c, 3u, 2u); X86UnaryGroup(c, 2u, 3u);
                X86BinaryRegister(c, 0x21u, 0u, 3u);
                X86UnaryGroup(c, 2u, 0u);
            }
            X86MovImmediate(c, 1u, dataKey);
            X86BinaryRegister(c, 0x21u, 1u, 3u);
            X86BinaryRegister(c, 0x31u, 0u, 1u);
            c.Bind(done);
            return true;
        }
        case VM_UOP_FLAGS_PACK_AH: {
            constexpr uint32_t packedMask = VM_FLAG_SF | VM_FLAG_ZF |
                VM_FLAG_AF | VM_FLAG_PF | VM_FLAG_CF;
            const uint32_t rawKey = CoreKey32(c, strategy + 2u);
            uint32_t packedKey = CoreKey32(c, strategy + 6u) & packedMask;
            if (packedKey == 0u)
                packedKey = 1u << ((rawKey % 5u == 0u) ? 0u :
                    (rawKey % 5u == 1u) ? 2u :
                    (rawKey % 5u == 2u) ? 4u :
                    (rawKey % 5u == 3u) ? 6u : 7u);
            const uint8_t rotation = static_cast<uint8_t>(1u + rawKey % 31u);
            const uint32_t rotatedMask = strategy == 0u
                ? ((packedMask >> rotation) |
                    (packedMask << (32u - rotation)))
                : ((packedMask << rotation) |
                    (packedMask >> (32u - rotation)));
            c.Raw({0x89,0xD0});
            X86BinaryImmediate32(c, 6u, 0u, packedKey);
            c.Raw({0xC1, static_cast<uint8_t>(strategy == 0u ? 0xC8 : 0xC0),
                rotation, 0x25});
            c.U32(rotatedMask);
            c.Raw({0xC1, static_cast<uint8_t>(strategy == 0u ? 0xC0 : 0xC8),
                rotation});
            X86BinaryImmediate32(c, 6u, 0u, packedKey);
            c.Raw({0x83,0xC8,0x02});
            return true;
        }
        case VM_UOP_FLAGS_UNPACK_AH: {
            // Uniform XOR conjugation commutes with the masked bit-select:
            // status bits come from EAX, every other bit remains from EDX.
            const uint32_t key = CoreKey32(c, strategy + 6u);
            X86BinaryImmediate32(c, 6u, 0u, key);
            X86BinaryImmediate32(c, 6u, 2u, key);
            if (strategy == 0u) {
                c.Raw({0x81,0xE2});
                c.U32(~static_cast<uint32_t>(
                    VM_FLAG_SF|VM_FLAG_ZF|VM_FLAG_AF|VM_FLAG_PF|VM_FLAG_CF));
                c.Raw({0x25,0xD5,0x00,0x00,0x00,0x09,0xC2});
            } else c.Raw({0x31,0xD0,0x25,0xD5,0x00,0x00,0x00,0x31,0xC2});
            X86BinaryImmediate32(c, 6u, 2u, key);
            return true;
        }
        case VM_UOP_PUSH_CONDITION:
            if (strategy == 0u) c.Raw({0x83,0xE0,0x01});
            else c.Raw({0x85,0xC0,0x0F,0x95,0xC0,0x0F,0xB6,0xC0});
            return true;
        case VM_UOP_SELECT:
            EmitKeyedSelectCore(c, false, strategy);
            return true;
        case VM_UOP_BRANCH:
            EmitKeyedAddSubCore(c, false, false, strategy);
            return true;
        case VM_UOP_BRANCH_IF:
            EmitKeyedAddSubCore(c, false, false, strategy);
            return true;
        case VM_UOP_CALL_VM:
            EmitKeyedAddSubCore(c, false, false, strategy);
            return true;
        case VM_UOP_CALL_HOST:
            if (strategy == 0u) EmitX86CallTargetVariant(c, 0u);
            else EmitX86CallTargetVariant(c, 1u);
            return true;
        case VM_UOP_RET:
            EmitKeyedAddSubCore(c, false, false, strategy);
            return true;
        case VM_UOP_BRIDGE_EXTENDED:
            EmitKeyedAddSubCore(c, false, false, strategy);
            return true;
        case VM_UOP_INT3:
            if (strategy == 0u) c.U8(0xCC);
            else c.Raw({0xCD,0x03});
            return true;
        default:
            return false;
    }
}

bool EmitTrackedBusinessCoreVariant(
    CodeBuffer& c,
    bool x64,
    VM_MICRO_OPCODE semantic,
    uint8_t strategy,
    uint32_t& offset,
    uint32_t& size)
{
    const uint32_t begin = static_cast<uint32_t>(c.bytes.size());
    // DeriveBusinessCoreStrategy already guarantees alternating K choices
    // while letting the build seed choose which physical strategy starts at
    // K=0.  Re-XORing a handler-local layout bit here could cancel that
    // alternation and make all four K entries select one fixed lowering.
    if (!EmitBusinessCoreVariant(c, x64, semantic,
            static_cast<uint8_t>(strategy & 1u)))
        return false;
    if (size == 0u) {
        offset = begin;
        size = static_cast<uint32_t>(c.bytes.size()) - begin;
    }
    return true;
}

bool ValidateBusinessCoreStrategyReemission(
    const VMHandlerSemanticCodegenConfig& config,
    bool x64,
    std::string& error)
{
    if (!HasBusinessCoreVariant(config.semantic)) return true;

    std::array<std::vector<uint8_t>, 2> emitted{};
    for (uint8_t strategy = 0;
         strategy < static_cast<uint8_t>(emitted.size()); ++strategy) {
        CodeBuffer code;
        ConfigurePermutationPlans(code, config);
        code.registerAssignment = DeriveVariantRegisters(
            x64, config.variant, config.semantic, config.buildSeed,
            strategy);
        if (!EmitBusinessCoreVariant(code, x64, config.semantic, strategy)) {
            error = "business core strategy could not be re-emitted";
            return false;
        }
        std::string resolveError;
        if (!code.Resolve(resolveError) || code.bytes.empty()) {
            error = "business core strategy re-emission is empty or unresolved";
            return false;
        }
        emitted[strategy] = std::move(code.bytes);
    }
    if (emitted[0] == emitted[1]) {
        error = "business core strategies emitted identical bytes";
        return false;
    }
    return true;
}

void EmitExecutableSeedJunk(
    CodeBuffer& c,
    bool x64,
    const std::array<uint8_t, 4>& registers,
    SeedStream& random,
    uint32_t instructionCount)
{
    for (uint32_t index = 0; index < instructionCount; ++index) {
        const uint8_t reg = registers[index & 3u];
        if (x64)
            X64MovImmediate(c, reg, random.Next64());
        else
            X86MovImmediate(c, reg, random.Next32());
    }
}

void EmitLiveIdentityMBA(
    CodeBuffer& c,
    bool x64,
    uint8_t variant,
    const std::array<uint8_t, 4>& registers,
    SeedStream& random)
{
    // Every pair is executed and restores mutationScratch exactly.  The
    // selected physical registers are the allocation published in the result.
    for (uint32_t round = 0; round < 12u; ++round) {
        const uint8_t destination = registers[round & 3u];
        uint8_t source = registers[(round + 1u) & 3u];
        if (source == destination) source = registers[(round + 2u) & 3u];
        const uint64_t key = random.Next64() | 1u;
        if (x64) {
            X64LoadQ(c, destination, CtxMutationScratch);
            X64MovImmediate(c, source, key);
            switch ((variant + round) % 3u) {
                case 0:
                    X64BinaryRegister(c, 0x31, destination, source);
                    X64BinaryRegister(c, 0x31, destination, source);
                    break;
                case 1:
                    X64BinaryRegister(c, 0x01, destination, source);
                    X64BinaryRegister(c, 0x29, destination, source);
                    break;
                default:
                    X64BinaryRegister(c, 0x29, destination, source);
                    X64BinaryRegister(c, 0x01, destination, source);
                    break;
            }
            X64StoreQ(c, CtxMutationScratch, destination);
        } else {
            X86LoadD(c, destination, CtxMutationScratch);
            X86MovImmediate(c, source, static_cast<uint32_t>(key));
            switch ((variant + round) % 3u) {
                case 0:
                    X86BinaryRegister(c, 0x31, destination, source);
                    X86BinaryRegister(c, 0x31, destination, source);
                    break;
                case 1:
                    X86BinaryRegister(c, 0x01, destination, source);
                    X86BinaryRegister(c, 0x29, destination, source);
                    break;
                default:
                    X86BinaryRegister(c, 0x29, destination, source);
                    X86BinaryRegister(c, 0x01, destination, source);
                    break;
            }
            X86StoreD(c, CtxMutationScratch, destination);
        }
    }
}

void EmitOpaqueEvenProductPredicate(
    CodeBuffer& c,
    bool x64,
    const std::array<uint8_t, 4>& registers,
    CodeBuffer::Label impossible)
{
    const uint8_t value = registers[0];
    uint8_t product = registers[1];
    if (product == value) product = registers[2];
    if (x64) {
        X64LoadQ(c, value, CtxMutationScratch);
        X64MovRegister(c, product, value);
        const uint8_t rexProduct = static_cast<uint8_t>(0x48u |
            ((product & 8u) ? 1u : 0u));
        c.Raw({rexProduct, 0xFF,
            static_cast<uint8_t>(0xC0u | (product & 7u))});
        const uint8_t rexImul = static_cast<uint8_t>(0x48u |
            ((product & 8u) ? 4u : 0u) | ((value & 8u) ? 1u : 0u));
        c.Raw({rexImul, 0x0F, 0xAF, static_cast<uint8_t>(0xC0u |
            ((product & 7u) << 3u) | (value & 7u))});
        c.Raw({rexProduct, 0xF7,
            static_cast<uint8_t>(0xC0u | (product & 7u))});
        c.U32(1u);
    } else {
        X86LoadD(c, value, CtxMutationScratch);
        X86MovRegister(c, product, value);
        c.Raw({0xFF, static_cast<uint8_t>(0xC0u | (product & 7u))});
        c.Raw({0x0F, 0xAF, static_cast<uint8_t>(0xC0u |
            ((product & 7u) << 3u) | (value & 7u))});
        c.Raw({0xF7, static_cast<uint8_t>(0xC0u | (product & 7u))});
        c.U32(1u);
    }
    // n*(n+1) is even for every machine integer, so this branch is a live,
    // internally-derived opaque predicate rather than an unconditional jump.
    c.Jcc(JccNE, impossible);
}

void X64RequireAndPop(
    CodeBuffer& c,
    uint8_t count,
    CodeBuffer::Label stackFailure)
{
    uint32_t key = 0;
    if (!DeriveControlDispatchKey(
            c, 0x535441434B504F50ULL, count, key)) return;
    const auto encodedFailure = c.NewLabel();
    const auto encodedSuccess = c.NewLabel();
    X64LoadD(c, 1, CtxValueDepth);             // ecx = old depth
    c.Raw({0x48,0x8D,0x89}); c.U32(key);       // rcx = depth + K
    // depth<count is exactly the encoded half-open interval [K,K+count).
    // The lower check also rejects no valid depth and keeps the x86 form
    // below correct when its 32-bit LEA wraps for a corrupt high depth.
    c.Raw({0x48,0x81,0xF9}); c.U32(key);
    c.Jcc(JccB, encodedSuccess);
    c.Raw({0x48,0x81,0xF9}); c.U32(key + count);
    c.Jcc(JccB, encodedFailure);
    c.Jmp(encodedSuccess);

    c.Bind(encodedFailure);
    c.Raw({0x48,0x8D,0x89}); c.U32(0u - key);
    c.Raw({0x83,0xF9,count});                  // restore original CMP flags
    c.Jmp(stackFailure);

    c.Bind(encodedSuccess);
    c.Raw({0x48,0x8D,0x89}); c.U32(0u - key);
    c.Raw({0x83,0xF9,count});
    c.Raw({0x83,0xE9,count});                  // ecx = first popped slot
    X64StoreD(c, CtxValueDepth, 1);
    if (count >= 1) {
        X64LoadIndexedQ(c, 0, 1, CtxValues);
        EmitValuePermutation(c, true, 0, true);
    }
    if (count >= 2) {
        X64LoadIndexedQ(c, 2, 1, CtxValues + 8u);
        EmitValuePermutation(c, true, 2, true);
    }
    if (count >= 3) {
        X64LoadIndexedQ(c, 8, 1, CtxValues + 16u);
        EmitValuePermutation(c, true, 8, true);
    }
}

void X64PushOne(
    CodeBuffer& c,
    uint8_t source,
    CodeBuffer::Label stackFailure)
{
    uint32_t key = 0;
    if (!DeriveControlDispatchKey(
            c, 0x535441434B505331ULL, source, key)) return;
    const auto encodedFailure = c.NewLabel();
    const auto encodedSuccess = c.NewLabel();
    X64LoadD(c, 1, CtxValueDepth);
    c.Raw({0x48,0x8D,0x89}); c.U32(key);
    c.Raw({0x48,0x81,0xF9}); c.U32(key);
    c.Jcc(JccB, encodedFailure);
    c.Raw({0x48,0x81,0xF9});
    c.U32(key + VM_RUNTIME_VALUE_STACK_DEPTH);
    c.Jcc(JccB, encodedSuccess);
    c.Jmp(encodedFailure);

    c.Bind(encodedFailure);
    c.Raw({0x48,0x8D,0x89}); c.U32(0u - key);
    c.Raw({0x81,0xF9}); c.U32(VM_RUNTIME_VALUE_STACK_DEPTH);
    c.Jmp(stackFailure);

    c.Bind(encodedSuccess);
    c.Raw({0x48,0x8D,0x89}); c.U32(0u - key);
    c.Raw({0x81,0xF9}); c.U32(VM_RUNTIME_VALUE_STACK_DEPTH);
    EmitValuePermutation(c, true, source, false);
    X64StoreIndexedQ(c, CtxValues, 1, source);
    c.Raw({0xFF,0xC1});
    X64StoreD(c, CtxValueDepth, 1);
}

void X64PushTwo(
    CodeBuffer& c,
    uint8_t first,
    uint8_t second,
    CodeBuffer::Label stackFailure)
{
    uint32_t key = 0;
    const uint8_t operand = static_cast<uint8_t>((first << 4u) ^ second);
    if (!DeriveControlDispatchKey(
            c, 0x535441434B505332ULL, operand, key)) return;
    const auto encodedFailure = c.NewLabel();
    const auto encodedSuccess = c.NewLabel();
    X64LoadD(c, 1, CtxValueDepth);
    c.Raw({0x48,0x8D,0x89}); c.U32(key);
    c.Raw({0x48,0x81,0xF9}); c.U32(key);
    c.Jcc(JccB, encodedFailure);
    c.Raw({0x48,0x81,0xF9});
    c.U32(key + VM_RUNTIME_VALUE_STACK_DEPTH - 1u);
    c.Jcc(JccB, encodedSuccess);
    c.Jmp(encodedFailure);

    c.Bind(encodedFailure);
    c.Raw({0x48,0x8D,0x89}); c.U32(0u - key);
    c.Raw({0x81,0xF9}); c.U32(VM_RUNTIME_VALUE_STACK_DEPTH - 1u);
    c.Jmp(stackFailure);

    c.Bind(encodedSuccess);
    c.Raw({0x48,0x8D,0x89}); c.U32(0u - key);
    c.Raw({0x81,0xF9}); c.U32(VM_RUNTIME_VALUE_STACK_DEPTH - 1u);
    EmitValuePermutation(c, true, first, false);
    EmitValuePermutation(c, true, second, false);
    X64StoreIndexedQ(c, CtxValues, 1, first);
    X64StoreIndexedQ(c, CtxValues + 8u, 1, second);
    c.Raw({0x83,0xC1,0x02});
    X64StoreD(c, CtxValueDepth, 1);
}

void X86RequireAndPop(
    CodeBuffer& c,
    uint8_t count,
    CodeBuffer::Label stackFailure)
{
    uint32_t key = 0;
    if (!DeriveControlDispatchKey(
            c, 0x535441434B504F50ULL, count, key)) return;
    const auto encodedFailure = c.NewLabel();
    const auto encodedSuccess = c.NewLabel();
    X86LoadD(c, 1, CtxValueDepth);
    c.Raw({0x8D,0x89}); c.U32(key);
    c.Raw({0x81,0xF9}); c.U32(key);
    c.Jcc(JccB, encodedSuccess);
    c.Raw({0x81,0xF9}); c.U32(key + count);
    c.Jcc(JccB, encodedFailure);
    c.Jmp(encodedSuccess);

    c.Bind(encodedFailure);
    c.Raw({0x8D,0x89}); c.U32(0u - key);
    c.Raw({0x83,0xF9,count});
    c.Jmp(stackFailure);

    c.Bind(encodedSuccess);
    c.Raw({0x8D,0x89}); c.U32(0u - key);
    c.Raw({0x83,0xF9,count});
    c.Raw({0x83,0xE9,count});
    X86StoreD(c, CtxValueDepth, 1);
    if (count >= 1) {
        X86LoadIndexedD(c, 0, CtxValues);
        EmitValuePermutation(c, false, 0, true);
    }
    if (count >= 2) {
        X86LoadIndexedD(c, 2, CtxValues + 8u);
        EmitValuePermutation(c, false, 2, true);
    }
    if (count >= 3) {
        X86LoadIndexedD(c, 1, CtxValues + 16u);
        EmitValuePermutation(c, false, 1, true);
    }
}

void X86PushOne(
    CodeBuffer& c,
    uint8_t source,
    CodeBuffer::Label stackFailure)
{
    uint32_t key = 0;
    if (!DeriveControlDispatchKey(
            c, 0x535441434B505331ULL, source, key)) return;
    const auto encodedFailure = c.NewLabel();
    const auto encodedSuccess = c.NewLabel();
    X86LoadD(c, 1, CtxValueDepth);
    c.Raw({0x8D,0x89}); c.U32(key);
    c.Raw({0x81,0xF9}); c.U32(key);
    c.Jcc(JccB, encodedFailure);
    c.Raw({0x81,0xF9});
    c.U32(key + VM_RUNTIME_VALUE_STACK_DEPTH);
    c.Jcc(JccB, encodedSuccess);
    c.Jmp(encodedFailure);

    c.Bind(encodedFailure);
    c.Raw({0x8D,0x89}); c.U32(0u - key);
    c.Raw({0x81,0xF9}); c.U32(VM_RUNTIME_VALUE_STACK_DEPTH);
    c.Jmp(stackFailure);

    c.Bind(encodedSuccess);
    c.Raw({0x8D,0x89}); c.U32(0u - key);
    c.Raw({0x81,0xF9}); c.U32(VM_RUNTIME_VALUE_STACK_DEPTH);
    EmitValuePermutation(c, false, source, false);
    X86StoreIndexedD(c, CtxValues, source);
    c.Raw({0xC7,0x84,0xCF}); c.U32(CtxValues + 4u); c.U32(0);
    c.Raw({0x41});
    X86StoreD(c, CtxValueDepth, 1);
}

void X86PushTwo(
    CodeBuffer& c,
    uint8_t first,
    uint8_t second,
    CodeBuffer::Label stackFailure)
{
    uint32_t key = 0;
    const uint8_t operand = static_cast<uint8_t>((first << 4u) ^ second);
    if (!DeriveControlDispatchKey(
            c, 0x535441434B505332ULL, operand, key)) return;
    const auto encodedFailure = c.NewLabel();
    const auto encodedSuccess = c.NewLabel();
    X86LoadD(c, 1, CtxValueDepth);
    c.Raw({0x8D,0x89}); c.U32(key);
    c.Raw({0x81,0xF9}); c.U32(key);
    c.Jcc(JccB, encodedFailure);
    c.Raw({0x81,0xF9});
    c.U32(key + VM_RUNTIME_VALUE_STACK_DEPTH - 1u);
    c.Jcc(JccB, encodedSuccess);
    c.Jmp(encodedFailure);

    c.Bind(encodedFailure);
    c.Raw({0x8D,0x89}); c.U32(0u - key);
    c.Raw({0x81,0xF9}); c.U32(VM_RUNTIME_VALUE_STACK_DEPTH - 1u);
    c.Jmp(stackFailure);

    c.Bind(encodedSuccess);
    c.Raw({0x8D,0x89}); c.U32(0u - key);
    c.Raw({0x81,0xF9}); c.U32(VM_RUNTIME_VALUE_STACK_DEPTH - 1u);
    EmitValuePermutation(c, false, first, false);
    EmitValuePermutation(c, false, second, false);
    X86StoreIndexedD(c, CtxValues, first);
    c.Raw({0xC7,0x84,0xCF}); c.U32(CtxValues + 4u); c.U32(0);
    X86StoreIndexedD(c, CtxValues + 8u, second);
    c.Raw({0xC7,0x84,0xCF}); c.U32(CtxValues + 12u); c.U32(0);
    c.Raw({0x83,0xC1,0x02});
    X86StoreD(c, CtxValueDepth, 1);
}

void X64DispatchPendingWidth(CodeBuffer& c, const WidthLabels& labels) {
    uint32_t key = 0;
    if (!DeriveControlDispatchKey(
            c, 0x50454E4457494454ULL, 0u, key)) return;
    const auto restoreInvalid = c.NewLabel();
    const auto restoreWidth1 = c.NewLabel();
    const auto restoreWidth2 = c.NewLabel();
    const auto restoreWidth4 = c.NewLabel();
    const auto restoreWidth8 = c.NewLabel();

    X64LoadByte(c, 11, RECORD_OFFSET(CtxPendingFlags, width));
    c.Raw({0x4D,0x8D,0x9B}); c.U32(key);
    c.Raw({0x49,0x81,0xFB}); c.U32(key + 1u); c.Jcc(JccE, restoreWidth1);
    c.Raw({0x49,0x81,0xFB}); c.U32(key + 2u); c.Jcc(JccE, restoreWidth2);
    c.Raw({0x49,0x81,0xFB}); c.U32(key + 4u); c.Jcc(JccE, restoreWidth4);
    c.Raw({0x49,0x81,0xFB}); c.U32(key + 8u); c.Jcc(JccE, restoreWidth8);

    c.Bind(restoreInvalid);
    c.Raw({0x4D,0x8D,0x9B}); c.U32(0u - key);
    c.Raw({0x49,0x83,0xFB,0x08});
    c.Jmp(labels.invalid);

    const auto restore = [&](CodeBuffer::Label local,
                             CodeBuffer::Label destination) {
        c.Bind(local);
        c.Raw({0x4D,0x8D,0x9B}); c.U32(0u - key);
        c.Jmp(destination);
    };
    restore(restoreWidth1, labels.width1);
    restore(restoreWidth2, labels.width2);
    restore(restoreWidth4, labels.width4);
    restore(restoreWidth8, labels.width8);
}

void X86DispatchPendingWidth(CodeBuffer& c, const WidthLabels& labels) {
    uint32_t key = 0;
    if (!DeriveControlDispatchKey(
            c, 0x50454E4457494454ULL, 0u, key)) return;
    const auto restoreInvalid = c.NewLabel();
    const auto restoreWidth1 = c.NewLabel();
    const auto restoreWidth2 = c.NewLabel();
    const auto restoreWidth4 = c.NewLabel();

    X86LoadByte(c, 1, RECORD_OFFSET(CtxPendingFlags, width));
    c.Raw({0x8D,0x89}); c.U32(key);
    c.Raw({0x81,0xF9}); c.U32(key + 1u); c.Jcc(JccE, restoreWidth1);
    c.Raw({0x81,0xF9}); c.U32(key + 2u); c.Jcc(JccE, restoreWidth2);
    c.Raw({0x81,0xF9}); c.U32(key + 4u); c.Jcc(JccE, restoreWidth4);

    c.Bind(restoreInvalid);
    c.Raw({0x8D,0x89}); c.U32(0u - key);
    c.Raw({0x83,0xF9,0x04});
    c.Jmp(labels.invalid);

    const auto restore = [&](CodeBuffer::Label local,
                             CodeBuffer::Label destination) {
        c.Bind(local);
        c.Raw({0x8D,0x89}); c.U32(0u - key);
        c.Jmp(destination);
    };
    restore(restoreWidth1, labels.width1);
    restore(restoreWidth2, labels.width2);
    restore(restoreWidth4, labels.width4);
}

void X64MaskForWidthInR11(CodeBuffer& c) {
    /* r9 = UINT64_MAX >> ((8-r11d)*8). */
    c.Raw({0xB9,0x08,0x00,0x00,0x00});
    c.Raw({0x44,0x29,0xD9,0xC1,0xE1,0x03});
    c.Raw({0x49,0xC7,0xC1,0xFF,0xFF,0xFF,0xFF});
    c.Raw({0x49,0xD3,0xE9});
}

void X86BuildMaskInScratch(CodeBuffer& c) {
    /* ecx contains a validated width. Preserve eax/edx and publish the mask
       in the low half; the high half is an independent 32-bit spill slot. */
    c.Raw({0x50,0x51,0xB8,0x04,0x00,0x00,0x00,0x29,0xC8,
           0xC1,0xE0,0x03,0x89,0xC1,0xB8,0xFF,0xFF,0xFF,0xFF,
           0xD3,0xE8});
    X86StoreD(c, CtxMutationScratch, 0);
    c.Raw({0x59,0x58});
}

void X64ClearLastAlu(CodeBuffer& c) {
    for (uint32_t offset = 0; offset < 40u; offset += 8u) {
        c.Raw({0x49,0xC7,0x87}); c.U32(CtxLastAlu + offset); c.U32(0);
    }
    X64StoreDImmediate(c, CtxLastAlu + 40u, 0);
}

void X64Latch(
    CodeBuffer& c,
    uint8_t a,
    uint8_t b,
    uint8_t result,
    uint8_t auxiliary,
    uint8_t widthRegister)
{
    X64ClearLastAlu(c);
    X64StoreQ(c, RECORD_OFFSET(CtxLastAlu, a), a);
    X64StoreQ(c, RECORD_OFFSET(CtxLastAlu, b), b);
    X64StoreQ(c, RECORD_OFFSET(CtxLastAlu, result), result);
    X64StoreQ(c, RECORD_OFFSET(CtxLastAlu, auxiliary), auxiliary);
    X64StoreDImmediate(c, RECORD_OFFSET(CtxLastAlu, definedMask), 0);
    X64StoreDImmediate(c, RECORD_OFFSET(CtxLastAlu, preserveMask), 0);
    /* mov byte ptr [r15+width], r11b/r8b. */
    const uint8_t rex = static_cast<uint8_t>(0x41u | ((widthRegister & 8u) ? 0x04u : 0u));
    c.Raw({rex,0x88,static_cast<uint8_t>(0x87u | ((widthRegister & 7u) << 3u))});
    c.U32(RECORD_OFFSET(CtxLastAlu, width));
    X64StoreByteImmediate(c, RECORD_OFFSET(CtxLastAlu, valid), 1);
}

void X86ClearLastAlu(CodeBuffer& c) {
    for (uint32_t offset = 0; offset < sizeof(VM_LAZY_FLAGS_RECORD); offset += 4u) {
        X86StoreDImmediate(c, CtxLastAlu + offset, 0);
    }
}

void X86LatchFromStoredOperands(
    CodeBuffer& c,
    uint8_t resultRegister,
    uint8_t auxiliaryRegister,
    uint8_t widthRegister)
{
    X86StoreD(c, RECORD_OFFSET(CtxLastAlu, result), resultRegister);
    X86StoreDImmediate(c, RECORD_OFFSET(CtxLastAlu, result) + 4u, 0);
    X86StoreD(c, RECORD_OFFSET(CtxLastAlu, auxiliary), auxiliaryRegister);
    X86StoreDImmediate(c, RECORD_OFFSET(CtxLastAlu, auxiliary) + 4u, 0);
    c.Raw({0x88,static_cast<uint8_t>(0x87u | ((widthRegister & 7u) << 3u))});
    c.U32(RECORD_OFFSET(CtxLastAlu, width));
    X86StoreByteImmediate(c, RECORD_OFFSET(CtxLastAlu, valid), 1);
}

void X86BeginLatch(CodeBuffer& c, uint8_t aRegister, uint8_t bRegister) {
    X86ClearLastAlu(c);
    X86StoreD(c, RECORD_OFFSET(CtxLastAlu, a), aRegister);
    X86StoreDImmediate(c, RECORD_OFFSET(CtxLastAlu, a) + 4u, 0);
    X86StoreD(c, RECORD_OFFSET(CtxLastAlu, b), bRegister);
    X86StoreDImmediate(c, RECORD_OFFSET(CtxLastAlu, b) + 4u, 0);
}

void X64Move(CodeBuffer& c, uint8_t destination, uint8_t source) {
    const uint8_t rex = static_cast<uint8_t>(0x48u |
        ((source & 8u) ? 0x04u : 0u) | ((destination & 8u) ? 0x01u : 0u));
    c.Raw({rex,0x89,static_cast<uint8_t>(0xC0u | ((source & 7u) << 3u) |
        (destination & 7u))});
}

void X64Binary(CodeBuffer& c, uint8_t opcode, uint8_t destination, uint8_t source) {
    const uint8_t rex = static_cast<uint8_t>(0x48u |
        ((source & 8u) ? 0x04u : 0u) | ((destination & 8u) ? 0x01u : 0u));
    c.Raw({rex,opcode,static_cast<uint8_t>(0xC0u | ((source & 7u) << 3u) |
        (destination & 7u))});
}

void X64Not(CodeBuffer& c, uint8_t reg) {
    const uint8_t rex = static_cast<uint8_t>(0x48u | ((reg & 8u) ? 0x01u : 0u));
    c.Raw({rex,0xF7,static_cast<uint8_t>(0xD0u | (reg & 7u))});
}

void X64Neg(CodeBuffer& c, uint8_t reg) {
    const uint8_t rex = static_cast<uint8_t>(0x48u | ((reg & 8u) ? 0x01u : 0u));
    c.Raw({rex,0xF7,static_cast<uint8_t>(0xD8u | (reg & 7u))});
}

void X64ShiftImmediate(CodeBuffer& c, uint8_t group, uint8_t reg, uint8_t count) {
    const uint8_t rex = static_cast<uint8_t>(0x48u | ((reg & 8u) ? 0x01u : 0u));
    c.Raw({rex,0xC1,static_cast<uint8_t>(0xC0u | (group << 3u) | (reg & 7u)),count});
}

void X64ShiftCl(CodeBuffer& c, uint8_t group, uint8_t reg) {
    const uint8_t rex = static_cast<uint8_t>(0x48u | ((reg & 8u) ? 0x01u : 0u));
    c.Raw({rex,0xD3,static_cast<uint8_t>(0xC0u | (group << 3u) | (reg & 7u))});
}

void X64CallFlagMaterializer(
    CodeBuffer& c,
    uint8_t maskOperand,
    bool immediate,
    uint32_t immediateMask,
    CodeBuffer::Label failure)
{
    X64LoadQ(c, 0, CtxFlagMaterializer);
    c.Raw({0x48,0x85,0xC0}); c.Jcc(JccE, failure);
    c.Raw({0x4C,0x89,0xF9});                 // rcx = context
    if (immediate) { c.Raw({0xBA}); c.U32(immediateMask); }
    else X64LoadD(c, 2, CtxDecodedOperands + static_cast<uint32_t>(maskOperand) * 8u);
    const size_t funcletBegin = c.bytes.size();
    c.Raw({0x48,0x83,0xEC,0x28,0xFF,0xD0,0x48,0x83,0xC4,0x28});
    RecordX64StackFunclet(c, funcletBegin,
        VMHandlerSemanticUnwindKind::StackAllocation,
        kX64FlagCallStackBytes, kX64FlagCallPrologSize);
}

void X86CallFlagMaterializer(
    CodeBuffer& c,
    uint8_t maskOperand,
    bool immediate,
    uint32_t immediateMask,
    CodeBuffer::Label failure)
{
    X86LoadD(c, 0, CtxFlagMaterializer);
    c.Raw({0x85,0xC0}); c.Jcc(JccE, failure);
    if (immediate) { c.Raw({0x68}); c.U32(immediateMask); }
    else { X86LoadD(c, 2, CtxDecodedOperands + static_cast<uint32_t>(maskOperand) * 8u); c.U8(0x52); }
    c.U8(0x57);                               // context
    c.Raw({0xFF,0xD0,0x83,0xC4,0x08});
}

// The selected K core has already placed the requested mask in EDX.  Keeping
// the canonical stack-adjust/call funclet here preserves x64 unwind coverage
// while allowing the live mask data path itself to vary per build.
void X64CallPreparedFlagMaterializer(
    CodeBuffer& c,
    CodeBuffer::Label failure)
{
    X64LoadQ(c, 0, CtxFlagMaterializer);
    c.Raw({0x48,0x85,0xC0}); c.Jcc(JccE, failure);
    c.Raw({0x4C,0x89,0xF9});
    const size_t funcletBegin = c.bytes.size();
    c.Raw({0x48,0x83,0xEC,0x28,0xFF,0xD0,0x48,0x83,0xC4,0x28});
    RecordX64StackFunclet(c, funcletBegin,
        VMHandlerSemanticUnwindKind::StackAllocation,
        kX64FlagCallStackBytes, kX64FlagCallPrologSize);
}

void X86CallPreparedFlagMaterializer(
    CodeBuffer& c,
    CodeBuffer::Label failure)
{
    X86LoadD(c, 0, CtxFlagMaterializer);
    c.Raw({0x85,0xC0}); c.Jcc(JccE, failure);
    c.Raw({0x52,0x57,0xFF,0xD0,0x83,0xC4,0x08});
}

void X64CallFlagMaterializerForPreviousRecord(
    CodeBuffer& c,
    CodeBuffer::Label failure)
{
    X64LoadQ(c, 0, CtxFlagMaterializer);
    c.Raw({0x48,0x85,0xC0}); c.Jcc(JccE, failure);
    c.Raw({0x4C,0x89,0xF9});
    c.Raw({0xBA}); c.U32(VM_FLAG_ARCHITECTURAL_MASK);
    const size_t funcletBegin = c.bytes.size();
    c.Raw({0x48,0x83,0xEC,0x28,0xFF,0xD0,0x48,0x83,0xC4,0x28});
    RecordX64StackFunclet(c, funcletBegin,
        VMHandlerSemanticUnwindKind::StackAllocation,
        kX64FlagCallStackBytes, kX64FlagCallPrologSize);
}

void X86CallFlagMaterializerForPreviousRecord(
    CodeBuffer& c,
    CodeBuffer::Label failure)
{
    X86LoadD(c, 0, CtxFlagMaterializer);
    c.Raw({0x85,0xC0}); c.Jcc(JccE, failure);
    c.Raw({0x68}); c.U32(VM_FLAG_ARCHITECTURAL_MASK);
    c.Raw({0x57,0xFF,0xD0,0x83,0xC4,0x08});
}

void X64EvaluateCondition(
    CodeBuffer& c,
    uint8_t operand,
    CodeBuffer::Label invalid)
{
    uint32_t key = 0;
    if (!DeriveControlDispatchKey(
            c, 0x434F4E4444495350ULL, operand, key)) return;
    std::array<CodeBuffer::Label, VM_CONDITION_G + 1u> cases{};
    for (auto& label : cases) label = c.NewLabel();
    const auto done = c.NewLabel();
    X64LoadByte(c, 1, CtxDecodedOperands + static_cast<uint32_t>(operand) * 8u);
    // Keep dispatch on the live condition value while making every compared
    // representation handler-seed dependent.  LEA is flag-neutral, and a
    // successful equality CMP publishes the same flags as the raw comparison.
    c.Raw({0x48,0x8D,0x89}); c.U32(key);
    for (uint8_t condition = VM_CONDITION_ALWAYS; condition <= VM_CONDITION_G; ++condition) {
        c.Raw({0x48,0x81,0xF9}); c.U32(key + condition);
        c.Jcc(JccE, cases[condition]);
    }
    // Preserve the original invalid-path register and final-CMP flag state.
    c.Raw({0x48,0x8D,0x89}); c.U32(0u - key);
    c.Raw({0x83,0xF9,VM_CONDITION_G});
    c.Jmp(invalid);

    c.Bind(cases[VM_CONDITION_ALWAYS]);
    c.Raw({0xB8,0x01,0x00,0x00,0x00}); c.Jmp(done);
    const auto emitTest = [&](VM_CONDITION condition, uint32_t mask, bool inverse) {
        c.Bind(cases[condition]);
        X64LoadQ(c, 2, CtxVirtualFlags);
        c.Raw({0x48,0xF7,0xC2}); c.U32(mask);
        c.Raw({0x0F,static_cast<uint8_t>(inverse ? 0x94 : 0x95),0xC0,0x0F,0xB6,0xC0});
        c.Jmp(done);
    };
    emitTest(VM_CONDITION_O, VM_FLAG_OF, false);
    emitTest(VM_CONDITION_NO, VM_FLAG_OF, true);
    emitTest(VM_CONDITION_B, VM_FLAG_CF, false);
    emitTest(VM_CONDITION_AE, VM_FLAG_CF, true);
    emitTest(VM_CONDITION_E, VM_FLAG_ZF, false);
    emitTest(VM_CONDITION_NE, VM_FLAG_ZF, true);
    emitTest(VM_CONDITION_BE, VM_FLAG_CF | VM_FLAG_ZF, false);
    emitTest(VM_CONDITION_A, VM_FLAG_CF | VM_FLAG_ZF, true);
    emitTest(VM_CONDITION_S, VM_FLAG_SF, false);
    emitTest(VM_CONDITION_NS, VM_FLAG_SF, true);
    emitTest(VM_CONDITION_P, VM_FLAG_PF, false);
    emitTest(VM_CONDITION_NP, VM_FLAG_PF, true);

    const auto emitSigned = [&](VM_CONDITION condition, bool invert, bool includeZero) {
        c.Bind(cases[condition]);
        X64LoadQ(c, 2, CtxVirtualFlags);
        c.Raw({0x48,0x89,0xD0,0x48,0xC1,0xE8,0x07,0x83,0xE0,0x01,
               0x48,0xC1,0xEA,0x0B,0x83,0xE2,0x01,0x31,0xD0});
        if (invert) c.Raw({0x83,0xF0,0x01});
        if (includeZero) {
            X64LoadQ(c, 2, CtxVirtualFlags);
            c.Raw({0x48,0xC1,0xEA,0x06,0x83,0xE2,0x01,0x09,0xD0});
        } else if (condition == VM_CONDITION_G) {
            X64LoadQ(c, 2, CtxVirtualFlags);
            c.Raw({0x48,0xC1,0xEA,0x06,0x83,0xE2,0x01,0x83,0xF2,0x01,0x21,0xD0});
        }
        c.Jmp(done);
    };
    emitSigned(VM_CONDITION_L, false, false);
    emitSigned(VM_CONDITION_GE, true, false);
    emitSigned(VM_CONDITION_LE, false, true);
    emitSigned(VM_CONDITION_G, true, false);
    c.Bind(done);
}

void X86EvaluateCondition(
    CodeBuffer& c,
    uint8_t operand,
    CodeBuffer::Label invalid)
{
    uint32_t key = 0;
    if (!DeriveControlDispatchKey(
            c, 0x434F4E4444495350ULL, operand, key)) return;
    std::array<CodeBuffer::Label, VM_CONDITION_G + 1u> cases{};
    for (auto& label : cases) label = c.NewLabel();
    const auto done = c.NewLabel();
    X86LoadByte(c, 1, CtxDecodedOperands + static_cast<uint32_t>(operand) * 8u);
    c.Raw({0x8D,0x89}); c.U32(key);
    for (uint8_t condition = VM_CONDITION_ALWAYS; condition <= VM_CONDITION_G; ++condition) {
        c.Raw({0x81,0xF9}); c.U32(key + condition);
        c.Jcc(JccE, cases[condition]);
    }
    c.Raw({0x8D,0x89}); c.U32(0u - key);
    c.Raw({0x83,0xF9,VM_CONDITION_G});
    c.Jmp(invalid);
    c.Bind(cases[VM_CONDITION_ALWAYS]);
    c.Raw({0xB8,0x01,0x00,0x00,0x00}); c.Jmp(done);
    const auto emitTest = [&](VM_CONDITION condition, uint32_t mask, bool inverse) {
        c.Bind(cases[condition]);
        X86LoadD(c, 2, CtxVirtualFlags);
        c.Raw({0xF7,0xC2}); c.U32(mask);
        c.Raw({0x0F,static_cast<uint8_t>(inverse ? 0x94 : 0x95),0xC0,0x0F,0xB6,0xC0});
        c.Jmp(done);
    };
    emitTest(VM_CONDITION_O, VM_FLAG_OF, false);
    emitTest(VM_CONDITION_NO, VM_FLAG_OF, true);
    emitTest(VM_CONDITION_B, VM_FLAG_CF, false);
    emitTest(VM_CONDITION_AE, VM_FLAG_CF, true);
    emitTest(VM_CONDITION_E, VM_FLAG_ZF, false);
    emitTest(VM_CONDITION_NE, VM_FLAG_ZF, true);
    emitTest(VM_CONDITION_BE, VM_FLAG_CF | VM_FLAG_ZF, false);
    emitTest(VM_CONDITION_A, VM_FLAG_CF | VM_FLAG_ZF, true);
    emitTest(VM_CONDITION_S, VM_FLAG_SF, false);
    emitTest(VM_CONDITION_NS, VM_FLAG_SF, true);
    emitTest(VM_CONDITION_P, VM_FLAG_PF, false);
    emitTest(VM_CONDITION_NP, VM_FLAG_PF, true);
    const auto emitSigned = [&](VM_CONDITION condition, bool invert, bool includeZero) {
        c.Bind(cases[condition]);
        X86LoadD(c, 2, CtxVirtualFlags);
        c.Raw({0x89,0xD0,0xC1,0xE8,0x07,0x83,0xE0,0x01,
               0xC1,0xEA,0x0B,0x83,0xE2,0x01,0x31,0xD0});
        if (invert) c.Raw({0x83,0xF0,0x01});
        if (includeZero) {
            X86LoadD(c, 2, CtxVirtualFlags);
            c.Raw({0xC1,0xEA,0x06,0x83,0xE2,0x01,0x09,0xD0});
        } else if (condition == VM_CONDITION_G) {
            X86LoadD(c, 2, CtxVirtualFlags);
            c.Raw({0xC1,0xEA,0x06,0x83,0xE2,0x01,0x83,0xF2,0x01,0x21,0xD0});
        }
        c.Jmp(done);
    };
    emitSigned(VM_CONDITION_L, false, false);
    emitSigned(VM_CONDITION_GE, true, false);
    emitSigned(VM_CONDITION_LE, false, true);
    emitSigned(VM_CONDITION_G, true, false);
    c.Bind(done);
}

void X64ValidateWidth(
    CodeBuffer& c,
    uint8_t operand,
    CodeBuffer::Label invalid)
{
    uint32_t key = 0;
    if (!DeriveControlDispatchKey(
            c, 0x574944544856414CULL, operand, key)) return;
    const auto restoreInvalid = c.NewLabel();
    const auto restoreValid = c.NewLabel();

    X64LoadByte(c, 11, CtxDecodedOperands + static_cast<uint32_t>(operand) * 8u);
    c.Raw({0x4D,0x8D,0x9B}); c.U32(key);
    c.Raw({0x49,0x81,0xFB}); c.U32(key + 1u); c.Jcc(JccE, restoreValid);
    c.Raw({0x49,0x81,0xFB}); c.U32(key + 2u); c.Jcc(JccE, restoreValid);
    c.Raw({0x49,0x81,0xFB}); c.U32(key + 4u); c.Jcc(JccE, restoreValid);
    c.Raw({0x49,0x81,0xFB}); c.U32(key + 8u); c.Jcc(JccE, restoreValid);

    c.Bind(restoreInvalid);
    c.Raw({0x4D,0x8D,0x9B}); c.U32(0u - key);
    c.Raw({0x49,0x83,0xFB,0x08});
    c.Jmp(invalid);

    c.Bind(restoreValid);
    c.Raw({0x4D,0x8D,0x9B}); c.U32(0u - key);
}

void X86ValidateWidth(
    CodeBuffer& c,
    uint8_t operand,
    CodeBuffer::Label invalid)
{
    uint32_t key = 0;
    if (!DeriveControlDispatchKey(
            c, 0x574944544856414CULL, operand, key)) return;
    const auto restoreInvalid = c.NewLabel();
    const auto restoreValid = c.NewLabel();

    X86LoadByte(c, 1, CtxDecodedOperands + static_cast<uint32_t>(operand) * 8u);
    c.Raw({0x8D,0x89}); c.U32(key);
    c.Raw({0x81,0xF9}); c.U32(key + 1u); c.Jcc(JccE, restoreValid);
    c.Raw({0x81,0xF9}); c.U32(key + 2u); c.Jcc(JccE, restoreValid);
    c.Raw({0x81,0xF9}); c.U32(key + 4u); c.Jcc(JccE, restoreValid);

    c.Bind(restoreInvalid);
    c.Raw({0x8D,0x89}); c.U32(0u - key);
    c.Raw({0x83,0xF9,0x04});
    c.Jmp(invalid);

    c.Bind(restoreValid);
    c.Raw({0x8D,0x89}); c.U32(0u - key);
}

void X64CopyRecord(CodeBuffer& c, uint32_t destination, uint32_t source) {
    for (uint32_t offset = 0; offset < 40u; offset += 8u) {
        X64LoadQ(c, 0, source + offset);
        X64StoreQ(c, destination + offset, 0);
    }
    X64LoadD(c, 0, source + 40u);
    X64StoreD(c, destination + 40u, 0);
}

void X86CopyRecord(CodeBuffer& c, uint32_t destination, uint32_t source) {
    for (uint32_t offset = 0; offset < sizeof(VM_LAZY_FLAGS_RECORD); offset += 4u) {
        X86LoadD(c, 0, source + offset);
        X86StoreD(c, destination + offset, 0);
    }
}

bool IsBinaryAlu(VM_MICRO_OPCODE semantic) {
    switch (semantic) {
        case VM_UOP_ADD:
        case VM_UOP_SUB:
        case VM_UOP_MUL:
        case VM_UOP_AND:
        case VM_UOP_OR:
        case VM_UOP_XOR:
        case VM_UOP_SHL:
        case VM_UOP_SHR:
        case VM_UOP_SAR:
        case VM_UOP_ROL:
        case VM_UOP_ROR:
        case VM_UOP_BIT_TEST:
        case VM_UOP_BIT_SET:
        case VM_UOP_BIT_RESET:
            return true;
        default:
            return false;
    }
}

bool IsUnaryAlu(VM_MICRO_OPCODE semantic) {
    return semantic == VM_UOP_NOT || semantic == VM_UOP_NEG ||
        semantic == VM_UOP_BSWAP;
}

bool HasConcreteEmitter(VM_MICRO_OPCODE semantic) {
    switch (semantic) {
        case VM_UOP_PUSH_VREG:
        case VM_UOP_PUSH_IMM:
        case VM_UOP_PUSH_FLAGS:
        case VM_UOP_PUSH_IP:
        case VM_UOP_PUSH_IMAGE_BASE:
        case VM_UOP_POP_VREG:
        case VM_UOP_LOAD_TEMP:
        case VM_UOP_STORE_TEMP:
        case VM_UOP_DUP:
        case VM_UOP_SWAP:
        case VM_UOP_ROT:
        case VM_UOP_DROP:
        case VM_UOP_LOAD:
        case VM_UOP_STORE:
        case VM_UOP_ADD:
        case VM_UOP_ADD_CARRY:
        case VM_UOP_SUB:
        case VM_UOP_SUB_BORROW:
        case VM_UOP_MUL:
        case VM_UOP_UMUL_WIDE:
        case VM_UOP_SMUL_WIDE:
        case VM_UOP_UDIV_WIDE:
        case VM_UOP_IDIV_WIDE:
        case VM_UOP_AND:
        case VM_UOP_OR:
        case VM_UOP_XOR:
        case VM_UOP_NOT:
        case VM_UOP_NEG:
        case VM_UOP_SHL:
        case VM_UOP_SHR:
        case VM_UOP_SAR:
        case VM_UOP_ROL:
        case VM_UOP_ROR:
        case VM_UOP_BIT_TEST:
        case VM_UOP_BIT_SET:
        case VM_UOP_BIT_RESET:
        case VM_UOP_BSWAP:
        case VM_UOP_ZERO_EXTEND:
        case VM_UOP_SIGN_EXTEND:
        case VM_UOP_FLAGS_LAZY:
        case VM_UOP_FLAGS_MATERIALIZE:
        case VM_UOP_FLAGS_WRITE:
        case VM_UOP_FLAGS_UPDATE:
        case VM_UOP_FLAGS_PACK_AH:
        case VM_UOP_FLAGS_UNPACK_AH:
        case VM_UOP_PUSH_CONDITION:
        case VM_UOP_SELECT:
        case VM_UOP_BRANCH:
        case VM_UOP_BRANCH_IF:
        case VM_UOP_CALL_VM:
        case VM_UOP_CALL_HOST:
        case VM_UOP_RET:
        case VM_UOP_EXIT:
        case VM_UOP_BRIDGE_EXTENDED:
        case VM_UOP_RDTSC:
        case VM_UOP_CPUID:
        case VM_UOP_INT3:
            return true;
        case VM_UOP_TRAP:
        case VM_UOP_COUNT:
        default:
            return false;
    }
}

bool ExpectedX64StackFunclet(
    VM_MICRO_OPCODE semantic,
    VMHandlerSemanticStackFunclet& expected)
{
    expected = {};
    switch (semantic) {
        case VM_UOP_PUSH_FLAGS:
        case VM_UOP_FLAGS_LAZY:
        case VM_UOP_FLAGS_MATERIALIZE:
        case VM_UOP_FLAGS_WRITE:
        case VM_UOP_FLAGS_UPDATE:
        case VM_UOP_FLAGS_PACK_AH:
        case VM_UOP_FLAGS_UNPACK_AH:
        case VM_UOP_PUSH_CONDITION:
        case VM_UOP_SELECT:
        case VM_UOP_BRANCH_IF:
            expected.kind = VMHandlerSemanticUnwindKind::StackAllocation;
            expected.stackBytes = kX64FlagCallStackBytes;
            expected.prologSize = kX64FlagCallPrologSize;
            return true;
        case VM_UOP_CALL_HOST:
            expected.kind = VMHandlerSemanticUnwindKind::StackAllocation;
            expected.stackBytes = kX64NativeCallStackBytes;
            expected.prologSize = kX64NativeCallPrologSize;
            return true;
        case VM_UOP_BRIDGE_EXTENDED:
            expected.kind = VMHandlerSemanticUnwindKind::StackAllocation;
            expected.stackBytes = kX64BridgeStackBytes;
            expected.prologSize = kX64BridgePrologSize;
            return true;
        case VM_UOP_CPUID:
            expected.kind = VMHandlerSemanticUnwindKind::PushNonvolatile;
            expected.prologSize = kX64CpuidPrologSize;
            expected.nonvolatileRegister = kX64RbxUnwindRegister;
            return true;
        default:
            return false;
    }
}

void EmitX64SizedShiftOrRotate(
    CodeBuffer& c,
    VM_MICRO_OPCODE semantic,
    CodeBuffer::Label widthFailure)
{
    const WidthLabels width = MakeWidthLabels(c);
    const auto done = c.NewLabel();
    X64DispatchWidth(c, 0, width);
    const auto emit = [&](uint8_t bytes, CodeBuffer::Label label) {
        c.Bind(label);
        c.Raw({0x48,0x89,0xD1});
        uint8_t modrm = 0xE0;
        if (semantic == VM_UOP_SHR) modrm = 0xE8;
        else if (semantic == VM_UOP_SAR) modrm = 0xF8;
        else if (semantic == VM_UOP_ROL) modrm = 0xC0;
        else if (semantic == VM_UOP_ROR) modrm = 0xC8;
        if (bytes == 1u) c.Raw({0xD2,modrm});
        else {
            if (bytes == 2u) c.U8(0x66);
            if (bytes == 8u) c.U8(0x48);
            c.Raw({0xD3,modrm});
        }
        if (bytes == 1u) c.Raw({0x0F,0xB6,0xC0});
        else if (bytes == 2u) c.Raw({0x0F,0xB7,0xC0});
        else if (bytes == 4u) c.Raw({0x89,0xC0});
        c.Jmp(done);
    };
    emit(1, width.width1);
    emit(2, width.width2);
    emit(4, width.width4);
    emit(8, width.width8);
    c.Bind(width.invalid); c.Jmp(widthFailure);
    c.Bind(done);
}

void EmitX86SizedShiftOrRotate(
    CodeBuffer& c,
    VM_MICRO_OPCODE semantic,
    CodeBuffer::Label widthFailure)
{
    const WidthLabels width = MakeWidthLabels(c);
    const auto done = c.NewLabel();
    X86DispatchWidth(c, 0, width);
    const auto emit = [&](uint8_t bytes, CodeBuffer::Label label) {
        c.Bind(label);
        c.Raw({0x89,0xD1});
        uint8_t modrm = 0xE0;
        if (semantic == VM_UOP_SHR) modrm = 0xE8;
        else if (semantic == VM_UOP_SAR) modrm = 0xF8;
        else if (semantic == VM_UOP_ROL) modrm = 0xC0;
        else if (semantic == VM_UOP_ROR) modrm = 0xC8;
        if (bytes == 1u) c.Raw({0xD2,modrm});
        else {
            if (bytes == 2u) c.U8(0x66);
            c.Raw({0xD3,modrm});
        }
        if (bytes == 1u) c.Raw({0x0F,0xB6,0xC0});
        else if (bytes == 2u) c.Raw({0x0F,0xB7,0xC0});
        c.Jmp(done);
    };
    emit(1, width.width1);
    emit(2, width.width2);
    emit(4, width.width4);
    c.Bind(width.invalid); c.Jmp(widthFailure);
    c.Bind(done);
}

void X64LoadMemoryByWidth(
    CodeBuffer& c,
    CodeBuffer::Label widthFailure)
{
    const WidthLabels width = MakeWidthLabels(c);
    const auto done = c.NewLabel();
    X64DispatchWidth(c, 0, width);
    c.Bind(width.width1); c.Raw({0x48,0x0F,0xB6,0x00}); c.Jmp(done);
    c.Bind(width.width2); c.Raw({0x48,0x0F,0xB7,0x00}); c.Jmp(done);
    c.Bind(width.width4); c.Raw({0x8B,0x00}); c.Jmp(done);
    c.Bind(width.width8); c.Raw({0x48,0x8B,0x00}); c.Jmp(done);
    c.Bind(width.invalid); c.Jmp(widthFailure);
    c.Bind(done);
}

void X64StoreMemoryByWidth(
    CodeBuffer& c,
    CodeBuffer::Label widthFailure)
{
    const WidthLabels width = MakeWidthLabels(c);
    const auto done = c.NewLabel();
    X64DispatchWidth(c, 0, width);
    c.Bind(width.width1); c.Raw({0x88,0x10}); c.Jmp(done);
    c.Bind(width.width2); c.Raw({0x66,0x89,0x10}); c.Jmp(done);
    c.Bind(width.width4); c.Raw({0x89,0x10}); c.Jmp(done);
    c.Bind(width.width8); c.Raw({0x48,0x89,0x10}); c.Jmp(done);
    c.Bind(width.invalid); c.Jmp(widthFailure);
    c.Bind(done);
}

void X86LoadMemoryByWidth(CodeBuffer& c, CodeBuffer::Label widthFailure) {
    const WidthLabels width = MakeWidthLabels(c);
    const auto done = c.NewLabel();
    X86DispatchWidth(c, 0, width);
    c.Bind(width.width1); c.Raw({0x0F,0xB6,0x00}); c.Jmp(done);
    c.Bind(width.width2); c.Raw({0x0F,0xB7,0x00}); c.Jmp(done);
    c.Bind(width.width4); c.Raw({0x8B,0x00}); c.Jmp(done);
    c.Bind(width.invalid); c.Jmp(widthFailure);
    c.Bind(done);
}

void X86StoreMemoryByWidth(CodeBuffer& c, CodeBuffer::Label widthFailure) {
    const WidthLabels width = MakeWidthLabels(c);
    const auto done = c.NewLabel();
    X86DispatchWidth(c, 0, width);
    c.Bind(width.width1); c.Raw({0x88,0x10}); c.Jmp(done);
    c.Bind(width.width2); c.Raw({0x66,0x89,0x10}); c.Jmp(done);
    c.Bind(width.width4); c.Raw({0x89,0x10}); c.Jmp(done);
    c.Bind(width.invalid); c.Jmp(widthFailure);
    c.Bind(done);
}

void EmitX64DataSemantic(
    CodeBuffer& c,
    VM_MICRO_OPCODE semantic,
    CodeBuffer::Label stackFailure,
    CodeBuffer::Label widthFailure,
    CodeBuffer::Label rangeFailure,
    CodeBuffer::Label flagsFailure,
    uint8_t coreStrategy,
    uint32_t& coreVariantOffset,
    uint32_t& coreVariantSize)
{
    switch (semantic) {
        case VM_UOP_PUSH_VREG: {
            X64LoadD(c, 10, CtxDecodedOperands);
            c.Raw({0x41,0x83,0xFA,VM_RUNTIME_REGISTER_COUNT});
            c.Jcc(JccAE, rangeFailure);
            X64LoadByte(c, 11, CtxDecodedOperands + 8u);
            X64ValidateWidth(c, 1, widthFailure);
            X64LoadD(c, 1, CtxDecodedOperands + 16u);
            c.Raw({0x41,0x0F,0xB6,0xD3,0xC1,0xE2,0x03,0x01,0xCA,
                   0x83,0xFA,0x40});
            c.Jcc(JccA, rangeFailure);
            X64LoadIndexedQ(c, 0, 10, CtxVregs);
            EmitTrackedBusinessCoreVariant(c, true, semantic, coreStrategy,
                coreVariantOffset, coreVariantSize);
            X64MaskForWidthInR11(c);
            X64Binary(c, 0x21, 0, 9);
            X64PushOne(c, 0, stackFailure);
            return;
        }
        case VM_UOP_PUSH_IMM:
            X64LoadQ(c, 0, CtxDecodedOperands);
            X64ValidateWidth(c, 1, widthFailure);
            X64MaskForWidthInR11(c);
            EmitTrackedBusinessCoreVariant(c, true, semantic, coreStrategy,
                coreVariantOffset, coreVariantSize);
            X64PushOne(c, 0, stackFailure);
            return;
        case VM_UOP_PUSH_FLAGS:
            X64CallFlagMaterializer(c, 0, false, 0, flagsFailure);
            EmitTrackedBusinessCoreVariant(c, true, semantic, coreStrategy,
                coreVariantOffset, coreVariantSize);
            X64PushOne(c, 0, stackFailure);
            return;
        case VM_UOP_PUSH_IP:
            X64LoadQ(c, 0, CtxVip); X64LoadQ(c, 2, CtxBytecodeBegin);
            EmitTrackedBusinessCoreVariant(c, true, semantic, coreStrategy,
                coreVariantOffset, coreVariantSize);
            X64PushOne(c, 0, stackFailure);
            return;
        case VM_UOP_PUSH_IMAGE_BASE:
            EmitTrackedBusinessCoreVariant(c, true, semantic, coreStrategy,
                coreVariantOffset, coreVariantSize);
            X64PushOne(c, 0, stackFailure);
            return;
        case VM_UOP_POP_VREG: {
            X64RequireAndPop(c, 1, stackFailure);
            X64StoreQ(c, CtxMutationScratch, 0);
            X64LoadD(c, 10, CtxDecodedOperands);
            c.Raw({0x41,0x83,0xFA,VM_RUNTIME_REGISTER_COUNT}); c.Jcc(JccAE, rangeFailure);
            X64ValidateWidth(c, 1, widthFailure);
            X64LoadD(c, 1, CtxDecodedOperands + 16u);
            c.Raw({0x41,0x0F,0xB6,0xD3,0xC1,0xE2,0x03,0x01,0xCA,
                   0x83,0xFA,0x40}); c.Jcc(JccA, rangeFailure);
            X64MaskForWidthInR11(c);
            X64LoadQ(c, 0, CtxMutationScratch); X64Binary(c, 0x21, 0, 9);
            X64LoadD(c, 8, CtxDecodedOperands + 24u);
            c.Raw({0x41,0x83,0xF8,0x01}); c.Jcc(JccA, rangeFailure);
            EmitTrackedBusinessCoreVariant(c, true, semantic, coreStrategy,
                coreVariantOffset, coreVariantSize);
            X64StoreIndexedQ(c, CtxVregs, 10, 0);
            return;
        }
        case VM_UOP_LOAD_TEMP:
            X64LoadD(c, 10, CtxDecodedOperands);
            c.Raw({0x41,0x83,0xFA,VM_RUNTIME_TEMP_COUNT}); c.Jcc(JccAE, rangeFailure);
            EmitTrackedBusinessCoreVariant(c, true, semantic, coreStrategy,
                coreVariantOffset, coreVariantSize);
            X64PushOne(c, 0, stackFailure);
            return;
        case VM_UOP_STORE_TEMP:
            X64RequireAndPop(c, 1, stackFailure); X64LoadD(c, 10, CtxDecodedOperands);
            c.Raw({0x41,0x83,0xFA,VM_RUNTIME_TEMP_COUNT}); c.Jcc(JccAE, rangeFailure);
            EmitTrackedBusinessCoreVariant(c, true, semantic, coreStrategy,
                coreVariantOffset, coreVariantSize); return;
        case VM_UOP_DUP:
            X64RequireAndPop(c, 1, stackFailure);
            EmitTrackedBusinessCoreVariant(c, true, semantic, coreStrategy,
                coreVariantOffset, coreVariantSize);
            X64PushTwo(c, 0, 2, stackFailure); return;
        case VM_UOP_SWAP:
            X64RequireAndPop(c, 2, stackFailure);
            EmitTrackedBusinessCoreVariant(c, true, semantic, coreStrategy,
                coreVariantOffset, coreVariantSize);
            X64PushTwo(c, 0, 2, stackFailure); return;
        case VM_UOP_ROT:
            X64RequireAndPop(c, 3, stackFailure);
            EmitTrackedBusinessCoreVariant(c, true, semantic, coreStrategy,
                coreVariantOffset, coreVariantSize);
            X64PushOne(c, 0, stackFailure); X64PushOne(c, 2, stackFailure);
            X64PushOne(c, 8, stackFailure); return;
        case VM_UOP_DROP:
            X64RequireAndPop(c, 1, stackFailure);
            EmitTrackedBusinessCoreVariant(c, true, semantic, coreStrategy,
                coreVariantOffset, coreVariantSize);
            return;
        case VM_UOP_LOAD:
            X64RequireAndPop(c, 1, stackFailure); X64ValidateWidth(c, 0, widthFailure);
            c.Raw({0x48,0x85,0xC0}); c.Jcc(JccE, rangeFailure);
            EmitTrackedBusinessCoreVariant(c, true, semantic, coreStrategy,
                coreVariantOffset, coreVariantSize);
            X64PushOne(c, 0, stackFailure); return;
        case VM_UOP_STORE:
            X64RequireAndPop(c, 2, stackFailure); X64ValidateWidth(c, 0, widthFailure);
            c.Raw({0x48,0x85,0xC0}); c.Jcc(JccE, rangeFailure);
            EmitTrackedBusinessCoreVariant(c, true, semantic, coreStrategy,
                coreVariantOffset, coreVariantSize); return;
        default:
            return;
    }
}

void EmitX86DataSemantic(
    CodeBuffer& c,
    VM_MICRO_OPCODE semantic,
    CodeBuffer::Label stackFailure,
    CodeBuffer::Label widthFailure,
    CodeBuffer::Label rangeFailure,
    CodeBuffer::Label flagsFailure,
    uint8_t coreStrategy,
    uint32_t& coreVariantOffset,
    uint32_t& coreVariantSize)
{
    switch (semantic) {
        case VM_UOP_PUSH_VREG:
            X86LoadD(c, 2, CtxDecodedOperands);
            c.Raw({0x83,0xFA,VM_RUNTIME_REGISTER_COUNT}); c.Jcc(JccAE, rangeFailure);
            X86ValidateWidth(c, 1, widthFailure);
            X86LoadD(c, 1, CtxDecodedOperands + 16u);
            c.Raw({0x0F,0xB6,0x87}); c.U32(CtxDecodedOperands + 8u);
            c.Raw({0xC1,0xE0,0x03,0x01,0xC8,0x83,0xF8,0x20}); c.Jcc(JccA, rangeFailure);
            c.Raw({0x89,0xD1}); X86LoadIndexedD(c, 0, CtxVregs);
            X86LoadD(c, 1, CtxDecodedOperands + 16u);
            EmitTrackedBusinessCoreVariant(c, false, semantic, coreStrategy,
                coreVariantOffset, coreVariantSize);
            X86LoadByte(c, 1, CtxDecodedOperands + 8u); X86BuildMaskInScratch(c);
            c.Raw({0x23,0x87}); c.U32(CtxMutationScratch);
            X86PushOne(c, 0, stackFailure); return;
        case VM_UOP_PUSH_IMM:
            X86LoadD(c, 0, CtxDecodedOperands); X86ValidateWidth(c, 1, widthFailure);
            X86LoadByte(c, 1, CtxDecodedOperands + 8u); X86BuildMaskInScratch(c);
            EmitTrackedBusinessCoreVariant(c, false, semantic, coreStrategy,
                coreVariantOffset, coreVariantSize);
            X86PushOne(c, 0, stackFailure); return;
        case VM_UOP_PUSH_FLAGS:
            X86CallFlagMaterializer(c, 0, false, 0, flagsFailure);
            EmitTrackedBusinessCoreVariant(c, false, semantic, coreStrategy,
                coreVariantOffset, coreVariantSize);
            X86PushOne(c, 0, stackFailure); return;
        case VM_UOP_PUSH_IP:
            X86LoadD(c, 0, CtxVip); X86LoadD(c, 2, CtxBytecodeBegin);
            EmitTrackedBusinessCoreVariant(c, false, semantic, coreStrategy,
                coreVariantOffset, coreVariantSize);
            X86PushOne(c, 0, stackFailure); return;
        case VM_UOP_PUSH_IMAGE_BASE:
            EmitTrackedBusinessCoreVariant(c, false, semantic, coreStrategy,
                coreVariantOffset, coreVariantSize);
            X86PushOne(c, 0, stackFailure); return;
        case VM_UOP_POP_VREG: {
            X86RequireAndPop(c, 1, stackFailure);
            X86StoreD(c, CtxMutationScratch + 4u, 0);
            X86LoadD(c, 2, CtxDecodedOperands);
            c.Raw({0x83,0xFA,VM_RUNTIME_REGISTER_COUNT}); c.Jcc(JccAE, rangeFailure);
            X86ValidateWidth(c, 1, widthFailure);
            X86LoadD(c, 1, CtxDecodedOperands + 16u);
            X86LoadByte(c, 0, CtxDecodedOperands + 8u);
            c.Raw({0xC1,0xE0,0x03,0x01,0xC8,0x83,0xF8,0x20}); c.Jcc(JccA, rangeFailure);
            X86LoadByte(c, 1, CtxDecodedOperands + 8u); X86BuildMaskInScratch(c);
            X86LoadD(c, 0, CtxMutationScratch + 4u);
            c.Raw({0x23,0x87}); c.U32(CtxMutationScratch);
            X86LoadD(c, 1, CtxDecodedOperands + 24u);
            c.Raw({0x83,0xF9,0x01}); c.Jcc(JccA, rangeFailure);
            EmitTrackedBusinessCoreVariant(c, false, semantic, coreStrategy,
                coreVariantOffset, coreVariantSize);
            c.Raw({0x89,0xD1}); X86StoreIndexedD(c, CtxVregs, 0);
            c.Raw({0xC7,0x84,0xCF}); c.U32(CtxVregs + 4u); c.U32(0);
            return;
        }
        case VM_UOP_LOAD_TEMP:
            X86LoadD(c, 1, CtxDecodedOperands);
            c.Raw({0x83,0xF9,VM_RUNTIME_TEMP_COUNT}); c.Jcc(JccAE, rangeFailure);
            EmitTrackedBusinessCoreVariant(c, false, semantic, coreStrategy,
                coreVariantOffset, coreVariantSize);
            X86PushOne(c, 0, stackFailure); return;
        case VM_UOP_STORE_TEMP:
            X86RequireAndPop(c, 1, stackFailure); X86LoadD(c, 1, CtxDecodedOperands);
            c.Raw({0x83,0xF9,VM_RUNTIME_TEMP_COUNT}); c.Jcc(JccAE, rangeFailure);
            EmitTrackedBusinessCoreVariant(c, false, semantic, coreStrategy,
                coreVariantOffset, coreVariantSize);
            c.Raw({0xC7,0x84,0xCF}); c.U32(CtxTemps + 4u); c.U32(0); return;
        case VM_UOP_DUP:
            X86RequireAndPop(c, 1, stackFailure);
            EmitTrackedBusinessCoreVariant(c, false, semantic, coreStrategy,
                coreVariantOffset, coreVariantSize);
            X86PushTwo(c, 0, 2, stackFailure); return;
        case VM_UOP_SWAP:
            X86RequireAndPop(c, 2, stackFailure);
            EmitTrackedBusinessCoreVariant(c, false, semantic, coreStrategy,
                coreVariantOffset, coreVariantSize);
            X86PushTwo(c, 0, 2, stackFailure); return;
        case VM_UOP_ROT:
            X86RequireAndPop(c, 3, stackFailure);
            EmitTrackedBusinessCoreVariant(c, false, semantic, coreStrategy,
                coreVariantOffset, coreVariantSize);
            X86PushOne(c, 0, stackFailure); X86PushOne(c, 2, stackFailure);
            c.Raw({0x89,0xD8}); X86PushOne(c, 0, stackFailure); return;
        case VM_UOP_DROP:
            X86RequireAndPop(c, 1, stackFailure);
            EmitTrackedBusinessCoreVariant(c, false, semantic, coreStrategy,
                coreVariantOffset, coreVariantSize);
            return;
        case VM_UOP_LOAD:
            X86RequireAndPop(c, 1, stackFailure); X86ValidateWidth(c, 0, widthFailure);
            c.Raw({0x85,0xC0}); c.Jcc(JccE, rangeFailure);
            EmitTrackedBusinessCoreVariant(c, false, semantic, coreStrategy,
                coreVariantOffset, coreVariantSize);
            X86PushOne(c, 0, stackFailure); return;
        case VM_UOP_STORE:
            X86RequireAndPop(c, 2, stackFailure); X86ValidateWidth(c, 0, widthFailure);
            c.Raw({0x85,0xC0}); c.Jcc(JccE, rangeFailure);
            EmitTrackedBusinessCoreVariant(c, false, semantic, coreStrategy,
                coreVariantOffset, coreVariantSize); return;
        default: return;
    }
}

void X64FinishPrelatched(
    CodeBuffer& c,
    uint8_t resultRegister,
    uint8_t auxiliaryRegister,
    uint8_t widthRegister)
{
    X64StoreQ(c, RECORD_OFFSET(CtxLastAlu, result), resultRegister);
    X64StoreQ(c, RECORD_OFFSET(CtxLastAlu, auxiliary), auxiliaryRegister);
    const uint8_t rex = static_cast<uint8_t>(0x41u | ((widthRegister & 8u) ? 0x04u : 0u));
    c.Raw({rex,0x88,static_cast<uint8_t>(0x87u | ((widthRegister & 7u) << 3u))});
    c.U32(RECORD_OFFSET(CtxLastAlu, width));
    X64StoreByteImmediate(c, RECORD_OFFSET(CtxLastAlu, valid), 1);
}

void EmitX64BinaryAlu(
    CodeBuffer& c,
    VM_MICRO_OPCODE semantic,
    CodeBuffer::Label stackFailure,
    CodeBuffer::Label widthFailure,
    uint8_t coreStrategy,
    uint32_t& coreVariantOffset,
    uint32_t& coreVariantSize)
{
    X64RequireAndPop(c, 2, stackFailure);
    X64ValidateWidth(c, 0, widthFailure);
    X64MaskForWidthInR11(c);
    X64Binary(c, 0x21, 0, 9); X64Binary(c, 0x21, 2, 9);
    X64Move(c, 8, 0); X64Move(c, 11, 2);
    // Width dispatch for shifts/rotates uses r11d, so latch both original
    // operands before the semantic core is allowed to reuse that register.
    // Keeping b in r11 until the end silently changed a zero count into the
    // operand width and corrupted the subsequent lazy-flags record.
    X64ClearLastAlu(c);
    X64StoreQ(c, RECORD_OFFSET(CtxLastAlu, a), 8);
    X64StoreQ(c, RECORD_OFFSET(CtxLastAlu, b), 11);
    c.Raw({0x45,0x31,0xD2});                  // auxiliary = 0
    coreVariantOffset = static_cast<uint32_t>(c.bytes.size());
    if (EmitTrackedBusinessCoreVariant(c, true, semantic, coreStrategy,
            coreVariantOffset, coreVariantSize)) {
    } else {
        coreVariantOffset = 0;
        switch (semantic) {
            case VM_UOP_SHL:
            case VM_UOP_SHR:
            case VM_UOP_SAR:
            case VM_UOP_ROL:
            case VM_UOP_ROR:
                EmitX64SizedShiftOrRotate(c, semantic, widthFailure);
                break;
            default: break;
        }
    }
    X64Binary(c, 0x21, 0, 9);
    X64LoadByte(c, 1, CtxDecodedOperands);
    X64FinishPrelatched(c, 0, 10, 1);
    X64PushOne(c, 0, stackFailure);
}

void EmitX64CarryAlu(
    CodeBuffer& c,
    VM_MICRO_OPCODE semantic,
    CodeBuffer::Label stackFailure,
    CodeBuffer::Label widthFailure,
    uint8_t coreStrategy,
    uint32_t& coreVariantOffset,
    uint32_t& coreVariantSize)
{
    X64RequireAndPop(c, 3, stackFailure);
    X64ValidateWidth(c, 0, widthFailure); X64MaskForWidthInR11(c);
    X64Binary(c, 0x21, 0, 9); X64Binary(c, 0x21, 2, 9);
    c.Raw({0x49,0x83,0xE0,0x01});
    X64Move(c, 10, 0); X64Move(c, 11, 2);
    EmitTrackedBusinessCoreVariant(c, true, semantic, coreStrategy,
        coreVariantOffset, coreVariantSize);
    X64Binary(c, 0x21, 0, 9);
    X64LoadByte(c, 1, CtxDecodedOperands);
    X64Latch(c, 10, 11, 0, 8, 1); X64PushOne(c, 0, stackFailure);
}

void EmitX64UnaryAlu(
    CodeBuffer& c,
    VM_MICRO_OPCODE semantic,
    CodeBuffer::Label stackFailure,
    CodeBuffer::Label widthFailure,
    uint8_t coreStrategy,
    uint32_t& coreVariantOffset,
    uint32_t& coreVariantSize)
{
    X64RequireAndPop(c, 1, stackFailure); X64ValidateWidth(c, 0, widthFailure);
    X64MaskForWidthInR11(c); X64Binary(c, 0x21, 0, 9); X64Move(c, 8, 0);
    coreVariantOffset = static_cast<uint32_t>(c.bytes.size());
    if (EmitTrackedBusinessCoreVariant(c, true, semantic, coreStrategy,
            coreVariantOffset, coreVariantSize)) {
    } else {
        coreVariantOffset = 0;
        const WidthLabels width = MakeWidthLabels(c); const auto done = c.NewLabel();
        X64DispatchWidth(c, 0, width);
        c.Bind(width.width1); c.Jmp(done);
        c.Bind(width.width2); c.Raw({0x66,0xC1,0xC0,0x08}); c.Jmp(done);
        c.Bind(width.width4); c.Raw({0x0F,0xC8}); c.Jmp(done);
        c.Bind(width.width8); c.Raw({0x48,0x0F,0xC8}); c.Jmp(done);
        c.Bind(width.invalid); c.Jmp(widthFailure); c.Bind(done);
    }
    X64Binary(c, 0x21, 0, 9); c.Raw({0x31,0xD2,0x45,0x31,0xD2});
    X64LoadByte(c, 1, CtxDecodedOperands);
    X64Latch(c, 8, 2, 0, 10, 1); X64PushOne(c, 0, stackFailure);
}

void EmitX64Extend(
    CodeBuffer& c,
    bool signExtend,
    CodeBuffer::Label stackFailure,
    CodeBuffer::Label widthFailure,
    CodeBuffer::Label rangeFailure,
    uint8_t coreStrategy,
    uint32_t& coreVariantOffset,
    uint32_t& coreVariantSize)
{
    X64RequireAndPop(c, 1, stackFailure);
    X64ValidateWidth(c, 0, widthFailure); X64LoadByte(c, 10, CtxDecodedOperands);
    X64ValidateWidth(c, 1, widthFailure);       // r11 = to width
    c.Raw({0x45,0x39,0xDA}); c.Jcc(JccAE, rangeFailure);
    X64MaskForWidthInR11(c);                   // destination mask r9
    X64Move(c, 8, 0);
    EmitTrackedBusinessCoreVariant(c, true,
        signExtend ? VM_UOP_SIGN_EXTEND : VM_UOP_ZERO_EXTEND,
        coreStrategy, coreVariantOffset, coreVariantSize);
    X64LoadByte(c, 11, CtxDecodedOperands + 8u); X64MaskForWidthInR11(c);
    X64Binary(c, 0x21, 0, 9); c.Raw({0x31,0xD2,0x45,0x31,0xD2});
    X64LoadByte(c, 1, CtxDecodedOperands + 8u);
    X64Latch(c, 8, 2, 0, 10, 1); X64PushOne(c, 0, stackFailure);
}

void EmitX64WideMultiply(
    CodeBuffer& c,
    bool signedMultiply,
    CodeBuffer::Label stackFailure,
    CodeBuffer::Label widthFailure,
    uint8_t coreStrategy,
    uint32_t& coreVariantOffset,
    uint32_t& coreVariantSize)
{
    X64RequireAndPop(c, 2, stackFailure); X64ValidateWidth(c, 0, widthFailure);
    X64MaskForWidthInR11(c); X64Binary(c, 0x21, 0, 9); X64Binary(c, 0x21, 2, 9);
    X64Move(c, 8, 0); X64Move(c, 11, 2); X64Move(c, 9, 2);
    const WidthLabels width = MakeWidthLabels(c); const auto product = c.NewLabel();
    const auto split = c.NewLabel(); const auto finish = c.NewLabel();
    X64DispatchWidth(c, 0, width);
    const auto emitNarrow = [&](CodeBuffer::Label label, uint8_t bytes) {
        c.Bind(label);
        if (signedMultiply) {
            if (bytes == 1u) c.Raw({0x48,0x0F,0xBE,0xC0,0x4D,0x0F,0xBE,0xC9});
            else if (bytes == 2u) c.Raw({0x48,0x0F,0xBF,0xC0,0x4D,0x0F,0xBF,0xC9});
            else c.Raw({0x48,0x63,0xC0,0x4D,0x63,0xC9});
            EmitTrackedBusinessCoreVariant(c, true, VM_UOP_SMUL_WIDE,
                coreStrategy, coreVariantOffset, coreVariantSize);
        } else EmitTrackedBusinessCoreVariant(c, true, VM_UOP_UMUL_WIDE,
            coreStrategy, coreVariantOffset, coreVariantSize);
        c.Raw({0x48,0x89,0xC2});
        c.Raw({0xB9}); c.U32(bytes * 8u); c.Raw({0x48,0xD3,0xEA});
        X64LoadByte(c, 11, CtxDecodedOperands); X64MaskForWidthInR11(c);
        X64Binary(c, 0x21, 0, 9); X64Binary(c, 0x21, 2, 9); c.Jmp(finish);
    };
    emitNarrow(width.width1,1); emitNarrow(width.width2,2); emitNarrow(width.width4,4);
    c.Bind(width.width8);
    EmitTrackedBusinessCoreVariant(c, true,
        signedMultiply ? VM_UOP_SMUL_WIDE : VM_UOP_UMUL_WIDE,
        coreStrategy, coreVariantOffset, coreVariantSize);
    c.Jmp(finish);
    c.Bind(width.invalid); c.Jmp(widthFailure);
    c.Bind(product); c.Bind(split);
    c.Bind(finish);
    X64LoadByte(c, 1, CtxDecodedOperands);
    X64Latch(c, 8, 11, 0, 2, 1); X64PushTwo(c, 0, 2, stackFailure);
}

void EmitX64WideDivide(
    CodeBuffer& c,
    bool signedDivide,
    CodeBuffer::Label stackFailure,
    CodeBuffer::Label widthFailure,
    CodeBuffer::Label divideFailure,
    uint8_t coreStrategy,
    uint32_t& coreVariantOffset,
    uint32_t& coreVariantSize)
{
    X64RequireAndPop(c, 3, stackFailure);       // rax=high, rdx=low, r8=divisor
    X64ValidateWidth(c, 0, widthFailure); X64MaskForWidthInR11(c);
    X64Binary(c, 0x21, 0, 9); X64Binary(c, 0x21, 2, 9); X64Binary(c, 0x21, 8, 9);
    X64ClearLastAlu(c); X64StoreQ(c, RECORD_OFFSET(CtxLastAlu, a), 0);
    X64StoreQ(c, RECORD_OFFSET(CtxLastAlu, b), 8);
    X64StoreQ(c, CtxMutationScratch, 8);
    const WidthLabels width = MakeWidthLabels(c); const auto finish = c.NewLabel();
    X64DispatchWidth(c, 0, width);
    const auto emitNarrow = [&](CodeBuffer::Label label, uint8_t bytes) {
        c.Bind(label);
        X64Move(c, 10, 0); c.Raw({0xB9}); c.U32(bytes * 8u); X64ShiftCl(c, 4, 10);
        X64Binary(c, 0x09, 10, 2); X64Move(c, 0, 10);
        X64LoadQ(c, 9, CtxMutationScratch);
        if (signedDivide) {
            if (bytes == 1u) c.Raw({0x48,0x0F,0xBF,0xC0,0x4D,0x0F,0xBE,0xC9});
            else if (bytes == 2u) c.Raw({0x48,0x63,0xC0,0x4D,0x0F,0xBF,0xC9});
            else c.Raw({0x4D,0x63,0xC9});
            c.Raw({0x4D,0x85,0xC9}); c.Jcc(JccE, divideFailure);
            const auto safe = c.NewLabel();
            c.Raw({0x48,0xBA,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x80,
                   0x48,0x39,0xD0}); c.Jcc(JccNE, safe);
            c.Raw({0x49,0x83,0xF9,0xFF}); c.Jcc(JccE, divideFailure); c.Bind(safe);
            c.Raw({0x48,0x99});
            EmitTrackedBusinessCoreVariant(c, true, VM_UOP_IDIV_WIDE,
                coreStrategy, coreVariantOffset, coreVariantSize);
        } else {
            c.Raw({0x4D,0x85,0xC9}); c.Jcc(JccE, divideFailure);
            c.Raw({0x31,0xD2});
            EmitTrackedBusinessCoreVariant(c, true, VM_UOP_UDIV_WIDE,
                coreStrategy, coreVariantOffset, coreVariantSize);
        }
        X64LoadByte(c, 11, CtxDecodedOperands); X64MaskForWidthInR11(c);
        if (signedDivide) {
            X64Move(c, 10, 0); X64Binary(c, 0x21, 10, 9);
            c.Raw({0xB9}); c.U32(8u - bytes); c.Raw({0xC1,0xE1,0x03});
            X64ShiftCl(c, 4, 10); X64ShiftCl(c, 7, 10);
            c.Raw({0x49,0x39,0xC2}); c.Jcc(JccNE, divideFailure);
        } else {
            X64Move(c, 10, 0); X64Binary(c, 0x21, 10, 9);
            c.Raw({0x49,0x39,0xC2}); c.Jcc(JccNE, divideFailure);
        }
        X64Binary(c, 0x21, 0, 9); X64Binary(c, 0x21, 2, 9); c.Jmp(finish);
    };
    emitNarrow(width.width1,1); emitNarrow(width.width2,2); emitNarrow(width.width4,4);
    c.Bind(width.width8);
    X64LoadQ(c, 9, CtxMutationScratch);
    if (!signedDivide) {
        c.Raw({0x4D,0x85,0xC9}); c.Jcc(JccE, divideFailure);
        c.Raw({0x4C,0x39,0xC8}); c.Jcc(JccAE, divideFailure);
        X64Move(c, 10, 0); X64Move(c, 0, 2); X64Move(c, 2, 10);
        EmitTrackedBusinessCoreVariant(c, true, VM_UOP_UDIV_WIDE,
            coreStrategy, coreVariantOffset, coreVariantSize);
    } else {
        c.Raw({0x4D,0x85,0xC9}); c.Jcc(JccE, divideFailure);
        // The VM stack is unpacked as RAX=high,RDX=low; IDIV requires the
        // opposite register placement RDX:RAX=high:low.  Keep the original
        // signed bit pattern and only swap the halves here.  This is correct
        // for the INT64_MIN divisor, whose magnitude cannot be represented as
        // a positive int64.  Hardware #DE remains the required VM behavior for
        // divisor zero and quotient overflow.
        X64Move(c, 10, 0); X64Move(c, 0, 2); X64Move(c, 2, 10);
        EmitTrackedBusinessCoreVariant(c, true, VM_UOP_IDIV_WIDE,
            coreStrategy, coreVariantOffset, coreVariantSize);
    }
    c.Jmp(finish);
    c.Bind(width.invalid); c.Jmp(widthFailure);
    c.Bind(finish);
    X64LoadByte(c, 1, CtxDecodedOperands); X64FinishPrelatched(c, 0, 2, 1);
    X64PushTwo(c, 0, 2, stackFailure);
}

void EmitX86BinaryAlu(
    CodeBuffer& c,
    VM_MICRO_OPCODE semantic,
    CodeBuffer::Label stackFailure,
    CodeBuffer::Label widthFailure,
    uint8_t coreStrategy,
    uint32_t& coreVariantOffset,
    uint32_t& coreVariantSize)
{
    X86RequireAndPop(c, 2, stackFailure); X86ValidateWidth(c, 0, widthFailure);
    X86LoadByte(c, 1, CtxDecodedOperands); X86BuildMaskInScratch(c);
    c.Raw({0x23,0x87}); c.U32(CtxMutationScratch);
    c.Raw({0x23,0x97}); c.U32(CtxMutationScratch);
    X86BeginLatch(c, 0, 2);
    coreVariantOffset = static_cast<uint32_t>(c.bytes.size());
    if (EmitTrackedBusinessCoreVariant(c, false, semantic, coreStrategy,
            coreVariantOffset, coreVariantSize)) {
    } else {
        coreVariantOffset = 0;
        switch (semantic) {
            case VM_UOP_SHL:
            case VM_UOP_SHR:
            case VM_UOP_SAR:
            case VM_UOP_ROL:
            case VM_UOP_ROR:
                EmitX86SizedShiftOrRotate(c, semantic, widthFailure);
                break;
            default: break;
        }
    }
    c.Raw({0x23,0x87}); c.U32(CtxMutationScratch);
    X86LoadD(c, 2, CtxMutationScratch + 4u);
    if (semantic != VM_UOP_BIT_TEST && semantic != VM_UOP_BIT_SET &&
        semantic != VM_UOP_BIT_RESET) c.Raw({0x31,0xD2});
    X86LoadByte(c, 1, CtxDecodedOperands);
    X86LatchFromStoredOperands(c, 0, 2, 1); X86PushOne(c, 0, stackFailure);
}

void EmitX86CarryAlu(
    CodeBuffer& c,
    VM_MICRO_OPCODE semantic,
    CodeBuffer::Label stackFailure,
    CodeBuffer::Label widthFailure,
    uint8_t coreStrategy,
    uint32_t& coreVariantOffset,
    uint32_t& coreVariantSize)
{
    X86RequireAndPop(c, 3, stackFailure);       // eax=a, edx=b, ecx=carry
    X86StoreD(c, CtxMutationScratch + 4u, 1);
    X86ValidateWidth(c, 0, widthFailure);
    X86LoadByte(c, 3, CtxDecodedOperands);     // ebx=width
    c.Raw({0x89,0xD9}); X86BuildMaskInScratch(c);
    c.Raw({0x23,0x87}); c.U32(CtxMutationScratch);
    c.Raw({0x23,0x97}); c.U32(CtxMutationScratch);
    X86BeginLatch(c, 0, 2);
    X86LoadD(c, 1, CtxMutationScratch + 4u); c.Raw({0x83,0xE1,0x01});
    EmitTrackedBusinessCoreVariant(c, false, semantic, coreStrategy,
        coreVariantOffset, coreVariantSize);
    c.Raw({0x23,0x87}); c.U32(CtxMutationScratch);
    c.Raw({0x89,0xCA}); X86LoadByte(c, 1, CtxDecodedOperands);
    X86LatchFromStoredOperands(c, 0, 2, 1); X86PushOne(c, 0, stackFailure);
}

void EmitX86UnaryAlu(
    CodeBuffer& c,
    VM_MICRO_OPCODE semantic,
    CodeBuffer::Label stackFailure,
    CodeBuffer::Label widthFailure,
    uint8_t coreStrategy,
    uint32_t& coreVariantOffset,
    uint32_t& coreVariantSize)
{
    X86RequireAndPop(c, 1, stackFailure); X86ValidateWidth(c, 0, widthFailure);
    X86LoadByte(c, 1, CtxDecodedOperands); X86BuildMaskInScratch(c);
    c.Raw({0x23,0x87}); c.U32(CtxMutationScratch); c.Raw({0x31,0xD2});
    X86BeginLatch(c, 0, 2);
    coreVariantOffset = static_cast<uint32_t>(c.bytes.size());
    if (EmitTrackedBusinessCoreVariant(c, false, semantic, coreStrategy,
            coreVariantOffset, coreVariantSize)) {
    } else {
        coreVariantOffset = 0;
        const WidthLabels width = MakeWidthLabels(c); const auto done = c.NewLabel();
        X86DispatchWidth(c, 0, width);
        c.Bind(width.width1); c.Jmp(done);
        c.Bind(width.width2); c.Raw({0x66,0xC1,0xC0,0x08}); c.Jmp(done);
        c.Bind(width.width4); c.Raw({0x0F,0xC8}); c.Jmp(done);
        c.Bind(width.invalid); c.Jmp(widthFailure); c.Bind(done);
    }
    c.Raw({0x23,0x87}); c.U32(CtxMutationScratch); c.Raw({0x31,0xD2});
    X86LoadByte(c, 1, CtxDecodedOperands);
    X86LatchFromStoredOperands(c, 0, 2, 1); X86PushOne(c, 0, stackFailure);
}

void EmitX86Extend(
    CodeBuffer& c,
    bool signExtend,
    CodeBuffer::Label stackFailure,
    CodeBuffer::Label widthFailure,
    CodeBuffer::Label rangeFailure,
    uint8_t coreStrategy,
    uint32_t& coreVariantOffset,
    uint32_t& coreVariantSize)
{
    X86RequireAndPop(c, 1, stackFailure); X86StoreD(c, CtxMutationScratch + 4u, 0);
    X86ValidateWidth(c, 0, widthFailure); X86LoadByte(c, 2, CtxDecodedOperands);
    X86ValidateWidth(c, 1, widthFailure); X86LoadByte(c, 1, CtxDecodedOperands + 8u);
    c.Raw({0x39,0xCA}); c.Jcc(JccAE, rangeFailure);
    X86LoadD(c, 0, CtxMutationScratch + 4u); c.Raw({0x31,0xD2}); X86BeginLatch(c, 0, 2);
    EmitTrackedBusinessCoreVariant(c, false,
        signExtend ? VM_UOP_SIGN_EXTEND : VM_UOP_ZERO_EXTEND,
        coreStrategy, coreVariantOffset, coreVariantSize);
    X86LoadByte(c, 1, CtxDecodedOperands + 8u); X86BuildMaskInScratch(c);
    c.Raw({0x23,0x87}); c.U32(CtxMutationScratch); c.Raw({0x31,0xD2});
    X86LoadByte(c, 1, CtxDecodedOperands + 8u);
    X86LatchFromStoredOperands(c, 0, 2, 1); X86PushOne(c, 0, stackFailure);
}

void EmitX86WideMultiply(
    CodeBuffer& c,
    bool signedMultiply,
    CodeBuffer::Label stackFailure,
    CodeBuffer::Label widthFailure,
    uint8_t coreStrategy,
    uint32_t& coreVariantOffset,
    uint32_t& coreVariantSize)
{
    X86RequireAndPop(c, 2, stackFailure); X86ValidateWidth(c, 0, widthFailure);
    X86LoadByte(c, 1, CtxDecodedOperands); X86BuildMaskInScratch(c);
    c.Raw({0x23,0x87}); c.U32(CtxMutationScratch); c.Raw({0x23,0x97}); c.U32(CtxMutationScratch);
    X86BeginLatch(c, 0, 2); c.Raw({0x89,0xD1});
    const WidthLabels width = MakeWidthLabels(c); const auto finish = c.NewLabel();
    X86DispatchWidth(c, 0, width);
    const auto narrow = [&](CodeBuffer::Label label, uint8_t bytes) {
        c.Bind(label);
        X86LoadD(c, 1, RECORD_OFFSET(CtxLastAlu, b));
        if (signedMultiply) {
            if (bytes == 1u) c.Raw({0x0F,0xBE,0xC0,0x0F,0xBE,0xC9});
            else c.Raw({0x0F,0xBF,0xC0,0x0F,0xBF,0xC9});
            EmitTrackedBusinessCoreVariant(c, false, VM_UOP_SMUL_WIDE,
                coreStrategy, coreVariantOffset, coreVariantSize);
        } else EmitTrackedBusinessCoreVariant(c, false, VM_UOP_UMUL_WIDE,
            coreStrategy, coreVariantOffset, coreVariantSize);
        c.Raw({0x89,0xC2,0xB9}); c.U32(bytes * 8u); c.Raw({0xD3,0xEA});
        X86LoadByte(c, 1, CtxDecodedOperands); X86BuildMaskInScratch(c);
        c.Raw({0x23,0x87}); c.U32(CtxMutationScratch); c.Raw({0x23,0x97}); c.U32(CtxMutationScratch);
        c.Jmp(finish);
    };
    narrow(width.width1,1); narrow(width.width2,2);
    c.Bind(width.width4); X86LoadD(c, 1, RECORD_OFFSET(CtxLastAlu, b));
    EmitTrackedBusinessCoreVariant(c, false,
        signedMultiply ? VM_UOP_SMUL_WIDE : VM_UOP_UMUL_WIDE,
        coreStrategy, coreVariantOffset, coreVariantSize);
    c.Jmp(finish);
    c.Bind(width.invalid); c.Jmp(widthFailure); c.Bind(finish);
    X86LoadByte(c, 1, CtxDecodedOperands);
    X86LatchFromStoredOperands(c, 0, 2, 1); X86PushTwo(c, 0, 2, stackFailure);
}

void EmitX86WideDivide(
    CodeBuffer& c,
    bool signedDivide,
    CodeBuffer::Label stackFailure,
    CodeBuffer::Label widthFailure,
    CodeBuffer::Label divideFailure,
    uint8_t coreStrategy,
    uint32_t& coreVariantOffset,
    uint32_t& coreVariantSize)
{
    X86RequireAndPop(c, 3, stackFailure);       // eax=high, edx=low, ecx=divisor
    X86BeginLatch(c, 0, 1);                    // preserve high and divisor
    X86ValidateWidth(c, 0, widthFailure);
    X86LoadByte(c, 1, CtxDecodedOperands); X86BuildMaskInScratch(c);
    c.Raw({0x23,0x87}); c.U32(CtxMutationScratch); c.Raw({0x23,0x97}); c.U32(CtxMutationScratch);
    X86LoadD(c, 1, RECORD_OFFSET(CtxLastAlu, b)); c.Raw({0x23,0x8F}); c.U32(CtxMutationScratch);
    const WidthLabels width = MakeWidthLabels(c); const auto finish = c.NewLabel();
    X86DispatchWidth(c, 0, width);
    const auto narrow = [&](CodeBuffer::Label label, uint8_t bytes) {
        c.Bind(label); X86LoadD(c, 3, RECORD_OFFSET(CtxLastAlu, b));
        c.Raw({0x89,0xC6,0xB9}); c.U32(bytes * 8u);
        c.Raw({0xD3,0xE6,0x09,0xD6,0x89,0xF0,0x89,0xD9});
        if (signedDivide) {
            if (bytes == 1u) c.Raw({0x0F,0xBF,0xC0,0x0F,0xBE,0xCB});
            else c.Raw({0x0F,0xBF,0xCB});
            c.Raw({0x85,0xC9}); c.Jcc(JccE, divideFailure);
            c.Raw({0x99});
            EmitTrackedBusinessCoreVariant(c, false, VM_UOP_IDIV_WIDE,
                coreStrategy, coreVariantOffset, coreVariantSize);
        } else {
            c.Raw({0x85,0xC9}); c.Jcc(JccE, divideFailure);
            c.Raw({0x31,0xD2});
            EmitTrackedBusinessCoreVariant(c, false, VM_UOP_UDIV_WIDE,
                coreStrategy, coreVariantOffset, coreVariantSize);
        }
        // Native 32-bit DIV/IDIV only checks whether the quotient fits EAX;
        // the VM operation additionally requires it to fit the requested
        // 8/16-bit destination.  Compare the full quotient with its explicit
        // zero/sign extension before truncating, so narrow overflow keeps the
        // architectural #DE contract on x86 as it already does on x64.
        if (bytes == 1u) {
            c.Raw(signedDivide
                ? std::initializer_list<uint8_t>{0x0F,0xBE,0xF0}
                : std::initializer_list<uint8_t>{0x0F,0xB6,0xF0});
        } else {
            c.Raw(signedDivide
                ? std::initializer_list<uint8_t>{0x0F,0xBF,0xF0}
                : std::initializer_list<uint8_t>{0x0F,0xB7,0xF0});
        }
        c.Raw({0x39,0xC6}); c.Jcc(JccNE, divideFailure);
        X86LoadByte(c, 1, CtxDecodedOperands); X86BuildMaskInScratch(c);
        c.Raw({0x23,0x87}); c.U32(CtxMutationScratch); c.Raw({0x23,0x97}); c.U32(CtxMutationScratch);
        c.Jmp(finish);
    };
    narrow(width.width1,1); narrow(width.width2,2);
    c.Bind(width.width4);
    X86LoadD(c, 1, RECORD_OFFSET(CtxLastAlu, b));
    c.Raw({0x85,0xC9}); c.Jcc(JccE, divideFailure);
    if (!signedDivide) {
        c.Raw({0x39,0xC8}); c.Jcc(JccAE, divideFailure);
        c.Raw({0x89,0xC6,0x89,0xD0,0x89,0xF2});
        EmitTrackedBusinessCoreVariant(c, false, VM_UOP_UDIV_WIDE,
            coreStrategy, coreVariantOffset, coreVariantSize);
    } else {
        // The VM stack is unpacked as EAX=high,EDX=low; put the original
        // signed halves in IDIV's required EDX:EAX=high:low order.  Direct
        // IDIV preserves the INT32_MIN-divisor meaning and raises the
        // architecturally required #DE for zero or quotient overflow.
        c.Raw({0x89,0xC6,0x89,0xD0,0x89,0xF2});
        EmitTrackedBusinessCoreVariant(c, false, VM_UOP_IDIV_WIDE,
            coreStrategy, coreVariantOffset, coreVariantSize);
    }
    c.Jmp(finish);
    c.Bind(width.invalid); c.Jmp(widthFailure); c.Bind(finish);
    X86LoadByte(c, 1, CtxDecodedOperands);
    X86LatchFromStoredOperands(c, 0, 2, 1); X86PushTwo(c, 0, 2, stackFailure);
}

void EmitX64FlagsSemantic(
    CodeBuffer& c,
    VM_MICRO_OPCODE semantic,
    CodeBuffer::Label stackFailure,
    CodeBuffer::Label widthFailure,
    CodeBuffer::Label rangeFailure,
    CodeBuffer::Label flagsFailure,
    uint8_t coreStrategy,
    uint32_t& coreVariantOffset,
    uint32_t& coreVariantSize)
{
    switch (semantic) {
        case VM_UOP_PUSH_FLAGS:
            X64CallFlagMaterializer(c, 0, false, 0, flagsFailure);
            EmitTrackedBusinessCoreVariant(c, true, semantic, coreStrategy,
                coreVariantOffset, coreVariantSize);
            X64PushOne(c, 0, stackFailure);
            return;
        case VM_UOP_FLAGS_LAZY: {
            X64LoadByte(c, 0, RECORD_OFFSET(CtxLastAlu, valid));
            c.Raw({0x85,0xC0}); c.Jcc(JccE, flagsFailure);
            X64CallFlagMaterializerForPreviousRecord(c, flagsFailure);
            X64LoadByte(c, 0, CtxDecodedOperands);
            c.Raw({0x83,0xF8,VM_LAZY_ADD}); c.Jcc(JccB, flagsFailure);
            c.Raw({0x83,0xF8,VM_LAZY_BIT_TEST}); c.Jcc(JccA, flagsFailure);
            X64ValidateWidth(c, 1, widthFailure);
            X64LoadD(c, 1, CtxDecodedOperands + 16u);
            X64LoadD(c, 2, CtxDecodedOperands + 24u);
            c.Raw({0x89,0xC8,0x09,0xD0,0xA9});
            c.U32(~static_cast<uint32_t>(VM_FLAG_ARCHITECTURAL_MASK));
            c.Jcc(JccNE, flagsFailure); c.Raw({0x85,0xD1}); c.Jcc(JccNE, flagsFailure);
            EmitTrackedBusinessCoreVariant(c, true, semantic, coreStrategy,
                coreVariantOffset, coreVariantSize);
            X64LoadByte(c, 0, CtxDecodedOperands); X64StoreByteRegister(c,
                RECORD_OFFSET(CtxPendingFlags, operation), 0);
            X64LoadByte(c, 0, CtxDecodedOperands + 8u); X64StoreByteRegister(c,
                RECORD_OFFSET(CtxPendingFlags, width), 0);
            X64LoadD(c, 0, CtxDecodedOperands + 16u); X64StoreD(c,
                RECORD_OFFSET(CtxPendingFlags, definedMask), 0);
            X64LoadD(c, 0, CtxDecodedOperands + 24u); X64StoreD(c,
                RECORD_OFFSET(CtxPendingFlags, preserveMask), 0);
            X64StoreByteImmediate(c, RECORD_OFFSET(CtxPendingFlags, valid), 1);
            return;
        }
        case VM_UOP_FLAGS_MATERIALIZE:
            EmitTrackedBusinessCoreVariant(c, true, semantic, coreStrategy,
                coreVariantOffset, coreVariantSize);
            X64CallPreparedFlagMaterializer(c, flagsFailure); return;
        case VM_UOP_FLAGS_WRITE: {
            X64RequireAndPop(c, 1, stackFailure); X64StoreQ(c, CtxMutationScratch, 0);
            X64CallFlagMaterializer(c, 0, true, VM_FLAG_ARCHITECTURAL_MASK, flagsFailure);
            X64LoadQ(c, 1, CtxDecodedOperands); X64LoadQ(c, 0, CtxVirtualFlags);
            X64LoadQ(c, 2, CtxMutationScratch);
            EmitTrackedBusinessCoreVariant(c, true, semantic, coreStrategy,
                coreVariantOffset, coreVariantSize);
            X64StoreQ(c, CtxVirtualFlags, 0);
            X64StoreByteImmediate(c, RECORD_OFFSET(CtxPendingFlags, valid), 0); return;
        }
        case VM_UOP_FLAGS_UPDATE: {
            X64CallFlagMaterializer(c, 0, true,
                VM_FLAG_ARCHITECTURAL_MASK, flagsFailure);
            X64LoadD(c, 1, CtxDecodedOperands); c.Raw({0x83,0xF9,VM_FLAG_UPDATE_TOGGLE});
            c.Jcc(JccA, rangeFailure);
            X64LoadQ(c, 2, CtxDecodedOperands + 8u); X64LoadQ(c, 0, CtxVirtualFlags);
            EmitTrackedBusinessCoreVariant(c, true, semantic, coreStrategy,
                coreVariantOffset, coreVariantSize);
            X64StoreQ(c, CtxVirtualFlags, 0);
            X64StoreByteImmediate(c, RECORD_OFFSET(CtxPendingFlags, valid), 0); return;
        }
        case VM_UOP_FLAGS_PACK_AH: {
            X64CallFlagMaterializer(c, 0, true,
                VM_FLAG_SF | VM_FLAG_ZF | VM_FLAG_AF | VM_FLAG_PF | VM_FLAG_CF, flagsFailure);
            X64LoadQ(c, 2, CtxVirtualFlags);
            EmitTrackedBusinessCoreVariant(c, true, semantic, coreStrategy,
                coreVariantOffset, coreVariantSize);
            X64PushOne(c, 0, stackFailure); return;
        }
        case VM_UOP_FLAGS_UNPACK_AH: {
            X64RequireAndPop(c, 1, stackFailure); X64StoreQ(c, CtxMutationScratch, 0);
            X64CallFlagMaterializer(c, 0, true,
                VM_FLAG_ARCHITECTURAL_MASK, flagsFailure);
            X64LoadQ(c, 0, CtxMutationScratch); X64LoadQ(c, 2, CtxVirtualFlags);
            EmitTrackedBusinessCoreVariant(c, true, semantic, coreStrategy,
                coreVariantOffset, coreVariantSize);
            X64StoreQ(c, CtxVirtualFlags, 2);
            X64StoreByteImmediate(c, RECORD_OFFSET(CtxPendingFlags, valid), 0); return;
        }
        case VM_UOP_PUSH_CONDITION:
            X64CallFlagMaterializer(c, 0, true, VM_FLAG_STATUS_MASK, flagsFailure);
            X64EvaluateCondition(c, 0, rangeFailure);
            EmitTrackedBusinessCoreVariant(c, true, semantic, coreStrategy,
                coreVariantOffset, coreVariantSize);
            X64PushOne(c, 0, stackFailure); return;
        case VM_UOP_SELECT: {
            X64CallFlagMaterializer(c, 0, true, VM_FLAG_STATUS_MASK, flagsFailure);
            X64EvaluateCondition(c, 0, rangeFailure); X64Move(c, 10, 0);
            X64RequireAndPop(c, 2, stackFailure);
            EmitTrackedBusinessCoreVariant(c, true, semantic, coreStrategy,
                coreVariantOffset, coreVariantSize);
            X64PushOne(c, 0, stackFailure); return;
        }
        default: return;
    }
}

void EmitX86FlagsSemantic(
    CodeBuffer& c,
    VM_MICRO_OPCODE semantic,
    CodeBuffer::Label stackFailure,
    CodeBuffer::Label widthFailure,
    CodeBuffer::Label rangeFailure,
    CodeBuffer::Label flagsFailure,
    uint8_t coreStrategy,
    uint32_t& coreVariantOffset,
    uint32_t& coreVariantSize)
{
    switch (semantic) {
        case VM_UOP_PUSH_FLAGS:
            X86CallFlagMaterializer(c, 0, false, 0, flagsFailure);
            EmitTrackedBusinessCoreVariant(c, false, semantic, coreStrategy,
                coreVariantOffset, coreVariantSize);
            X86PushOne(c, 0, stackFailure);
            return;
        case VM_UOP_FLAGS_LAZY:
            X86LoadByte(c, 0, RECORD_OFFSET(CtxLastAlu, valid)); c.Raw({0x85,0xC0}); c.Jcc(JccE, flagsFailure);
            X86CallFlagMaterializerForPreviousRecord(c, flagsFailure);
            X86LoadByte(c, 0, CtxDecodedOperands); c.Raw({0x83,0xF8,VM_LAZY_ADD}); c.Jcc(JccB, flagsFailure);
            c.Raw({0x83,0xF8,VM_LAZY_BIT_TEST}); c.Jcc(JccA, flagsFailure);
            X86ValidateWidth(c, 1, widthFailure);
            X86LoadD(c, 1, CtxDecodedOperands + 16u); X86LoadD(c, 2, CtxDecodedOperands + 24u);
            c.Raw({0x89,0xC8,0x09,0xD0,0xA9});
            c.U32(~static_cast<uint32_t>(VM_FLAG_ARCHITECTURAL_MASK));
            c.Jcc(JccNE, flagsFailure);
            c.Raw({0x85,0xD1}); c.Jcc(JccNE, flagsFailure);
            EmitTrackedBusinessCoreVariant(c, false, semantic, coreStrategy,
                coreVariantOffset, coreVariantSize);
            X86LoadByte(c, 0, CtxDecodedOperands); X86StoreByteRegister(c, RECORD_OFFSET(CtxPendingFlags, operation), 0);
            X86LoadByte(c, 0, CtxDecodedOperands + 8u); X86StoreByteRegister(c, RECORD_OFFSET(CtxPendingFlags, width), 0);
            X86LoadD(c, 0, CtxDecodedOperands + 16u); X86StoreD(c, RECORD_OFFSET(CtxPendingFlags, definedMask), 0);
            X86LoadD(c, 0, CtxDecodedOperands + 24u); X86StoreD(c, RECORD_OFFSET(CtxPendingFlags, preserveMask), 0);
            X86StoreByteImmediate(c, RECORD_OFFSET(CtxPendingFlags, valid), 1); return;
        case VM_UOP_FLAGS_MATERIALIZE:
            EmitTrackedBusinessCoreVariant(c,false,semantic,coreStrategy,
                coreVariantOffset,coreVariantSize);
            X86CallPreparedFlagMaterializer(c,flagsFailure); return;
        case VM_UOP_FLAGS_WRITE:
            X86RequireAndPop(c,1,stackFailure); X86StoreD(c,CtxMutationScratch,0);
            X86CallFlagMaterializer(c,0,true,VM_FLAG_ARCHITECTURAL_MASK,flagsFailure);
            X86LoadD(c,1,CtxDecodedOperands); X86LoadD(c,0,CtxVirtualFlags);
            X86LoadD(c,2,CtxMutationScratch);
            EmitTrackedBusinessCoreVariant(c,false,semantic,coreStrategy,
                coreVariantOffset,coreVariantSize);
            X86StoreD(c,CtxVirtualFlags,0);
            X86StoreByteImmediate(c,RECORD_OFFSET(CtxPendingFlags,valid),0); return;
        case VM_UOP_FLAGS_UPDATE: {
            X86CallFlagMaterializer(c,0,true,VM_FLAG_ARCHITECTURAL_MASK,flagsFailure);
            X86LoadD(c,1,CtxDecodedOperands);
            c.Raw({0x83,0xF9,VM_FLAG_UPDATE_TOGGLE}); c.Jcc(JccA,rangeFailure);
            X86LoadD(c,2,CtxDecodedOperands+8u); X86LoadD(c,0,CtxVirtualFlags);
            EmitTrackedBusinessCoreVariant(c,false,semantic,coreStrategy,
                coreVariantOffset,coreVariantSize);
            X86StoreD(c,CtxVirtualFlags,0);
            X86StoreByteImmediate(c,RECORD_OFFSET(CtxPendingFlags,valid),0); return;
        }
        case VM_UOP_FLAGS_PACK_AH:
            X86CallFlagMaterializer(c,0,true,VM_FLAG_SF|VM_FLAG_ZF|VM_FLAG_AF|VM_FLAG_PF|VM_FLAG_CF,flagsFailure);
            X86LoadD(c,2,CtxVirtualFlags);
            EmitTrackedBusinessCoreVariant(c,false,semantic,coreStrategy,
                coreVariantOffset,coreVariantSize);
            X86PushOne(c,0,stackFailure); return;
        case VM_UOP_FLAGS_UNPACK_AH:
            X86RequireAndPop(c,1,stackFailure); X86StoreD(c,CtxMutationScratch,0);
            X86CallFlagMaterializer(c,0,true,VM_FLAG_ARCHITECTURAL_MASK,flagsFailure);
            X86LoadD(c,0,CtxMutationScratch); X86LoadD(c,2,CtxVirtualFlags);
            EmitTrackedBusinessCoreVariant(c,false,semantic,coreStrategy,
                coreVariantOffset,coreVariantSize);
            X86StoreD(c,CtxVirtualFlags,2);
            X86StoreByteImmediate(c,RECORD_OFFSET(CtxPendingFlags,valid),0); return;
        case VM_UOP_PUSH_CONDITION:
            X86CallFlagMaterializer(c,0,true,VM_FLAG_STATUS_MASK,flagsFailure);
            X86EvaluateCondition(c,0,rangeFailure);
            EmitTrackedBusinessCoreVariant(c,false,semantic,coreStrategy,
                coreVariantOffset,coreVariantSize);
            X86PushOne(c,0,stackFailure); return;
        case VM_UOP_SELECT: {
            X86CallFlagMaterializer(c,0,true,VM_FLAG_STATUS_MASK,flagsFailure);
            X86EvaluateCondition(c,0,rangeFailure); X86StoreD(c,CtxMutationScratch,0);
            X86RequireAndPop(c,2,stackFailure); X86LoadD(c,1,CtxMutationScratch);
            EmitTrackedBusinessCoreVariant(c,false,semantic,coreStrategy,
                coreVariantOffset,coreVariantSize);
            X86PushOne(c,0,stackFailure); return;
        }
        default:return;
    }
}

void EmitX64ControlSemantic(
    CodeBuffer& c,
    VM_MICRO_OPCODE semantic,
    CodeBuffer::Label stackFailure,
    CodeBuffer::Label rangeFailure,
    CodeBuffer::Label flagsFailure,
    uint8_t coreStrategy,
    uint32_t& coreVariantOffset,
    uint32_t& coreVariantSize)
{
    (void)stackFailure;
    switch (semantic) {
        case VM_UOP_BRANCH:
            X64LoadQ(c,0,CtxBytecodeBegin); X64LoadD(c,2,CtxDecodedOperands);
            EmitTrackedBusinessCoreVariant(c,true,semantic,coreStrategy,
                coreVariantOffset,coreVariantSize); X64StoreQ(c,CtxVip,0); return;
        case VM_UOP_BRANCH_IF: {
            X64CallFlagMaterializer(c,0,true,VM_FLAG_STATUS_MASK,flagsFailure);
            X64EvaluateCondition(c,0,rangeFailure); c.Raw({0x85,0xC0}); const auto done=c.NewLabel(); c.Jcc(JccE,done);
            X64LoadQ(c,0,CtxBytecodeBegin); X64LoadD(c,2,CtxDecodedOperands+8u);
            EmitTrackedBusinessCoreVariant(c,true,semantic,coreStrategy,
                coreVariantOffset,coreVariantSize); X64StoreQ(c,CtxVip,0); c.Bind(done); return;
        }
        case VM_UOP_CALL_VM: {
            X64LoadD(c,1,CtxCallDepth); c.Raw({0x81,0xF9}); c.U32(VM_RUNTIME_CALL_DEPTH); c.Jcc(JccAE,rangeFailure);
            X64LoadQ(c,0,CtxVip); X64LoadQ(c,2,CtxBytecodeBegin); X64Binary(c,0x29,0,2);
            c.Raw({0x41,0x89,0x84,0x8F}); c.U32(CtxCallStack); c.Raw({0xFF,0xC1}); X64StoreD(c,CtxCallDepth,1);
            X64LoadQ(c,0,CtxBytecodeBegin); X64LoadD(c,2,CtxDecodedOperands);
            EmitTrackedBusinessCoreVariant(c,true,semantic,coreStrategy,
                coreVariantOffset,coreVariantSize); X64StoreQ(c,CtxVip,0); return;
        }
        case VM_UOP_RET: {
            X64LoadD(c,1,CtxCallDepth); c.Raw({0x85,0xC9}); const auto top=c.NewLabel(),done=c.NewLabel(); c.Jcc(JccE,top);
            c.Raw({0xFF,0xC9}); X64StoreD(c,CtxCallDepth,1); c.Raw({0x41,0x8B,0x84,0x8F}); c.U32(CtxCallStack);
            X64LoadQ(c,2,CtxBytecodeBegin);
            EmitTrackedBusinessCoreVariant(c,true,semantic,coreStrategy,
                coreVariantOffset,coreVariantSize); X64StoreQ(c,CtxVip,0); c.Jmp(done);
            c.Bind(top); X64LoadD(c,0,CtxDecodedOperands); X64StoreD(c,CtxReturnStackCleanup,0); X64StoreDImmediate(c,CtxHalted,1);
            c.Bind(done); return;
        }
        case VM_UOP_EXIT:
            X64LoadD(c,0,CtxDecodedOperands); X64StoreD(c,CtxReturnStackCleanup,0); X64StoreDImmediate(c,CtxHalted,1); return;
        default:return;
    }
}

void EmitX86ControlSemantic(
    CodeBuffer& c,
    VM_MICRO_OPCODE semantic,
    CodeBuffer::Label stackFailure,
    CodeBuffer::Label rangeFailure,
    CodeBuffer::Label flagsFailure,
    uint8_t coreStrategy,
    uint32_t& coreVariantOffset,
    uint32_t& coreVariantSize)
{
    (void)stackFailure;
    switch(semantic){
        case VM_UOP_BRANCH:X86LoadD(c,0,CtxBytecodeBegin);X86LoadD(c,2,CtxDecodedOperands);
            EmitTrackedBusinessCoreVariant(c,false,semantic,coreStrategy,coreVariantOffset,coreVariantSize);X86StoreD(c,CtxVip,0);return;
        case VM_UOP_BRANCH_IF:{X86CallFlagMaterializer(c,0,true,VM_FLAG_STATUS_MASK,flagsFailure);X86EvaluateCondition(c,0,rangeFailure);
            c.Raw({0x85,0xC0});const auto done=c.NewLabel();c.Jcc(JccE,done);X86LoadD(c,0,CtxBytecodeBegin);X86LoadD(c,2,CtxDecodedOperands+8u);
            EmitTrackedBusinessCoreVariant(c,false,semantic,coreStrategy,coreVariantOffset,coreVariantSize);X86StoreD(c,CtxVip,0);c.Bind(done);return;}
        case VM_UOP_CALL_VM:{X86LoadD(c,1,CtxCallDepth);c.Raw({0x81,0xF9});c.U32(VM_RUNTIME_CALL_DEPTH);c.Jcc(JccAE,rangeFailure);
            X86LoadD(c,0,CtxVip);X86LoadD(c,2,CtxBytecodeBegin);c.Raw({0x29,0xD0,0x89,0x84,0x8F});c.U32(CtxCallStack);
            c.Raw({0x41});X86StoreD(c,CtxCallDepth,1);X86LoadD(c,0,CtxBytecodeBegin);X86LoadD(c,2,CtxDecodedOperands);
            EmitTrackedBusinessCoreVariant(c,false,semantic,coreStrategy,coreVariantOffset,coreVariantSize);X86StoreD(c,CtxVip,0);return;}
        case VM_UOP_RET:{X86LoadD(c,1,CtxCallDepth);c.Raw({0x85,0xC9});const auto top=c.NewLabel(),done=c.NewLabel();c.Jcc(JccE,top);
            c.Raw({0x49});X86StoreD(c,CtxCallDepth,1);c.Raw({0x8B,0x84,0x8F});c.U32(CtxCallStack);X86LoadD(c,2,CtxBytecodeBegin);
            EmitTrackedBusinessCoreVariant(c,false,semantic,coreStrategy,coreVariantOffset,coreVariantSize);
            X86StoreD(c,CtxVip,0);c.Jmp(done);c.Bind(top);X86LoadD(c,0,CtxDecodedOperands);X86StoreD(c,CtxReturnStackCleanup,0);X86StoreDImmediate(c,CtxHalted,1);c.Bind(done);return;}
        case VM_UOP_EXIT:X86LoadD(c,0,CtxDecodedOperands);X86StoreD(c,CtxReturnStackCleanup,0);X86StoreDImmediate(c,CtxHalted,1);return;
        default:return;
    }
}

void X64StoreStackQ(CodeBuffer& c, uint32_t displacement, uint8_t reg) {
    const uint8_t rex = static_cast<uint8_t>(0x48u | ((reg & 8u) ? 0x04u : 0u));
    c.Raw({rex,0x89,static_cast<uint8_t>(0x84u | ((reg & 7u) << 3u)),0x24}); c.U32(displacement);
}

void X64StoreStackD(CodeBuffer& c, uint32_t displacement, uint8_t reg) {
    const uint8_t rex = static_cast<uint8_t>(0x40u | ((reg & 8u) ? 0x04u : 0u));
    c.Raw({rex,0x89,static_cast<uint8_t>(0x84u | ((reg & 7u) << 3u)),0x24});
    c.U32(displacement);
}

void X64LoadStackQ(CodeBuffer& c, uint8_t reg, uint32_t displacement) {
    const uint8_t rex = static_cast<uint8_t>(0x48u | ((reg & 8u) ? 0x04u : 0u));
    c.Raw({rex,0x8B,static_cast<uint8_t>(0x84u | ((reg & 7u) << 3u)),0x24}); c.U32(displacement);
}

void X86StoreStackD(CodeBuffer& c, uint32_t displacement, uint8_t reg) {
    c.Raw({0x89,static_cast<uint8_t>(0x84u | ((reg & 7u) << 3u)),0x24}); c.U32(displacement);
}

void X86LoadStackD(CodeBuffer& c, uint8_t reg, uint32_t displacement) {
    c.Raw({0x8B,static_cast<uint8_t>(0x84u | ((reg & 7u) << 3u)),0x24}); c.U32(displacement);
}

void X64LoadMappedVreg(
    CodeBuffer& c,
    uint8_t destination,
    uint8_t family)
{
    X64LoadQ(c, 11, CtxRegisterMap);
    X64LoadByteIndirect(c, 1, 11, family);
    X64LoadIndexedQ(c, destination, 1, CtxVregs);
}

void X64SpillMappedVreg(
    CodeBuffer& c,
    uint8_t family,
    uint32_t stackDisplacement)
{
    // Resolve one guest-family mapping at a time while RCX/R11 are still
    // scratch registers, then freeze the value in the native-call frame.
    // Loading all call registers directly through X64LoadMappedVreg would
    // overwrite an already restored guest RCX on the very next mapping lookup.
    X64LoadMappedVreg(c, 0, family);
    X64StoreStackQ(c, stackDisplacement, 0);
}

void X64StoreMappedVregFromStack(
    CodeBuffer& c,
    uint8_t family,
    uint32_t stackDisplacement)
{
    X64LoadQ(c, 11, CtxRegisterMap);
    X64LoadByteIndirect(c, 1, 11, family);
    X64LoadStackQ(c, 0, stackDisplacement);
    X64StoreIndexedQ(c, CtxVregs, 1, 0);
}

void EmitX64ByteCopyLoop(
    CodeBuffer& c,
    uint8_t source,
    uint8_t destination,
    uint8_t count)
{
    const auto done = c.NewLabel();
    const auto loop = c.NewLabel();
    const uint8_t loadRex = static_cast<uint8_t>(0x40u |
        ((source & 8u) ? 0x01u : 0u));
    const uint8_t storeRex = static_cast<uint8_t>(0x40u |
        ((destination & 8u) ? 0x01u : 0u));
    const uint8_t countRex = static_cast<uint8_t>(0x40u |
        ((count & 8u) ? 0x01u : 0u));
    if (count & 8u) c.U8(0x45);
    c.Raw({0x85,static_cast<uint8_t>(0xC0u | ((count & 7u) << 3u) |
        (count & 7u))});
    c.Jcc(JccE, done);
    c.Bind(loop);
    c.Raw({loadRex,0x8A,static_cast<uint8_t>(source & 7u)});
    c.Raw({storeRex,0x88,static_cast<uint8_t>(destination & 7u)});
    const uint8_t sourceRex = static_cast<uint8_t>(0x48u |
        ((source & 8u) ? 0x01u : 0u));
    const uint8_t destinationRex = static_cast<uint8_t>(0x48u |
        ((destination & 8u) ? 0x01u : 0u));
    c.Raw({sourceRex,0xFF,static_cast<uint8_t>(0xC0u | (source & 7u))});
    c.Raw({destinationRex,0xFF,
        static_cast<uint8_t>(0xC0u | (destination & 7u))});
    c.Raw({countRex,0xFF,static_cast<uint8_t>(0xC8u | (count & 7u))});
    c.Jcc(JccNE, loop);
    c.Bind(done);
}

void EmitX64CallHost(
    CodeBuffer& c,
    CodeBuffer::Label stackFailure,
    CodeBuffer::Label rangeFailure,
    CodeBuffer::Label flagsFailure,
    uint8_t coreStrategy,
    uint32_t& coreVariantOffset,
    uint32_t& coreVariantSize)
{
    constexpr uint32_t metaFlags =
        static_cast<uint32_t>(offsetof(VM_METADATA_HEADER, flags));
    constexpr uint32_t metaGuardDispatch = static_cast<uint32_t>(
        offsetof(VM_METADATA_HEADER, guardCFDispatchPointerRVA));
    constexpr uint32_t extendedFlags =
        static_cast<uint32_t>(offsetof(VM_EXTENDED_STATE, flags));

    X64RequireAndPop(c, 1, stackFailure);             // rax = target token
    X64LoadD(c, 1, CtxDecodedOperands + 8u);
    c.Raw({0x83,0xF9,VM_ABI_WIN64}); c.Jcc(JccNE, rangeFailure);
    X64LoadD(c, 1, CtxDecodedOperands + 16u);
    c.Raw({0x81,0xF9}); c.U32(VM_NATIVE_MAX_STACK_ARGUMENT_BYTES);
    c.Jcc(JccA, rangeFailure);
    c.Raw({0xF7,0xC1,0x07,0x00,0x00,0x00}); c.Jcc(JccNE, rangeFailure);
    X64LoadQ(c, 11, CtxRegisterMap);
    c.Raw({0x4D,0x85,0xDB}); c.Jcc(JccE, rangeFailure);
    X64LoadQ(c, 10, CtxExtendedState);
    c.Raw({0x4D,0x85,0xD2}); c.Jcc(JccE, rangeFailure);
    X64LoadQ(c, 10, CtxMetadata);
    c.Raw({0x4D,0x85,0xD2}); c.Jcc(JccE, rangeFailure);
    X64LoadQ(c, 10, CtxFlagMaterializer);
    c.Raw({0x4D,0x85,0xD2}); c.Jcc(JccE, flagsFailure);

    EmitTrackedBusinessCoreVariant(c, true, VM_UOP_CALL_HOST,
        coreStrategy, coreVariantOffset, coreVariantSize);
    c.Raw({0x48,0x85,0xC0}); c.Jcc(JccE, rangeFailure);
    X64LoadMappedVreg(c, 10, 4u);                    // guest RSP
    c.Raw({0x4D,0x85,0xD2}); c.Jcc(JccE, rangeFailure);
    c.Raw({0x41,0xF6,0xC2,0x0F}); c.Jcc(JccNE, rangeFailure);

    const auto cfgReady = c.NewLabel();
    const auto cfgFailure = c.NewLabel();
    const auto saveHostFx = c.NewLabel();
    const auto hostSaved = c.NewLabel();
    const auto restoreGuestFx = c.NewLabel();
    const auto guestRestored = c.NewLabel();
    const auto directCall = c.NewLabel();
    const auto callComplete = c.NewLabel();
    const auto saveGuestFx = c.NewLabel();
    const auto guestSaved = c.NewLabel();
    const auto restoreHostFx = c.NewLabel();
    const auto hostRestored = c.NewLabel();
    const auto materializerFailure = c.NewLabel();
    const auto leave = c.NewLabel();
    const auto leaveFlags = c.NewLabel();
    const auto leaveNative = c.NewLabel();
    const auto finished = c.NewLabel();

    const size_t funcletBegin = c.bytes.size();
    c.Raw({0x48,0x81,0xEC}); c.U32(kX64NativeCallStackBytes);
    X64StoreStackQ(c, kNativeCallTargetSpill, 0);
    X64StoreStackQ(c, kNativeCallGuestStackSpill, 10);
    c.Raw({0x31,0xC0}); X64StoreStackQ(c, kNativeCallGuardSpill, 0);

    // Materialize every architectural flag while the one declared native-call
    // frame is active, avoiding a second overlapping unwind funclet.
    X64LoadQ(c, 0, CtxFlagMaterializer);
    c.Raw({0x4C,0x89,0xF9,0xBA}); c.U32(VM_FLAG_ARCHITECTURAL_MASK);
    c.Raw({0xFF,0xD0});
    X64LoadD(c, 0, CtxError); c.Raw({0x85,0xC0});
    c.Jcc(JccNE, materializerFailure);

    // CFG mirrors the historical bridge contract: native RVAs are known
    // direct targets; import-slot and indirect calls use the image's Guard
    // dispatch pointer whenever CFG is enabled.
    X64LoadD(c, 0, CtxDecodedOperands);
    c.Raw({0x83,0xF8,VM_MICRO_CALL_NATIVE_RVA}); c.Jcc(JccE, cfgReady);
    X64LoadQ(c, 10, CtxMetadata);
    c.Raw({0x45,0x8B,0x9A}); c.U32(metaFlags);
    c.Raw({0x41,0xF7,0xC3}); c.U32(VM_METADATA_FLAG_CFG_ENABLED);
    c.Jcc(JccE, cfgReady);
    c.Raw({0x45,0x8B,0x9A}); c.U32(metaGuardDispatch);
    c.Raw({0x45,0x85,0xDB}); c.Jcc(JccE, cfgFailure);
    X64LoadQ(c, 2, CtxImageBase);
    X64BinaryRegister(c, 0x01, 11, 2);
    c.Raw({0x4D,0x8B,0x1B,0x4D,0x85,0xDB}); c.Jcc(JccE, cfgFailure);
    X64StoreStackQ(c, kNativeCallGuardSpill, 11);
    c.Bind(cfgReady);

    // Save the handler's host extended state into an aligned local image.
    c.Raw({0x4C,0x8D,0x94,0x24});
    c.U32(kNativeCallHostExtendedBase + 63u);
    c.Raw({0x49,0x83,0xE2,0xC0});
    X64StoreStackQ(c, kNativeCallHostExtendedSpill, 10);
    X64LoadQ(c, 11, CtxExtendedState);
    c.Raw({0x41,0x8B,0x93}); c.U32(extendedFlags);
    c.Raw({0x85,0xD2}); c.Jcc(JccE, saveHostFx);
    c.Raw({0xB8,0x07,0x00,0x00,0x00,0x31,0xD2,0x49,0x0F,0xAE,0x22});
    c.Jmp(hostSaved);
    c.Bind(saveHostFx); c.Raw({0x49,0x0F,0xAE,0x02});
    c.Bind(hostSaved);

    // Copy only the statically declared stack-argument window.  Byte loops
    // avoid clobbering RSI/RDI, which remain nonvolatile at every unwind point.
    X64LoadStackQ(c, 10, kNativeCallGuestStackSpill);
    c.Raw({0x49,0x83,0xC2,0x20});
    c.Raw({0x4C,0x8D,0x9C,0x24}); c.U32(kNativeCallArgumentBase);
    X64LoadD(c, 1, CtxDecodedOperands + 16u);
    EmitX64ByteCopyLoop(c, 10, 11, 1);

    // Snapshot every volatile guest GPR before the ABI call.  The same frame
    // slots are overwritten with post-call values below, so no additional
    // unwind-visible storage is needed.
    X64SpillMappedVreg(c, 0u, kNativeCallRaxSpill);
    X64SpillMappedVreg(c, 1u, kNativeCallRcxSpill);
    X64SpillMappedVreg(c, 2u, kNativeCallRdxSpill);
    X64SpillMappedVreg(c, 8u, kNativeCallR8Spill);
    X64SpillMappedVreg(c, 9u, kNativeCallR9Spill);
    X64SpillMappedVreg(c, 10u, kNativeCallR10Spill);
    X64SpillMappedVreg(c, 11u, kNativeCallR11Spill);

    // Restore guest SIMD/x87 state immediately before the external call.
    X64LoadQ(c, 10, CtxExtendedState);
    c.Raw({0x41,0x8B,0x92}); c.U32(extendedFlags);
    c.Raw({0x85,0xD2}); c.Jcc(JccE, restoreGuestFx);
    c.Raw({0xB8,0x07,0x00,0x00,0x00,0x31,0xD2,0x49,0x0F,0xAE,0x2A});
    c.Jmp(guestRestored);
    c.Bind(restoreGuestFx); c.Raw({0x49,0x0F,0xAE,0x0A});
    c.Bind(guestRestored);

    X64LoadStackQ(c, 11, kNativeCallGuardSpill);
    c.Raw({0x4D,0x85,0xDB}); c.Jcc(JccE, directCall);
    // Guard-dispatch path: Windows requires the validated target in RAX.
    X64LoadQ(c, 0, CtxVirtualFlags); c.U8(0x50); c.U8(0x9D);
    X64LoadStackQ(c, 1, kNativeCallRcxSpill);
    X64LoadStackQ(c, 2, kNativeCallRdxSpill);
    X64LoadStackQ(c, 8, kNativeCallR8Spill);
    X64LoadStackQ(c, 9, kNativeCallR9Spill);
    X64LoadStackQ(c, 10, kNativeCallR10Spill);
    X64LoadStackQ(c, 11, kNativeCallR11Spill);
    X64LoadStackQ(c, 0, kNativeCallTargetSpill);
    c.Raw({0xFF,0x94,0x24}); c.U32(kNativeCallGuardSpill);
    c.Jmp(callComplete);
    c.Bind(directCall);
    X64LoadQ(c, 0, CtxVirtualFlags); c.U8(0x50); c.U8(0x9D);
    X64LoadStackQ(c, 1, kNativeCallRcxSpill);
    X64LoadStackQ(c, 2, kNativeCallRdxSpill);
    X64LoadStackQ(c, 8, kNativeCallR8Spill);
    X64LoadStackQ(c, 9, kNativeCallR9Spill);
    X64LoadStackQ(c, 10, kNativeCallR10Spill);
    X64LoadStackQ(c, 11, kNativeCallR11Spill);
    X64LoadStackQ(c, 0, kNativeCallRaxSpill);
    c.Raw({0xFF,0x94,0x24}); c.U32(kNativeCallTargetSpill);
    c.Bind(callComplete);

    X64StoreStackQ(c, kNativeCallRaxSpill, 0);
    X64StoreStackQ(c, kNativeCallRcxSpill, 1);
    X64StoreStackQ(c, kNativeCallRdxSpill, 2);
    X64StoreStackQ(c, kNativeCallR8Spill, 8);
    X64StoreStackQ(c, kNativeCallR9Spill, 9);
    X64StoreStackQ(c, kNativeCallR10Spill, 10);
    X64StoreStackQ(c, kNativeCallR11Spill, 11);
    c.U8(0x9C); c.U8(0x58);
    X64StoreStackQ(c, kNativeCallFlagsSpill, 0);

    // Save the guest's post-call extended state, then restore the handler's
    // host state before using any SIMD/x87 instruction in the VM again.
    X64LoadQ(c, 10, CtxExtendedState);
    c.Raw({0x41,0x8B,0x92}); c.U32(extendedFlags);
    c.Raw({0x85,0xD2}); c.Jcc(JccE, saveGuestFx);
    c.Raw({0xB8,0x07,0x00,0x00,0x00,0x31,0xD2,0x49,0x0F,0xAE,0x22});
    c.Jmp(guestSaved);
    c.Bind(saveGuestFx); c.Raw({0x49,0x0F,0xAE,0x02});
    c.Bind(guestSaved);
    X64LoadStackQ(c, 10, kNativeCallHostExtendedSpill);
    X64LoadQ(c, 11, CtxExtendedState);
    c.Raw({0x41,0x8B,0x93}); c.U32(extendedFlags);
    c.Raw({0x85,0xD2}); c.Jcc(JccE, restoreHostFx);
    c.Raw({0xB8,0x07,0x00,0x00,0x00,0x31,0xD2,0x49,0x0F,0xAE,0x2A});
    c.Jmp(hostRestored);
    c.Bind(restoreHostFx); c.Raw({0x49,0x0F,0xAE,0x0A});
    c.Bind(hostRestored);

    c.Raw({0x4C,0x8D,0x94,0x24}); c.U32(kNativeCallArgumentBase);
    X64LoadStackQ(c, 11, kNativeCallGuestStackSpill);
    c.Raw({0x49,0x83,0xC3,0x20});
    X64LoadD(c, 1, CtxDecodedOperands + 16u);
    EmitX64ByteCopyLoop(c, 10, 11, 1);

    X64StoreMappedVregFromStack(c, 0u, kNativeCallRaxSpill);
    X64StoreMappedVregFromStack(c, 1u, kNativeCallRcxSpill);
    X64StoreMappedVregFromStack(c, 2u, kNativeCallRdxSpill);
    X64StoreMappedVregFromStack(c, 8u, kNativeCallR8Spill);
    X64StoreMappedVregFromStack(c, 9u, kNativeCallR9Spill);
    X64StoreMappedVregFromStack(c, 10u, kNativeCallR10Spill);
    X64StoreMappedVregFromStack(c, 11u, kNativeCallR11Spill);
    X64LoadStackQ(c, 0, kNativeCallFlagsSpill);
    X64StoreQ(c, CtxVirtualFlags, 0);
    c.Raw({0x45,0x31,0xDB}); c.Jmp(leave);       // status 0

    c.Bind(materializerFailure);
    c.Raw({0x41,0xBB,0x01,0x00,0x00,0x00}); c.Jmp(leave);
    c.Bind(cfgFailure);
    c.Raw({0x41,0xBB,0x02,0x00,0x00,0x00});
    c.Bind(leave);
    c.Raw({0x48,0x81,0xC4}); c.U32(kX64NativeCallStackBytes);
    RecordX64StackFunclet(c, funcletBegin,
        VMHandlerSemanticUnwindKind::StackAllocation,
        kX64NativeCallStackBytes, kX64NativeCallPrologSize);
    c.Raw({0x45,0x85,0xDB}); c.Jcc(JccE, finished);
    c.Raw({0x41,0x83,0xFB,0x01}); c.Jcc(JccE, leaveFlags);
    c.Jmp(leaveNative);
    c.Bind(leaveFlags); c.Jmp(flagsFailure);
    c.Bind(leaveNative);
    EmitX64Failure(c, VM_MICRO_ERR_NATIVE_BRIDGE);
    c.Bind(finished);
}

void X86StoreFrameD(CodeBuffer& c, uint32_t displacement, uint8_t reg) {
    c.Raw({0x89,static_cast<uint8_t>(0x85u | ((reg & 7u) << 3u))});
    c.U32(displacement);
}

void X86LoadFrameD(CodeBuffer& c, uint8_t reg, uint32_t displacement) {
    c.Raw({0x8B,static_cast<uint8_t>(0x85u | ((reg & 7u) << 3u))});
    c.U32(displacement);
}

void X86LoadMappedVregToFrame(
    CodeBuffer& c,
    uint8_t family,
    uint32_t frameDisplacement)
{
    X86LoadD(c, 2, CtxRegisterMap);
    X86LoadByteIndirect(c, 1, 2, family);
    X86LoadIndexedDVariant(c, 0, 1, CtxVregs);
    X86StoreFrameD(c, frameDisplacement, 0);
}

void X86StoreMappedVregFromFrame(
    CodeBuffer& c,
    uint8_t family,
    uint32_t frameDisplacement)
{
    X86LoadD(c, 2, CtxRegisterMap);
    X86LoadByteIndirect(c, 1, 2, family);
    X86LoadFrameD(c, 0, frameDisplacement);
    X86StoreIndexedDVariant(c, CtxVregs, 1, 0);
    c.Raw({0xC7,0x84,0xCF}); c.U32(CtxVregs + 4u); c.U32(0);
}

void EmitX86CallHost(
    CodeBuffer& c,
    CodeBuffer::Label stackFailure,
    CodeBuffer::Label rangeFailure,
    CodeBuffer::Label flagsFailure,
    uint8_t coreStrategy,
    uint32_t& coreVariantOffset,
    uint32_t& coreVariantSize)
{
    constexpr uint32_t metaFlags =
        static_cast<uint32_t>(offsetof(VM_METADATA_HEADER, flags));
    constexpr uint32_t metaGuardCheck = static_cast<uint32_t>(
        offsetof(VM_METADATA_HEADER, guardCFCheckPointerRVA));
    constexpr uint32_t extendedFlags =
        static_cast<uint32_t>(offsetof(VM_EXTENDED_STATE, flags));

    X86RequireAndPop(c, 1, stackFailure);             // eax = target token
    X86LoadD(c, 1, CtxDecodedOperands + 8u);
    c.Raw({0x83,0xF9,VM_ABI_X86_CDECL}); c.Jcc(JccB, rangeFailure);
    c.Raw({0x83,0xF9,VM_ABI_X86_AUTO}); c.Jcc(JccA, rangeFailure);
    X86LoadD(c, 1, CtxDecodedOperands + 16u);
    c.Raw({0x81,0xF9}); c.U32(VM_NATIVE_MAX_STACK_ARGUMENT_BYTES);
    c.Jcc(JccA, rangeFailure);
    c.Raw({0xF7,0xC1,0x01,0x00,0x00,0x00}); c.Jcc(JccNE, rangeFailure);
    X86LoadD(c, 2, CtxRegisterMap); c.Raw({0x85,0xD2});
    c.Jcc(JccE, rangeFailure);
    X86LoadD(c, 2, CtxExtendedState); c.Raw({0x85,0xD2});
    c.Jcc(JccE, rangeFailure);
    X86LoadD(c, 2, CtxMetadata); c.Raw({0x85,0xD2});
    c.Jcc(JccE, rangeFailure);
    X86LoadD(c, 2, CtxFlagMaterializer); c.Raw({0x85,0xD2});
    c.Jcc(JccE, flagsFailure);

    EmitTrackedBusinessCoreVariant(c, false, VM_UOP_CALL_HOST,
        coreStrategy, coreVariantOffset, coreVariantSize);
    c.Raw({0x85,0xC0}); c.Jcc(JccE, rangeFailure);
    X86StoreD(c, CtxMutationScratch, 0);
    X86LoadD(c, 2, CtxRegisterMap);
    X86LoadByteIndirect(c, 1, 2, 4u);
    X86LoadIndexedDVariant(c, 0, 1, CtxVregs);
    c.Raw({0x85,0xC0}); c.Jcc(JccE, rangeFailure);
    X86StoreD(c, CtxMutationScratch + 4u, 0);
    X86LoadD(c, 0, CtxMutationScratch);

    const auto cfgReady = c.NewLabel();
    const auto cfgFailure = c.NewLabel();
    const auto saveHostFx = c.NewLabel();
    const auto hostSaved = c.NewLabel();
    const auto restoreGuestFx = c.NewLabel();
    const auto guestRestored = c.NewLabel();
    const auto guardComplete = c.NewLabel();
    const auto cleanupRangeFailure = c.NewLabel();
    const auto cleanupAbiReady = c.NewLabel();
    const auto cleanupValid = c.NewLabel();
    const auto saveGuestFx = c.NewLabel();
    const auto guestSaved = c.NewLabel();
    const auto restoreHostFx = c.NewLabel();
    const auto hostRestored = c.NewLabel();
    const auto skipWriteback = c.NewLabel();
    const auto materializerFailure = c.NewLabel();
    const auto leave = c.NewLabel();
    const auto leaveFlags = c.NewLabel();
    const auto leaveNative = c.NewLabel();
    const auto finished = c.NewLabel();

    c.Raw({0x81,0xEC}); c.U32(kX86NativeCallStackBytes);
    // Save the direct-threaded ABI and establish a frame base that every x86
    // calling convention in the explicit CALL_HOST contract must preserve.
    c.Raw({0x89,0xAC,0x24}); c.U32(kX86NativeCallOriginalEbpSpill);
    c.Raw({0x89,0xE5});
    X86StoreFrameD(c, kX86NativeCallOriginalEbxSpill, 3);
    X86StoreFrameD(c, kX86NativeCallOriginalEsiSpill, 6);
    X86StoreFrameD(c, kX86NativeCallOriginalEdiSpill, 7);
    X86StoreFrameD(c, kX86NativeCallTargetSpill, 0);
    X86LoadD(c, 0, CtxMutationScratch + 4u);
    X86StoreFrameD(c, kX86NativeCallGuestStackSpill, 0);
    c.Raw({0x31,0xC0});
    X86StoreFrameD(c, kX86NativeCallGuardSpill, 0);
    X86StoreFrameD(c, kX86NativeCallStatusSpill, 0);

    X86LoadD(c, 0, CtxFlagMaterializer);
    c.Raw({0x68}); c.U32(VM_FLAG_ARCHITECTURAL_MASK);
    c.Raw({0x57,0xFF,0xD0,0x83,0xC4,0x08});
    X86LoadD(c, 0, CtxError); c.Raw({0x85,0xC0});
    c.Jcc(JccNE, materializerFailure);

    X86LoadD(c, 0, CtxDecodedOperands);
    c.Raw({0x83,0xF8,VM_MICRO_CALL_NATIVE_RVA}); c.Jcc(JccE, cfgReady);
    X86LoadD(c, 2, CtxMetadata);
    c.Raw({0x8B,0x82}); c.U32(metaFlags);
    c.Raw({0xA9}); c.U32(VM_METADATA_FLAG_CFG_ENABLED); c.Jcc(JccE, cfgReady);
    c.Raw({0x8B,0x82}); c.U32(metaGuardCheck);
    c.Raw({0x85,0xC0}); c.Jcc(JccE, cfgFailure);
    X86LoadD(c, 2, CtxImageBase); c.Raw({0x01,0xD0,0x8B,0x00,0x85,0xC0});
    c.Jcc(JccE, cfgFailure);
    X86StoreFrameD(c, kX86NativeCallGuardSpill, 0);
    c.Bind(cfgReady);

    c.Raw({0x8D,0x85}); c.U32(kX86NativeCallHostExtendedBase + 63u);
    c.Raw({0x83,0xE0,0xC0});
    X86StoreFrameD(c, kX86NativeCallHostExtendedSpill, 0);
    X86LoadD(c, 2, CtxExtendedState);
    c.Raw({0x8B,0x8A}); c.U32(extendedFlags);
    c.Raw({0x85,0xC9}); c.Jcc(JccE, saveHostFx);
    c.Raw({0xB8,0x07,0x00,0x00,0x00,0x31,0xD2});
    X86LoadFrameD(c, 1, kX86NativeCallHostExtendedSpill);
    c.Raw({0x0F,0xAE,0x21});
    c.Jmp(hostSaved);
    c.Bind(saveHostFx);
    X86LoadFrameD(c, 0, kX86NativeCallHostExtendedSpill);
    c.Raw({0x0F,0xAE,0x00});
    c.Bind(hostSaved);

    // ESI/EDI are temporarily used only for the copy and are restored before
    // any external call, preserving the direct-threaded EBX/ESI/EDI contract.
    X86LoadD(c, 1, CtxDecodedOperands + 16u);
    X86LoadFrameD(c, 6, kX86NativeCallGuestStackSpill);
    c.Raw({0x89,0xEF});
    c.Raw({0xFC,0xF3,0xA4});
    X86LoadFrameD(c, 6, kX86NativeCallOriginalEsiSpill);
    X86LoadFrameD(c, 7, kX86NativeCallOriginalEdiSpill);

    X86LoadD(c, 0, CtxExtendedState);
    c.Raw({0x8B,0x88}); c.U32(extendedFlags);
    c.Raw({0x85,0xC9}); c.Jcc(JccE, restoreGuestFx);
    c.Raw({0xB8,0x07,0x00,0x00,0x00,0x31,0xD2});
    X86LoadD(c, 0, CtxExtendedState); c.Raw({0x0F,0xAE,0x28});
    c.Jmp(guestRestored);
    c.Bind(restoreGuestFx);
    X86LoadD(c, 0, CtxExtendedState); c.Raw({0x0F,0xAE,0x08});
    c.Bind(guestRestored);

    X86LoadFrameD(c, 0, kX86NativeCallGuardSpill);
    c.Raw({0x85,0xC0}); c.Jcc(JccE, guardComplete);
    X86LoadFrameD(c, 1, kX86NativeCallTargetSpill);
    c.Raw({0xFF,0xD0});
    c.Bind(guardComplete);

    // Stage guest volatile inputs in locals so register-map lookups cannot
    // overwrite another input immediately before the native call.
    X86LoadMappedVregToFrame(c, 0u, kX86NativeCallEaxSpill);
    X86LoadMappedVregToFrame(c, 1u, kX86NativeCallEcxSpill);
    X86LoadMappedVregToFrame(c, 2u, kX86NativeCallEdxSpill);
    X86LoadD(c, 0, CtxVirtualFlags); c.U8(0x50); c.U8(0x9D);
    X86LoadFrameD(c, 0, kX86NativeCallEaxSpill);
    X86LoadFrameD(c, 1, kX86NativeCallEcxSpill);
    X86LoadFrameD(c, 2, kX86NativeCallEdxSpill);
    c.Raw({0xFF,0x95}); c.U32(kX86NativeCallTargetSpill);

    X86StoreFrameD(c, kX86NativeCallEaxSpill, 0);
    X86StoreFrameD(c, kX86NativeCallEcxSpill, 1);
    X86StoreFrameD(c, kX86NativeCallEdxSpill, 2);
    c.Raw({0x89,0xE1,0x29,0xE9});             // cleanup = esp - ebp
    X86StoreFrameD(c, kX86NativeCallCleanupSpill, 1);
    // A callee-clean ABI returns with ESP above the copied argument window.
    // Capture the cleanup before restoring ESP, then move below that window
    // before PUSHFD; otherwise PUSHFD overwrites the last stdcall/fastcall
    // argument and corrupts the subsequent guest-stack writeback.
    c.Raw({0x89,0xEC});
    c.U8(0x9C); c.U8(0x58);
    X86StoreFrameD(c, kX86NativeCallFlagsSpill, 0);
    X86LoadD(c, 0, CtxDecodedOperands + 16u);
    c.Raw({0x39,0xC1}); c.Jcc(JccA, cleanupRangeFailure);
    X86LoadD(c, 0, CtxDecodedOperands + 8u);
    c.Raw({0x83,0xF8,VM_ABI_X86_AUTO}); c.Jcc(JccE, cleanupValid);
    c.Raw({0x83,0xF8,VM_ABI_X86_CDECL}); c.Jcc(JccNE, cleanupAbiReady);
    c.Raw({0x85,0xC9}); c.Jcc(JccE, cleanupValid);
    c.Jmp(cleanupRangeFailure);
    c.Bind(cleanupAbiReady);
    X86LoadD(c, 0, CtxDecodedOperands + 16u);
    c.Raw({0x39,0xC1}); c.Jcc(JccE, cleanupValid);
    c.Jmp(cleanupRangeFailure);
    c.Bind(cleanupRangeFailure);
    c.Raw({0x89,0xEC,0xC7,0x85}); c.U32(kX86NativeCallStatusSpill); c.U32(2u);
    c.Bind(cleanupValid);

    X86LoadD(c, 0, CtxExtendedState);
    c.Raw({0x8B,0x88}); c.U32(extendedFlags);
    c.Raw({0x85,0xC9}); c.Jcc(JccE, saveGuestFx);
    c.Raw({0xB8,0x07,0x00,0x00,0x00,0x31,0xD2});
    X86LoadD(c, 0, CtxExtendedState); c.Raw({0x0F,0xAE,0x20});
    c.Jmp(guestSaved);
    c.Bind(saveGuestFx);
    X86LoadD(c, 0, CtxExtendedState); c.Raw({0x0F,0xAE,0x00});
    c.Bind(guestSaved);
    X86LoadFrameD(c, 0, kX86NativeCallHostExtendedSpill);
    X86LoadD(c, 2, CtxExtendedState);
    c.Raw({0x8B,0x8A}); c.U32(extendedFlags);
    c.Raw({0x85,0xC9}); c.Jcc(JccE, restoreHostFx);
    c.Raw({0xB8,0x07,0x00,0x00,0x00,0x31,0xD2});
    X86LoadFrameD(c, 0, kX86NativeCallHostExtendedSpill);
    c.Raw({0x0F,0xAE,0x28}); c.Jmp(hostRestored);
    c.Bind(restoreHostFx);
    X86LoadFrameD(c, 0, kX86NativeCallHostExtendedSpill);
    c.Raw({0x0F,0xAE,0x08});
    c.Bind(hostRestored);

    X86LoadD(c, 1, CtxDecodedOperands + 16u);
    c.Raw({0x89,0xEE});
    X86LoadFrameD(c, 7, kX86NativeCallGuestStackSpill);
    c.Raw({0xFC,0xF3,0xA4});
    X86LoadFrameD(c, 6, kX86NativeCallOriginalEsiSpill);
    X86LoadFrameD(c, 7, kX86NativeCallOriginalEdiSpill);

    X86LoadFrameD(c, 0, kX86NativeCallStatusSpill);
    c.Raw({0x85,0xC0}); c.Jcc(JccNE, skipWriteback);
    X86StoreMappedVregFromFrame(c, 0u, kX86NativeCallEaxSpill);
    X86StoreMappedVregFromFrame(c, 1u, kX86NativeCallEcxSpill);
    X86StoreMappedVregFromFrame(c, 2u, kX86NativeCallEdxSpill);
    X86LoadFrameD(c, 0, kX86NativeCallGuestStackSpill);
    X86LoadFrameD(c, 1, kX86NativeCallCleanupSpill);
    c.Raw({0x01,0xC8}); X86StoreFrameD(c, kX86NativeCallCleanupSpill, 0);
    X86StoreMappedVregFromFrame(c, 4u, kX86NativeCallCleanupSpill);
    X86LoadFrameD(c, 0, kX86NativeCallFlagsSpill);
    X86StoreD(c, CtxVirtualFlags, 0);
    c.Bind(skipWriteback);
    c.Jmp(leave);

    c.Bind(materializerFailure);
    c.Raw({0xC7,0x85}); c.U32(kX86NativeCallStatusSpill); c.U32(1u);
    c.Jmp(leave);
    c.Bind(cfgFailure);
    c.Raw({0xC7,0x85}); c.U32(kX86NativeCallStatusSpill); c.U32(2u);
    c.Bind(leave);
    X86LoadFrameD(c, 0, kX86NativeCallStatusSpill);
    X86LoadFrameD(c, 3, kX86NativeCallOriginalEbxSpill);
    X86LoadFrameD(c, 6, kX86NativeCallOriginalEsiSpill);
    X86LoadFrameD(c, 7, kX86NativeCallOriginalEdiSpill);
    X86LoadFrameD(c, 2, kX86NativeCallOriginalEbpSpill);
    c.Raw({0x89,0xEC,0x89,0xD5,0x81,0xC4}); c.U32(kX86NativeCallStackBytes);
    c.Raw({0x85,0xC0}); c.Jcc(JccE, finished);
    c.Raw({0x83,0xF8,0x01}); c.Jcc(JccE, leaveFlags);
    c.Jmp(leaveNative);
    c.Bind(leaveFlags); c.Jmp(flagsFailure);
    c.Bind(leaveNative); EmitX86Failure(c, VM_MICRO_ERR_NATIVE_BRIDGE);
    c.Bind(finished);
}

void EmitX64BridgeExtended(
    CodeBuffer& c,
    CodeBuffer::Label rangeFailure,
    CodeBuffer::Label flagsFailure,
    uint8_t coreStrategy,
    uint32_t& coreVariantOffset,
    uint32_t& coreVariantSize)
{
    constexpr uint32_t stateBase = kX64BridgeStateBase;
    constexpr uint32_t allocation = kX64BridgeStackBytes;
    (void)flagsFailure;
    X64LoadD(c,0,CtxDecodedOperands+8u); c.Raw({0xA9}); c.U32(~VM_MICRO_BRIDGE_KNOWN_MASK);
    c.Jcc(JccNE,rangeFailure);
    X64LoadQ(c,0,CtxImageBase); X64LoadD(c,2,CtxDecodedOperands);
    EmitTrackedBusinessCoreVariant(c, true, VM_UOP_BRIDGE_EXTENDED,
        coreStrategy, coreVariantOffset, coreVariantSize);
    X64StoreQ(c,CtxMutationScratch,0);
    X64LoadQ(c,11,CtxRegisterMap); c.Raw({0x4D,0x85,0xDB}); c.Jcc(JccE,rangeFailure);
    const size_t funcletBegin = c.bytes.size();
    c.Raw({0x48,0x81,0xEC}); c.U32(allocation);
    for(uint8_t family=0;family<16;++family){
        c.Raw({0x41,0x0F,0xB6,0x4B,family});
        X64LoadIndexedQ(c,0,1,CtxVregs);
        X64StoreStackQ(c,stateBase+static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE,gpr))+family*8u,0);
    }
    c.Raw({0xB8,0x02,0x02,0x00,0x00});
    X64StoreStackQ(c,stateBase+offsetof(VM_INSTRUCTION_BRIDGE_STATE,rflags),0);
    X64LoadQ(c,0,CtxMutationScratch); X64StoreStackQ(c,stateBase+offsetof(VM_INSTRUCTION_BRIDGE_STATE,target),0);
    X64StoreStackQ(c,stateBase+offsetof(VM_INSTRUCTION_BRIDGE_STATE,guardTarget),0);
    X64LoadQ(c,0,CtxExtendedState); X64StoreStackQ(c,stateBase+offsetof(VM_INSTRUCTION_BRIDGE_STATE,extendedState),0);
    X64LoadD(c,0,CtxDecodedOperands+8u); c.Raw({0x89,0xC2,0x81,0xE2}); c.U32(VM_MICRO_BRIDGE_AVX);
    c.Raw({0xC1,0xEA,0x08}); X64StoreStackD(c,stateBase+offsetof(VM_INSTRUCTION_BRIDGE_STATE,extendedStateFlags),2);
    c.Raw({0x83,0xE0,VM_MICRO_BRIDGE_HIDDEN_REGISTER_MASK}); X64StoreStackD(c,stateBase+offsetof(VM_INSTRUCTION_BRIDGE_STATE,hiddenRegister),0);
    X64LoadStackQ(c,0,stateBase+offsetof(VM_INSTRUCTION_BRIDGE_STATE,target));
    c.Raw({0x48,0x8D,0x8C,0x24}); c.U32(stateBase); c.Raw({0xFF,0xD0});
    X64LoadQ(c,11,CtxRegisterMap);
    for(uint8_t family=0;family<16;++family){
        X64LoadStackQ(c,0,stateBase+static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE,gpr))+family*8u);
        c.Raw({0x41,0x0F,0xB6,0x4B,family}); X64StoreIndexedQ(c,CtxVregs,1,0);
    }
    c.Raw({0x48,0x81,0xC4}); c.U32(allocation);
    RecordX64StackFunclet(c, funcletBegin,
        VMHandlerSemanticUnwindKind::StackAllocation,
        allocation, kX64BridgePrologSize);
}

void EmitX86BridgeExtended(
    CodeBuffer& c,
    CodeBuffer::Label rangeFailure,
    CodeBuffer::Label flagsFailure,
    uint8_t coreStrategy,
    uint32_t& coreVariantOffset,
    uint32_t& coreVariantSize)
{
    constexpr uint32_t allocation=sizeof(VM_INSTRUCTION_BRIDGE_STATE);
    (void)flagsFailure;
    X86LoadD(c,0,CtxDecodedOperands+8u);c.Raw({0xA9});c.U32(~VM_MICRO_BRIDGE_KNOWN_MASK);c.Jcc(JccNE,rangeFailure);
    X86LoadD(c,0,CtxImageBase);X86LoadD(c,2,CtxDecodedOperands);
    EmitTrackedBusinessCoreVariant(c, false, VM_UOP_BRIDGE_EXTENDED,
        coreStrategy, coreVariantOffset, coreVariantSize);
    X86StoreD(c,CtxMutationScratch,0);
    X86LoadD(c,2,CtxRegisterMap);c.Raw({0x85,0xD2});c.Jcc(JccE,rangeFailure);
    c.Raw({0x81,0xEC});c.U32(allocation);
    for(uint8_t family=0;family<8;++family){
        c.Raw({0x0F,0xB6,0x4A,family});X86LoadIndexedD(c,0,CtxVregs);
        X86StoreStackD(c,offsetof(VM_INSTRUCTION_BRIDGE_STATE,gpr)+family*8u,0);
        c.Raw({0xC7,0x84,0x24});c.U32(offsetof(VM_INSTRUCTION_BRIDGE_STATE,gpr)+family*8u+4u);c.U32(0);
    }
    c.Raw({0xB8,0x02,0x02,0x00,0x00});X86StoreStackD(c,offsetof(VM_INSTRUCTION_BRIDGE_STATE,rflags),0);
    X86LoadD(c,0,CtxMutationScratch);X86StoreStackD(c,offsetof(VM_INSTRUCTION_BRIDGE_STATE,target),0);
    X86StoreStackD(c,offsetof(VM_INSTRUCTION_BRIDGE_STATE,guardTarget),0);
    X86LoadD(c,0,CtxExtendedState);X86StoreStackD(c,offsetof(VM_INSTRUCTION_BRIDGE_STATE,extendedState),0);
    X86LoadD(c,0,CtxDecodedOperands+8u);c.Raw({0x89,0xC2,0x81,0xE2});c.U32(VM_MICRO_BRIDGE_AVX);c.Raw({0xC1,0xEA,0x08});
    X86StoreStackD(c,offsetof(VM_INSTRUCTION_BRIDGE_STATE,extendedStateFlags),2);c.Raw({0x83,0xE0,VM_MICRO_BRIDGE_HIDDEN_REGISTER_MASK});
    X86StoreStackD(c,offsetof(VM_INSTRUCTION_BRIDGE_STATE,hiddenRegister),0);
    X86LoadStackD(c,0,offsetof(VM_INSTRUCTION_BRIDGE_STATE,target));c.Raw({0x54,0xFF,0xD0,0x83,0xC4,0x04});
    X86LoadD(c,2,CtxRegisterMap);
    for(uint8_t family=0;family<8;++family){
        X86LoadStackD(c,0,offsetof(VM_INSTRUCTION_BRIDGE_STATE,gpr)+family*8u);
        c.Raw({0x0F,0xB6,0x4A,family});X86StoreIndexedD(c,CtxVregs,0);
        c.Raw({0xC7,0x84,0xCF});c.U32(CtxVregs+4u);c.U32(0);
    }
    c.Raw({0x81,0xC4});c.U32(allocation);
}

void EmitX64SpecialSemantic(
    CodeBuffer& c,
    VM_MICRO_OPCODE semantic,
    CodeBuffer::Label rangeFailure,
    uint8_t coreStrategy,
    uint32_t& coreVariantOffset,
    uint32_t& coreVariantSize)
{
    if(semantic==VM_UOP_INT3){
        EmitTrackedBusinessCoreVariant(c, true, semantic, coreStrategy,
            coreVariantOffset, coreVariantSize);
        return;
    }
    X64LoadQ(c,11,CtxRegisterMap);c.Raw({0x4D,0x85,0xDB});c.Jcc(JccE,rangeFailure);
    if(semantic==VM_UOP_RDTSC){
        c.Raw({0x0F,0x31,0x41,0x89,0xC0,0x41,0x89,0xD1});
        c.Raw({0x41,0x0F,0xB6,0x0B});X64StoreIndexedQ(c,CtxVregs,1,8);
        c.Raw({0x41,0x0F,0xB6,0x4B,0x02});X64StoreIndexedQ(c,CtxVregs,1,9);return;
    }
    const size_t funcletBegin = c.bytes.size();
    c.U8(0x53);c.Raw({0x41,0x0F,0xB6,0x0B});X64LoadIndexedQ(c,0,1,CtxVregs);
    c.Raw({0x41,0x0F,0xB6,0x4B,0x01});X64LoadIndexedQ(c,1,1,CtxVregs);c.Raw({0x0F,0xA2,
        0x41,0x89,0xC0,0x41,0x89,0xD9,0x41,0x89,0xCA,0x41,0x89,0xD3,0x5B});
    RecordX64StackFunclet(c, funcletBegin,
        VMHandlerSemanticUnwindKind::PushNonvolatile,
        0, kX64CpuidPrologSize, kX64RbxUnwindRegister);
    X64LoadQ(c,0,CtxRegisterMap);c.Raw({0x0F,0xB6,0x08});X64StoreIndexedQ(c,CtxVregs,1,8);
    c.Raw({0x0F,0xB6,0x48,0x03});X64StoreIndexedQ(c,CtxVregs,1,9);
    c.Raw({0x0F,0xB6,0x48,0x01});X64StoreIndexedQ(c,CtxVregs,1,10);
    c.Raw({0x0F,0xB6,0x48,0x02});X64StoreIndexedQ(c,CtxVregs,1,11);
}

void EmitX86SpecialSemantic(
    CodeBuffer& c,
    VM_MICRO_OPCODE semantic,
    CodeBuffer::Label rangeFailure,
    uint8_t coreStrategy,
    uint32_t& coreVariantOffset,
    uint32_t& coreVariantSize)
{
    if(semantic==VM_UOP_INT3){
        EmitTrackedBusinessCoreVariant(c, false, semantic, coreStrategy,
            coreVariantOffset, coreVariantSize);
        return;
    }
    X86LoadD(c,2,CtxRegisterMap);c.Raw({0x85,0xD2});c.Jcc(JccE,rangeFailure);
    if(semantic==VM_UOP_RDTSC){c.Raw({0x0F,0x31,0x52,0x50});X86LoadD(c,2,CtxRegisterMap);
        c.Raw({0x0F,0xB6,0x0A,0x58});X86StoreIndexedD(c,CtxVregs,0);c.Raw({0xC7,0x84,0xCF});c.U32(CtxVregs+4u);c.U32(0);
        c.Raw({0x0F,0xB6,0x4A,0x02,0x58});X86StoreIndexedD(c,CtxVregs,0);c.Raw({0xC7,0x84,0xCF});c.U32(CtxVregs+4u);c.U32(0);return;}
    c.U8(0x53);c.Raw({0x0F,0xB6,0x0A});X86LoadIndexedD(c,0,CtxVregs);c.Raw({0x0F,0xB6,0x4A,0x01});X86LoadIndexedD(c,1,CtxVregs);
    c.Raw({0x0F,0xA2,0x52,0x51,0x53,0x50});X86LoadD(c,2,CtxRegisterMap);
    const uint8_t families[4]={0,3,1,2};for(uint8_t i=0;i<4;++i){c.U8(0x58);c.Raw({0x0F,0xB6,static_cast<uint8_t>(0x4A),families[i]});
        X86StoreIndexedD(c,CtxVregs,0);c.Raw({0xC7,0x84,0xCF});c.U32(CtxVregs+4u);c.U32(0);}c.U8(0x5B);
}



} // namespace

VMHandlerSemanticCodegenResult GenerateVMHandlerSemanticKernel(
    const VMHandlerSemanticCodegenConfig& config)
{
    VMHandlerSemanticCodegenResult result{};
    if (config.architecture != VM_ARCH_X64 && config.architecture != VM_ARCH_X86) {
        result.error = "semantic code generator received an unknown architecture";
        return result;
    }
    if (config.semantic <= VM_UOP_TRAP || config.semantic >= VM_UOP_COUNT) {
        result.error = "TRAP/out-of-range semantic has no successful kernel";
        return result;
    }
    const VMOpcodeDescriptor* descriptor = VMSchema::Lookup(config.semantic);
    if (!descriptor) {
        result.error = "semantic descriptor is missing";
        return result;
    }
    const bool x64 = config.architecture == VM_ARCH_X64;
    if ((x64 && !descriptor->runtimeSupportedX64) ||
        (!x64 && !descriptor->runtimeSupportedX86)) {
        result.error = "semantic is intentionally fail-closed for this architecture";
        return result;
    }
    if (!HasConcreteEmitter(config.semantic)) {
        result.error = "semantic has no concrete fail-closed emitter";
        return result;
    }

    CodeBuffer code;
    ConfigurePermutationPlans(code, config);
    result.semanticCoreStrategy = DeriveBusinessCoreStrategy(config);
    result.registerAssignment = DeriveVariantRegisters(
        x64, config.variant, config.semantic, config.buildSeed,
        result.semanticCoreStrategy);
    code.registerAssignment = result.registerAssignment;
    result.variantPrefixOffset = static_cast<uint32_t>(code.bytes.size());
    result.variantPrefixSize = static_cast<uint32_t>(code.bytes.size()) -
        result.variantPrefixOffset;
    result.semanticBodyOffset = static_cast<uint32_t>(code.bytes.size());
    const auto stackFailure = code.NewLabel();
    const auto widthFailure = code.NewLabel();
    const auto rangeFailure = code.NewLabel();
    const auto flagsFailure = code.NewLabel();
    const auto divideFailure = code.NewLabel();
    const auto success = code.NewLabel();

    const SemanticMutationPlan inputPlan = DeriveSemanticMutationPlan(
        config, 0x494E505554504154ULL);
    const SemanticMutationPlan outputPlan = DeriveSemanticMutationPlan(
        config, 0x4F55545055545041ULL);
    result.semanticInputStrategy = inputPlan.strategy;
    result.semanticResultStrategy = outputPlan.strategy;
    result.semanticInputPathOffset = static_cast<uint32_t>(code.bytes.size());
    result.semanticInputPathSize = static_cast<uint32_t>(code.bytes.size()) -
        result.semanticInputPathOffset;
    result.semanticCoreOffset = static_cast<uint32_t>(code.bytes.size());

    if (x64) {
        switch (descriptor->opcodeClass) {
            case VMOpcodeClass::Data:
            case VMOpcodeClass::Stack:
            case VMOpcodeClass::Memory:
                EmitX64DataSemantic(code, config.semantic, stackFailure,
                    widthFailure, rangeFailure, flagsFailure,
                    result.semanticCoreStrategy,
                    result.semanticCoreVariantOffset,
                    result.semanticCoreVariantSize);
                break;
            case VMOpcodeClass::Arithmetic:
                if (IsBinaryAlu(config.semantic))
                    EmitX64BinaryAlu(code, config.semantic, stackFailure,
                        widthFailure, result.semanticCoreStrategy,
                        result.semanticCoreVariantOffset,
                        result.semanticCoreVariantSize);
                else if (config.semantic == VM_UOP_ADD_CARRY ||
                         config.semantic == VM_UOP_SUB_BORROW)
                    EmitX64CarryAlu(code, config.semantic, stackFailure, widthFailure,
                        result.semanticCoreStrategy,
                        result.semanticCoreVariantOffset,
                        result.semanticCoreVariantSize);
                else if (IsUnaryAlu(config.semantic))
                    EmitX64UnaryAlu(code, config.semantic, stackFailure,
                        widthFailure, result.semanticCoreStrategy,
                        result.semanticCoreVariantOffset,
                        result.semanticCoreVariantSize);
                else if (config.semantic == VM_UOP_ZERO_EXTEND ||
                         config.semantic == VM_UOP_SIGN_EXTEND)
                    EmitX64Extend(code, config.semantic == VM_UOP_SIGN_EXTEND,
                        stackFailure, widthFailure, rangeFailure,
                        result.semanticCoreStrategy,
                        result.semanticCoreVariantOffset,
                        result.semanticCoreVariantSize);
                else if (config.semantic == VM_UOP_UMUL_WIDE ||
                         config.semantic == VM_UOP_SMUL_WIDE)
                    EmitX64WideMultiply(code, config.semantic == VM_UOP_SMUL_WIDE,
                        stackFailure, widthFailure, result.semanticCoreStrategy,
                        result.semanticCoreVariantOffset,
                        result.semanticCoreVariantSize);
                else if (config.semantic == VM_UOP_UDIV_WIDE ||
                         config.semantic == VM_UOP_IDIV_WIDE)
                    EmitX64WideDivide(code, config.semantic == VM_UOP_IDIV_WIDE,
                        stackFailure, widthFailure, divideFailure,
                        result.semanticCoreStrategy,
                        result.semanticCoreVariantOffset,
                        result.semanticCoreVariantSize);
                else {
                    result.error = "arithmetic semantic has no x64 emitter";
                    return result;
                }
                break;
            case VMOpcodeClass::Flags:
                EmitX64FlagsSemantic(code, config.semantic, stackFailure,
                    widthFailure, rangeFailure, flagsFailure,
                    result.semanticCoreStrategy,
                    result.semanticCoreVariantOffset,
                    result.semanticCoreVariantSize);
                break;
            case VMOpcodeClass::ControlFlow:
                EmitX64ControlSemantic(code, config.semantic, stackFailure,
                    rangeFailure, flagsFailure, result.semanticCoreStrategy,
                    result.semanticCoreVariantOffset,
                    result.semanticCoreVariantSize);
                break;
            case VMOpcodeClass::Call:
                if (config.semantic == VM_UOP_CALL_HOST) {
                    EmitX64CallHost(code, stackFailure, rangeFailure,
                        flagsFailure, result.semanticCoreStrategy,
                        result.semanticCoreVariantOffset,
                        result.semanticCoreVariantSize);
                } else {
                    EmitX64ControlSemantic(code, config.semantic, stackFailure,
                        rangeFailure, flagsFailure, result.semanticCoreStrategy,
                        result.semanticCoreVariantOffset,
                        result.semanticCoreVariantSize);
                }
                break;
            case VMOpcodeClass::Bridge:
                EmitX64BridgeExtended(code, rangeFailure, flagsFailure,
                    result.semanticCoreStrategy,
                    result.semanticCoreVariantOffset,
                    result.semanticCoreVariantSize);
                break;
            case VMOpcodeClass::Special:
                EmitX64SpecialSemantic(code, config.semantic, rangeFailure,
                    result.semanticCoreStrategy,
                    result.semanticCoreVariantOffset,
                    result.semanticCoreVariantSize);
                break;
            default:
                result.error = "semantic opcode class is not executable";
                return result;
        }
    } else {
        switch (descriptor->opcodeClass) {
            case VMOpcodeClass::Data:
            case VMOpcodeClass::Stack:
            case VMOpcodeClass::Memory:
                EmitX86DataSemantic(code, config.semantic, stackFailure,
                    widthFailure, rangeFailure, flagsFailure,
                    result.semanticCoreStrategy,
                    result.semanticCoreVariantOffset,
                    result.semanticCoreVariantSize);
                break;
            case VMOpcodeClass::Arithmetic:
                if (IsBinaryAlu(config.semantic))
                    EmitX86BinaryAlu(code, config.semantic, stackFailure,
                        widthFailure, result.semanticCoreStrategy,
                        result.semanticCoreVariantOffset,
                        result.semanticCoreVariantSize);
                else if (config.semantic == VM_UOP_ADD_CARRY ||
                         config.semantic == VM_UOP_SUB_BORROW)
                    EmitX86CarryAlu(code, config.semantic, stackFailure, widthFailure,
                        result.semanticCoreStrategy,
                        result.semanticCoreVariantOffset,
                        result.semanticCoreVariantSize);
                else if (IsUnaryAlu(config.semantic))
                    EmitX86UnaryAlu(code, config.semantic, stackFailure,
                        widthFailure, result.semanticCoreStrategy,
                        result.semanticCoreVariantOffset,
                        result.semanticCoreVariantSize);
                else if (config.semantic == VM_UOP_ZERO_EXTEND ||
                         config.semantic == VM_UOP_SIGN_EXTEND)
                    EmitX86Extend(code, config.semantic == VM_UOP_SIGN_EXTEND,
                        stackFailure, widthFailure, rangeFailure,
                        result.semanticCoreStrategy,
                        result.semanticCoreVariantOffset,
                        result.semanticCoreVariantSize);
                else if (config.semantic == VM_UOP_UMUL_WIDE ||
                         config.semantic == VM_UOP_SMUL_WIDE)
                    EmitX86WideMultiply(code, config.semantic == VM_UOP_SMUL_WIDE,
                        stackFailure, widthFailure, result.semanticCoreStrategy,
                        result.semanticCoreVariantOffset,
                        result.semanticCoreVariantSize);
                else if (config.semantic == VM_UOP_UDIV_WIDE ||
                         config.semantic == VM_UOP_IDIV_WIDE)
                    EmitX86WideDivide(code, config.semantic == VM_UOP_IDIV_WIDE,
                        stackFailure, widthFailure, divideFailure,
                        result.semanticCoreStrategy,
                        result.semanticCoreVariantOffset,
                        result.semanticCoreVariantSize);
                else {
                    result.error = "arithmetic semantic has no x86 emitter";
                    return result;
                }
                break;
            case VMOpcodeClass::Flags:
                EmitX86FlagsSemantic(code, config.semantic, stackFailure,
                    widthFailure, rangeFailure, flagsFailure,
                    result.semanticCoreStrategy,
                    result.semanticCoreVariantOffset,
                    result.semanticCoreVariantSize);
                break;
            case VMOpcodeClass::ControlFlow:
                EmitX86ControlSemantic(code, config.semantic, stackFailure,
                    rangeFailure, flagsFailure, result.semanticCoreStrategy,
                    result.semanticCoreVariantOffset,
                    result.semanticCoreVariantSize);
                break;
            case VMOpcodeClass::Call:
                if (config.semantic == VM_UOP_CALL_HOST) {
                    EmitX86CallHost(code, stackFailure, rangeFailure,
                        flagsFailure, result.semanticCoreStrategy,
                        result.semanticCoreVariantOffset,
                        result.semanticCoreVariantSize);
                } else {
                    EmitX86ControlSemantic(code, config.semantic, stackFailure,
                        rangeFailure, flagsFailure, result.semanticCoreStrategy,
                        result.semanticCoreVariantOffset,
                        result.semanticCoreVariantSize);
                }
                break;
            case VMOpcodeClass::Bridge:
                EmitX86BridgeExtended(code, rangeFailure, flagsFailure,
                    result.semanticCoreStrategy,
                    result.semanticCoreVariantOffset,
                    result.semanticCoreVariantSize);
                break;
            case VMOpcodeClass::Special:
                EmitX86SpecialSemantic(code, config.semantic, rangeFailure,
                    result.semanticCoreStrategy,
                    result.semanticCoreVariantOffset,
                    result.semanticCoreVariantSize);
                break;
            default:
                result.error = "semantic opcode class is not executable";
                return result;
        }
    }
    result.semanticCoreSize = static_cast<uint32_t>(code.bytes.size()) -
        result.semanticCoreOffset;
    result.semanticResultPathOffset = static_cast<uint32_t>(code.bytes.size());
    result.semanticResultPathSize = static_cast<uint32_t>(code.bytes.size()) -
        result.semanticResultPathOffset;
    result.semanticBodySize = static_cast<uint32_t>(code.bytes.size()) -
        result.semanticBodyOffset;
    result.variantSuffixOffset = static_cast<uint32_t>(code.bytes.size());
    result.variantSuffixSize = static_cast<uint32_t>(code.bytes.size()) -
        result.variantSuffixOffset;
    code.Jmp(success);

    const std::array<CodeBuffer::Label, 5> failureLabels = {
        stackFailure, widthFailure, rangeFailure, flagsFailure, divideFailure
    };
    const std::array<uint32_t, 4> failureErrors = {
        VM_MICRO_ERR_VALUE_STACK_UNDERFLOW,
        VM_MICRO_ERR_OPCODE_UNSUPPORTED,
        VM_MICRO_ERR_HANDLER_BUG,
        VM_MICRO_ERR_FLAGS_STATE
    };
    const uint32_t failureRotation = config.variant %
        static_cast<uint8_t>(failureLabels.size());
    for (uint32_t order = 0;
         order < static_cast<uint32_t>(failureLabels.size()); ++order) {
        const uint32_t failure = (order + failureRotation) %
            static_cast<uint32_t>(failureLabels.size());
        code.Bind(failureLabels[failure]);
        result.failureBlockOffsets[failure] =
            static_cast<uint32_t>(code.bytes.size());
        if (failure < failureErrors.size()) {
            if (x64) EmitX64Failure(code, failureErrors[failure]);
            else EmitX86Failure(code, failureErrors[failure]);
        } else if (x64) {
            code.Raw({0x31,0xC9,0x31,0xD2,0xB8,0x01,0x00,0x00,0x00,
                      0x48,0xF7,0xF1});
        } else {
            code.Raw({0x31,0xC9,0x31,0xD2,0xB8,0x01,0x00,0x00,0x00,0xF7,0xF1});
        }
    }
    code.Bind(success);

    if (!code.Resolve(result.error)) return result;
    result.operandCount = descriptor->operandCount;
    result.stackPops = descriptor->stackPops;
    result.stackPushes = descriptor->stackPushes;
    result.decodedOperandCount = descriptor->operandCount;
    result.stackFunclets = std::move(code.stackFunclets);
    result.valueCodecRanges.reserve(code.valueCodecRanges.size());
    for (const auto& range : code.valueCodecRanges)
        result.valueCodecRanges.push_back({range.first, range.second});
    result.code = std::move(code.bytes);
    result.semanticComplete = !result.code.empty();
    result.success = result.semanticComplete;
    std::string evidenceError;
    if (!ValidateVMHandlerSemanticVariantKernel(config, result, evidenceError)) {
        result.success = false;
        result.semanticComplete = false;
        result.error = "variant machine-code evidence failed: " + evidenceError;
    }
    return result;
}

bool ValidateVMHandlerSemanticVariantKernel(
    const VMHandlerSemanticCodegenConfig& config,
    const VMHandlerSemanticCodegenResult& result,
    std::string& error)
{
    const bool x64 = config.architecture == VM_ARCH_X64;
    if ((!x64 && config.architecture != VM_ARCH_X86) || result.code.empty()) {
        error = "variant evidence has invalid architecture or empty code";
        return false;
    }
    const auto rangeValid = [&](uint32_t offset, uint32_t size) {
        return offset <= result.code.size() &&
            size <= result.code.size() - offset;
    };
    const auto rangeInside = [](uint32_t outerOffset, uint32_t outerSize,
                                uint32_t innerOffset, uint32_t innerSize) {
        return innerOffset >= outerOffset &&
            innerOffset - outerOffset <= outerSize &&
            innerSize <= outerSize - (innerOffset - outerOffset);
    };
    if (!rangeValid(result.variantPrefixOffset, result.variantPrefixSize) ||
        !rangeValid(result.semanticBodyOffset, result.semanticBodySize) ||
        !rangeValid(result.semanticInputPathOffset,
            result.semanticInputPathSize) ||
        !rangeValid(result.semanticCoreOffset, result.semanticCoreSize) ||
        !rangeValid(result.semanticResultPathOffset,
            result.semanticResultPathSize) ||
        !rangeValid(result.variantSuffixOffset, result.variantSuffixSize) ||
        !rangeValid(result.opaquePredicateOffset, result.opaquePredicateSize) ||
        result.variantPrefixOffset != 0 ||
        result.variantPrefixOffset + result.variantPrefixSize !=
            result.semanticBodyOffset ||
        result.semanticBodyOffset + result.semanticBodySize !=
            result.variantSuffixOffset ||
        result.variantPrefixSize != 0u || result.variantSuffixSize != 0u ||
        result.semanticInputPathSize != 0u ||
        result.semanticResultPathSize != 0u ||
        result.opaquePredicateSize != 0u ||
        result.semanticBodySize == 0 || result.semanticCoreSize == 0) {
        error = "variant executable ranges are missing, overlapping, or too small";
        return false;
    }
    if (!rangeInside(result.semanticBodyOffset, result.semanticBodySize,
            result.semanticInputPathOffset, result.semanticInputPathSize) ||
        !rangeInside(result.semanticBodyOffset, result.semanticBodySize,
            result.semanticCoreOffset, result.semanticCoreSize) ||
        !rangeInside(result.semanticBodyOffset, result.semanticBodySize,
            result.semanticResultPathOffset, result.semanticResultPathSize) ||
        result.semanticInputPathOffset != result.semanticCoreOffset ||
        result.semanticCoreOffset + result.semanticCoreSize !=
            result.semanticResultPathOffset ||
        result.semanticResultPathOffset !=
            result.semanticBodyOffset + result.semanticBodySize ||
        result.semanticBodyOffset != result.semanticCoreOffset ||
        result.semanticBodySize != result.semanticCoreSize) {
        error = "semantic input/core/result evidence is outside semanticBody";
        return false;
    }
    const uint8_t expectedCoreStrategy = DeriveBusinessCoreStrategy(config);
    const std::array<uint8_t, 4> expectedRegisters = DeriveVariantRegisters(
        x64, config.variant, config.semantic, config.buildSeed,
        expectedCoreStrategy);
    if (result.registerAssignment != expectedRegisters) {
        error = "published register allocation does not match variant/seed";
        return false;
    }
    if (result.registerAssignment[0] == result.registerAssignment[1] ||
        result.registerAssignment[0] == result.registerAssignment[2] ||
        result.registerAssignment[1] == result.registerAssignment[2]) {
        error = "semantic data path lacks three distinct physical registers";
        return false;
    }
    for (uint8_t reg : result.registerAssignment) {
        const bool x86MemoryContract = !x64 &&
            (config.semantic == VM_UOP_LOAD ||
             config.semantic == VM_UOP_STORE);
        const bool x86UmulWideContract = !x64 &&
            config.semantic == VM_UOP_UMUL_WIDE;
        const bool x86MultiplyContract = !x64 &&
            config.semantic == VM_UOP_MUL;
        const bool valid = x64
            ? (reg == 0 || reg == 1 || reg == 2 ||
               reg == 8 || reg == 9 || reg == 10 || reg == 11)
             : (reg <= 2 || (x86MemoryContract &&
                (reg == 3 || reg == 6)) ||
                (x86MultiplyContract && reg == 3) ||
                (x86UmulWideContract && (reg == 3 || reg == 6)));
        if (!valid) {
            error = "variant register allocation violates its liveness contract";
            return false;
        }
    }

    const VMOpcodeDescriptor* descriptor = VMSchema::Lookup(config.semantic);
    if (!descriptor) {
        error = "semantic data-path descriptor is missing";
        return false;
    }
    VMHandlerSemanticStackFunclet expectedFunclet{};
    const bool expectsFunclet = x64 && ExpectedX64StackFunclet(
        config.semantic, expectedFunclet);
    if ((!x64 && !result.stackFunclets.empty()) ||
        result.stackFunclets.size() != (expectsFunclet ? 1u : 0u)) {
        error = "semantic stack-funclet coverage is incomplete or unexpected";
        return false;
    }
    if (expectsFunclet) {
        const VMHandlerSemanticStackFunclet& funclet = result.stackFunclets[0];
        if (!rangeValid(funclet.offset, funclet.size) || funclet.size == 0 ||
            !rangeInside(result.semanticCoreOffset, result.semanticCoreSize,
                funclet.offset, funclet.size) ||
            funclet.kind != expectedFunclet.kind ||
            funclet.stackBytes != expectedFunclet.stackBytes ||
            funclet.prologSize != expectedFunclet.prologSize ||
            funclet.nonvolatileRegister !=
                expectedFunclet.nonvolatileRegister) {
            error = "semantic stack-funclet metadata disagrees with emitted core";
            return false;
        }
        const auto begin = result.code.begin() + funclet.offset;
        const auto end = begin + funclet.size;
        if (funclet.kind ==
                VMHandlerSemanticUnwindKind::StackAllocation &&
            funclet.stackBytes == kX64FlagCallStackBytes) {
            constexpr std::array<uint8_t, 10> expectedCode = {
                0x48,0x83,0xEC,0x28,0xFF,0xD0,0x48,0x83,0xC4,0x28
            };
            if (funclet.size != expectedCode.size() ||
                !std::equal(expectedCode.begin(), expectedCode.end(), begin)) {
                error = "flag-materializer funclet bytes are not canonical";
                return false;
            }
        } else if (funclet.kind ==
                       VMHandlerSemanticUnwindKind::StackAllocation &&
                   funclet.stackBytes == kX64BridgeStackBytes) {
            constexpr std::array<uint8_t, 7> prolog = {
                0x48,0x81,0xEC,0x98,0x04,0x00,0x00
            };
            constexpr std::array<uint8_t, 7> epilog = {
                0x48,0x81,0xC4,0x98,0x04,0x00,0x00
            };
            constexpr std::array<uint8_t, 2> call = {0xFF,0xD0};
            if (funclet.size < prolog.size() + epilog.size() + call.size() ||
                !std::equal(prolog.begin(), prolog.end(), begin) ||
                !std::equal(epilog.begin(), epilog.end(),
                    end - static_cast<ptrdiff_t>(epilog.size())) ||
                std::search(begin, end, call.begin(), call.end()) == end) {
                error = "extended-bridge funclet bytes are not canonical";
                return false;
            }
        } else if (funclet.kind ==
                       VMHandlerSemanticUnwindKind::StackAllocation &&
                   funclet.stackBytes == kX64NativeCallStackBytes) {
            constexpr std::array<uint8_t, 7> prolog = {
                0x48,0x81,0xEC,0x08,0x06,0x00,0x00
            };
            constexpr std::array<uint8_t, 7> epilog = {
                0x48,0x81,0xC4,0x08,0x06,0x00,0x00
            };
            constexpr std::array<uint8_t, 2> call = {0xFF,0xD0};
            if (funclet.size < prolog.size() + epilog.size() + call.size() ||
                !std::equal(prolog.begin(), prolog.end(), begin) ||
                !std::equal(epilog.begin(), epilog.end(),
                    end - static_cast<ptrdiff_t>(epilog.size())) ||
                std::search(begin, end, call.begin(), call.end()) == end) {
                error = "native-call funclet bytes are not canonical";
                return false;
            }
        } else if (funclet.kind ==
                       VMHandlerSemanticUnwindKind::PushNonvolatile &&
                   funclet.nonvolatileRegister == kX64RbxUnwindRegister) {
            constexpr std::array<uint8_t, 2> cpuid = {0x0F,0xA2};
            if (funclet.size < 4u || *begin != 0x53 || *(end - 1) != 0x5B ||
                std::search(begin, end, cpuid.begin(), cpuid.end()) == end) {
                error = "CPUID RBX-save funclet bytes are not canonical";
                return false;
            }
        } else {
            error = "semantic stack-funclet kind is unsupported";
            return false;
        }
    }
    const SemanticMutationPlan expectedInputPlan = DeriveSemanticMutationPlan(
        config, 0x494E505554504154ULL);
    const SemanticMutationPlan expectedOutputPlan = DeriveSemanticMutationPlan(
        config, 0x4F55545055545041ULL);
    if (result.semanticInputStrategy != expectedInputPlan.strategy ||
        result.semanticCoreStrategy != expectedCoreStrategy ||
        result.semanticResultStrategy != expectedOutputPlan.strategy) {
        error = "semantic strategy metadata does not match variant/seed";
        return false;
    }

    const auto rangeEquals = [&](uint32_t offset, uint32_t size,
                                 const std::vector<uint8_t>& expected) {
        return size == expected.size() && rangeValid(offset, size) &&
            std::equal(expected.begin(), expected.end(),
                result.code.begin() + offset);
    };
    if (!ValidateBusinessCoreStrategyReemission(config, x64, error)) {
        return false;
    }
    if (HasBusinessCoreVariant(config.semantic)) {
        if (!rangeValid(result.semanticCoreVariantOffset,
                result.semanticCoreVariantSize) ||
            !rangeInside(result.semanticCoreOffset, result.semanticCoreSize,
                result.semanticCoreVariantOffset,
                result.semanticCoreVariantSize)) {
            error = "business core variant evidence is outside semantic core";
            return false;
        }
        CodeBuffer expectedCoreVariant;
        ConfigurePermutationPlans(expectedCoreVariant, config);
        expectedCoreVariant.registerAssignment = expectedRegisters;
        uint32_t expectedOffset = 0;
        uint32_t expectedSize = 0;
        if (!EmitTrackedBusinessCoreVariant(expectedCoreVariant, x64,
                config.semantic, expectedCoreStrategy,
                expectedOffset, expectedSize)) {
            error = "business core variant could not be re-emitted";
            return false;
        }
        std::string coreResolveError;
        if (!expectedCoreVariant.Resolve(coreResolveError) ||
            expectedOffset != 0u ||
            expectedSize != expectedCoreVariant.bytes.size() ||
            !rangeEquals(result.semanticCoreVariantOffset,
                result.semanticCoreVariantSize,
                expectedCoreVariant.bytes)) {
            error = "business core is fixed or disagrees with variant/seed";
            return false;
        }
    } else if (result.semanticCoreVariantOffset != 0 ||
               result.semanticCoreVariantSize != 0) {
        error = "semantic without a business alternative published false core evidence";
        return false;
    }

    const auto contains = [&](uint32_t offset, uint32_t size,
                              const std::vector<uint8_t>& needle) {
        if (needle.empty() || !rangeValid(offset, size)) return false;
        const auto begin = result.code.begin() + offset;
        const auto end = begin + size;
        return std::search(begin, end, needle.begin(), needle.end()) != end;
    };
    const KeyedPermutationPlan valuePlan = DerivePermutationPlan(config,
        0x56414C5545434F44ULL, static_cast<uint8_t>(kValueCodecRoundCount), 4u);
    const KeyedPermutationPlan corePlan = DerivePermutationPlan(config,
        0x434F524553454C45ULL ^
            (static_cast<uint64_t>(config.semantic) << 13u) ^
            (static_cast<uint64_t>(config.variant) << 41u),
        static_cast<uint8_t>(kCoreSelectorRoundCount), 8u);
    const auto validatePlan = [&](const KeyedPermutationPlan& plan,
                                  uint8_t expectedRounds,
                                  uint8_t expectedFamilies,
                                  const char* name) {
        if (plan.roundCount != expectedRounds) {
            error = std::string(name) + " has the wrong fixed round budget";
            return false;
        }
        std::array<uint8_t, 8> families{};
        for (uint8_t index = 0; index < plan.roundCount; ++index) {
            const auto& round = plan.rounds[index];
            const uint8_t family = static_cast<uint8_t>(round.op);
            if (family >= families.size()) {
                error = std::string(name) + " has an invalid permutation op";
                return false;
            }
            ++families[family];
            if ((round.op == KeyedPermutationOp::Xor ||
                 round.op == KeyedPermutationOp::Add) && round.key == 0u) {
                error = std::string(name) + " contains a zero key";
                return false;
            }
            if (round.op == KeyedPermutationOp::Multiply &&
                (((round.key & 1u) == 0u) || round.key == 1u ||
                 round.key * round.inverse != 1u)) {
                if (!x64 && static_cast<uint32_t>(round.key) *
                        static_cast<uint32_t>(round.inverse) == 1u) {
                    continue;
                }
                error = std::string(name) +
                    " contains a degenerate multiplier or wrong inverse";
                return false;
            }
            const uint8_t width = x64 ? 64u : 32u;
            if (round.op == KeyedPermutationOp::Rotate &&
                (round.rotate == 0u || round.rotate >= width)) {
                error = std::string(name) + " has a degenerate rotation";
                return false;
            }
        }
        if (std::any_of(families.begin(),
                families.begin() + expectedFamilies,
                [](uint8_t count) { return count == 0u; }) ||
            std::any_of(families.begin() + expectedFamilies,
                families.end(), [](uint8_t count) { return count != 0u; })) {
            error = std::string(name) + " omits a required permutation family";
            return false;
        }
        return true;
    };
    if (!validatePlan(valuePlan, static_cast<uint8_t>(kValueCodecRoundCount),
            4u, "value codec") ||
        !validatePlan(corePlan, static_cast<uint8_t>(kCoreSelectorRoundCount),
            8u, "core selector")) {
        return false;
    }

    const auto applyRound = [&](uint64_t value,
                                const KeyedPermutationRound& round,
                                bool inverse) {
        const uint8_t width = x64 ? 64u : 32u;
        const uint64_t mask = x64 ? ~uint64_t{0} : 0xFFFFFFFFu;
        value &= mask;
        switch (round.op) {
            case KeyedPermutationOp::Xor:
                value ^= round.key;
                break;
            case KeyedPermutationOp::Add:
                value = inverse ? value - round.key : value + round.key;
                break;
            case KeyedPermutationOp::Rotate: {
                const uint8_t rotate = inverse
                    ? static_cast<uint8_t>(width - round.rotate)
                    : round.rotate;
                value = ((value << rotate) |
                    (value >> (width - rotate))) & mask;
                break;
            }
            case KeyedPermutationOp::Multiply:
                value *= inverse ? round.inverse : round.key;
                break;
        }
        return value & mask;
    };
    constexpr std::array<uint64_t, 6> oracleValues = {
        0u, 1u, ~uint64_t{0}, 0x8000000000000000ULL,
        0x0123456789ABCDEFULL, 0xA5A5A5A55A5A5A5AULL
    };
    for (uint64_t original : oracleValues) {
        if (!x64) original = static_cast<uint32_t>(original);
        uint64_t value = original;
        for (uint8_t index = 0; index < valuePlan.roundCount; ++index)
            value = applyRound(value, valuePlan.rounds[index], false);
        for (uint8_t index = valuePlan.roundCount; index != 0u; --index)
            value = applyRound(value, valuePlan.rounds[index - 1u], true);
        if (value != original) {
            error = "value codec failed the independent inverse oracle";
            return false;
        }
    }

    const size_t expectedCodecRanges =
        static_cast<size_t>(std::max<int>(0, descriptor->stackPops)) +
        static_cast<size_t>(std::max<int>(0, descriptor->stackPushes));
    if (result.valueCodecRanges.size() != expectedCodecRanges) {
        error = "value codec ranges do not cover every stack pop/push";
        return false;
    }
    uint32_t previousCodecEnd = result.semanticCoreOffset;
    for (const auto& range : result.valueCodecRanges) {
        if (range.size < 32u || !rangeValid(range.offset, range.size) ||
            !rangeInside(result.semanticCoreOffset, result.semanticCoreSize,
                range.offset, range.size) ||
            range.offset < previousCodecEnd) {
            error = "value codec range is invalid, reordered, or outside core";
            return false;
        }
        previousCodecEnd = range.offset + range.size;
        bool matched = false;
        const std::array<uint8_t, 3> registers = x64
            ? std::array<uint8_t, 3>{0u, 2u, 8u}
            : std::array<uint8_t, 3>{0u, 1u, 2u};
        for (uint8_t reg : registers) {
            for (bool inverse : {false, true}) {
                CodeBuffer expectedCodec;
                ConfigurePermutationPlans(expectedCodec, config);
                EmitValuePermutation(expectedCodec, x64, reg, inverse);
                if (rangeEquals(range.offset, range.size,
                        expectedCodec.bytes)) {
                    matched = true;
                    break;
                }
            }
            if (matched) break;
        }
        if (!matched) {
            error = "value codec range disagrees with the build-wide plan";
            return false;
        }
    }

    const uint32_t failureRotation = config.variant % 5u;
    uint32_t previousOffset = 0;
    for (uint32_t order = 0; order < 5u; ++order) {
        const uint32_t failure = (order + failureRotation) % 5u;
        const uint32_t offset = result.failureBlockOffsets[failure];
        if (offset >= result.code.size() || (order != 0 && offset <= previousOffset)) {
            error = "variant failure-block physical order does not follow its layout";
            return false;
        }
        previousOffset = offset;
        if (failure < 4u) {
            const std::vector<uint8_t> prefix = x64
                ? std::vector<uint8_t>{0x41, 0xC7, 0x87}
                : std::vector<uint8_t>{0xC7, 0x87};
            if (!contains(offset,
                    static_cast<uint32_t>(result.code.size() - offset), prefix)) {
                error = "failure block offset does not point at emitted machine code";
                return false;
            }
        } else if (!contains(offset,
                static_cast<uint32_t>(result.code.size() - offset),
                {0x31, 0xC9, 0x31, 0xD2})) {
            error = "divide failure block is not the native #DE path";
            return false;
        }
    }
    return true;
}

} // namespace CipherShell
