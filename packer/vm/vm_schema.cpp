#include "vm_schema.h"

#include <algorithm>
#include <array>
#include <limits>
#include <queue>
#include <unordered_map>

namespace CipherShell {
namespace {

using Kinds = std::array<VM_MICRO_OPERAND_KIND, VM_MICRO_MAX_OPERANDS>;

VMOpcodeDescriptor D(
    VM_MICRO_OPCODE opcode,
    const char* name,
    VMOpcodeClass cls,
    int pops,
    int pushes,
    VM_MICRO_FLAG_EFFECT flagEffect = VM_MICRO_FLAGS_NONE,
    Kinds operands = {},
    uint8_t operandCount = 0,
    bool branch = false,
    bool conditional = false,
    bool terminal = false,
    int8_t targetOperand = -1,
    bool runtimeSupportedX86 = true,
    bool runtimeSupportedX64 = true)
{
    VMOpcodeDescriptor descriptor{};
    descriptor.opcode = opcode;
    descriptor.name = name;
    descriptor.opcodeClass = cls;
    descriptor.operandCount = operandCount;
    descriptor.operands = operands;
    descriptor.stackPops = static_cast<int8_t>(pops);
    descriptor.stackPushes = static_cast<int8_t>(pushes);
    descriptor.flagEffect = flagEffect;
    descriptor.branchTargetOperand = targetOperand;
    descriptor.branch = branch;
    descriptor.conditional = conditional;
    descriptor.terminal = terminal;
    descriptor.runtimeSupportedX86 = runtimeSupportedX86;
    descriptor.runtimeSupportedX64 = runtimeSupportedX64;
    return descriptor;
}

#define K1(a) Kinds{a, VM_MICRO_OPERAND_NONE, VM_MICRO_OPERAND_NONE, VM_MICRO_OPERAND_NONE}
#define K2(a,b) Kinds{a, b, VM_MICRO_OPERAND_NONE, VM_MICRO_OPERAND_NONE}
#define K3(a,b,c) Kinds{a, b, c, VM_MICRO_OPERAND_NONE}
#define K4(a,b,c,d) Kinds{a, b, c, d}

const std::vector<VMOpcodeDescriptor> kOpcodes = {
    D(VM_UOP_TRAP, "TRAP", VMOpcodeClass::Invalid, 0, 0,
      VM_MICRO_FLAGS_NONE, {}, 0, false, false, true),
    D(VM_UOP_PUSH_VREG, "PUSH_VREG", VMOpcodeClass::Data, 0, 1,
      VM_MICRO_FLAGS_NONE, K3(VM_MICRO_OPERAND_REGISTER, VM_MICRO_OPERAND_WIDTH,
                              VM_MICRO_OPERAND_U8), 3),
    D(VM_UOP_PUSH_IMM, "PUSH_IMM", VMOpcodeClass::Data, 0, 1,
      VM_MICRO_FLAGS_NONE, K2(VM_MICRO_OPERAND_VAR_UINT, VM_MICRO_OPERAND_WIDTH), 2),
    D(VM_UOP_PUSH_FLAGS, "PUSH_FLAGS", VMOpcodeClass::Flags, 0, 1,
      VM_MICRO_FLAGS_MATERIALIZE, K1(VM_MICRO_OPERAND_FLAG_MASK), 1),
    D(VM_UOP_PUSH_IP, "PUSH_IP", VMOpcodeClass::Data, 0, 1),
    D(VM_UOP_PUSH_IMAGE_BASE, "PUSH_IMAGE_BASE", VMOpcodeClass::Data, 0, 1),
    D(VM_UOP_POP_VREG, "POP_VREG", VMOpcodeClass::Data, 1, 0,
      VM_MICRO_FLAGS_NONE, K4(VM_MICRO_OPERAND_REGISTER, VM_MICRO_OPERAND_WIDTH,
                              VM_MICRO_OPERAND_U8, VM_MICRO_OPERAND_U8), 4),
    D(VM_UOP_LOAD_TEMP, "LOAD_TEMP", VMOpcodeClass::Stack, 0, 1,
      VM_MICRO_FLAGS_NONE, K1(VM_MICRO_OPERAND_TEMP), 1),
    D(VM_UOP_STORE_TEMP, "STORE_TEMP", VMOpcodeClass::Stack, 1, 0,
      VM_MICRO_FLAGS_NONE, K1(VM_MICRO_OPERAND_TEMP), 1),
    D(VM_UOP_DUP, "DUP", VMOpcodeClass::Stack, 1, 2),
    D(VM_UOP_SWAP, "SWAP", VMOpcodeClass::Stack, 2, 2),
    D(VM_UOP_ROT, "ROT", VMOpcodeClass::Stack, 3, 3),
    D(VM_UOP_DROP, "DROP", VMOpcodeClass::Stack, 1, 0),
    D(VM_UOP_LOAD, "LOAD", VMOpcodeClass::Memory, 1, 1,
      VM_MICRO_FLAGS_NONE, K1(VM_MICRO_OPERAND_WIDTH), 1),
    D(VM_UOP_STORE, "STORE", VMOpcodeClass::Memory, 2, 0,
      VM_MICRO_FLAGS_NONE, K1(VM_MICRO_OPERAND_WIDTH), 1),

    D(VM_UOP_ADD, "ADD", VMOpcodeClass::Arithmetic, 2, 1,
      VM_MICRO_FLAGS_LATCH, K1(VM_MICRO_OPERAND_WIDTH), 1),
    D(VM_UOP_ADD_CARRY, "ADD_CARRY", VMOpcodeClass::Arithmetic, 3, 1,
      VM_MICRO_FLAGS_LATCH, K1(VM_MICRO_OPERAND_WIDTH), 1),
    D(VM_UOP_SUB, "SUB", VMOpcodeClass::Arithmetic, 2, 1,
      VM_MICRO_FLAGS_LATCH, K1(VM_MICRO_OPERAND_WIDTH), 1),
    D(VM_UOP_SUB_BORROW, "SUB_BORROW", VMOpcodeClass::Arithmetic, 3, 1,
      VM_MICRO_FLAGS_LATCH, K1(VM_MICRO_OPERAND_WIDTH), 1),
    D(VM_UOP_MUL, "MUL", VMOpcodeClass::Arithmetic, 2, 1,
      VM_MICRO_FLAGS_LATCH, K1(VM_MICRO_OPERAND_WIDTH), 1),
    D(VM_UOP_UMUL_WIDE, "UMUL_WIDE", VMOpcodeClass::Arithmetic, 2, 2,
      VM_MICRO_FLAGS_LATCH, K1(VM_MICRO_OPERAND_WIDTH), 1),
    D(VM_UOP_SMUL_WIDE, "SMUL_WIDE", VMOpcodeClass::Arithmetic, 2, 2,
      VM_MICRO_FLAGS_LATCH, K1(VM_MICRO_OPERAND_WIDTH), 1),
    D(VM_UOP_UDIV_WIDE, "UDIV_WIDE", VMOpcodeClass::Arithmetic, 3, 2,
      VM_MICRO_FLAGS_LATCH, K1(VM_MICRO_OPERAND_WIDTH), 1),
    D(VM_UOP_IDIV_WIDE, "IDIV_WIDE", VMOpcodeClass::Arithmetic, 3, 2,
      VM_MICRO_FLAGS_LATCH, K1(VM_MICRO_OPERAND_WIDTH), 1),
    D(VM_UOP_AND, "AND", VMOpcodeClass::Arithmetic, 2, 1,
      VM_MICRO_FLAGS_LATCH, K1(VM_MICRO_OPERAND_WIDTH), 1),
    D(VM_UOP_OR, "OR", VMOpcodeClass::Arithmetic, 2, 1,
      VM_MICRO_FLAGS_LATCH, K1(VM_MICRO_OPERAND_WIDTH), 1),
    D(VM_UOP_XOR, "XOR", VMOpcodeClass::Arithmetic, 2, 1,
      VM_MICRO_FLAGS_LATCH, K1(VM_MICRO_OPERAND_WIDTH), 1),
    D(VM_UOP_NOT, "NOT", VMOpcodeClass::Arithmetic, 1, 1,
      VM_MICRO_FLAGS_LATCH, K1(VM_MICRO_OPERAND_WIDTH), 1),
    D(VM_UOP_NEG, "NEG", VMOpcodeClass::Arithmetic, 1, 1,
      VM_MICRO_FLAGS_LATCH, K1(VM_MICRO_OPERAND_WIDTH), 1),
    D(VM_UOP_SHL, "SHL", VMOpcodeClass::Arithmetic, 2, 1,
      VM_MICRO_FLAGS_LATCH, K1(VM_MICRO_OPERAND_WIDTH), 1),
    D(VM_UOP_SHR, "SHR", VMOpcodeClass::Arithmetic, 2, 1,
      VM_MICRO_FLAGS_LATCH, K1(VM_MICRO_OPERAND_WIDTH), 1),
    D(VM_UOP_SAR, "SAR", VMOpcodeClass::Arithmetic, 2, 1,
      VM_MICRO_FLAGS_LATCH, K1(VM_MICRO_OPERAND_WIDTH), 1),
    D(VM_UOP_ROL, "ROL", VMOpcodeClass::Arithmetic, 2, 1,
      VM_MICRO_FLAGS_LATCH, K1(VM_MICRO_OPERAND_WIDTH), 1),
    D(VM_UOP_ROR, "ROR", VMOpcodeClass::Arithmetic, 2, 1,
      VM_MICRO_FLAGS_LATCH, K1(VM_MICRO_OPERAND_WIDTH), 1),
    D(VM_UOP_BIT_TEST, "BIT_TEST", VMOpcodeClass::Arithmetic, 2, 1,
      VM_MICRO_FLAGS_LATCH, K1(VM_MICRO_OPERAND_WIDTH), 1),
    D(VM_UOP_BIT_SET, "BIT_SET", VMOpcodeClass::Arithmetic, 2, 1,
      VM_MICRO_FLAGS_LATCH, K1(VM_MICRO_OPERAND_WIDTH), 1),
    D(VM_UOP_BIT_RESET, "BIT_RESET", VMOpcodeClass::Arithmetic, 2, 1,
      VM_MICRO_FLAGS_LATCH, K1(VM_MICRO_OPERAND_WIDTH), 1),
    D(VM_UOP_BSWAP, "BSWAP", VMOpcodeClass::Arithmetic, 1, 1,
      VM_MICRO_FLAGS_LATCH, K1(VM_MICRO_OPERAND_WIDTH), 1),
    D(VM_UOP_ZERO_EXTEND, "ZERO_EXTEND", VMOpcodeClass::Arithmetic, 1, 1,
      VM_MICRO_FLAGS_LATCH, K2(VM_MICRO_OPERAND_WIDTH, VM_MICRO_OPERAND_WIDTH), 2),
    D(VM_UOP_SIGN_EXTEND, "SIGN_EXTEND", VMOpcodeClass::Arithmetic, 1, 1,
      VM_MICRO_FLAGS_LATCH, K2(VM_MICRO_OPERAND_WIDTH, VM_MICRO_OPERAND_WIDTH), 2),

    D(VM_UOP_FLAGS_LAZY, "FLAGS_LAZY", VMOpcodeClass::Flags, 0, 0,
      VM_MICRO_FLAGS_RECORD, K4(VM_MICRO_OPERAND_LAZY_KIND, VM_MICRO_OPERAND_WIDTH,
                                VM_MICRO_OPERAND_FLAG_MASK, VM_MICRO_OPERAND_FLAG_MASK), 4),
    D(VM_UOP_FLAGS_MATERIALIZE, "FLAGS_MATERIALIZE", VMOpcodeClass::Flags, 0, 0,
      VM_MICRO_FLAGS_MATERIALIZE, K1(VM_MICRO_OPERAND_FLAG_MASK), 1),
    D(VM_UOP_FLAGS_WRITE, "FLAGS_WRITE", VMOpcodeClass::Flags, 1, 0,
      VM_MICRO_FLAGS_WRITE, K1(VM_MICRO_OPERAND_FLAG_MASK), 1),
    D(VM_UOP_FLAGS_UPDATE, "FLAGS_UPDATE", VMOpcodeClass::Flags, 0, 0,
      VM_MICRO_FLAGS_WRITE, K2(VM_MICRO_OPERAND_U8, VM_MICRO_OPERAND_FLAG_MASK), 2),
    D(VM_UOP_FLAGS_PACK_AH, "FLAGS_PACK_AH", VMOpcodeClass::Flags, 0, 1,
      VM_MICRO_FLAGS_MATERIALIZE),
    D(VM_UOP_FLAGS_UNPACK_AH, "FLAGS_UNPACK_AH", VMOpcodeClass::Flags, 1, 0,
      VM_MICRO_FLAGS_WRITE),
    D(VM_UOP_PUSH_CONDITION, "PUSH_CONDITION", VMOpcodeClass::Flags, 0, 1,
      VM_MICRO_FLAGS_CONSUME, K1(VM_MICRO_OPERAND_CONDITION), 1),
    D(VM_UOP_SELECT, "SELECT", VMOpcodeClass::Flags, 2, 1,
      VM_MICRO_FLAGS_CONSUME, K1(VM_MICRO_OPERAND_CONDITION), 1),

    D(VM_UOP_BRANCH, "BRANCH", VMOpcodeClass::ControlFlow, 0, 0,
      VM_MICRO_FLAGS_NONE, K1(VM_MICRO_OPERAND_U32), 1, true, false, false, 0),
    D(VM_UOP_BRANCH_IF, "BRANCH_IF", VMOpcodeClass::ControlFlow, 0, 0,
      VM_MICRO_FLAGS_CONSUME, K2(VM_MICRO_OPERAND_CONDITION, VM_MICRO_OPERAND_U32),
      2, true, true, false, 1),
    D(VM_UOP_CALL_VM, "CALL_VM", VMOpcodeClass::Call, 0, 0,
      VM_MICRO_FLAGS_NONE, K1(VM_MICRO_OPERAND_U32), 1, true, true, false, 0),
    D(VM_UOP_CALL_HOST, "CALL_HOST", VMOpcodeClass::Call, 1, 0,
      VM_MICRO_FLAGS_NONE, K3(VM_MICRO_OPERAND_CALL_KIND, VM_MICRO_OPERAND_U8,
                              VM_MICRO_OPERAND_U16), 3,
      false, false, false, -1, false, false),
    D(VM_UOP_RET, "RET", VMOpcodeClass::ControlFlow, 0, 0,
      VM_MICRO_FLAGS_NONE, K1(VM_MICRO_OPERAND_U16), 1, false, false, true),
    D(VM_UOP_EXIT, "EXIT", VMOpcodeClass::ControlFlow, 0, 0,
      VM_MICRO_FLAGS_NONE, K1(VM_MICRO_OPERAND_U16), 1, false, false, true),
    D(VM_UOP_BRIDGE_EXTENDED, "BRIDGE_EXTENDED", VMOpcodeClass::Bridge, 0, 0,
      VM_MICRO_FLAGS_NONE, K3(VM_MICRO_OPERAND_U32, VM_MICRO_OPERAND_U32,
                              VM_MICRO_OPERAND_U32), 3),
    D(VM_UOP_RDTSC, "RDTSC", VMOpcodeClass::Special, 0, 0),
    D(VM_UOP_CPUID, "CPUID", VMOpcodeClass::Special, 0, 0),
    D(VM_UOP_INT3, "INT3", VMOpcodeClass::Special, 0, 0)
};

#undef K1
#undef K2
#undef K3
#undef K4

uint64_t Mix64(uint64_t value) {
    value += 0x9E3779B97F4A7C15ULL;
    value = (value ^ (value >> 30u)) * 0xBF58476D1CE4E5B9ULL;
    value = (value ^ (value >> 27u)) * 0x94D049BB133111EBULL;
    return value ^ (value >> 31u);
}

uint8_t Rotl8(uint8_t value, unsigned count) {
    count &= 7u;
    if (count == 0) return value;
    return static_cast<uint8_t>((value << count) | (value >> (8u - count)));
}

uint8_t Rotr8(uint8_t value, unsigned count) {
    count &= 7u;
    if (count == 0) return value;
    return static_cast<uint8_t>((value >> count) | (value << (8u - count)));
}

uint8_t Rotl7(uint8_t value, unsigned count) {
    value &= 0x7Fu;
    count %= 7u;
    if (count == 0) return value;
    return static_cast<uint8_t>(((value << count) | (value >> (7u - count))) & 0x7Fu);
}

uint8_t Rotr7(uint8_t value, unsigned count) {
    value &= 0x7Fu;
    count %= 7u;
    if (count == 0) return value;
    return static_cast<uint8_t>(((value >> count) | (value << (7u - count))) & 0x7Fu);
}

uint8_t Inverse8(uint8_t odd) {
    for (unsigned candidate = 1; candidate < 256; candidate += 2) {
        if (static_cast<uint8_t>(candidate * odd) == 1u) {
            return static_cast<uint8_t>(candidate);
        }
    }
    return 1u;
}

uint64_t FieldKey(
    const VM_OPERAND_CODEC& codec,
    VM_MICRO_OPCODE opcode,
    uint8_t operandIndex,
    VM_MICRO_OPERAND_KIND kind)
{
    uint64_t value = codec.fieldKey;
    value ^= static_cast<uint64_t>(opcode + 1u) * 0xD6E8FEB86659FD93ULL;
    value ^= static_cast<uint64_t>(operandIndex + 1u) * 0xA0761D6478BD642FULL;
    value ^= static_cast<uint64_t>(kind + 1u) * 0xE7037ED1A0B428DBULL;
    return Mix64(value);
}

std::array<uint8_t, VM_MICRO_MAX_OPERANDS> OperandOrder(
    const VM_OPERAND_CODEC& codec,
    VM_MICRO_OPCODE opcode,
    uint8_t operandCount)
{
    std::array<uint8_t, VM_MICRO_MAX_OPERANDS> order{0, 1, 2, 3};
    uint64_t state = Mix64(codec.fieldKey ^
        (static_cast<uint64_t>(opcode) * 0x8EBC6AF09C88C6E3ULL));
    for (uint8_t i = operandCount; i > 1; --i) {
        state = Mix64(state);
        const uint8_t j = static_cast<uint8_t>(state % i);
        std::swap(order[i - 1u], order[j]);
    }
    return order;
}

size_t FixedWidth(VM_MICRO_OPERAND_KIND kind) {
    switch (kind) {
        case VM_MICRO_OPERAND_U8:
        case VM_MICRO_OPERAND_REGISTER:
        case VM_MICRO_OPERAND_TEMP:
        case VM_MICRO_OPERAND_WIDTH:
        case VM_MICRO_OPERAND_CONDITION:
        case VM_MICRO_OPERAND_LAZY_KIND:
        case VM_MICRO_OPERAND_CALL_KIND: return 1;
        case VM_MICRO_OPERAND_U16: return 2;
        case VM_MICRO_OPERAND_U32:
        case VM_MICRO_OPERAND_FLAG_MASK: return 4;
        case VM_MICRO_OPERAND_U64: return 8;
        default: return 0;
    }
}

std::vector<uint8_t> ByteOrder(uint64_t key, size_t width) {
    std::vector<uint8_t> order(width);
    for (size_t i = 0; i < width; ++i) order[i] = static_cast<uint8_t>(i);
    uint64_t state = key;
    for (size_t i = width; i > 1; --i) {
        state = Mix64(state);
        const size_t j = static_cast<size_t>(state % i);
        std::swap(order[i - 1u], order[j]);
    }
    return order;
}

bool EncodeOperand(
    uint64_t value,
    VM_MICRO_OPERAND_KIND kind,
    const VM_OPERAND_CODEC& codec,
    VM_MICRO_OPCODE opcode,
    uint8_t operandIndex,
    std::vector<uint8_t>& output)
{
    const uint64_t key = FieldKey(codec, opcode, operandIndex, kind);
    const size_t width = FixedWidth(kind);
    if (width == 1) {
        uint8_t byte = static_cast<uint8_t>(value);
        byte = static_cast<uint8_t>(byte * codec.affineMultiplier +
            codec.affineAddend + static_cast<uint8_t>(key));
        byte ^= static_cast<uint8_t>(key >> 8u);
        output.push_back(Rotl8(byte, codec.rotate + operandIndex));
        return true;
    }
    if (width != 0) {
        const auto order = ByteOrder(key, width);
        uint64_t stream = key;
        for (size_t outIndex = 0; outIndex < width; ++outIndex) {
            stream = Mix64(stream + outIndex);
            const uint8_t sourceIndex = order[outIndex];
            const uint8_t byte = static_cast<uint8_t>(value >> (sourceIndex * 8u));
            output.push_back(static_cast<uint8_t>(byte ^ stream));
        }
        return true;
    }
    if (kind != VM_MICRO_OPERAND_VAR_UINT && kind != VM_MICRO_OPERAND_VAR_SINT) {
        return false;
    }
    uint64_t encoded = value;
    if (kind == VM_MICRO_OPERAND_VAR_SINT) {
        const int64_t signedValue = static_cast<int64_t>(value);
        encoded = (static_cast<uint64_t>(signedValue) << 1u) ^
            static_cast<uint64_t>(signedValue >> 63u);
    }
    uint8_t chunkIndex = 0;
    do {
        const uint8_t raw = static_cast<uint8_t>(encoded & 0x7Fu);
        encoded >>= 7u;
        const uint8_t chunkKey = static_cast<uint8_t>(Mix64(key + chunkIndex +
            codec.varintKey) & 0x7Fu);
        const uint8_t low = Rotl7(static_cast<uint8_t>(raw ^ chunkKey),
            static_cast<unsigned>(codec.rotate + chunkIndex));
        output.push_back(static_cast<uint8_t>(low | (encoded != 0 ? 0x80u : 0u)));
        ++chunkIndex;
    } while (encoded != 0);
    return true;
}

bool DecodeOperand(
    const uint8_t* bytes,
    size_t size,
    size_t& cursor,
    VM_MICRO_OPERAND_KIND kind,
    const VM_OPERAND_CODEC& codec,
    VM_MICRO_OPCODE opcode,
    uint8_t operandIndex,
    uint64_t& value,
    std::string& reason)
{
    const uint64_t key = FieldKey(codec, opcode, operandIndex, kind);
    const size_t width = FixedWidth(kind);
    if (width == 1) {
        if (cursor >= size) {
            reason = "truncated one-byte micro operand";
            return false;
        }
        uint8_t byte = Rotr8(bytes[cursor++], codec.rotate + operandIndex);
        byte ^= static_cast<uint8_t>(key >> 8u);
        byte = static_cast<uint8_t>(byte - codec.affineAddend -
            static_cast<uint8_t>(key));
        value = static_cast<uint8_t>(byte * codec.affineInverse);
        return true;
    }
    if (width != 0) {
        if (width > size - cursor) {
            reason = "truncated fixed-width micro operand";
            return false;
        }
        const auto order = ByteOrder(key, width);
        uint64_t decoded = 0;
        uint64_t stream = key;
        for (size_t outIndex = 0; outIndex < width; ++outIndex) {
            stream = Mix64(stream + outIndex);
            const uint8_t sourceIndex = order[outIndex];
            const uint8_t byte = static_cast<uint8_t>(bytes[cursor++] ^ stream);
            decoded |= static_cast<uint64_t>(byte) << (sourceIndex * 8u);
        }
        value = decoded;
        return true;
    }
    if (kind != VM_MICRO_OPERAND_VAR_UINT && kind != VM_MICRO_OPERAND_VAR_SINT) {
        reason = "unknown micro operand encoding";
        return false;
    }
    uint64_t decoded = 0;
    unsigned shift = 0;
    uint8_t chunkIndex = 0;
    while (true) {
        if (cursor >= size || chunkIndex >= 10u) {
            reason = "truncated or overlong micro varint";
            return false;
        }
        const uint8_t byte = bytes[cursor++];
        const uint8_t chunkKey = static_cast<uint8_t>(Mix64(key + chunkIndex +
            codec.varintKey) & 0x7Fu);
        const uint8_t raw = static_cast<uint8_t>(
            Rotr7(byte & 0x7Fu, codec.rotate + chunkIndex) ^ chunkKey);
        if (shift == 63u && raw > 1u) {
            reason = "micro varint overflow";
            return false;
        }
        decoded |= static_cast<uint64_t>(raw) << shift;
        ++chunkIndex;
        if ((byte & 0x80u) == 0) {
            if (chunkIndex > 1u && raw == 0u) {
                reason = "non-canonical overlong micro varint";
                return false;
            }
            break;
        }
        shift += 7u;
    }
    if (kind == VM_MICRO_OPERAND_VAR_SINT) {
        value = (decoded >> 1u) ^ static_cast<uint64_t>(-
            static_cast<int64_t>(decoded & 1u));
    } else {
        value = decoded;
    }
    return true;
}

bool IsWidth(uint64_t width) {
    return width == 1u || width == 2u || width == 4u || width == 8u;
}

void FillRuntimeOperandPlan(
    const VM_OPERAND_CODEC& codec,
    VM_MICRO_OPCODE opcode,
    uint8_t operandIndex,
    VM_MICRO_OPERAND_KIND kind,
    VM_RUNTIME_OPERAND_DECODE_PLAN& plan)
{
    plan = {};
    plan.kind = static_cast<uint8_t>(kind);
    plan.canonicalIndex = operandIndex;
    const uint64_t key = FieldKey(codec, opcode, operandIndex, kind);
    const size_t width = FixedWidth(kind);
    plan.fixedWidth = static_cast<uint8_t>(width);
    if (width == 1) {
        plan.u8Bias = static_cast<uint8_t>(codec.affineAddend + static_cast<uint8_t>(key));
        plan.u8Xor = static_cast<uint8_t>(key >> 8u);
        plan.u8Rotate = static_cast<uint8_t>((codec.rotate + operandIndex) & 7u);
        return;
    }
    if (width != 0) {
        const auto order = ByteOrder(key, width);
        uint64_t stream = key;
        for (size_t i = 0; i < width; ++i) {
            stream = Mix64(stream + i);
            plan.byteOrder[i] = order[i];
            plan.byteXor[i] = static_cast<uint8_t>(stream);
        }
        return;
    }
    for (uint8_t chunk = 0; chunk < 10u; ++chunk) {
        plan.varintXor[chunk] = static_cast<uint8_t>(Mix64(key + chunk +
            codec.varintKey) & 0x7Fu);
        plan.varintRotate[chunk] = static_cast<uint8_t>((codec.rotate + chunk) % 7u);
    }
}

} // namespace

uint32_t VMSchema::Version() { return VM_SCHEMA_VERSION; }

const std::vector<VMOpcodeDescriptor>& VMSchema::Opcodes() { return kOpcodes; }

const VMOpcodeDescriptor* VMSchema::Lookup(VM_MICRO_OPCODE opcode) {
    const auto found = std::find_if(kOpcodes.begin(), kOpcodes.end(),
        [opcode](const VMOpcodeDescriptor& descriptor) {
            return descriptor.opcode == opcode;
        });
    return found == kOpcodes.end() ? nullptr : &*found;
}

const VMOpcodeDescriptor* VMSchema::Lookup(uint8_t semanticOpcode) {
    if (semanticOpcode >= static_cast<uint8_t>(VM_UOP_COUNT)) return nullptr;
    return Lookup(static_cast<VM_MICRO_OPCODE>(semanticOpcode));
}

VM_OPERAND_CODEC VMSchema::DeriveOperandCodec(uint64_t buildSeed, uint32_t functionRva) {
    VM_OPERAND_CODEC codec{};
    codec.seed = Mix64(buildSeed ^ VM_OPERAND_CODEC_DOMAIN ^ functionRva);
    codec.fieldKey = Mix64(codec.seed ^ 0x4F504552414E4431ULL);
    codec.functionRva = functionRva;
    codec.affineMultiplier = static_cast<uint8_t>(Mix64(codec.seed) | 1u);
    if (codec.affineMultiplier == 1u) codec.affineMultiplier = 0xB5u;
    codec.affineInverse = Inverse8(codec.affineMultiplier);
    codec.affineAddend = static_cast<uint8_t>(Mix64(codec.fieldKey) >> 16u);
    codec.rotate = static_cast<uint8_t>((Mix64(codec.seed ^ 0x524F544154453031ULL) % 7u) + 1u);
    codec.varintKey = static_cast<uint8_t>(Mix64(codec.fieldKey ^ 0x564152494E543031ULL) & 0x7Fu);
    return codec;
}

bool VMSchema::BuildRuntimeDecodePlans(
    const VM_OPERAND_CODEC& codec,
    VM_RUNTIME_DECODE_PLAN plans[VM_UOP_COUNT],
    std::string& reason)
{
    if (!plans || codec.affineMultiplier == 0 ||
        static_cast<uint8_t>(codec.affineMultiplier * codec.affineInverse) != 1u ||
        codec.rotate == 0 || codec.rotate > 7u) {
        reason = "operand codec cannot produce runtime decode plans";
        return false;
    }
    for (uint32_t semantic = 0; semantic < static_cast<uint32_t>(VM_UOP_COUNT); ++semantic) {
        VM_RUNTIME_DECODE_PLAN& plan = plans[semantic];
        plan = {};
        plan.semantic = static_cast<uint8_t>(semantic);
        const auto* descriptor = Lookup(static_cast<uint8_t>(semantic));
        if (!descriptor) continue;
        FillRuntimeOperandPlan(codec, descriptor->opcode, 0xFEu,
            VM_MICRO_OPERAND_U8, plan.variant);
        if (descriptor->opcode == VM_UOP_TRAP) continue;
        plan.semanticComplete = 1;
        plan.operandCount = descriptor->operandCount;
        const auto order = OperandOrder(codec, descriptor->opcode, descriptor->operandCount);
        for (uint8_t i = 0; i < descriptor->operandCount; ++i) {
            plan.fieldOrder[i] = order[i];
            FillRuntimeOperandPlan(codec, descriptor->opcode, i,
                descriptor->operands[i], plan.operands[i]);
        }
    }
    return true;
}

bool VMSchema::ValidateInstruction(
    const MicroInstruction& instruction,
    uint32_t registerCount,
    std::string& reason)
{
    const auto* descriptor = Lookup(instruction.opcode);
    if (!descriptor || instruction.opcode == VM_UOP_TRAP) {
        reason = "invalid or trap micro semantic";
        return false;
    }
    if (instruction.handlerVariant >= VM_MICRO_MAX_HANDLER_VARIANTS) {
        reason = "micro handler variant selector out of range";
        return false;
    }
    if (instruction.operandCount != descriptor->operandCount) {
        reason = "micro operand arity does not match semantic descriptor";
        return false;
    }
    for (uint8_t i = 0; i < descriptor->operandCount; ++i) {
        const uint64_t value = instruction.operands[i];
        switch (descriptor->operands[i]) {
            case VM_MICRO_OPERAND_U8:
                if (value > 0xFFu) { reason = "u8 micro operand overflow"; return false; }
                break;
            case VM_MICRO_OPERAND_U16:
                if (value > 0xFFFFu) { reason = "u16 micro operand overflow"; return false; }
                break;
            case VM_MICRO_OPERAND_U32:
                if (value > 0xFFFFFFFFULL) { reason = "u32 micro operand overflow"; return false; }
                break;
            case VM_MICRO_OPERAND_FLAG_MASK:
                if (value > 0xFFFFFFFFULL) { reason = "flag-mask micro operand overflow"; return false; }
                break;
            case VM_MICRO_OPERAND_REGISTER:
                if (value >= registerCount || value == VM_REGISTER_INVALID) {
                    reason = "micro virtual register index out of range";
                    return false;
                }
                break;
            case VM_MICRO_OPERAND_TEMP:
                if (value >= VM_MICRO_TEMP_COUNT) {
                    reason = "micro temporary index out of range";
                    return false;
                }
                break;
            case VM_MICRO_OPERAND_WIDTH:
                if (!IsWidth(value)) { reason = "invalid micro operand width"; return false; }
                break;
            case VM_MICRO_OPERAND_CONDITION:
                if (value > VM_CONDITION_G) { reason = "invalid micro condition"; return false; }
                break;
            case VM_MICRO_OPERAND_LAZY_KIND:
                if (value == VM_LAZY_NONE || value > VM_LAZY_BIT_TEST) {
                    reason = "invalid lazy flag operation";
                    return false;
                }
                break;
            case VM_MICRO_OPERAND_CALL_KIND:
                if (value > VM_MICRO_CALL_INDIRECT) { reason = "invalid host call kind"; return false; }
                break;
            default: break;
        }
    }
    if (instruction.opcode == VM_UOP_PUSH_VREG) {
        const uint64_t widthBits = instruction.operands[1] * 8u;
        if (instruction.operands[2] + widthBits > 64u) {
            reason = "virtual register read exceeds register width";
            return false;
        }
    } else if (instruction.opcode == VM_UOP_POP_VREG) {
        const uint64_t widthBits = instruction.operands[1] * 8u;
        if (instruction.operands[2] + widthBits > 64u || instruction.operands[3] > 1u ||
            (instruction.operands[3] != 0u && instruction.operands[2] != 0u)) {
            reason = "virtual register write contract is invalid";
            return false;
        }
    } else if (instruction.opcode == VM_UOP_ZERO_EXTEND ||
               instruction.opcode == VM_UOP_SIGN_EXTEND) {
        if (instruction.operands[0] >= instruction.operands[1]) {
            reason = "extension widths are not increasing";
            return false;
        }
    } else if (instruction.opcode == VM_UOP_FLAGS_LAZY) {
        const uint64_t defined = instruction.operands[2];
        const uint64_t preserved = instruction.operands[3];
        if (((defined | preserved) & ~static_cast<uint64_t>(VM_FLAG_ARCHITECTURAL_MASK)) != 0 ||
            (defined & preserved) != 0) {
            reason = "lazy flag masks overlap or escape architectural flags";
            return false;
        }
    } else if (instruction.opcode == VM_UOP_CALL_HOST) {
        if (instruction.operands[1] > VM_ABI_X86_AUTO ||
            instruction.operands[2] > VM_NATIVE_MAX_STACK_ARGUMENT_BYTES) {
            reason = "host call ABI contract is invalid";
            return false;
        }
    } else if (instruction.opcode == VM_UOP_FLAGS_UPDATE) {
        if (instruction.operands[0] > VM_FLAG_UPDATE_TOGGLE) {
            reason = "unknown flag update operation";
            return false;
        }
    }
    return true;
}

bool VMSchema::Encode(
    const MicroInstruction& instruction,
    const std::unordered_map<uint8_t, uint8_t>& opcodeMap,
    const VM_OPERAND_CODEC& codec,
    std::vector<uint8_t>& output,
    std::string& reason)
{
    if (!ValidateInstruction(instruction, 0xFFu, reason)) return false;
    const auto mapped = opcodeMap.find(static_cast<uint8_t>(instruction.opcode));
    if (mapped == opcodeMap.end()) {
        reason = "micro semantic has no per-build opcode mapping";
        return false;
    }
    const auto* descriptor = Lookup(instruction.opcode);
    output.push_back(mapped->second);
    if (!EncodeOperand(instruction.handlerVariant, VM_MICRO_OPERAND_U8,
            codec, instruction.opcode, 0xFEu, output)) {
        reason = "micro handler variant encoder failed";
        return false;
    }
    const auto order = OperandOrder(codec, instruction.opcode, descriptor->operandCount);
    for (uint8_t position = 0; position < descriptor->operandCount; ++position) {
        const uint8_t operandIndex = order[position];
        if (!EncodeOperand(instruction.operands[operandIndex],
                descriptor->operands[operandIndex], codec, instruction.opcode,
                operandIndex, output)) {
            reason = "micro operand encoder rejected descriptor kind";
            return false;
        }
    }
    return true;
}

bool VMSchema::DecodeOne(
    const uint8_t* bytes,
    size_t size,
    const uint8_t reverseOpcodeMap[256],
    const VM_OPERAND_CODEC& codec,
    MicroInstruction& instruction,
    uint32_t& consumed,
    std::string& reason)
{
    consumed = 0;
    if (!bytes || !reverseOpcodeMap || size == 0) {
        reason = "empty or null micro instruction";
        return false;
    }
    const uint8_t semantic = reverseOpcodeMap[bytes[0]];
    const auto* descriptor = Lookup(semantic);
    if (!descriptor || descriptor->opcode == VM_UOP_TRAP) {
        reason = "mapped opcode has no production micro semantic";
        return false;
    }
    instruction = {};
    instruction.opcode = descriptor->opcode;
    instruction.operandCount = descriptor->operandCount;
    size_t cursor = 1;
    uint64_t variant = 0;
    if (!DecodeOperand(bytes, size, cursor, VM_MICRO_OPERAND_U8,
            codec, instruction.opcode, 0xFEu, variant, reason) ||
        variant >= VM_MICRO_MAX_HANDLER_VARIANTS) {
        if (reason.empty()) reason = "decoded handler variant selector out of range";
        return false;
    }
    instruction.handlerVariant = static_cast<uint8_t>(variant);
    const auto order = OperandOrder(codec, instruction.opcode, descriptor->operandCount);
    for (uint8_t position = 0; position < descriptor->operandCount; ++position) {
        const uint8_t operandIndex = order[position];
        if (!DecodeOperand(bytes, size, cursor, descriptor->operands[operandIndex],
                codec, instruction.opcode, operandIndex,
                instruction.operands[operandIndex], reason)) {
            return false;
        }
    }
    if (cursor > std::numeric_limits<uint32_t>::max()) {
        reason = "decoded micro instruction exceeds addressable stream";
        return false;
    }
    consumed = static_cast<uint32_t>(cursor);
    return true;
}

bool VMSchema::DecodeStream(
    const uint8_t* bytes,
    size_t size,
    const uint8_t reverseOpcodeMap[256],
    const VM_OPERAND_CODEC& codec,
    std::vector<DecodedMicroInstruction>& decoded,
    std::string& reason)
{
    decoded.clear();
    if (!bytes || size == 0 || size > std::numeric_limits<uint32_t>::max()) {
        reason = "invalid micro bytecode stream size";
        return false;
    }
    size_t offset = 0;
    while (offset < size) {
        DecodedMicroInstruction item{};
        item.byteOffset = static_cast<uint32_t>(offset);
        if (!DecodeOne(bytes + offset, size - offset, reverseOpcodeMap, codec,
                item.instruction, item.encodedSize, reason) || item.encodedSize == 0) {
            return false;
        }
        offset += item.encodedSize;
        decoded.push_back(std::move(item));
    }
    return offset == size;
}

VMStreamValidation VMSchema::ValidateStream(
    const uint8_t* bytes,
    size_t size,
    const uint8_t reverseOpcodeMap[256],
    const VM_OPERAND_CODEC& codec,
    uint32_t registerCount)
{
    VMStreamValidation result{};
    if (!DecodeStream(bytes, size, reverseOpcodeMap, codec, result.decoded, result.error)) {
        return result;
    }
    std::unordered_map<uint32_t, size_t> boundaryToIndex;
    for (size_t i = 0; i < result.decoded.size(); ++i) {
        const auto& item = result.decoded[i];
        if (!boundaryToIndex.emplace(item.byteOffset, i).second) {
            result.error = "duplicate micro instruction boundary";
            return result;
        }
        std::string reason;
        if (!ValidateInstruction(item.instruction, registerCount, reason)) {
            result.error = "invalid micro instruction at byte " +
                std::to_string(item.byteOffset) + ": " + reason;
            return result;
        }
        const auto* descriptor = Lookup(item.instruction.opcode);
        if (descriptor->branchTargetOperand >= 0) {
            const uint64_t target = item.instruction.operands[
                static_cast<uint8_t>(descriptor->branchTargetOperand)];
            if (target > std::numeric_limits<uint32_t>::max()) {
                result.error = "micro branch target overflows stream offset";
                return result;
            }
        }
    }

    if (result.decoded.empty()) {
        result.error = "empty micro program";
        return result;
    }
    std::vector<int32_t> entryDepth(result.decoded.size(), -1);
    std::queue<size_t> pending;
    entryDepth[0] = 0;
    pending.push(0);
    auto enqueue = [&](size_t index, int32_t depth) -> bool {
        if (index >= entryDepth.size()) return false;
        if (entryDepth[index] < 0) {
            entryDepth[index] = depth;
            pending.push(index);
            return true;
        }
        return entryDepth[index] == depth;
    };

    while (!pending.empty()) {
        const size_t index = pending.front();
        pending.pop();
        const auto& item = result.decoded[index];
        const auto* descriptor = Lookup(item.instruction.opcode);
        int32_t depth = entryDepth[index];
        if (depth < descriptor->stackPops) {
            result.error = "micro operand stack underflow at byte " +
                std::to_string(item.byteOffset);
            return result;
        }
        depth = depth - descriptor->stackPops + descriptor->stackPushes;
        if (depth > static_cast<int32_t>(VM_MICRO_STACK_LIMIT)) {
            result.error = "micro operand stack limit exceeded";
            return result;
        }
        result.maxOperandStackDepth = std::max(result.maxOperandStackDepth,
            static_cast<uint32_t>(depth));
        if (descriptor->terminal && depth != 0) {
            result.error = "terminal micro instruction leaves operand stack open at byte " +
                std::to_string(item.byteOffset);
            return result;
        }

        bool targetQueued = false;
        if (descriptor->branchTargetOperand >= 0) {
            const uint32_t target = static_cast<uint32_t>(item.instruction.operands[
                static_cast<uint8_t>(descriptor->branchTargetOperand)]);
            const auto found = boundaryToIndex.find(target);
            if (found == boundaryToIndex.end()) {
                result.error = "micro branch target is not an instruction boundary";
                return result;
            }
            if (!enqueue(found->second, depth)) {
                result.error = "micro branch merges incompatible operand stack depths";
                return result;
            }
            targetQueued = true;
        }
        if (!descriptor->terminal &&
            (!descriptor->branch || descriptor->conditional)) {
            if (index + 1u >= result.decoded.size()) {
                result.error = "micro program falls through past bytecode end";
                return result;
            }
            if (!enqueue(index + 1u, depth)) {
                result.error = "micro fallthrough merges incompatible operand stack depths";
                return result;
            }
        } else if (descriptor->branch && !descriptor->conditional && !targetQueued) {
            result.error = "unresolved micro control transfer";
            return result;
        }
    }
    for (size_t i = 0; i < entryDepth.size(); ++i) {
        if (entryDepth[i] < 0) {
            result.error = "unreachable micro instruction at byte " +
                std::to_string(result.decoded[i].byteOffset);
            return result;
        }
    }
    result.microOpCount = static_cast<uint32_t>(result.decoded.size());
    result.success = true;
    return result;
}

bool VMSchema::EncodedSize(
    const MicroInstruction& instruction,
    const VM_OPERAND_CODEC& codec,
    uint32_t& size,
    std::string& reason)
{
    if (!ValidateInstruction(instruction, 0xFFu, reason)) return false;
    const auto* descriptor = Lookup(instruction.opcode);
    uint64_t total = 2; /* mapped semantic + encoded handler variant */
    for (uint8_t i = 0; i < descriptor->operandCount; ++i) {
        const size_t fixed = FixedWidth(descriptor->operands[i]);
        if (fixed != 0) {
            total += fixed;
            continue;
        }
        uint64_t value = instruction.operands[i];
        if (descriptor->operands[i] == VM_MICRO_OPERAND_VAR_SINT) {
            const int64_t signedValue = static_cast<int64_t>(value);
            value = (static_cast<uint64_t>(signedValue) << 1u) ^
                static_cast<uint64_t>(signedValue >> 63u);
        }
        size_t bytes = 1;
        while (value >= 0x80u) { value >>= 7u; ++bytes; }
        total += bytes;
    }
    if (total > std::numeric_limits<uint32_t>::max()) {
        reason = "micro instruction encoded size overflow";
        return false;
    }
    size = static_cast<uint32_t>(total);
    (void)codec;
    return true;
}

} // namespace CipherShell
