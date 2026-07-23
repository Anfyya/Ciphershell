#include "micro_semantics.h"

#include <algorithm>
#include <limits>
#include <unordered_map>

namespace CipherShell {
namespace {

uint64_t WidthMask(uint8_t width) {
    return width == 8u ? UINT64_MAX : ((1ULL << (width * 8u)) - 1ULL);
}

uint64_t SignBit(uint8_t width) {
    return 1ULL << (width * 8u - 1u);
}

uint64_t Truncate(uint64_t value, uint8_t width) {
    return value & WidthMask(width);
}

uint64_t SignExtend(uint64_t value, uint8_t width) {
    const uint64_t mask = WidthMask(width);
    value &= mask;
    const uint64_t sign = SignBit(width);
    return (value ^ sign) - sign;
}

bool EvenParity(uint8_t value) {
    value ^= static_cast<uint8_t>(value >> 4u);
    value &= 0x0Fu;
    return ((0x6996u >> value) & 1u) == 0u;
}

void SetFlag(uint64_t& flags, uint32_t flag, bool set) {
    if (set) flags |= flag;
    else flags &= ~static_cast<uint64_t>(flag);
}

void UnsignedMultiply64(uint64_t a, uint64_t b, uint64_t& low, uint64_t& high) {
    const uint64_t a0 = static_cast<uint32_t>(a);
    const uint64_t a1 = a >> 32u;
    const uint64_t b0 = static_cast<uint32_t>(b);
    const uint64_t b1 = b >> 32u;
    const uint64_t p00 = a0 * b0;
    const uint64_t p01 = a0 * b1;
    const uint64_t p10 = a1 * b0;
    const uint64_t p11 = a1 * b1;
    const uint64_t carry = (p00 >> 32u) + static_cast<uint32_t>(p01) +
        static_cast<uint32_t>(p10);
    low = (carry << 32u) | static_cast<uint32_t>(p00);
    high = p11 + (p01 >> 32u) + (p10 >> 32u) + (carry >> 32u);
}

void SignedMultiply64(uint64_t a, uint64_t b, uint64_t& low, uint64_t& high) {
    UnsignedMultiply64(a, b, low, high);
    if ((a >> 63u) != 0) high -= b;
    if ((b >> 63u) != 0) high -= a;
}

bool UnsignedDivide128(
    uint64_t high,
    uint64_t low,
    uint64_t divisor,
    uint64_t& quotient,
    uint64_t& remainder)
{
    if (divisor == 0 || high >= divisor) return false;
    quotient = 0;
    remainder = high;
    for (int bit = 63; bit >= 0; --bit) {
        const bool carry = (remainder >> 63u) != 0;
        remainder = (remainder << 1u) | ((low >> bit) & 1u);
        if (carry || remainder >= divisor) {
            remainder -= divisor;
            quotient |= 1ULL << bit;
        }
    }
    return true;
}

bool SignedDivide128(
    uint64_t high,
    uint64_t low,
    uint64_t divisorBits,
    uint64_t& quotient,
    uint64_t& remainder)
{
    if (divisorBits == 0) return false;
    const bool dividendNegative = (high >> 63u) != 0;
    const bool divisorNegative = (divisorBits >> 63u) != 0;
    uint64_t magnitudeHigh = high;
    uint64_t magnitudeLow = low;
    if (dividendNegative) {
        magnitudeLow = ~magnitudeLow + 1u;
        magnitudeHigh = ~magnitudeHigh + (magnitudeLow == 0 ? 1u : 0u);
    }
    const uint64_t divisorMagnitude = divisorNegative ? (~divisorBits + 1u) : divisorBits;
    uint64_t quotientMagnitude = 0;
    uint64_t remainderMagnitude = 0;
    if (!UnsignedDivide128(magnitudeHigh, magnitudeLow, divisorMagnitude,
            quotientMagnitude, remainderMagnitude)) {
        return false;
    }
    const bool quotientNegative = dividendNegative != divisorNegative;
    if ((!quotientNegative && quotientMagnitude > INT64_MAX) ||
        (quotientNegative && quotientMagnitude > (1ULL << 63u))) {
        return false;
    }
    quotient = quotientNegative ? (~quotientMagnitude + 1u) : quotientMagnitude;
    remainder = dividendNegative ? (~remainderMagnitude + 1u) : remainderMagnitude;
    return true;
}

bool ConditionTrue(uint64_t flags, VM_CONDITION condition) {
    const bool cf = (flags & VM_FLAG_CF) != 0;
    const bool pf = (flags & VM_FLAG_PF) != 0;
    const bool zf = (flags & VM_FLAG_ZF) != 0;
    const bool sf = (flags & VM_FLAG_SF) != 0;
    const bool of = (flags & VM_FLAG_OF) != 0;
    switch (condition) {
        case VM_CONDITION_ALWAYS: return true;
        case VM_CONDITION_O: return of;
        case VM_CONDITION_NO: return !of;
        case VM_CONDITION_B: return cf;
        case VM_CONDITION_AE: return !cf;
        case VM_CONDITION_E: return zf;
        case VM_CONDITION_NE: return !zf;
        case VM_CONDITION_BE: return cf || zf;
        case VM_CONDITION_A: return !cf && !zf;
        case VM_CONDITION_S: return sf;
        case VM_CONDITION_NS: return !sf;
        case VM_CONDITION_P: return pf;
        case VM_CONDITION_NP: return !pf;
        case VM_CONDITION_L: return sf != of;
        case VM_CONDITION_GE: return sf == of;
        case VM_CONDITION_LE: return zf || (sf != of);
        case VM_CONDITION_G: return !zf && (sf == of);
        default: return false;
    }
}

bool MemoryRange(
    const VMMicroMemoryView& memory,
    uint64_t address,
    uint8_t width,
    size_t& offset)
{
    if (!memory.data || address < memory.baseAddress) return false;
    const uint64_t relative = address - memory.baseAddress;
    if (relative > memory.size || width > memory.size - static_cast<size_t>(relative)) return false;
    offset = static_cast<size_t>(relative);
    return true;
}

bool ReadMemory(
    const VMMicroMemoryView& memory,
    uint64_t address,
    uint8_t width,
    uint64_t& value)
{
    size_t offset = 0;
    if (!MemoryRange(memory, address, width, offset)) return false;
    value = 0;
    for (uint8_t i = 0; i < width; ++i) {
        value |= static_cast<uint64_t>(memory.data[offset + i]) << (i * 8u);
    }
    return true;
}

bool WriteMemory(
    VMMicroMemoryView memory,
    uint64_t address,
    uint8_t width,
    uint64_t value)
{
    size_t offset = 0;
    if (!MemoryRange(memory, address, width, offset)) return false;
    for (uint8_t i = 0; i < width; ++i) {
        memory.data[offset + i] = static_cast<uint8_t>(value >> (i * 8u));
    }
    return true;
}

void Latch(
    VMMicroMachineState& state,
    uint64_t a,
    uint64_t b,
    uint64_t result,
    uint64_t auxiliary,
    uint8_t width)
{
    state.lastAlu = {};
    state.lastAlu.a = Truncate(a, width);
    state.lastAlu.b = Truncate(b, width);
    state.lastAlu.result = Truncate(result, width);
    state.lastAlu.auxiliary = auxiliary;
    state.lastAlu.width = width;
    state.lastAlu.valid = 1;
}

bool SetError(
    VMMicroMachineState& state,
    VMMicroFault fault,
    const char* message,
    std::string& error)
{
    state.fault = fault;
    state.faultAddress = state.ip;
    error = message;
    return false;
}

} // namespace

uint64_t VMMicroSemanticExecutor::MaterializeFlags(
    VMMicroMachineState& state,
    uint32_t requestedMask)
{
    VM_LAZY_FLAGS_RECORD& pending = state.pendingFlags;
    const uint32_t requested = requestedMask & pending.definedMask;
    if (!pending.valid || requested == 0) return state.rflags;
    const uint8_t width = pending.width;
    if (width != 1u && width != 2u && width != 4u && width != 8u) {
        pending.valid = 0;
        return state.rflags;
    }
    const uint64_t mask = WidthMask(width);
    const uint64_t sign = SignBit(width);
    const uint64_t a = pending.a & mask;
    const uint64_t b = pending.b & mask;
    const uint64_t result = pending.result & mask;
    bool cf = false;
    bool of = false;
    bool af = false;
    bool updateResultFlags = false;
    bool noChange = false;

    switch (static_cast<VM_LAZY_FLAG_KIND>(pending.operation)) {
        case VM_LAZY_ADD:
            cf = result < a;
            of = ((~(a ^ b) & (a ^ result) & sign) != 0);
            af = ((a ^ b ^ result) & 0x10u) != 0;
            updateResultFlags = true;
            break;
        case VM_LAZY_ADC: {
            const bool carry = (pending.auxiliary & 1u) != 0;
            cf = result < a || (carry && result == a);
            of = ((~(a ^ b) & (a ^ result) & sign) != 0);
            af = ((a ^ b ^ result) & 0x10u) != 0;
            updateResultFlags = true;
            break;
        }
        case VM_LAZY_SUB:
        case VM_LAZY_DEC:
            cf = a < b;
            of = (((a ^ b) & (a ^ result) & sign) != 0);
            af = ((a ^ b ^ result) & 0x10u) != 0;
            updateResultFlags = true;
            break;
        case VM_LAZY_INC:
            cf = result < a;
            of = ((~(a ^ b) & (a ^ result) & sign) != 0);
            af = ((a ^ b ^ result) & 0x10u) != 0;
            updateResultFlags = true;
            break;
        case VM_LAZY_SBB: {
            const bool borrow = (pending.auxiliary & 1u) != 0;
            cf = a < b || (borrow && a == b);
            of = (((a ^ b) & (a ^ result) & sign) != 0);
            af = ((a ^ b ^ result) & 0x10u) != 0;
            updateResultFlags = true;
            break;
        }
        case VM_LAZY_LOGIC:
            cf = false;
            of = false;
            af = false;
            updateResultFlags = true;
            break;
        case VM_LAZY_NEG:
            cf = a != 0;
            of = a == sign;
            af = ((a ^ result) & 0x10u) != 0;
            updateResultFlags = true;
            break;
        case VM_LAZY_SHL:
        case VM_LAZY_SHR:
        case VM_LAZY_SAR: {
            const unsigned bits = width * 8u;
            const unsigned countMask = width == 8u ? 63u : 31u;
            const unsigned count = static_cast<unsigned>(b) & countMask;
            if (count == 0) { noChange = true; break; }
            if (static_cast<VM_LAZY_FLAG_KIND>(pending.operation) == VM_LAZY_SHL) {
                cf = count < bits ? ((a >> (bits - count)) & 1u) != 0 : false;
                of = count == 1u ? (((result & sign) != 0) != cf) : false;
            } else {
                cf = count < bits ? ((a >> (count - 1u)) & 1u) != 0 : false;
                of = static_cast<VM_LAZY_FLAG_KIND>(pending.operation) == VM_LAZY_SHR &&
                    count == 1u ? (a & sign) != 0 : false;
            }
            updateResultFlags = true;
            break;
        }
        case VM_LAZY_ROL:
        case VM_LAZY_ROR: {
            const unsigned count = static_cast<unsigned>(b) & (width == 8u ? 63u : 31u);
            // Only an architectural masked count of zero preserves flags.
            // For 8/16-bit operands a non-zero count can rotate by a complete
            // width: the value is unchanged, but CF is still defined and OF
            // is undefined unless the masked count itself is one.
            if (count == 0) { noChange = true; break; }
            if (static_cast<VM_LAZY_FLAG_KIND>(pending.operation) == VM_LAZY_ROL) {
                cf = (result & 1u) != 0;
                of = count == 1u ? (((result & sign) != 0) != cf) : false;
            } else {
                cf = (result & sign) != 0;
                of = count == 1u ?
                    (((result & sign) != 0) != ((result & (sign >> 1u)) != 0)) : false;
            }
            break;
        }
        case VM_LAZY_MUL:
            cf = of = pending.auxiliary != 0;
            break;
        case VM_LAZY_IMUL: {
            const uint64_t expected = (result & sign) ? mask : 0;
            cf = of = pending.auxiliary != expected;
            break;
        }
        case VM_LAZY_BIT_TEST:
            cf = (pending.auxiliary & 1u) != 0;
            break;
        default:
            pending.valid = 0;
            return state.rflags;
    }

    if (!noChange) {
        if ((requested & VM_FLAG_CF) != 0) SetFlag(state.rflags, VM_FLAG_CF, cf);
        if ((requested & VM_FLAG_OF) != 0) SetFlag(state.rflags, VM_FLAG_OF, of);
        if ((requested & VM_FLAG_AF) != 0) SetFlag(state.rflags, VM_FLAG_AF, af);
        if (updateResultFlags) {
            if ((requested & VM_FLAG_ZF) != 0) SetFlag(state.rflags, VM_FLAG_ZF, result == 0);
            if ((requested & VM_FLAG_SF) != 0) SetFlag(state.rflags, VM_FLAG_SF, (result & sign) != 0);
            if ((requested & VM_FLAG_PF) != 0) SetFlag(state.rflags, VM_FLAG_PF,
                EvenParity(static_cast<uint8_t>(result)));
        }
    }
    return state.rflags;
}

bool VMMicroSemanticExecutor::ExecuteOne(
    const MicroInstruction& instruction,
    uint32_t fallthroughIp,
    VMMicroMachineState& state,
    VMMicroMemoryView memory,
    const VMMicroExecutionOptions& options,
    std::string& error)
{
    // ValidateInstruction only checks `regIndex < options.registerCount`; it
    // trusts the caller to also keep registerCount within state.gpr's actual
    // capacity. A caller-supplied registerCount above 32 would let a
    // schema-valid register operand pass validation and then index
    // state.gpr[reg] out of bounds below. Every call path funnels through
    // here, so clamp once instead of trusting each individual caller.
    if (options.registerCount == 0 || options.registerCount > state.gpr.size()) {
        return SetError(state, VMMicroFault::Decode,
            "micro execution registerCount exceeds machine state capacity", error);
    }
    std::string schemaError;
    if (!VMSchema::ValidateInstruction(instruction, options.registerCount, schemaError)) {
        return SetError(state, VMMicroFault::Decode, schemaError.c_str(), error);
    }
    auto pop = [&](uint64_t& value) -> bool {
        if (state.operandStackDepth == 0) return false;
        value = state.operandStack[--state.operandStackDepth];
        return true;
    };
    auto push = [&](uint64_t value) -> bool {
        if (state.operandStackDepth >= state.operandStack.size()) return false;
        state.operandStack[state.operandStackDepth++] = value;
        return true;
    };
    auto width = [&]() -> uint8_t { return static_cast<uint8_t>(instruction.operands[0]); };
    auto stackFault = [&]() -> bool {
        return SetError(state, VMMicroFault::OperandStack,
            "micro operand stack contract violated", error);
    };

    state.ip = fallthroughIp;
    uint64_t a = 0, b = 0, c = 0, result = 0;
    switch (instruction.opcode) {
        case VM_UOP_PUSH_VREG: {
            const uint8_t reg = static_cast<uint8_t>(instruction.operands[0]);
            const uint8_t operandWidth = static_cast<uint8_t>(instruction.operands[1]);
            const uint8_t bitOffset = static_cast<uint8_t>(instruction.operands[2]);
            return push(Truncate(state.gpr[reg] >> bitOffset, operandWidth)) || stackFault();
        }
        case VM_UOP_PUSH_IMM:
            return push(Truncate(instruction.operands[0],
                static_cast<uint8_t>(instruction.operands[1]))) || stackFault();
        case VM_UOP_PUSH_FLAGS:
            MaterializeFlags(state, static_cast<uint32_t>(instruction.operands[0]));
            return push(state.rflags) || stackFault();
        case VM_UOP_PUSH_IP: return push(fallthroughIp) || stackFault();
        case VM_UOP_PUSH_IMAGE_BASE: return push(state.imageBase) || stackFault();
        case VM_UOP_POP_VREG: {
            if (!pop(a)) return stackFault();
            const uint8_t reg = static_cast<uint8_t>(instruction.operands[0]);
            const uint8_t operandWidth = static_cast<uint8_t>(instruction.operands[1]);
            const uint8_t bitOffset = static_cast<uint8_t>(instruction.operands[2]);
            const bool zeroExtend = instruction.operands[3] != 0;
            const uint64_t valueMask = WidthMask(operandWidth);
            if (zeroExtend) state.gpr[reg] = a & valueMask;
            else {
                const uint64_t shiftedMask = valueMask << bitOffset;
                state.gpr[reg] = (state.gpr[reg] & ~shiftedMask) |
                    ((a & valueMask) << bitOffset);
            }
            return true;
        }
        case VM_UOP_LOAD_TEMP:
            return push(state.temporaries[static_cast<uint8_t>(instruction.operands[0])]) || stackFault();
        case VM_UOP_STORE_TEMP:
            if (!pop(a)) return stackFault();
            state.temporaries[static_cast<uint8_t>(instruction.operands[0])] = a;
            return true;
        case VM_UOP_DUP:
            if (!pop(a) || !push(a) || !push(a)) return stackFault();
            return true;
        case VM_UOP_SWAP:
            if (!pop(b) || !pop(a) || !push(b) || !push(a)) return stackFault();
            return true;
        case VM_UOP_ROT:
            if (!pop(c) || !pop(b) || !pop(a) || !push(b) || !push(c) || !push(a)) return stackFault();
            return true;
        case VM_UOP_DROP:
            return pop(a) || stackFault();
        case VM_UOP_LOAD: {
            if (!pop(a)) return stackFault();
            if (!ReadMemory(memory, a, width(), result)) {
                return SetError(state, VMMicroFault::Memory, "micro load is outside memory view", error);
            }
            return push(result) || stackFault();
        }
        case VM_UOP_STORE:
            if (!pop(b) || !pop(a)) return stackFault();
            if (!WriteMemory(memory, a, width(), b)) {
                return SetError(state, VMMicroFault::Memory, "micro store is outside memory view", error);
            }
            return true;
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
        case VM_UOP_BIT_RESET: {
            if (!pop(b) || !pop(a)) return stackFault();
            const uint8_t operandWidth = width();
            const uint64_t mask = WidthMask(operandWidth);
            const unsigned bits = operandWidth * 8u;
            uint64_t auxiliary = 0;
            switch (instruction.opcode) {
                case VM_UOP_ADD: result = a + b; break;
                case VM_UOP_SUB: result = a - b; break;
                case VM_UOP_MUL: result = a * b; break;
                case VM_UOP_AND: result = a & b; break;
                case VM_UOP_OR: result = a | b; break;
                case VM_UOP_XOR: result = a ^ b; break;
                case VM_UOP_SHL: {
                    const unsigned count = static_cast<unsigned>(b) & (operandWidth == 8u ? 63u : 31u);
                    result = count >= bits ? 0 : (a << count);
                    break;
                }
                case VM_UOP_SHR: {
                    const unsigned count = static_cast<unsigned>(b) & (operandWidth == 8u ? 63u : 31u);
                    result = count >= bits ? 0 : ((a & mask) >> count);
                    break;
                }
                case VM_UOP_SAR: {
                    const unsigned count = static_cast<unsigned>(b) & (operandWidth == 8u ? 63u : 31u);
                    if (count >= bits) result = (a & SignBit(operandWidth)) ? mask : 0;
                    else result = static_cast<uint64_t>(static_cast<int64_t>(SignExtend(a, operandWidth)) >> count);
                    break;
                }
                case VM_UOP_ROL: {
                    const unsigned count = (static_cast<unsigned>(b) & (operandWidth == 8u ? 63u : 31u)) % bits;
                    result = count == 0 ? a : ((a << count) | ((a & mask) >> (bits - count)));
                    break;
                }
                case VM_UOP_ROR: {
                    const unsigned count = (static_cast<unsigned>(b) & (operandWidth == 8u ? 63u : 31u)) % bits;
                    result = count == 0 ? a : (((a & mask) >> count) | (a << (bits - count)));
                    break;
                }
                case VM_UOP_BIT_TEST:
                case VM_UOP_BIT_SET:
                case VM_UOP_BIT_RESET: {
                    const unsigned bit = static_cast<unsigned>(b % bits);
                    auxiliary = (a >> bit) & 1u;
                    result = a;
                    if (instruction.opcode == VM_UOP_BIT_SET) result |= 1ULL << bit;
                    if (instruction.opcode == VM_UOP_BIT_RESET) result &= ~(1ULL << bit);
                    break;
                }
                default: break;
            }
            result &= mask;
            Latch(state, a, b, result, auxiliary, operandWidth);
            return push(result) || stackFault();
        }
        case VM_UOP_ADD_CARRY:
        case VM_UOP_SUB_BORROW: {
            if (!pop(c) || !pop(b) || !pop(a)) return stackFault();
            const uint8_t operandWidth = width();
            result = instruction.opcode == VM_UOP_ADD_CARRY ? a + b + (c & 1u) : a - b - (c & 1u);
            result = Truncate(result, operandWidth);
            Latch(state, a, b, result, c & 1u, operandWidth);
            return push(result) || stackFault();
        }
        case VM_UOP_NOT:
        case VM_UOP_NEG:
        case VM_UOP_BSWAP: {
            if (!pop(a)) return stackFault();
            const uint8_t operandWidth = width();
            if (instruction.opcode == VM_UOP_NOT) result = ~a;
            else if (instruction.opcode == VM_UOP_NEG) result = 0u - a;
            else {
                result = 0;
                for (uint8_t i = 0; i < operandWidth; ++i) {
                    result |= ((a >> (i * 8u)) & 0xFFu) << ((operandWidth - 1u - i) * 8u);
                }
            }
            result = Truncate(result, operandWidth);
            Latch(state, a, 0, result, 0, operandWidth);
            return push(result) || stackFault();
        }
        case VM_UOP_ZERO_EXTEND:
        case VM_UOP_SIGN_EXTEND: {
            if (!pop(a)) return stackFault();
            const uint8_t fromWidth = static_cast<uint8_t>(instruction.operands[0]);
            const uint8_t toWidth = static_cast<uint8_t>(instruction.operands[1]);
            result = instruction.opcode == VM_UOP_ZERO_EXTEND ? Truncate(a, fromWidth) : SignExtend(a, fromWidth);
            result = Truncate(result, toWidth);
            Latch(state, a, 0, result, 0, toWidth);
            return push(result) || stackFault();
        }
        case VM_UOP_UMUL_WIDE:
        case VM_UOP_SMUL_WIDE: {
            if (!pop(b) || !pop(a)) return stackFault();
            const uint8_t operandWidth = width();
            uint64_t low = 0, high = 0;
            if (operandWidth < 8u) {
                const uint64_t product = instruction.opcode == VM_UOP_UMUL_WIDE ?
                    Truncate(a, operandWidth) * Truncate(b, operandWidth) :
                    static_cast<uint64_t>(static_cast<int64_t>(SignExtend(a, operandWidth)) *
                                          static_cast<int64_t>(SignExtend(b, operandWidth)));
                low = Truncate(product, operandWidth);
                high = Truncate(product >> (operandWidth * 8u), operandWidth);
            } else if (instruction.opcode == VM_UOP_UMUL_WIDE) {
                UnsignedMultiply64(a, b, low, high);
            } else {
                SignedMultiply64(a, b, low, high);
            }
            Latch(state, a, b, low, high, operandWidth);
            return (push(low) && push(high)) || stackFault();
        }
        case VM_UOP_UDIV_WIDE:
        case VM_UOP_IDIV_WIDE: {
            uint64_t divisor = 0, low = 0, high = 0;
            if (!pop(divisor) || !pop(low) || !pop(high)) return stackFault();
            const uint8_t operandWidth = width();
            uint64_t quotient = 0, remainder = 0;
            bool valid = false;
            if (operandWidth < 8u) {
                const unsigned bits = operandWidth * 8u;
                const uint64_t combined = (Truncate(high, operandWidth) << bits) |
                    Truncate(low, operandWidth);
                const uint64_t divisorValue = Truncate(divisor, operandWidth);
                if (instruction.opcode == VM_UOP_UDIV_WIDE) {
                    valid = divisorValue != 0;
                    if (valid) {
                        quotient = combined / divisorValue;
                        remainder = combined % divisorValue;
                        valid = quotient <= WidthMask(operandWidth);
                    }
                } else {
                    const unsigned combinedBits = bits * 2u;
                    const uint64_t combinedSign = 1ULL << (combinedBits - 1u);
                    const int64_t signedDividend = static_cast<int64_t>((combined ^ combinedSign) - combinedSign);
                    const int64_t signedDivisor = static_cast<int64_t>(SignExtend(divisorValue, operandWidth));
                    valid = signedDivisor != 0 && !(signedDividend == INT64_MIN && signedDivisor == -1);
                    if (valid) {
                        const int64_t q = signedDividend / signedDivisor;
                        const int64_t r = signedDividend % signedDivisor;
                        const int64_t minimum = -(1LL << (bits - 1u));
                        const int64_t maximum = (1LL << (bits - 1u)) - 1;
                        valid = q >= minimum && q <= maximum;
                        quotient = Truncate(static_cast<uint64_t>(q), operandWidth);
                        remainder = Truncate(static_cast<uint64_t>(r), operandWidth);
                    }
                }
            } else if (instruction.opcode == VM_UOP_UDIV_WIDE) {
                valid = UnsignedDivide128(high, low, divisor, quotient, remainder);
            } else {
                valid = SignedDivide128(high, low, divisor, quotient, remainder);
            }
            if (!valid) {
                return SetError(state, VMMicroFault::DivideError,
                    "micro wide divide raised #DE", error);
            }
            Latch(state, high, divisor, quotient, remainder, operandWidth);
            return (push(quotient) && push(remainder)) || stackFault();
        }
        case VM_UOP_FLAGS_LAZY:
            if (!state.lastAlu.valid) {
                return SetError(state, VMMicroFault::UnsupportedSemantic,
                    "FLAGS_LAZY has no preceding ALU latch", error);
            }
            // A masked shift/rotate count of zero changes no flags.  The next
            // lazy record cannot know that merely from its static definedMask,
            // so settle the previous record before replacing it.  This is
            // still lazy: the previous flags are evaluated only when their
            // record would otherwise be destroyed.
            MaterializeFlags(state, VM_FLAG_ARCHITECTURAL_MASK);
            state.pendingFlags = state.lastAlu;
            state.pendingFlags.operation = static_cast<uint8_t>(instruction.operands[0]);
            state.pendingFlags.width = static_cast<uint8_t>(instruction.operands[1]);
            state.pendingFlags.definedMask = static_cast<uint32_t>(instruction.operands[2]);
            state.pendingFlags.preserveMask = static_cast<uint32_t>(instruction.operands[3]);
            state.pendingFlags.valid = 1;
            return true;
        case VM_UOP_FLAGS_MATERIALIZE:
            MaterializeFlags(state, static_cast<uint32_t>(instruction.operands[0]));
            return true;
        case VM_UOP_FLAGS_WRITE:
            if (!pop(a)) return stackFault();
            MaterializeFlags(state, VM_FLAG_ARCHITECTURAL_MASK);
            state.rflags = (state.rflags & ~instruction.operands[0]) | (a & instruction.operands[0]);
            state.pendingFlags.valid = 0;
            return true;
        case VM_UOP_FLAGS_UPDATE: {
            MaterializeFlags(state, VM_FLAG_ARCHITECTURAL_MASK);
            const uint64_t mask = instruction.operands[1];
            switch (static_cast<VM_FLAG_UPDATE_OPERATION>(instruction.operands[0])) {
                case VM_FLAG_UPDATE_CLEAR: state.rflags &= ~mask; break;
                case VM_FLAG_UPDATE_SET: state.rflags |= mask; break;
                case VM_FLAG_UPDATE_TOGGLE: state.rflags ^= mask; break;
                default: return SetError(state, VMMicroFault::UnsupportedSemantic,
                    "unknown flag update operation", error);
            }
            state.pendingFlags.valid = 0;
            return true;
        }
        case VM_UOP_FLAGS_PACK_AH:
            MaterializeFlags(state, VM_FLAG_SF | VM_FLAG_ZF | VM_FLAG_AF | VM_FLAG_PF | VM_FLAG_CF);
            result = 0x02u |
                ((state.rflags & VM_FLAG_SF) ? 0x80u : 0u) |
                ((state.rflags & VM_FLAG_ZF) ? 0x40u : 0u) |
                ((state.rflags & VM_FLAG_AF) ? 0x10u : 0u) |
                ((state.rflags & VM_FLAG_PF) ? 0x04u : 0u) |
                ((state.rflags & VM_FLAG_CF) ? 0x01u : 0u);
            return push(result) || stackFault();
        case VM_UOP_FLAGS_UNPACK_AH: {
            if (!pop(a)) return stackFault();
            MaterializeFlags(state, VM_FLAG_ARCHITECTURAL_MASK);
            const uint64_t mask = VM_FLAG_SF | VM_FLAG_ZF | VM_FLAG_AF | VM_FLAG_PF | VM_FLAG_CF;
            uint64_t packed = 0;
            if ((a & 0x80u) != 0) packed |= VM_FLAG_SF;
            if ((a & 0x40u) != 0) packed |= VM_FLAG_ZF;
            if ((a & 0x10u) != 0) packed |= VM_FLAG_AF;
            if ((a & 0x04u) != 0) packed |= VM_FLAG_PF;
            if ((a & 0x01u) != 0) packed |= VM_FLAG_CF;
            state.rflags = (state.rflags & ~mask) | packed;
            state.pendingFlags.valid = 0;
            return true;
        }
        case VM_UOP_PUSH_CONDITION:
        case VM_UOP_SELECT: {
            const VM_CONDITION condition = static_cast<VM_CONDITION>(instruction.operands[0]);
            MaterializeFlags(state, VM_FLAG_STATUS_MASK);
            const bool selected = ConditionTrue(state.rflags, condition);
            if (instruction.opcode == VM_UOP_PUSH_CONDITION) return push(selected ? 1u : 0u) || stackFault();
            if (!pop(b) || !pop(a)) return stackFault();
            return push(selected ? b : a) || stackFault();
        }
        case VM_UOP_BRANCH:
            state.ip = static_cast<uint32_t>(instruction.operands[0]);
            return true;
        case VM_UOP_BRANCH_IF:
            MaterializeFlags(state, VM_FLAG_STATUS_MASK);
            if (ConditionTrue(state.rflags, static_cast<VM_CONDITION>(instruction.operands[0]))) {
                state.ip = static_cast<uint32_t>(instruction.operands[1]);
            }
            return true;
        case VM_UOP_CALL_VM:
            if (state.callDepth >= state.callStack.size()) {
                return SetError(state, VMMicroFault::ControlFlow, "micro call stack overflow", error);
            }
            state.callStack[state.callDepth++] = fallthroughIp;
            state.ip = static_cast<uint32_t>(instruction.operands[0]);
            return true;
        case VM_UOP_RET:
            if (state.callDepth != 0) state.ip = state.callStack[--state.callDepth];
            else state.finished = true;
            return true;
        case VM_UOP_EXIT:
            state.finished = true;
            return true;
        case VM_UOP_CALL_HOST:
        case VM_UOP_BRIDGE_EXTENDED:
        case VM_UOP_RDTSC:
        case VM_UOP_CPUID:
            return SetError(state, VMMicroFault::UnsupportedSemantic,
                "micro semantic requires an external runtime effect", error);
        case VM_UOP_INT3:
            return SetError(state, VMMicroFault::ExplicitTrap, "micro INT3 trap", error);
        case VM_UOP_TRAP:
        default:
            return SetError(state, VMMicroFault::UnsupportedSemantic,
                "unsupported micro semantic", error);
    }
}

bool VMMicroSemanticExecutor::Execute(
    const uint8_t* bytecode,
    size_t bytecodeSize,
    const uint8_t reverseOpcodeMap[256],
    const VM_OPERAND_CODEC& codec,
    VMMicroMachineState& state,
    VMMicroMemoryView memory,
    const VMMicroExecutionOptions& options,
    std::string& error)
{
    const auto validation = VMSchema::ValidateStream(bytecode, bytecodeSize,
        reverseOpcodeMap, codec, options.registerCount);
    if (!validation.success) {
        state.fault = VMMicroFault::Decode;
        error = validation.error;
        return false;
    }
    state.finished = false;
    state.fault = VMMicroFault::None;
    uint32_t steps = 0;
    while (!state.finished) {
        if (state.ip >= bytecodeSize) {
            return SetError(state, VMMicroFault::ControlFlow,
                "micro instruction pointer escaped bytecode", error);
        }
        MicroInstruction instruction{};
        uint32_t consumed = 0;
        std::string decodeError;
        if (!VMSchema::DecodeOne(bytecode + state.ip, bytecodeSize - state.ip,
                reverseOpcodeMap, codec, instruction, consumed, decodeError)) {
            return SetError(state, VMMicroFault::Decode, decodeError.c_str(), error);
        }
        const uint32_t instructionIp = state.ip;
        const uint32_t fallthrough = state.ip + consumed;
        if (!ExecuteOne(instruction, fallthrough, state, memory, options, error)) {
            state.faultAddress = instructionIp;
            return false;
        }
        if (++steps > options.maxSteps) {
            return SetError(state, VMMicroFault::StepLimit,
                "micro execution step limit exceeded", error);
        }
    }
    MaterializeFlags(state, VM_FLAG_ARCHITECTURAL_MASK);
    return state.fault == VMMicroFault::None;
}

bool VMMicroSemanticExecutor::Execute(
    const VMMicroSemanticPlan& plan,
    VMMicroMachineState& state,
    VMMicroMemoryView memory,
    const VMMicroExecutionOptions& options,
    std::string& error)
{
    if (plan.instructions.empty() || plan.encodedOffsets.size() != plan.instructions.size()) {
        state.fault = VMMicroFault::Decode;
        error = "micro semantic plan has no exact encoded boundary table";
        return false;
    }
    std::unordered_map<uint32_t, size_t> indexByOffset;
    for (size_t i = 0; i < plan.encodedOffsets.size(); ++i) {
        if (!indexByOffset.emplace(plan.encodedOffsets[i], i).second) {
            state.fault = VMMicroFault::Decode;
            error = "micro semantic plan has duplicate boundaries";
            return false;
        }
    }
    state.finished = false;
    state.fault = VMMicroFault::None;
    uint32_t steps = 0;
    while (!state.finished) {
        const auto found = indexByOffset.find(state.ip);
        if (found == indexByOffset.end()) {
            return SetError(state, VMMicroFault::ControlFlow,
                "plan instruction pointer is not a micro boundary", error);
        }
        const size_t index = found->second;
        const uint32_t instructionIp = state.ip;
        const uint32_t fallthrough = index + 1u < plan.encodedOffsets.size() ?
            plan.encodedOffsets[index + 1u] : plan.encodedSize;
        if (!ExecuteOne(plan.instructions[index], fallthrough, state, memory, options, error)) {
            state.faultAddress = instructionIp;
            return false;
        }
        if (++steps > options.maxSteps) {
            return SetError(state, VMMicroFault::StepLimit,
                "micro plan execution step limit exceeded", error);
        }
    }
    MaterializeFlags(state, VM_FLAG_ARCHITECTURAL_MASK);
    return state.fault == VMMicroFault::None;
}

} // namespace CipherShell
