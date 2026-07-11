#include "vm_runtime_core.h"
#include "vm_crypto.h"
#include "vm_schema_contract.h"

#if defined(_MSC_VER)
#define VM_NOINLINE __declspec(noinline)
#else
#define VM_NOINLINE __attribute__((noinline))
#endif

typedef struct VM_EXECUTION_CONTEXT {
    uint64_t regs[VM_RUNTIME_REGISTER_COUNT];
    uint64_t flags;
    uintptr_t imageBase;
    VM_METADATA_HEADER* metadata;
    VM_FUNCTION_RECORD* record;
    const uint8_t* encryptedBytecode;
    const uint8_t* reverseOpcodeMap;
    const uint8_t* registerMap;
    const uint8_t* handlerSemanticToSlot;
    const uint8_t* handlerSlotToSemantic;
    const uint8_t* handlerVariants;
    VM_EXTENDED_STATE* extendedState;
    uint8_t recordKey[32];
    uint32_t ip;
    uint32_t callDepth;
    uint32_t callStack[VM_RUNTIME_CALL_DEPTH];
    uintptr_t nativeReturnStack[VM_RUNTIME_CALL_DEPTH];
    uint32_t architecture;
    uint32_t returnStackCleanup;
    uintptr_t originalStackPointer;
    uintptr_t guestStackLow;
    uintptr_t guardTarget;
    uint32_t imageSize;
    uint8_t currentHandlerSlot;
    uint8_t currentHandlerVariant;
    uint16_t handlerReserved;
    volatile uint64_t mutationScratch;
} VM_EXECUTION_CONTEXT;

#if defined(_MSC_VER)
#pragma section(".rdata$vmkey", read)
__declspec(allocate(".rdata$vmkey"))
#endif
volatile const uint8_t vm_runtime_key_share[VM_RUNTIME_KEY_SHARE_SIZE] = {
    0x43,0x53,0x56,0x4D,0x4B,0x45,0x59,0x33,
    0x91,0x2D,0xE7,0x54,0xA8,0x6B,0xC0,0x1F,
    0x37,0xD2,0x4A,0xB9,0x65,0x0E,0x83,0xFC,
    0x18,0xA1,0x5D,0x72,0xCE,0x39,0xB4,0x06
};

void* memset(void* destination, int value, size_t length) {
    uint8_t* bytes = (uint8_t*)destination;
    size_t i;
    for (i = 0; i < length; ++i) bytes[i] = (uint8_t)value;
    return destination;
}

void* memcpy(void* destination, const void* source, size_t length) {
    uint8_t* output = (uint8_t*)destination;
    const uint8_t* input = (const uint8_t*)source;
    size_t i;
    for (i = 0; i < length; ++i) output[i] = input[i];
    return destination;
}

static uint64_t width_mask(uint8_t width) {
    if (width >= 8) return UINT64_MAX;
    if (width == 4) return 0xFFFFFFFFULL;
    if (width == 2) return 0xFFFFULL;
    if (width == 1) return 0xFFULL;
    return 0;
}

static uint16_t read_u16(const uint8_t* address) {
    return (uint16_t)((uint16_t)address[0] | ((uint16_t)address[1] << 8));
}

static uint32_t read_u32(const uint8_t* address) {
    return (uint32_t)address[0] | ((uint32_t)address[1] << 8) |
        ((uint32_t)address[2] << 16) | ((uint32_t)address[3] << 24);
}

static uint32_t image_size_from_headers(uintptr_t imageBase) {
    const uint8_t* image = (const uint8_t*)imageBase;
    uint32_t ntOffset;
    const uint8_t* optional;
    uint16_t magic;
    if (!image || read_u16(image) != 0x5A4Du) return 0;
    ntOffset = read_u32(image + 0x3Cu);
    if (ntOffset < 0x40u || ntOffset > 0x100000u ||
        read_u32(image + ntOffset) != 0x00004550u) return 0;
    optional = image + ntOffset + 24u;
    magic = read_u16(optional);
    if (magic != 0x010Bu && magic != 0x020Bu) return 0;
    return read_u32(optional + 56u);
}

static int image_rva_range_has_permissions(
    uintptr_t imageBase,
    uint32_t imageSize,
    uint32_t rva,
    uint32_t size,
    uint32_t required,
    uint32_t forbidden)
{
    const uint8_t* image = (const uint8_t*)imageBase;
    uint32_t ntOffset;
    uint16_t sectionCount;
    uint16_t optionalSize;
    uint32_t sectionOffset;
    uint32_t i;
    if (!image || size == 0 || rva >= imageSize || size > imageSize - rva ||
        read_u16(image) != 0x5A4Du) return 0;
    ntOffset = read_u32(image + 0x3Cu);
    if (ntOffset > imageSize || 24u > imageSize - ntOffset) return 0;
    sectionCount = read_u16(image + ntOffset + 6u);
    optionalSize = read_u16(image + ntOffset + 20u);
    sectionOffset = ntOffset + 24u + optionalSize;
    if (sectionOffset > imageSize || sectionCount > (imageSize - sectionOffset) / 40u) return 0;
    for (i = 0; i < sectionCount; ++i) {
        const uint8_t* section = image + sectionOffset + i * 40u;
        uint32_t virtualSize = read_u32(section + 8u);
        uint32_t virtualAddress = read_u32(section + 12u);
        uint32_t rawSize = read_u32(section + 16u);
        uint32_t span = virtualSize > rawSize ? virtualSize : rawSize;
        uint32_t characteristics = read_u32(section + 36u);
        if (span && rva >= virtualAddress && rva - virtualAddress < span) {
            return size <= span - (rva - virtualAddress) &&
                (characteristics & required) == required &&
                (characteristics & forbidden) == 0;
        }
    }
    return 0;
}

static int image_rva_is_rx(uintptr_t imageBase, uint32_t imageSize, uint32_t rva) {
    return image_rva_range_has_permissions(imageBase, imageSize, rva, 1,
        0x20000000u | 0x40000000u, 0x80000000u);
}

static uint64_t sign_mask(uint8_t width) {
    if (width == 8) return 0x8000000000000000ULL;
    if (width == 4) return 0x80000000ULL;
    if (width == 2) return 0x8000ULL;
    if (width == 1) return 0x80ULL;
    return 0;
}

static uint64_t truncate_width(uint64_t value, uint8_t width) {
    return value & width_mask(width);
}

static uint64_t sign_extend_width(uint64_t value, uint8_t width) {
    uint64_t mask = width_mask(width);
    uint64_t sign = sign_mask(width);
    value &= mask;
    return (value & sign) ? (value | ~mask) : value;
}

static uint8_t parity_even(uint8_t value) {
    value ^= value >> 4;
    value &= 0x0Fu;
    return (uint8_t)((0x9669u >> value) & 1u);
}

static uint8_t flag_get(uint64_t flags, uint64_t bit) {
    return (uint8_t)((flags & bit) != 0);
}

static void flag_set(uint64_t* flags, uint64_t bit, uint8_t value) {
    if (value) *flags |= bit;
    else *flags &= ~bit;
}

static void set_common_flags(VM_EXECUTION_CONTEXT* context, uint64_t result, uint8_t width) {
    uint64_t value = truncate_width(result, width);
    flag_set(&context->flags, VM_FLAG_ZF, value == 0);
    flag_set(&context->flags, VM_FLAG_SF, (value & sign_mask(width)) != 0);
    flag_set(&context->flags, VM_FLAG_PF, parity_even((uint8_t)value));
}

static uint64_t register_read(
    const VM_EXECUTION_CONTEXT* context,
    uint8_t reg,
    uint8_t width,
    uint8_t bitOffset)
{
    if (reg >= VM_RUNTIME_REGISTER_COUNT || width == 0 || width > 8 ||
        bitOffset > 64u - (uint32_t)width * 8u) return 0;
    return (context->regs[reg] >> bitOffset) & width_mask(width);
}

static int register_write(
    VM_EXECUTION_CONTEXT* context,
    uint8_t reg,
    uint8_t width,
    uint8_t bitOffset,
    uint16_t flags,
    uint64_t value)
{
    uint64_t mask;
    if (reg >= VM_RUNTIME_REGISTER_COUNT || width == 0 || width > 8 ||
        (bitOffset != 0 && bitOffset != 8) ||
        bitOffset > 64u - (uint32_t)width * 8u) return 0;
    value = truncate_width(value, width);
    if ((flags & VM_OPERAND_DST_ZERO_EXTEND) && width == 4 && bitOffset == 0) {
        context->regs[reg] = value;
        return 1;
    }
    mask = width_mask(width) << bitOffset;
    context->regs[reg] = (context->regs[reg] & ~mask) | ((value << bitOffset) & mask);
    return 1;
}

static uintptr_t memory_address(
    const VM_EXECUTION_CONTEXT* context,
    const VM_BYTECODE_INSTRUCTION* instruction,
    uint32_t* error)
{
    uintptr_t address;
    uint64_t base = 0;
    uint64_t index = 0;
    if (instruction->memoryKind == VM_MEMORY_IMAGE_RVA) {
        if (instruction->memDisp < 0) {
            *error = VM_ERR_MEMORY_ADDR_INVALID;
            return 0;
        }
        address = context->imageBase + (uintptr_t)instruction->memDisp;
        if (address < context->imageBase ||
            (uint64_t)instruction->memDisp > context->imageSize ||
            instruction->memWidth > context->imageSize - (uint32_t)instruction->memDisp) {
            *error = VM_ERR_MEMORY_ADDR_INVALID;
            return 0;
        }
        return address;
    }
    if (instruction->memoryKind != VM_MEMORY_NATIVE) {
        *error = VM_ERR_MEMORY_ADDR_INVALID;
        return 0;
    }
    if (instruction->memBase != VM_REGISTER_INVALID) {
        if (instruction->memBase >= VM_RUNTIME_REGISTER_COUNT) {
            *error = VM_ERR_REGISTER_MAP_INVALID;
            return 0;
        }
        base = context->regs[instruction->memBase];
    }
    if (instruction->memIndex != VM_REGISTER_INVALID) {
        if (instruction->memIndex >= VM_RUNTIME_REGISTER_COUNT ||
            !(instruction->memScale == 1 || instruction->memScale == 2 ||
              instruction->memScale == 4 || instruction->memScale == 8)) {
            *error = VM_ERR_MEMORY_ADDR_INVALID;
            return 0;
        }
        index = context->regs[instruction->memIndex] * instruction->memScale;
    }
    address = (uintptr_t)(base + index + (uint64_t)instruction->memDisp);
    if (address == 0 ||
        (instruction->memBase == context->registerMap[4] &&
            (address < context->guestStackLow ||
             instruction->memWidth > ~(uintptr_t)0 - address))) {
        *error = VM_ERR_MEMORY_ADDR_INVALID;
    }
    return address;
}

static uint64_t memory_read(uintptr_t address, uint8_t width, uint32_t* error) {
    if (!address) {
        *error = VM_ERR_MEMORY_ADDR_INVALID;
        return 0;
    }
    switch (width) {
        case 1: return *(volatile const uint8_t*)address;
        case 2: return *(volatile const uint16_t*)address;
        case 4: return *(volatile const uint32_t*)address;
        case 8: return *(volatile const uint64_t*)address;
        default: *error = VM_ERR_MEMORY_ADDR_INVALID; return 0;
    }
}

static int memory_write(uintptr_t address, uint8_t width, uint64_t value, uint32_t* error) {
    if (!address) {
        *error = VM_ERR_MEMORY_ADDR_INVALID;
        return 0;
    }
    switch (width) {
        case 1: *(volatile uint8_t*)address = (uint8_t)value; return 1;
        case 2: *(volatile uint16_t*)address = (uint16_t)value; return 1;
        case 4: *(volatile uint32_t*)address = (uint32_t)value; return 1;
        case 8: *(volatile uint64_t*)address = value; return 1;
        default: *error = VM_ERR_MEMORY_ADDR_INVALID; return 0;
    }
}

static uint64_t source_value(
    VM_EXECUTION_CONTEXT* context,
    const VM_BYTECODE_INSTRUCTION* instruction,
    uint32_t* error)
{
    if (instruction->flags & VM_OPERAND_SOURCE_IMMEDIATE) {
        return (instruction->flags & VM_OPERAND_IMMEDIATE_SIGNED)
            ? sign_extend_width(instruction->immediate, instruction->operandWidth)
            : truncate_width(instruction->immediate, instruction->operandWidth);
    }
    if (instruction->flags & VM_OPERAND_SOURCE_MEMORY) {
        uintptr_t address = memory_address(context, instruction, error);
        return memory_read(address, instruction->memWidth, error);
    }
    return register_read(context, instruction->src, instruction->operandWidth,
        instruction->srcBitOffset);
}

static uint64_t destination_value(
    VM_EXECUTION_CONTEXT* context,
    const VM_BYTECODE_INSTRUCTION* instruction,
    uint32_t* error)
{
    if (instruction->flags & VM_OPERAND_DEST_MEMORY) {
        uintptr_t address = memory_address(context, instruction, error);
        return memory_read(address, instruction->memWidth, error);
    }
    return register_read(context, instruction->dst, instruction->operandWidth,
        instruction->dstBitOffset);
}

static int destination_write(
    VM_EXECUTION_CONTEXT* context,
    const VM_BYTECODE_INSTRUCTION* instruction,
    uint64_t value,
    uint32_t* error)
{
    if (instruction->flags & VM_OPERAND_DEST_MEMORY) {
        uintptr_t address = memory_address(context, instruction, error);
        return memory_write(address, instruction->memWidth, value, error);
    }
    if (!register_write(context, instruction->dst, instruction->operandWidth,
        instruction->dstBitOffset, instruction->flags, value)) {
        *error = VM_ERR_REGISTER_MAP_INVALID;
        return 0;
    }
    return 1;
}

static uint64_t add_flags(
    VM_EXECUTION_CONTEXT* context,
    uint64_t lhs,
    uint64_t rhs,
    uint8_t carry,
    uint8_t width)
{
    uint64_t mask = width_mask(width);
    uint64_t sign = sign_mask(width);
    uint64_t a = lhs & mask;
    uint64_t b = rhs & mask;
    uint64_t partial = a + b;
    uint64_t sum = partial + carry;
    uint64_t result = sum & mask;
    uint8_t cf = (uint8_t)(partial < a || sum < partial ||
        (width < 8 && sum > mask));
    uint8_t of = (uint8_t)((~(a ^ b) & (a ^ result) & sign) != 0);
    flag_set(&context->flags, VM_FLAG_CF, cf);
    flag_set(&context->flags, VM_FLAG_OF, of);
    flag_set(&context->flags, VM_FLAG_AF, ((a ^ b ^ result) & 0x10u) != 0);
    set_common_flags(context, result, width);
    return result;
}

static uint64_t sub_flags(
    VM_EXECUTION_CONTEXT* context,
    uint64_t lhs,
    uint64_t rhs,
    uint8_t borrow,
    uint8_t width)
{
    uint64_t mask = width_mask(width);
    uint64_t sign = sign_mask(width);
    uint64_t a = lhs & mask;
    uint64_t b = rhs & mask;
    uint64_t subtrahend = (b + borrow) & mask;
    uint64_t result = (a - subtrahend) & mask;
    uint8_t cf = a < b || (borrow && a == b);
    uint8_t of = (uint8_t)(((a ^ b) & (a ^ result) & sign) != 0);
    flag_set(&context->flags, VM_FLAG_CF, cf);
    flag_set(&context->flags, VM_FLAG_OF, of);
    flag_set(&context->flags, VM_FLAG_AF, ((a ^ b ^ result) & 0x10u) != 0);
    set_common_flags(context, result, width);
    return result;
}

static uint64_t logic_flags(VM_EXECUTION_CONTEXT* context, uint64_t value, uint8_t width) {
    uint64_t result = truncate_width(value, width);
    flag_set(&context->flags, VM_FLAG_CF, 0);
    flag_set(&context->flags, VM_FLAG_OF, 0);
    set_common_flags(context, result, width);
    return result;
}

static int condition_true(const VM_EXECUTION_CONTEXT* context, uint8_t condition) {
    uint8_t cf = flag_get(context->flags, VM_FLAG_CF);
    uint8_t pf = flag_get(context->flags, VM_FLAG_PF);
    uint8_t zf = flag_get(context->flags, VM_FLAG_ZF);
    uint8_t sf = flag_get(context->flags, VM_FLAG_SF);
    uint8_t of = flag_get(context->flags, VM_FLAG_OF);
    switch (condition) {
        case VM_CONDITION_ALWAYS: return 1;
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
        case VM_CONDITION_LE: return zf || sf != of;
        case VM_CONDITION_G: return !zf && sf == of;
        default: return 0;
    }
}

static void multiply_u64(uint64_t lhs, uint64_t rhs, uint64_t* high, uint64_t* low) {
    uint64_t a0 = (uint32_t)lhs;
    uint64_t a1 = lhs >> 32;
    uint64_t b0 = (uint32_t)rhs;
    uint64_t b1 = rhs >> 32;
    uint64_t p00 = a0 * b0;
    uint64_t p01 = a0 * b1;
    uint64_t p10 = a1 * b0;
    uint64_t p11 = a1 * b1;
    uint64_t middle = (p00 >> 32) + (uint32_t)p01 + (uint32_t)p10;
    *low = (middle << 32) | (uint32_t)p00;
    *high = p11 + (p01 >> 32) + (p10 >> 32) + (middle >> 32);
}

static void negate_u128(uint64_t* high, uint64_t* low) {
    *low = ~*low + 1u;
    *high = ~*high + (*low == 0);
}

static void multiply_signed_width(
    uint64_t lhs,
    uint64_t rhs,
    uint8_t width,
    uint64_t* high,
    uint64_t* low,
    uint8_t* overflow)
{
    uint64_t mask = width_mask(width);
    uint64_t sign = sign_mask(width);
    uint8_t negative = (uint8_t)(((lhs & sign) != 0) ^ ((rhs & sign) != 0));
    uint64_t leftMagnitude = (lhs & sign) ? ((~lhs + 1u) & mask) : (lhs & mask);
    uint64_t rightMagnitude = (rhs & sign) ? ((~rhs + 1u) & mask) : (rhs & mask);
    if (width < 8) {
        uint8_t bits = (uint8_t)(width * 8);
        uint8_t productBits = (uint8_t)(bits * 2);
        uint64_t product = leftMagnitude * rightMagnitude;
        uint64_t productMask = productBits == 64 ? UINT64_MAX : ((1ULL << productBits) - 1u);
        if (negative) product = (~product + 1u) & productMask;
        *low = product & mask;
        *high = (product >> bits) & mask;
    } else {
        multiply_u64(leftMagnitude, rightMagnitude, high, low);
        if (negative) negate_u128(high, low);
    }
    *overflow = (uint8_t)(*high != ((*low & sign) ? mask : 0));
}

static int divide_u64_u64(
    uint64_t dividend,
    uint64_t divisor,
    uint64_t* quotient,
    uint64_t* remainder)
{
    uint64_t q = 0;
    uint64_t r = 0;
    int bit;
    if (divisor == 0) return 0;
    for (bit = 63; bit >= 0; --bit) {
        uint8_t carry = (uint8_t)(r >> 63);
        r = (r << 1) | ((dividend >> bit) & 1u);
        if (carry || r >= divisor) {
            r -= divisor;
            q |= 1ULL << bit;
        }
    }
    *quotient = q;
    *remainder = r;
    return 1;
}

static int divide_u128_u64(
    uint64_t high,
    uint64_t low,
    uint64_t divisor,
    uint64_t* quotient,
    uint64_t* remainder)
{
    uint64_t q = 0;
    uint64_t r = 0;
    int bit;
    if (divisor == 0 || high >= divisor) return 0;
    for (bit = 127; bit >= 0; --bit) {
        uint64_t next = bit >= 64 ? ((high >> (bit - 64)) & 1u) : ((low >> bit) & 1u);
        uint8_t carry = (uint8_t)(r >> 63);
        r = (r << 1) | next;
        if (carry || r >= divisor) {
            r -= divisor;
            if (bit < 64) q |= 1ULL << bit;
        }
    }
    *quotient = q;
    *remainder = r;
    return 1;
}

static int divide_operands(
    uint64_t high,
    uint64_t low,
    uint64_t divisor,
    uint8_t width,
    uint8_t isSigned,
    uint64_t* quotient,
    uint64_t* remainder)
{
    uint64_t mask = width_mask(width);
    uint64_t sign = sign_mask(width);
    if (!mask || (divisor & mask) == 0) return 0;

    if (!isSigned) {
        if (width == 8) {
            return divide_u128_u64(high, low, divisor, quotient, remainder);
        } else {
            uint8_t bits = (uint8_t)(width * 8);
            uint64_t dividend = ((high & mask) << bits) | (low & mask);
            if (!divide_u64_u64(dividend, divisor & mask, quotient, remainder) ||
                *quotient > mask) return 0;
            return 1;
        }
    }

    {
        uint8_t divisorNegative = (uint8_t)((divisor & sign) != 0);
        uint64_t divisorMagnitude = divisorNegative
            ? ((~divisor + 1u) & mask) : (divisor & mask);
        uint8_t dividendNegative;
        uint8_t resultNegative;
        uint64_t quotientMagnitude = 0;
        uint64_t remainderMagnitude = 0;
        if (width == 8) {
            uint64_t magnitudeHigh = high;
            uint64_t magnitudeLow = low;
            dividendNegative = (uint8_t)((high & sign) != 0);
            if (dividendNegative) negate_u128(&magnitudeHigh, &magnitudeLow);
            if (!divide_u128_u64(magnitudeHigh, magnitudeLow, divisorMagnitude,
                    &quotientMagnitude, &remainderMagnitude)) return 0;
        } else {
            uint8_t bits = (uint8_t)(width * 8);
            uint8_t dividendBits = (uint8_t)(bits * 2);
            uint64_t dividendMask = dividendBits == 64
                ? UINT64_MAX : ((1ULL << dividendBits) - 1u);
            uint64_t dividend = (((high & mask) << bits) | (low & mask)) & dividendMask;
            uint64_t dividendSign = 1ULL << (dividendBits - 1u);
            dividendNegative = (uint8_t)((dividend & dividendSign) != 0);
            if (dividendNegative) dividend = (~dividend + 1u) & dividendMask;
            if (!divide_u64_u64(dividend, divisorMagnitude,
                    &quotientMagnitude, &remainderMagnitude)) return 0;
        }
        resultNegative = (uint8_t)(dividendNegative ^ divisorNegative);
        if (quotientMagnitude > (resultNegative ? sign : sign - 1u)) return 0;
        *quotient = resultNegative
            ? ((~quotientMagnitude + 1u) & mask) : quotientMagnitude;
        *remainder = dividendNegative
            ? ((~remainderMagnitude + 1u) & mask) : remainderMagnitude;
        return 1;
    }
}

static uint32_t validate_metadata(
    VM_METADATA_HEADER* metadata,
    uint32_t architecture,
    uint8_t masterKey[32])
{
    const uint32_t knownFlags = VM_METADATA_FLAG_AUTHENTICATED |
        VM_METADATA_FLAG_BYTECODE_CHACHA20 |
        VM_METADATA_FLAG_NATIVE_BODY_DESTROYED |
        VM_METADATA_FLAG_CFG_VERIFIED |
        VM_METADATA_FLAG_UNWIND_VERIFIED |
        VM_METADATA_FLAG_CFG_ENABLED |
        VM_METADATA_FLAG_HANDLER_MUTATED |
        VM_METADATA_FLAG_JUNK_HANDLERS;
    uint32_t i;
    uint64_t expected;
    VM_SIPHASH24_CONTEXT hash;
    const uint8_t zero[8] = {0,0,0,0,0,0,0,0};
    const size_t tagOffset = offsetof(VM_METADATA_HEADER, metadataTag);
    if (!metadata || metadata->headerSize != sizeof(VM_METADATA_HEADER) ||
        metadata->recordSize != sizeof(VM_FUNCTION_RECORD) ||
        metadata->metadataVersion != VM_METADATA_VERSION ||
        metadata->schemaVersion != VM_SCHEMA_VERSION ||
        metadata->runtimeVersion != VM_RUNTIME_VERSION ||
        metadata->keyEncodingVersion != VM_KEY_ENCODING_VERSION ||
        metadata->architecture != architecture ||
        (metadata->flags & ~knownFlags) != 0 ||
        (metadata->flags & (VM_METADATA_FLAG_AUTHENTICATED |
            VM_METADATA_FLAG_BYTECODE_CHACHA20 |
            VM_METADATA_FLAG_NATIVE_BODY_DESTROYED |
            VM_METADATA_FLAG_CFG_VERIFIED)) !=
            (VM_METADATA_FLAG_AUTHENTICATED |
             VM_METADATA_FLAG_BYTECODE_CHACHA20 |
             VM_METADATA_FLAG_NATIVE_BODY_DESTROYED |
             VM_METADATA_FLAG_CFG_VERIFIED) ||
        (architecture == VM_ARCH_X64 &&
            !(metadata->flags & VM_METADATA_FLAG_UNWIND_VERIFIED)) ||
        metadata->opcodeMapSize != VM_OPCODE_MAP_SIZE ||
        metadata->registerMapSize != VM_REGISTER_MAP_SIZE ||
        metadata->handlerTableSize != VM_HANDLER_TABLE_SIZE ||
        metadata->handlerVariantCount != VM_HANDLER_VARIANT_COUNT ||
        metadata->junkHandlerCount > VM_HANDLER_USABLE_SLOT_COUNT ||
        metadata->layoutSeed == 0 || metadata->imageSize == 0 ||
        metadata->runtimeBaseRVA == 0 || metadata->runtimeBaseRVA >= metadata->imageSize ||
        metadata->runtimeSize == 0 ||
        metadata->runtimeSize > metadata->imageSize - metadata->runtimeBaseRVA ||
        metadata->runtimeEntryRVA < metadata->runtimeBaseRVA ||
        metadata->runtimeEntryRVA - metadata->runtimeBaseRVA >= metadata->runtimeSize ||
        metadata->totalSize < metadata->headerSize ||
        metadata->guardCFCheckPointerRVA >= metadata->imageSize ||
        metadata->guardCFDispatchPointerRVA >= metadata->imageSize ||
        metadata->recordCount == 0 || metadata->recordCount > 0x100000u ||
        metadata->recordOffset < metadata->headerSize ||
        metadata->recordOffset > metadata->reverseOpcodeMapOffset ||
        metadata->recordCount > (metadata->reverseOpcodeMapOffset - metadata->recordOffset) / metadata->recordSize ||
        metadata->reverseOpcodeMapOffset > metadata->registerMapOffset ||
        metadata->opcodeMapSize > metadata->registerMapOffset - metadata->reverseOpcodeMapOffset ||
        metadata->registerMapOffset > metadata->handlerSemanticMapOffset ||
        metadata->registerMapSize > metadata->handlerSemanticMapOffset - metadata->registerMapOffset ||
        metadata->handlerSemanticMapOffset > metadata->handlerDescriptorOffset ||
        metadata->handlerTableSize > metadata->handlerDescriptorOffset - metadata->handlerSemanticMapOffset ||
        metadata->handlerDescriptorOffset > metadata->handlerVariantOffset ||
        metadata->handlerTableSize > metadata->handlerVariantOffset - metadata->handlerDescriptorOffset ||
        metadata->handlerVariantOffset > metadata->bytecodeOffset ||
        metadata->handlerTableSize > metadata->bytecodeOffset - metadata->handlerVariantOffset ||
        metadata->bytecodeOffset > metadata->totalSize ||
        metadata->bytecodeSize > metadata->totalSize - metadata->bytecodeOffset) {
        return VM_ERR_METADATA_INVALID;
    }
    for (i = 0; i < 32; ++i) {
        uint8_t cookieByte = (uint8_t)(metadata->cookie >> ((i & 3u) * 8u));
        masterKey[i] = metadata->encodedMasterKey[i] ^ vm_runtime_key_share[i] ^
            metadata->buildId[i & 15u] ^
            cookieByte ^ (uint8_t)(i * 0x5Bu);
    }
    vm_siphash24_init(&hash, masterKey);
    vm_siphash24_update(&hash, (const uint8_t*)metadata, tagOffset);
    vm_siphash24_update(&hash, zero, sizeof(zero));
    if (metadata->totalSize > tagOffset + 8) {
        vm_siphash24_update(&hash, (const uint8_t*)metadata + tagOffset + 8,
            metadata->totalSize - tagOffset - 8);
    }
    expected = vm_siphash24_final(&hash);
    if (!vm_constant_time_equal64(expected, metadata->metadataTag)) return VM_ERR_METADATA_INVALID;
    {
        uint8_t seenOpcodes[256];
        uint8_t seenRegisters[VM_RUNTIME_REGISTER_COUNT];
        uint8_t seenHandlerSlots[VM_HANDLER_TABLE_SIZE];
        uint32_t junkCount = 0;
        const uint8_t* reverse = (const uint8_t*)metadata + metadata->reverseOpcodeMapOffset;
        const uint8_t* registers = (const uint8_t*)metadata + metadata->registerMapOffset;
        const uint8_t* semanticToSlot = (const uint8_t*)metadata + metadata->handlerSemanticMapOffset;
        const uint8_t* slotToSemantic = (const uint8_t*)metadata + metadata->handlerDescriptorOffset;
        const uint8_t* variants = (const uint8_t*)metadata + metadata->handlerVariantOffset;
        for (i = 0; i < 256; ++i) {
            seenOpcodes[i] = 0;
            seenHandlerSlots[i] = 0;
        }
        for (i = 0; i < VM_RUNTIME_REGISTER_COUNT; ++i) seenRegisters[i] = 0;
        for (i = 0; i < 256; ++i) {
            if (seenOpcodes[reverse[i]]) return VM_ERR_METADATA_INVALID;
            seenOpcodes[reverse[i]] = 1;
            if (variants[i] >= VM_HANDLER_VARIANT_COUNT) return VM_ERR_METADATA_INVALID;
            if (i >= VM_HANDLER_USABLE_SLOT_COUNT) {
                if (slotToSemantic[i] != VM_HANDLER_INVALID || variants[i] != 0)
                    return VM_ERR_METADATA_INVALID;
                continue;
            }
            if (slotToSemantic[i] == VM_HANDLER_JUNK) {
                ++junkCount;
            } else if (slotToSemantic[i] != VM_HANDLER_INVALID) {
                const uint8_t semantic = slotToSemantic[i];
                if (semantic == VM_HANDLER_JUNK || semantic == VM_HANDLER_INVALID ||
                    semanticToSlot[semantic] != i || seenHandlerSlots[i])
                    return VM_ERR_METADATA_INVALID;
                seenHandlerSlots[i] = 1;
            }
        }
        for (i = 0; i < 256; ++i) {
            const uint8_t slot = semanticToSlot[i];
            if (slot == VM_HANDLER_INVALID) continue;
            if (slot >= VM_HANDLER_USABLE_SLOT_COUNT ||
                slotToSemantic[slot] != i || seenHandlerSlots[slot] == 0)
                return VM_ERR_METADATA_INVALID;
        }
        if (junkCount != metadata->junkHandlerCount ||
            (((metadata->flags & VM_METADATA_FLAG_JUNK_HANDLERS) != 0) != (junkCount != 0)))
            return VM_ERR_METADATA_INVALID;
        {
            uint8_t mutated = 0;
            for (i = 0; i < 256; ++i) {
                if (semanticToSlot[i] != VM_HANDLER_INVALID && semanticToSlot[i] != i) {
                    mutated = 1;
                    break;
                }
            }
            if (((metadata->flags & VM_METADATA_FLAG_HANDLER_MUTATED) != 0) != (mutated != 0))
                return VM_ERR_METADATA_INVALID;
        }
        for (i = 0; i < 16; ++i) {
            if (registers[i] >= VM_RUNTIME_REGISTER_COUNT || seenRegisters[registers[i]])
                return VM_ERR_REGISTER_MAP_INVALID;
            seenRegisters[registers[i]] = 1;
        }
    }
    return VM_ERR_NONE;
}

static VM_FUNCTION_RECORD* find_record(VM_METADATA_HEADER* metadata, uint32_t functionRva) {
    uint32_t i;
    VM_FUNCTION_RECORD* records = (VM_FUNCTION_RECORD*)((uint8_t*)metadata + metadata->recordOffset);
    for (i = 0; i < metadata->recordCount; ++i) {
        if (records[i].functionRVA == functionRva) return &records[i];
    }
    return 0;
}

static uint32_t validate_record(
    VM_EXECUTION_CONTEXT* context,
    const uint8_t masterKey[32])
{
    const uint32_t knownFlags = VM_RECORD_FLAG_X64 |
        VM_RECORD_FLAG_NATIVE_BODY_DESTROYED |
        VM_RECORD_FLAG_UNWIND_VERIFIED |
        VM_RECORD_FLAG_CFG_VERIFIED |
        VM_RECORD_FLAG_USES_SIMD |
        VM_RECORD_FLAG_USES_AVX |
        VM_RECORD_FLAG_USES_X87;
    uint64_t expectedTag;
    if (!context->record || context->record->bytecodeSize == 0 ||
        context->record->bytecodeSize % VM_INSTRUCTION_SIZE != 0 ||
        context->record->bytecodeOffset > context->metadata->bytecodeSize ||
        context->record->bytecodeSize >
            context->metadata->bytecodeSize - context->record->bytecodeOffset ||
        context->record->opcodeMapOffset != context->metadata->reverseOpcodeMapOffset ||
        context->record->registerMapOffset != context->metadata->registerMapOffset ||
        context->record->functionRVA == 0 || context->record->functionSize < 5 ||
        context->record->trampolineRVA == 0 || context->record->trampolineSize == 0 ||
        context->record->functionRVA >= context->imageSize ||
        context->record->functionSize > context->imageSize - context->record->functionRVA ||
        context->record->trampolineRVA >= context->imageSize ||
        context->record->trampolineSize >
            context->imageSize - context->record->trampolineRVA ||
        !image_rva_range_has_permissions(context->imageBase, context->imageSize,
            context->record->trampolineRVA, context->record->trampolineSize,
            0x20000000u | 0x40000000u, 0x80000000u) ||
        (context->record->flags & ~knownFlags) != 0 ||
        context->record->guestStackSize < 0x4000u ||
        context->record->guestStackSize > 0x70000u ||
        (context->record->guestStackSize & 0x0FFFu) != 0 ||
        ((context->architecture == VM_ARCH_X64) !=
            ((context->record->flags & VM_RECORD_FLAG_X64) != 0)) ||
        ((context->record->flags & VM_RECORD_FLAG_USES_AVX) != 0 &&
            (context->record->flags & VM_RECORD_FLAG_USES_SIMD) == 0) ||
        context->record->returnStackCleanup > 0xFFFFu ||
        (context->architecture == VM_ARCH_X64 && context->record->returnStackCleanup != 0) ||
        (context->record->flags & (VM_RECORD_FLAG_NATIVE_BODY_DESTROYED |
            VM_RECORD_FLAG_CFG_VERIFIED)) !=
            (VM_RECORD_FLAG_NATIVE_BODY_DESTROYED | VM_RECORD_FLAG_CFG_VERIFIED) ||
        (context->architecture == VM_ARCH_X64 &&
            !(context->record->flags & VM_RECORD_FLAG_UNWIND_VERIFIED))) {
        return VM_ERR_BYTECODE_RANGE;
    }
    vm_derive_record_key(masterKey, context->metadata->buildId,
        context->record->functionRVA, context->recordKey);
    context->encryptedBytecode = (const uint8_t*)context->metadata +
        context->metadata->bytecodeOffset + context->record->bytecodeOffset;
    context->reverseOpcodeMap = (const uint8_t*)context->metadata +
        context->metadata->reverseOpcodeMapOffset;
    context->registerMap = (const uint8_t*)context->metadata +
        context->metadata->registerMapOffset;
    context->handlerSemanticToSlot = (const uint8_t*)context->metadata +
        context->metadata->handlerSemanticMapOffset;
    context->handlerSlotToSemantic = (const uint8_t*)context->metadata +
        context->metadata->handlerDescriptorOffset;
    context->handlerVariants = (const uint8_t*)context->metadata +
        context->metadata->handlerVariantOffset;
    expectedTag = vm_siphash24(context->encryptedBytecode,
        context->record->bytecodeSize, context->recordKey + 16);
    return vm_constant_time_equal64(expectedTag, context->record->bytecodeTag)
        ? VM_ERR_NONE : VM_ERR_BYTECODE_AUTH;
}

static uint32_t decode_instruction(
    VM_EXECUTION_CONTEXT* context,
    VM_BYTECODE_INSTRUCTION* instruction)
{
    if (context->ip > context->record->bytecodeSize ||
        VM_INSTRUCTION_SIZE > context->record->bytecodeSize - context->ip ||
        context->ip % VM_INSTRUCTION_SIZE != 0) return VM_ERR_BYTECODE_RANGE;
    vm_chacha20_xor(context->encryptedBytecode + context->ip,
        (uint8_t*)instruction, sizeof(*instruction), context->recordKey,
        context->record->nonce, 1, context->ip);
    instruction->opcode = context->reverseOpcodeMap[instruction->opcode];
    {
        const uint8_t semantic = instruction->opcode;
        const uint8_t slot = context->handlerSemanticToSlot[semantic];
        uint8_t descriptor;
        if (slot == VM_HANDLER_INVALID) return VM_ERR_OPCODE_UNSUPPORTED;
        descriptor = context->handlerSlotToSemantic[slot];
        if (descriptor != semantic) return VM_ERR_HANDLER_BUG;
        context->currentHandlerSlot = slot;
        context->currentHandlerVariant = context->handlerVariants[slot];
        if (context->currentHandlerVariant >= VM_HANDLER_VARIANT_COUNT)
            return VM_ERR_HANDLER_BUG;
        instruction->opcode = descriptor;
    }
    if (vm_schema_validate_instruction(instruction, VM_RUNTIME_REGISTER_COUNT) !=
            VM_SCHEMA_CONTRACT_OK) return VM_ERR_SCHEMA_MISMATCH;
    if (vm_schema_opcode_has_branch(instruction->opcode) &&
        (instruction->branchTargetOffset >= context->record->bytecodeSize ||
         instruction->branchTargetOffset % VM_INSTRUCTION_SIZE != 0)) {
        return VM_ERR_BYTECODE_RANGE;
    }
    if (instruction->opcode == VM_CALL_VM) {
        const uint64_t functionEnd = (uint64_t)context->record->functionRVA +
            context->record->functionSize;
        if (instruction->immediate < context->record->functionRVA ||
            instruction->immediate >= functionEnd) return VM_ERR_SCHEMA_MISMATCH;
    }
    if (instruction->opcode == VM_CALL_NATIVE &&
        (instruction->immediate >= context->imageSize ||
         !image_rva_is_rx(context->imageBase, context->imageSize,
            (uint32_t)instruction->immediate))) return VM_ERR_NATIVE_BRIDGE;
    if (instruction->opcode == VM_CALL_IMPORT &&
        (instruction->immediate >= context->imageSize ||
         (context->architecture == VM_ARCH_X64 ? 8u : 4u) >
            context->imageSize - (uint32_t)instruction->immediate)) {
        return VM_ERR_NATIVE_BRIDGE;
    }
    if (instruction->opcode == VM_CALL_NATIVE || instruction->opcode == VM_CALL_IMPORT ||
        instruction->opcode == VM_CALL_INDIRECT_R ||
        instruction->opcode == VM_CALL_INDIRECT_M) {
        const uint32_t abi = VM_CALL_AUX_ABI(instruction->aux);
        if ((context->architecture == VM_ARCH_X64 && abi != VM_ABI_WIN64) ||
            (context->architecture == VM_ARCH_X86 &&
                (abi < VM_ABI_X86_CDECL || abi > VM_ABI_X86_AUTO))) {
            return VM_ERR_SCHEMA_MISMATCH;
        }
    }
    if (context->architecture == VM_ARCH_X64 &&
        instruction->opcode == VM_RET_VM && instruction->aux != 0) {
        return VM_ERR_SCHEMA_MISMATCH;
    }
    return VM_ERR_NONE;
}

static uint32_t initialize_registers(
    VM_EXECUTION_CONTEXT* context,
    void* nativeFrame)
{
    uint32_t i;
    for (i = 0; i < VM_RUNTIME_REGISTER_COUNT; ++i) context->regs[i] = 0;
    for (i = 0; i < 16; ++i) {
        if (context->registerMap[i] >= VM_RUNTIME_REGISTER_COUNT) return VM_ERR_REGISTER_MAP_INVALID;
    }
#if defined(_M_X64) || defined(__x86_64__)
    {
        VM_NATIVE_FRAME_X64* frame = (VM_NATIVE_FRAME_X64*)nativeFrame;
        uint64_t native[16];
        native[0] = frame->rax; native[1] = frame->rcx; native[2] = frame->rdx; native[3] = frame->rbx;
        native[4] = frame->originalRsp;
        native[5] = frame->rbp; native[6] = frame->rsi; native[7] = frame->rdi;
        native[8] = frame->r8; native[9] = frame->r9; native[10] = frame->r10; native[11] = frame->r11;
        native[12] = frame->r12; native[13] = frame->r13; native[14] = frame->r14; native[15] = frame->r15;
        for (i = 0; i < 16; ++i) context->regs[context->registerMap[i]] = native[i];
        context->flags = frame->rflags;
        context->originalStackPointer = (uintptr_t)frame->originalRsp;
    }
#else
    {
        VM_NATIVE_FRAME_X86* frame = (VM_NATIVE_FRAME_X86*)nativeFrame;
        uint32_t native[8];
        uintptr_t originalStackPointer;
        if (frame->originalEsp > UINT32_MAX - sizeof(uint32_t)) {
            return VM_ERR_STACK_ALIGNMENT;
        }
        originalStackPointer = (uintptr_t)frame->originalEsp + sizeof(uint32_t);
        if (*(const uint32_t*)originalStackPointer != frame->returnAddress) {
            return VM_ERR_RET_WITHOUT_CONTEXT;
        }
        native[0] = frame->eax; native[1] = frame->ecx; native[2] = frame->edx; native[3] = frame->ebx;
        native[4] = (uint32_t)originalStackPointer;
        native[5] = frame->ebp; native[6] = frame->esi; native[7] = frame->edi;
        for (i = 0; i < 8; ++i) context->regs[context->registerMap[i]] = native[i];
        context->flags = frame->eflags;
        context->originalStackPointer = originalStackPointer;
    }
#endif
    return VM_ERR_NONE;
}

static void writeback_registers(VM_EXECUTION_CONTEXT* context, void* nativeFrame) {
#if defined(_M_X64) || defined(__x86_64__)
    VM_NATIVE_FRAME_X64* frame = (VM_NATIVE_FRAME_X64*)nativeFrame;
    frame->rax = context->regs[context->registerMap[0]];
    frame->rcx = context->regs[context->registerMap[1]];
    frame->rdx = context->regs[context->registerMap[2]];
    frame->rbx = context->regs[context->registerMap[3]];
    frame->rbp = context->regs[context->registerMap[5]];
    frame->rsi = context->regs[context->registerMap[6]];
    frame->rdi = context->regs[context->registerMap[7]];
    frame->r8 = context->regs[context->registerMap[8]];
    frame->r9 = context->regs[context->registerMap[9]];
    frame->r10 = context->regs[context->registerMap[10]];
    frame->r11 = context->regs[context->registerMap[11]];
    frame->r12 = context->regs[context->registerMap[12]];
    frame->r13 = context->regs[context->registerMap[13]];
    frame->r14 = context->regs[context->registerMap[14]];
    frame->r15 = context->regs[context->registerMap[15]];
    frame->rflags = context->flags;
#else
    VM_NATIVE_FRAME_X86* frame = (VM_NATIVE_FRAME_X86*)nativeFrame;
    frame->eax = (uint32_t)context->regs[context->registerMap[0]];
    frame->ecx = (uint32_t)context->regs[context->registerMap[1]];
    frame->edx = (uint32_t)context->regs[context->registerMap[2]];
    frame->ebx = (uint32_t)context->regs[context->registerMap[3]];
    frame->ebp = (uint32_t)context->regs[context->registerMap[5]];
    frame->esi = (uint32_t)context->regs[context->registerMap[6]];
    frame->edi = (uint32_t)context->regs[context->registerMap[7]];
    frame->eflags = (uint32_t)context->flags;
#endif
}

static uint32_t execute_native_call(
    VM_EXECUTION_CONTEXT* context,
    const VM_BYTECODE_INSTRUCTION* instruction,
    uintptr_t target)
{
    VM_NATIVE_CALL_STATE state;
    uint32_t i;
    uint32_t result;
    uint32_t stackArgumentBytes = VM_CALL_AUX_STACK_BYTES(instruction->aux);
    uint32_t callAbi = VM_CALL_AUX_ABI(instruction->aux);
    uint64_t originalStackPointer;
    if (!target) return VM_ERR_NATIVE_BRIDGE;
    if (stackArgumentBytes > VM_NATIVE_MAX_STACK_ARGUMENT_BYTES ||
        (context->architecture == VM_ARCH_X64 &&
            (callAbi != VM_ABI_WIN64 || (stackArgumentBytes & 7u) != 0 ||
             (context->regs[context->registerMap[4]] & 0x0Fu) != 0)) ||
        (context->architecture == VM_ARCH_X86 &&
            ((callAbi < VM_ABI_X86_CDECL || callAbi > VM_ABI_X86_AUTO) ||
             (stackArgumentBytes & 1u) != 0))) {
        return VM_ERR_STACK_ALIGNMENT;
    }
    for (i = 0; i < 16; ++i) state.gpr[i] = context->regs[context->registerMap[i]];
    state.rflags = context->flags;
    state.stackPointer = context->regs[context->registerMap[4]];
    state.target = target;
    state.guardTarget = instruction->opcode == VM_CALL_NATIVE ? 0 : context->guardTarget;
    if ((context->metadata->flags & VM_METADATA_FLAG_CFG_ENABLED) &&
        instruction->opcode != VM_CALL_NATIVE && state.guardTarget == 0) {
        return VM_ERR_NATIVE_BRIDGE;
    }
    state.stackArgumentBytes = stackArgumentBytes;
    state.callAbi = callAbi;
    state.bridgeReserved = 0;
    originalStackPointer = state.stackPointer;
    state.extendedState = (uintptr_t)context->extendedState;
    state.extendedStateFlags = context->extendedState->flags;
    state.stateReserved = 0;
    result = vm_native_call_bridge(&state);
    if (result != 0) return VM_ERR_NATIVE_BRIDGE;
    if (state.stackPointer < originalStackPointer ||
        state.stackPointer - originalStackPointer > stackArgumentBytes) {
        return VM_ERR_STACK_ALIGNMENT;
    }
    if (context->architecture == VM_ARCH_X86) {
        const uint64_t cleanup = state.stackPointer - originalStackPointer;
        if ((callAbi == VM_ABI_X86_CDECL && cleanup != 0) ||
            (callAbi >= VM_ABI_X86_STDCALL && callAbi <= VM_ABI_X86_THISCALL &&
                cleanup != stackArgumentBytes)) {
            return VM_ERR_STACK_ALIGNMENT;
        }
    }
    for (i = 0; i < 16; ++i) context->regs[context->registerMap[i]] = state.gpr[i];
    context->regs[context->registerMap[4]] = state.stackPointer;
    context->flags = state.rflags;
    return VM_ERR_NONE;
}

static uint32_t execute_instruction_bridge(
    VM_EXECUTION_CONTEXT* context,
    const VM_BYTECODE_INSTRUCTION* instruction)
{
    VM_INSTRUCTION_BRIDGE_STATE state;
    uint32_t i;
    uint32_t result;
    const uint32_t hidden = instruction->aux & VM_BRIDGE_AUX_HIDDEN_REGISTER_MASK;
    const uint32_t isAvx = instruction->aux & VM_BRIDGE_AUX_AVX;
    const uint32_t isX87 = instruction->aux & VM_BRIDGE_AUX_X87;
    const uint32_t expectedRecordFlag = instruction->opcode == VM_BRIDGE_X87
        ? VM_RECORD_FLAG_USES_X87 : VM_RECORD_FLAG_USES_SIMD;
    if (instruction->immediate == 0 || instruction->immediate >= context->imageSize ||
        hidden >= 16u || !image_rva_is_rx(context->imageBase, context->imageSize,
            (uint32_t)instruction->immediate) ||
        (instruction->flags & (VM_OPERAND_NATIVE_BRIDGE | VM_OPERAND_BRIDGE_LINKED)) !=
            (VM_OPERAND_NATIVE_BRIDGE | VM_OPERAND_BRIDGE_LINKED) ||
        (context->record->flags & expectedRecordFlag) == 0 ||
        ((instruction->opcode == VM_BRIDGE_X87) != (isX87 != 0)) ||
        ((isAvx != 0) != ((context->record->flags & VM_RECORD_FLAG_USES_AVX) != 0) &&
            isAvx != 0)) {
        return VM_ERR_NATIVE_BRIDGE;
    }
    memset(&state, 0, sizeof(state));
    for (i = 0; i < 16; ++i) state.gpr[i] = context->regs[context->registerMap[i]];
    state.rflags = context->flags;
    state.target = context->imageBase + (uintptr_t)instruction->immediate;
    state.guardTarget = (context->metadata->flags & VM_METADATA_FLAG_CFG_ENABLED)
        ? context->guardTarget : 0;
    state.extendedState = (uintptr_t)context->extendedState;
    state.extendedStateFlags = context->extendedState->flags;
    state.hiddenRegister = hidden;
    result = vm_instruction_bridge(&state);
    if (result != 0) return VM_ERR_NATIVE_BRIDGE;
    for (i = 0; i < 16; ++i) context->regs[context->registerMap[i]] = state.gpr[i];
    context->flags = state.rflags;
    return VM_ERR_NONE;
}

static uint32_t execute_instruction(
    VM_EXECUTION_CONTEXT* context,
    const VM_BYTECODE_INSTRUCTION* instruction,
    int* finished)
{
    uint32_t error = VM_ERR_NONE;
    uint64_t lhs;
    uint64_t rhs;
    uint64_t value;
    uint64_t result;
    uint8_t width = instruction->operandWidth;
    uint8_t oldCf;
    uint32_t nextIp = context->ip + VM_INSTRUCTION_SIZE;
    uintptr_t address;

    switch (instruction->opcode) {
        case VM_NOP: break;
        case VM_MOV_RR: case VM_MOV_RC: case VM_MOV_RM:
            value = source_value(context, instruction, &error);
            if (!error && !destination_write(context, instruction, value, &error)) return error;
            break;
        case VM_MOV_MR: case VM_MOV_MC:
            value = source_value(context, instruction, &error);
            if (!error && !destination_write(context, instruction, value, &error)) return error;
            break;
        case VM_MOVZX_RR: case VM_MOVZX_RM:
        case VM_MOVSX_RR: case VM_MOVSX_RM:
        case VM_MOVSXD_RR: case VM_MOVSXD_RM:
            value = (instruction->flags & VM_OPERAND_SOURCE_MEMORY)
                ? source_value(context, instruction, &error)
                : register_read(context, instruction->src, (uint8_t)instruction->aux,
                    instruction->srcBitOffset);
            if (instruction->flags & VM_OPERAND_SRC_SIGNED) value = sign_extend_width(value, (uint8_t)instruction->aux);
            else value = truncate_width(value, (uint8_t)instruction->aux);
            if (!error && !destination_write(context, instruction, value, &error)) return error;
            break;
        case VM_LEA:
            address = memory_address(context, instruction, &error);
            if (!error && !destination_write(context, instruction, address, &error)) return error;
            break;
        case VM_XCHG: case VM_XCHG_RM:
            if (instruction->flags & VM_OPERAND_SOURCE_MEMORY) {
                lhs = register_read(context, instruction->dst, width, instruction->dstBitOffset);
                address = memory_address(context, instruction, &error);
                if (error || (context->architecture == VM_ARCH_X86 && width == 8)) {
                    return error ? error : VM_ERR_OPCODE_UNSUPPORTED;
                }
                rhs = vm_atomic_exchange(address, lhs, width);
                if (!register_write(context, instruction->dst, width,
                        instruction->dstBitOffset, instruction->flags, rhs)) {
                    return VM_ERR_REGISTER_MAP_INVALID;
                }
            } else {
                lhs = destination_value(context, instruction, &error);
                rhs = source_value(context, instruction, &error);
                if (error) return error;
                if (!destination_write(context, instruction, rhs, &error)) return error;
                if (!register_write(context, instruction->src, width,
                        instruction->srcBitOffset, instruction->flags, lhs)) {
                    return VM_ERR_REGISTER_MAP_INVALID;
                }
            }
            break;

        case VM_ADD_RR: case VM_ADD_RC: case VM_ADD_RM: case VM_ADD_MR:
        case VM_ADC_RR: case VM_ADC_RC: case VM_ADC_RM: case VM_ADC_MR:
            lhs = destination_value(context, instruction, &error);
            rhs = source_value(context, instruction, &error);
            result = add_flags(context, lhs, rhs,
                (uint8_t)(instruction->opcode == VM_ADC_RR || instruction->opcode == VM_ADC_RC ||
                          instruction->opcode == VM_ADC_RM || instruction->opcode == VM_ADC_MR)
                    ? flag_get(context->flags, VM_FLAG_CF) : 0,
                width);
            if (!error && !destination_write(context, instruction, result, &error)) return error;
            break;
        case VM_SUB_RR: case VM_SUB_RC: case VM_SUB_RM: case VM_SUB_MR:
        case VM_SBB_RR: case VM_SBB_RC: case VM_SBB_RM: case VM_SBB_MR:
        case VM_CMP_RR: case VM_CMP_RC: case VM_CMP_RM: case VM_CMP_MR:
            lhs = destination_value(context, instruction, &error);
            rhs = source_value(context, instruction, &error);
            result = sub_flags(context, lhs, rhs,
                (uint8_t)(instruction->opcode == VM_SBB_RR || instruction->opcode == VM_SBB_RC ||
                          instruction->opcode == VM_SBB_RM || instruction->opcode == VM_SBB_MR)
                    ? flag_get(context->flags, VM_FLAG_CF) : 0,
                width);
            if (instruction->opcode != VM_CMP_RR && instruction->opcode != VM_CMP_RC &&
                instruction->opcode != VM_CMP_RM && instruction->opcode != VM_CMP_MR &&
                !destination_write(context, instruction, result, &error)) return error;
            break;
        case VM_AND_RR: case VM_AND_RC: case VM_AND_RM: case VM_AND_MR:
        case VM_OR_RR: case VM_OR_RC: case VM_OR_RM: case VM_OR_MR:
        case VM_XOR_RR: case VM_XOR_RC: case VM_XOR_RM: case VM_XOR_MR:
        case VM_TEST_RR: case VM_TEST_RC: case VM_TEST_RM: case VM_TEST_MR:
            lhs = destination_value(context, instruction, &error);
            rhs = source_value(context, instruction, &error);
            if (instruction->opcode == VM_AND_RR || instruction->opcode == VM_AND_RC ||
                instruction->opcode == VM_AND_RM || instruction->opcode == VM_AND_MR ||
                instruction->opcode == VM_TEST_RR || instruction->opcode == VM_TEST_RC ||
                instruction->opcode == VM_TEST_RM || instruction->opcode == VM_TEST_MR) result = lhs & rhs;
            else if (instruction->opcode == VM_OR_RR || instruction->opcode == VM_OR_RC ||
                     instruction->opcode == VM_OR_RM || instruction->opcode == VM_OR_MR) result = lhs | rhs;
            else result = lhs ^ rhs;
            result = logic_flags(context, result, width);
            if (instruction->opcode != VM_TEST_RR && instruction->opcode != VM_TEST_RC &&
                instruction->opcode != VM_TEST_RM && instruction->opcode != VM_TEST_MR &&
                !destination_write(context, instruction, result, &error)) return error;
            break;
        case VM_NOT_R:
            result = ~destination_value(context, instruction, &error);
            if (!error && !destination_write(context, instruction, result, &error)) return error;
            break;

        case VM_BSWAP: {
            uint64_t swapped = 0;
            uint8_t index;
            lhs = destination_value(context, instruction, &error);
            if (error || (width != 4 && width != 8)) return error ? error : VM_ERR_SCHEMA_MISMATCH;
            for (index = 0; index < width; ++index) {
                swapped |= ((lhs >> (index * 8u)) & 0xFFu) << ((width - 1u - index) * 8u);
            }
            if (!destination_write(context, instruction, swapped, &error)) return error;
            break;
        }
        case VM_BT_RR: case VM_BTS_RR: case VM_BTR_RR: {
            const uint8_t bits = (uint8_t)(width * 8u);
            uint64_t rawIndex = source_value(context, instruction, &error);
            uint32_t bitIndex;
            if (error || (width != 2 && width != 4 && width != 8)) {
                return error ? error : VM_ERR_SCHEMA_MISMATCH;
            }
            if (instruction->flags & VM_OPERAND_DEST_MEMORY) {
                uint64_t magnitude;
                uint64_t wordCount;
                uint8_t negative = 0;
                address = memory_address(context, instruction, &error);
                if (error) return error;
                if (!(instruction->flags & VM_OPERAND_SOURCE_IMMEDIATE) &&
                    (rawIndex & sign_mask(width))) {
                    negative = 1;
                    magnitude = (~rawIndex + 1u) & width_mask(width);
                    wordCount = (magnitude + bits - 1u) >>
                        (width == 8 ? 6 : (width == 4 ? 5 : 4));
                    address -= (uintptr_t)(wordCount * width);
                    bitIndex = (uint32_t)((bits - (magnitude & (bits - 1u))) & (bits - 1u));
                } else {
                    bitIndex = (uint32_t)(rawIndex & (bits - 1u));
                    wordCount = rawIndex >> (width == 8 ? 6 : (width == 4 ? 5 : 4));
                    address += (uintptr_t)(wordCount * width);
                }
                if ((instruction->flags & VM_OPERAND_ATOMIC) != 0) {
                    const uint32_t operation = instruction->opcode == VM_BTS_RR ? 1u : 2u;
                    const uint32_t oldBit = vm_atomic_bit_operation(address, bitIndex, operation, width);
                    if (oldBit > 1u) return VM_ERR_HANDLER_BUG;
                    flag_set(&context->flags, VM_FLAG_CF, (uint8_t)oldBit);
                } else {
                    lhs = memory_read(address, width, &error);
                    if (error) return error;
                    flag_set(&context->flags, VM_FLAG_CF, (uint8_t)((lhs >> bitIndex) & 1u));
                    if (instruction->opcode == VM_BTS_RR) lhs |= 1ULL << bitIndex;
                    else if (instruction->opcode == VM_BTR_RR) lhs &= ~(1ULL << bitIndex);
                    if (instruction->opcode != VM_BT_RR &&
                        !memory_write(address, width, lhs, &error)) return error;
                }
                (void)negative;
            } else {
                bitIndex = (uint32_t)(rawIndex & (bits - 1u));
                lhs = destination_value(context, instruction, &error);
                if (error) return error;
                flag_set(&context->flags, VM_FLAG_CF, (uint8_t)((lhs >> bitIndex) & 1u));
                if (instruction->opcode == VM_BTS_RR) lhs |= 1ULL << bitIndex;
                else if (instruction->opcode == VM_BTR_RR) lhs &= ~(1ULL << bitIndex);
                if (instruction->opcode != VM_BT_RR &&
                    !destination_write(context, instruction, lhs, &error)) return error;
            }
            break;
        }
        case VM_SIGN_EXTEND_ACC: {
            const uint8_t rax = context->registerMap[0];
            const uint8_t rdx = context->registerMap[2];
            lhs = register_read(context, rax, width, 0);
            result = (lhs & sign_mask(width)) ? width_mask(width) : 0;
            if (!register_write(context, rdx, width, 0,
                    width == 4 ? VM_OPERAND_DST_ZERO_EXTEND : 0, result)) {
                return VM_ERR_REGISTER_MAP_INVALID;
            }
            break;
        }
        case VM_EXTEND_ACC: {
            const uint8_t rax = context->registerMap[0];
            const uint8_t sourceWidth = (uint8_t)(width / 2u);
            value = sign_extend_width(register_read(context, rax, sourceWidth, 0), sourceWidth);
            if (!register_write(context, rax, width, 0,
                    width == 4 ? VM_OPERAND_DST_ZERO_EXTEND : 0, value)) {
                return VM_ERR_REGISTER_MAP_INVALID;
            }
            break;
        }
        case VM_CLC: flag_set(&context->flags, VM_FLAG_CF, 0); break;
        case VM_STC: flag_set(&context->flags, VM_FLAG_CF, 1); break;
        case VM_CMC:
            flag_set(&context->flags, VM_FLAG_CF,
                (uint8_t)!flag_get(context->flags, VM_FLAG_CF));
            break;
        case VM_LAHF: {
            const uint8_t rax = context->registerMap[0];
            value = (context->flags & (VM_FLAG_SF | VM_FLAG_ZF | VM_FLAG_AF |
                VM_FLAG_PF | VM_FLAG_CF)) | 0x02u;
            if (!register_write(context, rax, 1, 8, 0, value)) return VM_ERR_REGISTER_MAP_INVALID;
            break;
        }
        case VM_SAHF: {
            const uint8_t rax = context->registerMap[0];
            const uint64_t mask = VM_FLAG_SF | VM_FLAG_ZF | VM_FLAG_AF | VM_FLAG_PF | VM_FLAG_CF;
            value = register_read(context, rax, 1, 8);
            context->flags = (context->flags & ~mask) | (value & mask);
            break;
        }
        case VM_NEG_R: case VM_NEG_M:
            lhs = destination_value(context, instruction, &error);
            result = sub_flags(context, 0, lhs, 0, width);
            if (!error && !destination_write(context, instruction, result, &error)) return error;
            break;
        case VM_INC_R: case VM_INC_M:
            oldCf = flag_get(context->flags, VM_FLAG_CF);
            lhs = destination_value(context, instruction, &error);
            result = add_flags(context, lhs, 1, 0, width);
            flag_set(&context->flags, VM_FLAG_CF, oldCf);
            if (!error && !destination_write(context, instruction, result, &error)) return error;
            break;
        case VM_DEC_R: case VM_DEC_M:
            oldCf = flag_get(context->flags, VM_FLAG_CF);
            lhs = destination_value(context, instruction, &error);
            result = sub_flags(context, lhs, 1, 0, width);
            flag_set(&context->flags, VM_FLAG_CF, oldCf);
            if (!error && !destination_write(context, instruction, result, &error)) return error;
            break;

        case VM_SHL_RR: case VM_SHL_RC: case VM_SHL_MR: case VM_SHL_MC:
        case VM_SHR_RR: case VM_SHR_RC: case VM_SHR_MR: case VM_SHR_MC:
        case VM_SAR_RR: case VM_SAR_RC: case VM_SAR_MR: case VM_SAR_MC:
        case VM_ROL_RR: case VM_ROL_RC: case VM_ROL_MR: case VM_ROL_MC:
        case VM_ROR_RR: case VM_ROR_RC: case VM_ROR_MR: case VM_ROR_MC: {
            uint8_t count = (uint8_t)source_value(context, instruction, &error);
            uint8_t bits = (uint8_t)(width * 8);
            uint8_t writeResult = 1;
            count &= width == 8 ? 0x3Fu : 0x1Fu;
            lhs = truncate_width(destination_value(context, instruction, &error), width);
            if (error || bits == 0) return error ? error : VM_ERR_SCHEMA_MISMATCH;
            result = lhs;
            if (count) {
                if (instruction->opcode == VM_SHL_RR || instruction->opcode == VM_SHL_RC ||
                    instruction->opcode == VM_SHL_MR || instruction->opcode == VM_SHL_MC) {
                    flag_set(&context->flags, VM_FLAG_CF,
                        count <= bits ? (uint8_t)((lhs >> (bits - count)) & 1u) : 0);
                    result = count < bits ? truncate_width(lhs << count, width) : 0;
                    if (count == 1) flag_set(&context->flags, VM_FLAG_OF,
                        (uint8_t)(((result & sign_mask(width)) != 0) ^ flag_get(context->flags, VM_FLAG_CF)));
                    set_common_flags(context, result, width);
                } else if (instruction->opcode == VM_SHR_RR || instruction->opcode == VM_SHR_RC ||
                           instruction->opcode == VM_SHR_MR || instruction->opcode == VM_SHR_MC) {
                    flag_set(&context->flags, VM_FLAG_CF,
                        count <= bits ? (uint8_t)((lhs >> (count - 1)) & 1u) : 0);
                    result = count < bits ? lhs >> count : 0;
                    if (count == 1) flag_set(&context->flags, VM_FLAG_OF, (uint8_t)((lhs & sign_mask(width)) != 0));
                    set_common_flags(context, result, width);
                } else if (instruction->opcode == VM_SAR_RR || instruction->opcode == VM_SAR_RC ||
                           instruction->opcode == VM_SAR_MR || instruction->opcode == VM_SAR_MC) {
                    const uint8_t negative = (uint8_t)((lhs & sign_mask(width)) != 0);
                    flag_set(&context->flags, VM_FLAG_CF,
                        count < bits ? (uint8_t)((lhs >> (count - 1)) & 1u) : negative);
                    if (count >= bits) result = negative ? width_mask(width) : 0;
                    else {
                        result = lhs >> count;
                        if (negative) result |= width_mask(width) ^ (width_mask(width) >> count);
                    }
                    if (count == 1) flag_set(&context->flags, VM_FLAG_OF, 0);
                    set_common_flags(context, result, width);
                } else if (instruction->opcode == VM_ROL_RR || instruction->opcode == VM_ROL_RC ||
                           instruction->opcode == VM_ROL_MR || instruction->opcode == VM_ROL_MC) {
                    count %= bits;
                    if (count) {
                        result = truncate_width((lhs << count) | (lhs >> (bits - count)), width);
                        flag_set(&context->flags, VM_FLAG_CF, (uint8_t)(result & 1u));
                        if (count == 1) flag_set(&context->flags, VM_FLAG_OF,
                            (uint8_t)(((result & sign_mask(width)) != 0) ^ flag_get(context->flags, VM_FLAG_CF)));
                    } else writeResult = 0;
                } else {
                    count %= bits;
                    if (count) {
                        result = truncate_width((lhs >> count) | (lhs << (bits - count)), width);
                        flag_set(&context->flags, VM_FLAG_CF, (uint8_t)((result & sign_mask(width)) != 0));
                        if (count == 1) flag_set(&context->flags, VM_FLAG_OF,
                            (uint8_t)(((result & sign_mask(width)) != 0) ^ ((result & (sign_mask(width) >> 1)) != 0)));
                    } else writeResult = 0;
                }
                if (writeResult && !destination_write(context, instruction, result, &error)) return error;
            }
            break;
        }

        case VM_MUL_RR: case VM_IMUL_RR: case VM_IMUL_RRC:
        case VM_DIV_RR: case VM_IDIV_RR: {
            uint8_t rax = context->registerMap[0];
            uint8_t rdx = context->registerMap[2];
            rhs = instruction->opcode == VM_IMUL_RRC
                ? 0 : source_value(context, instruction, &error);
            if (error) return error;
            if (instruction->opcode == VM_MUL_RR || instruction->opcode == VM_IMUL_RR ||
                instruction->opcode == VM_IMUL_RRC) {
                uint64_t high = 0;
                uint64_t low = 0;
                uint8_t overflow = 0;
                if (instruction->opcode == VM_IMUL_RRC) {
                    lhs = source_value(context, instruction, &error);
                    rhs = truncate_width(instruction->immediate, width);
                } else {
                    lhs = (instruction->flags & VM_OPERAND_IMPLICIT_ACCUMULATOR)
                        ? register_read(context, rax, width, 0)
                        : register_read(context, instruction->dst, width, instruction->dstBitOffset);
                }
                if (error) return error;
                if (instruction->opcode == VM_MUL_RR) {
                    if (width < 8) {
                        uint64_t product = truncate_width(lhs, width) * truncate_width(rhs, width);
                        low = product & width_mask(width);
                        high = (product >> (width * 8)) & width_mask(width);
                    } else multiply_u64(lhs, rhs, &high, &low);
                    overflow = (uint8_t)(high != 0);
                } else {
                    multiply_signed_width(lhs, rhs, width, &high, &low, &overflow);
                }
                if (instruction->flags & VM_OPERAND_IMPLICIT_ACCUMULATOR) {
                    if (width == 1) {
                        register_write(context, rax, 2, 0, 0,
                            (low & 0xFFu) | ((high & 0xFFu) << 8));
                    } else {
                        register_write(context, rax, width, 0,
                            width == 4 ? VM_OPERAND_DST_ZERO_EXTEND : 0, low);
                        register_write(context, rdx, width, 0,
                            width == 4 ? VM_OPERAND_DST_ZERO_EXTEND : 0, high);
                    }
                } else register_write(context, instruction->dst, width, instruction->dstBitOffset,
                    instruction->flags, low);
                flag_set(&context->flags, VM_FLAG_CF, overflow);
                flag_set(&context->flags, VM_FLAG_OF, overflow);
            } else {
                uint64_t high;
                uint64_t low;
                uint64_t quotient = 0;
                uint64_t remainder = 0;
                if (width == 1) {
                    const uint64_t accumulator = register_read(context, rax, 2, 0);
                    low = accumulator & 0xFFu;
                    high = (accumulator >> 8) & 0xFFu;
                } else {
                    high = register_read(context, rdx, width, 0);
                    low = register_read(context, rax, width, 0);
                }
                if (!divide_operands(high, low, truncate_width(rhs, width), width,
                        (uint8_t)(instruction->opcode == VM_IDIV_RR),
                        &quotient, &remainder)) {
                    if (truncate_width(rhs, width) == 0) vm_raise_divide_by_zero();
                    else vm_raise_divide_overflow();
                    return VM_ERR_DIVIDE;
                }
                if (width == 1) {
                    if (!register_write(context, rax, 1, 0, 0, quotient) ||
                        !register_write(context, rax, 1, 8, 0, remainder)) {
                        return VM_ERR_REGISTER_MAP_INVALID;
                    }
                } else {
                    register_write(context, rax, width, 0,
                        width == 4 ? VM_OPERAND_DST_ZERO_EXTEND : 0, quotient);
                    register_write(context, rdx, width, 0,
                        width == 4 ? VM_OPERAND_DST_ZERO_EXTEND : 0, remainder);
                }
            }
            break;
        }

        case VM_PUSH_R: case VM_PUSH_C: case VM_PUSH_MEM: {
            uint8_t stackWidth = instruction->operandWidth == 2
                ? 2 : (context->architecture == VM_ARCH_X64 ? 8 : 4);
            uint8_t rsp = context->registerMap[4];
            value = source_value(context, instruction, &error);
            if (error) return error;
            if (context->regs[rsp] < stackWidth ||
                context->regs[rsp] - stackWidth < context->guestStackLow) {
                return VM_ERR_STACK_ALIGNMENT;
            }
            context->regs[rsp] -= stackWidth;
            if (!memory_write((uintptr_t)context->regs[rsp], stackWidth, value, &error)) return error;
            break;
        }
        case VM_PUSHF: {
            uint8_t rsp = context->registerMap[4];
            if (context->regs[rsp] < width ||
                context->regs[rsp] - width < context->guestStackLow) {
                return VM_ERR_STACK_ALIGNMENT;
            }
            context->regs[rsp] -= width;
            if (!memory_write((uintptr_t)context->regs[rsp], width,
                    (context->flags & ~(0x00010000u | 0x00020000u)) | 0x02u,
                    &error)) return error;
            break;
        }
        case VM_POPF: {
            const uint64_t writable = (VM_FLAG_CF | VM_FLAG_PF | VM_FLAG_AF | VM_FLAG_ZF |
                VM_FLAG_SF | VM_FLAG_TF | VM_FLAG_DF | VM_FLAG_OF |
                0x00040000u | 0x00200000u) & width_mask(width);
            uint8_t rsp = context->registerMap[4];
            value = memory_read((uintptr_t)context->regs[rsp], width, &error);
            if (error) return error;
            context->regs[rsp] += width;
            context->flags = (context->flags & ~writable) | (value & writable) | 0x02u;
            break;
        }
        case VM_LEAVE: {
            const uint8_t rsp = context->registerMap[4];
            const uint8_t rbp = context->registerMap[5];
            context->regs[rsp] = register_read(context, rbp, width, 0);
            if (context->regs[rsp] < context->guestStackLow) return VM_ERR_STACK_ALIGNMENT;
            value = memory_read((uintptr_t)context->regs[rsp], width, &error);
            if (error || !register_write(context, rbp, width, 0,
                    width == 4 ? VM_OPERAND_DST_ZERO_EXTEND : 0, value)) {
                return error ? error : VM_ERR_REGISTER_MAP_INVALID;
            }
            context->regs[rsp] += width;
            break;
        }
        case VM_POP_R: case VM_POP_MEM: {
            uint8_t stackWidth = instruction->operandWidth == 2
                ? 2 : (context->architecture == VM_ARCH_X64 ? 8 : 4);
            uint8_t rsp = context->registerMap[4];
            const uint64_t oldRsp = context->regs[rsp];
            value = memory_read((uintptr_t)oldRsp, stackWidth, &error);
            if (error || oldRsp > UINT64_MAX - stackWidth) {
                return error ? error : VM_ERR_STACK_ALIGNMENT;
            }
            context->regs[rsp] = oldRsp + stackWidth;
            if (instruction->opcode == VM_POP_R) {
                if (!register_write(context, instruction->dst, instruction->operandWidth,
                    instruction->dstBitOffset, instruction->flags, value)) return VM_ERR_REGISTER_MAP_INVALID;
            } else if (!destination_write(context, instruction, value, &error)) return error;
            break;
        }

        case VM_JMP: case VM_JZ: case VM_JNZ: case VM_JA: case VM_JAE:
        case VM_JB: case VM_JBE: case VM_JG: case VM_JGE: case VM_JL:
        case VM_JLE: case VM_JO: case VM_JNO: case VM_JS: case VM_JNS:
        case VM_JP: case VM_JNP:
            if (condition_true(context, instruction->condition)) nextIp = instruction->branchTargetOffset;
            break;
        case VM_CMOV_RR: case VM_CMOV_RM:
            if (condition_true(context, instruction->condition)) {
                value = source_value(context, instruction, &error);
                if (!destination_write(context, instruction, value, &error)) return error;
            }
            break;
        case VM_SET_R: case VM_SET_M:
            if (!destination_write(context, instruction,
                (uint64_t)condition_true(context, instruction->condition), &error)) return error;
            break;
        case VM_CALL_VM:
            if (context->callDepth >= VM_RUNTIME_CALL_DEPTH) return VM_ERR_CALL_STACK;
            {
                const uint8_t stackWidth = context->architecture == VM_ARCH_X64 ? 8 : 4;
                const uint8_t rsp = context->registerMap[4];
                const uintptr_t expectedReturn = context->imageBase +
                    (uintptr_t)instruction->immediate;
                if (instruction->immediate >= context->imageSize ||
                    context->regs[rsp] < stackWidth ||
                    context->regs[rsp] - stackWidth < context->guestStackLow) {
                    return VM_ERR_CALL_STACK;
                }
                context->regs[rsp] -= stackWidth;
                if (!memory_write((uintptr_t)context->regs[rsp], stackWidth,
                        expectedReturn, &error)) return error;
                context->callStack[context->callDepth] = nextIp;
                context->nativeReturnStack[context->callDepth] = expectedReturn;
                ++context->callDepth;
            }
            nextIp = instruction->branchTargetOffset;
            break;
        case VM_CALL_NATIVE:
            error = execute_native_call(context, instruction,
                context->imageBase + (uintptr_t)instruction->immediate);
            if (error) return error;
            break;
        case VM_CALL_INDIRECT_R:
            error = execute_native_call(context, instruction,
                (uintptr_t)register_read(context, instruction->src,
                    context->architecture == VM_ARCH_X64 ? 8 : 4, instruction->srcBitOffset));
            if (error) return error;
            break;
        case VM_CALL_INDIRECT_M:
            address = memory_address(context, instruction, &error);
            value = memory_read(address, context->architecture == VM_ARCH_X64 ? 8 : 4, &error);
            if (error) return error;
            error = execute_native_call(context, instruction, (uintptr_t)value);
            if (error) return error;
            break;
        case VM_CALL_IMPORT:
            address = context->imageBase + (uintptr_t)instruction->immediate;
            value = memory_read(address, context->architecture == VM_ARCH_X64 ? 8 : 4, &error);
            if (error) return error;
            error = execute_native_call(context, instruction, (uintptr_t)value);
            if (error) return error;
            break;
        case VM_RET_VM:
            if (context->callDepth) {
                const uint8_t stackWidth = context->architecture == VM_ARCH_X64 ? 8 : 4;
                const uint8_t rsp = context->registerMap[4];
                const uint32_t frame = context->callDepth - 1u;
                const uintptr_t actualReturn = (uintptr_t)memory_read(
                    (uintptr_t)context->regs[rsp], stackWidth, &error);
                const uintptr_t cleanup = (uintptr_t)stackWidth +
                    (uintptr_t)instruction->aux;
                if (error || actualReturn != context->nativeReturnStack[frame] ||
                    (uintptr_t)context->regs[rsp] > ~(uintptr_t)0 - cleanup) {
                    return error ? error : VM_ERR_CALL_STACK;
                }
                context->regs[rsp] += cleanup;
                nextIp = context->callStack[frame];
                context->callDepth = frame;
            }
            else {
                context->returnStackCleanup = instruction->aux;
                *finished = 1;
            }
            break;
        case VM_VMEXIT:
            *finished = 1;
            break;
        case VM_BRIDGE_SIMD: case VM_BRIDGE_X87:
            error = execute_instruction_bridge(context, instruction);
            if (error) return error;
            break;
        default:
            return VM_ERR_OPCODE_UNSUPPORTED;
    }
    if (error) return error;
    if (!*finished) {
        if (nextIp >= context->record->bytecodeSize || nextIp % VM_INSTRUCTION_SIZE != 0) {
            return VM_ERR_BYTECODE_RANGE;
        }
        context->ip = nextIp;
    }
    return VM_ERR_NONE;
}


typedef uint32_t (*VM_HANDLER_ENTRY)(
    VM_EXECUTION_CONTEXT*, const VM_BYTECODE_INSTRUCTION*, int*);

static VM_NOINLINE uint32_t execute_handler_variant_0(
    VM_EXECUTION_CONTEXT* context,
    const VM_BYTECODE_INSTRUCTION* instruction,
    int* finished)
{
    return execute_instruction(context, instruction, finished);
}

static VM_NOINLINE uint32_t execute_handler_variant_1(
    VM_EXECUTION_CONTEXT* context,
    const VM_BYTECODE_INSTRUCTION* instruction,
    int* finished)
{
    volatile uint64_t barrier = context->mutationScratch ^
        ((uint64_t)context->currentHandlerSlot << 40) ^
        ((uint64_t)instruction->opcode << 8) ^ context->metadata->layoutSeed;
    barrier += 0x9E3779B97F4A7C15ULL;
    barrier -= 0x9E3779B97F4A7C15ULL;
    context->mutationScratch = barrier;
    return execute_instruction(context, instruction, finished);
}

static VM_NOINLINE uint32_t execute_handler_variant_2(
    VM_EXECUTION_CONTEXT* context,
    const VM_BYTECODE_INSTRUCTION* instruction,
    int* finished)
{
    VM_BYTECODE_INSTRUCTION local = *instruction;
    const uint64_t mask = ((uint64_t)context->metadata->layoutSeed << 32) |
        (uint64_t)context->currentHandlerSlot;
    local.immediate ^= mask;
    local.immediate ^= mask;
    return execute_instruction(context, &local, finished);
}

static VM_NOINLINE uint32_t execute_handler_variant_3(
    VM_EXECUTION_CONTEXT* context,
    const VM_BYTECODE_INSTRUCTION* instruction,
    int* finished)
{
    volatile uintptr_t barrier = (uintptr_t)context ^ (uintptr_t)instruction ^
        (uintptr_t)context->metadata->buildId[context->currentHandlerSlot & 15u];
    if (barrier == ~(uintptr_t)0) return VM_ERR_HANDLER_BUG;
    context->mutationScratch ^= (uint64_t)barrier;
    context->mutationScratch ^= (uint64_t)barrier;
    return execute_instruction(context, instruction, finished);
}

static VM_NOINLINE uint32_t junk_handler_0(
    VM_EXECUTION_CONTEXT* context, const VM_BYTECODE_INSTRUCTION* instruction, int* finished)
{
    volatile uint64_t value = context->mutationScratch ^ instruction->immediate;
    (void)finished;
    return value ? VM_ERR_OPCODE_UNSUPPORTED : VM_ERR_HANDLER_BUG;
}

static VM_NOINLINE uint32_t junk_handler_1(
    VM_EXECUTION_CONTEXT* context, const VM_BYTECODE_INSTRUCTION* instruction, int* finished)
{
    volatile uint64_t value = context->metadata->layoutSeed + instruction->aux;
    (void)finished;
    return value ? VM_ERR_SCHEMA_MISMATCH : VM_ERR_HANDLER_BUG;
}

static VM_NOINLINE uint32_t junk_handler_2(
    VM_EXECUTION_CONTEXT* context, const VM_BYTECODE_INSTRUCTION* instruction, int* finished)
{
    volatile uintptr_t value = context->imageBase ^ (uintptr_t)instruction;
    (void)finished;
    return value ? VM_ERR_BYTECODE_RANGE : VM_ERR_HANDLER_BUG;
}

static VM_NOINLINE uint32_t junk_handler_3(
    VM_EXECUTION_CONTEXT* context, const VM_BYTECODE_INSTRUCTION* instruction, int* finished)
{
    volatile uint64_t value = context->flags + instruction->branchTargetOffset;
    (void)finished;
    return value ? VM_ERR_HANDLER_BUG : VM_ERR_OPCODE_UNSUPPORTED;
}

static const VM_HANDLER_ENTRY vm_handler_variants[VM_HANDLER_VARIANT_COUNT] = {
    execute_handler_variant_0,
    execute_handler_variant_1,
    execute_handler_variant_2,
    execute_handler_variant_3
};

static const VM_HANDLER_ENTRY vm_junk_handler_variants[VM_HANDLER_VARIANT_COUNT] = {
    junk_handler_0,
    junk_handler_1,
    junk_handler_2,
    junk_handler_3
};

VM_NOINLINE uint32_t vm_runtime_interpret(
    void* nativeFrame,
    uint32_t functionRva,
    VM_METADATA_HEADER* metadata,
    uintptr_t imageBase,
    VM_EXTENDED_STATE* extendedState)
{
    VM_EXECUTION_CONTEXT context;
    VM_BYTECODE_INSTRUCTION instruction;
    uint8_t masterKey[32];
    uint32_t error;
    int finished = 0;
    uint32_t i;
#if defined(_M_X64) || defined(__x86_64__)
    const uint32_t architecture = VM_ARCH_X64;
#else
    const uint32_t architecture = VM_ARCH_X86;
#endif
    memset(&context, 0, sizeof(context));
    memset(masterKey, 0, sizeof(masterKey));
    if (!nativeFrame || !metadata || !extendedState || !imageBase ||
        ((uintptr_t)extendedState & 0x3Fu) != 0) return VM_ERR_METADATA_INVALID;
    context.imageSize = image_size_from_headers(imageBase);
    if (context.imageSize < sizeof(VM_METADATA_HEADER) || (uintptr_t)metadata < imageBase ||
        (uintptr_t)metadata - imageBase > context.imageSize - sizeof(VM_METADATA_HEADER)) {
        return VM_ERR_METADATA_INVALID;
    }
    error = validate_metadata(metadata, architecture, masterKey);
    if (error) return error;
    if (metadata->totalSize > context.imageSize - (uint32_t)((uintptr_t)metadata - imageBase) ||
        metadata->imageSize > context.imageSize) return VM_ERR_METADATA_INVALID;
    if (!image_rva_range_has_permissions(imageBase, context.imageSize,
            (uint32_t)((uintptr_t)metadata - imageBase), metadata->totalSize,
            0x40000000u, 0x20000000u | 0x80000000u) ||
        !image_rva_range_has_permissions(imageBase, context.imageSize,
            metadata->runtimeBaseRVA, metadata->runtimeSize,
            0x20000000u | 0x40000000u, 0x80000000u)) {
        return VM_ERR_METADATA_INVALID;
    }
    if ((uintptr_t)&vm_runtime_interpret < imageBase ||
        (uintptr_t)&vm_runtime_interpret - imageBase != metadata->runtimeEntryRVA) {
        return VM_ERR_SCHEMA_MISMATCH;
    }
    context.imageBase = imageBase;
    context.metadata = metadata;
    context.record = find_record(metadata, functionRva);
    context.architecture = architecture;
    context.extendedState = extendedState;
    if (!context.record) return VM_ERR_RECORD_NOT_FOUND;
    if ((context.record->flags & VM_RECORD_FLAG_USES_AVX) != 0) {
        context.extendedState->flags |= VM_EXTENDED_STATE_FLAG_AVX;
    }
    {
        const uint32_t guardPointerRVA = architecture == VM_ARCH_X64
            ? metadata->guardCFDispatchPointerRVA : metadata->guardCFCheckPointerRVA;
        if ((metadata->flags & VM_METADATA_FLAG_CFG_ENABLED) && guardPointerRVA == 0) {
            return VM_ERR_NATIVE_BRIDGE;
        }
        if (guardPointerRVA) {
            uint32_t guardError = VM_ERR_NONE;
            if (guardPointerRVA > context.imageSize ||
                (architecture == VM_ARCH_X64 ? 8u : 4u) > context.imageSize - guardPointerRVA) {
                return VM_ERR_METADATA_INVALID;
            }
            context.guardTarget = (uintptr_t)memory_read(imageBase + guardPointerRVA,
                architecture == VM_ARCH_X64 ? 8 : 4, &guardError);
            if (guardError || !context.guardTarget) return VM_ERR_NATIVE_BRIDGE;
        }
    }
    error = validate_record(&context, masterKey);
    for (i = 0; i < sizeof(masterKey); ++i) masterKey[i] = 0;
    if (error) return error;
    if (metadata->flags & VM_METADATA_FLAG_JUNK_HANDLERS) {
        volatile uintptr_t catalogFingerprint = 0;
        uint32_t observedJunk = 0;
        for (i = 0; i < VM_HANDLER_TABLE_SIZE; ++i) {
            if (context.handlerSlotToSemantic[i] != VM_HANDLER_JUNK) continue;
            if (context.handlerVariants[i] >= VM_HANDLER_VARIANT_COUNT)
                return VM_ERR_HANDLER_BUG;
            catalogFingerprint |=
                (uintptr_t)vm_junk_handler_variants[context.handlerVariants[i]];
            ++observedJunk;
        }
        if (observedJunk != metadata->junkHandlerCount || catalogFingerprint == 0)
            return VM_ERR_HANDLER_BUG;
    }
    error = initialize_registers(&context, nativeFrame);
    if (error) return error;
    if (context.originalStackPointer < context.record->guestStackSize) {
        return VM_ERR_STACK_ALIGNMENT;
    }
    context.guestStackLow = context.originalStackPointer - context.record->guestStackSize;

    while (!finished) {
        error = decode_instruction(&context, &instruction);
        if (error) return error;
        if (context.currentHandlerVariant >= VM_HANDLER_VARIANT_COUNT)
            return VM_ERR_HANDLER_BUG;
        error = vm_handler_variants[context.currentHandlerVariant](
            &context, &instruction, &finished);
        if (error) return error;
        if (context.regs[context.registerMap[4]] < context.guestStackLow) {
            return VM_ERR_STACK_ALIGNMENT;
        }
    }

    if (context.callDepth != 0 ||
        context.returnStackCleanup != context.record->returnStackCleanup ||
        context.regs[context.registerMap[4]] != context.originalStackPointer) {
        return VM_ERR_STACK_ALIGNMENT;
    }
    writeback_registers(&context, nativeFrame);
    for (i = 0; i < sizeof(context.recordKey); ++i) context.recordKey[i] = 0;
    return VM_ERR_NONE;
}
