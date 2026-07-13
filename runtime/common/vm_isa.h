#ifndef CS_RUNTIME_VM_ISA_H
#define CS_RUNTIME_VM_ISA_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * v4 is a compact micro-operation stream.  No serialized C structure and no
 * fixed instruction stride are part of this contract.  The only byte which is
 * common to every instruction is the per-build mapped opcode at byte zero;
 * each handler consumes the operands described by its semantic descriptor.
 */
#define VM_SCHEMA_VERSION 0x00040000u
#define VM_OPERAND_CODEC_VERSION 0x00010000u
#define VM_OPERAND_CODEC_DOMAIN 0x43534D4943524F31ULL /* "CSMICRO1" */
#define VM_REGISTER_INVALID 0xFFu
#define VM_MICRO_MAX_OPERANDS 4u
#define VM_MICRO_MAX_HANDLER_VARIANTS 16u
#define VM_MICRO_TEMP_COUNT 32u
#define VM_MICRO_STACK_LIMIT 256u
#define VM_MICRO_HEAVY_MIN_RATIO 8u
#define VM_CALL_AUX_ABI_MASK 0x000000FFu
#define VM_CALL_AUX_STACK_BYTES_SHIFT 8u
#define VM_CALL_AUX_STACK_BYTES_MASK 0x00FFFF00u
#define VM_NATIVE_MAX_STACK_ARGUMENT_BYTES 512u
#define VM_MAX_INTERNAL_CALL_DEPTH 256u

/* Stable semantic ids.  Serialized opcode bytes are always mapped per build. */
typedef enum VM_MICRO_OPCODE {
    VM_UOP_TRAP = 0,
    VM_UOP_PUSH_VREG,
    VM_UOP_PUSH_IMM,
    VM_UOP_PUSH_FLAGS,
    VM_UOP_PUSH_IP,
    VM_UOP_PUSH_IMAGE_BASE,
    VM_UOP_POP_VREG,
    VM_UOP_LOAD_TEMP,
    VM_UOP_STORE_TEMP,
    VM_UOP_DUP,
    VM_UOP_SWAP,
    VM_UOP_ROT,
    VM_UOP_DROP,
    VM_UOP_LOAD,
    VM_UOP_STORE,

    VM_UOP_ADD,
    VM_UOP_ADD_CARRY,
    VM_UOP_SUB,
    VM_UOP_SUB_BORROW,
    VM_UOP_MUL,
    VM_UOP_UMUL_WIDE,
    VM_UOP_SMUL_WIDE,
    VM_UOP_UDIV_WIDE,
    VM_UOP_IDIV_WIDE,
    VM_UOP_AND,
    VM_UOP_OR,
    VM_UOP_XOR,
    VM_UOP_NOT,
    VM_UOP_NEG,
    VM_UOP_SHL,
    VM_UOP_SHR,
    VM_UOP_SAR,
    VM_UOP_ROL,
    VM_UOP_ROR,
    VM_UOP_BIT_TEST,
    VM_UOP_BIT_SET,
    VM_UOP_BIT_RESET,
    VM_UOP_BSWAP,
    VM_UOP_ZERO_EXTEND,
    VM_UOP_SIGN_EXTEND,

    VM_UOP_FLAGS_LAZY,
    VM_UOP_FLAGS_MATERIALIZE,
    VM_UOP_FLAGS_WRITE,
    VM_UOP_FLAGS_UPDATE,
    VM_UOP_FLAGS_PACK_AH,
    VM_UOP_FLAGS_UNPACK_AH,
    VM_UOP_PUSH_CONDITION,
    VM_UOP_SELECT,

    VM_UOP_BRANCH,
    VM_UOP_BRANCH_IF,
    VM_UOP_CALL_VM,
    VM_UOP_CALL_HOST,
    VM_UOP_RET,
    VM_UOP_EXIT,
    VM_UOP_BRIDGE_EXTENDED,

    VM_UOP_RDTSC,
    VM_UOP_CPUID,
    VM_UOP_INT3,
    VM_UOP_COUNT
} VM_MICRO_OPCODE;

typedef enum VM_MICRO_OPERAND_KIND {
    VM_MICRO_OPERAND_NONE = 0,
    VM_MICRO_OPERAND_U8,
    VM_MICRO_OPERAND_U16,
    VM_MICRO_OPERAND_U32,
    VM_MICRO_OPERAND_U64,
    VM_MICRO_OPERAND_VAR_UINT,
    VM_MICRO_OPERAND_VAR_SINT,
    VM_MICRO_OPERAND_REGISTER,
    VM_MICRO_OPERAND_TEMP,
    VM_MICRO_OPERAND_WIDTH,
    VM_MICRO_OPERAND_CONDITION,
    VM_MICRO_OPERAND_FLAG_MASK,
    VM_MICRO_OPERAND_LAZY_KIND,
    VM_MICRO_OPERAND_CALL_KIND
} VM_MICRO_OPERAND_KIND;

typedef enum VM_MICRO_FLAG_EFFECT {
    VM_MICRO_FLAGS_NONE = 0,
    VM_MICRO_FLAGS_LATCH,
    VM_MICRO_FLAGS_RECORD,
    VM_MICRO_FLAGS_MATERIALIZE,
    VM_MICRO_FLAGS_WRITE,
    VM_MICRO_FLAGS_CONSUME
} VM_MICRO_FLAG_EFFECT;

typedef enum VM_LAZY_FLAG_KIND {
    VM_LAZY_NONE = 0,
    VM_LAZY_ADD,
    VM_LAZY_ADC,
    VM_LAZY_SUB,
    VM_LAZY_SBB,
    VM_LAZY_LOGIC,
    VM_LAZY_NEG,
    VM_LAZY_INC,
    VM_LAZY_DEC,
    VM_LAZY_SHL,
    VM_LAZY_SHR,
    VM_LAZY_SAR,
    VM_LAZY_ROL,
    VM_LAZY_ROR,
    VM_LAZY_MUL,
    VM_LAZY_IMUL,
    VM_LAZY_BIT_TEST
} VM_LAZY_FLAG_KIND;

typedef enum VM_CONDITION {
    VM_CONDITION_ALWAYS = 0,
    VM_CONDITION_O,
    VM_CONDITION_NO,
    VM_CONDITION_B,
    VM_CONDITION_AE,
    VM_CONDITION_E,
    VM_CONDITION_NE,
    VM_CONDITION_BE,
    VM_CONDITION_A,
    VM_CONDITION_S,
    VM_CONDITION_NS,
    VM_CONDITION_P,
    VM_CONDITION_NP,
    VM_CONDITION_L,
    VM_CONDITION_GE,
    VM_CONDITION_LE,
    VM_CONDITION_G
} VM_CONDITION;

typedef enum VM_MEMORY_KIND {
    VM_MEMORY_NATIVE = 0,
    VM_MEMORY_IMAGE_RVA = 1
} VM_MEMORY_KIND;

typedef enum VM_CALL_ABI {
    VM_ABI_WIN64 = 0,
    VM_ABI_X86_CDECL = 1,
    VM_ABI_X86_STDCALL = 2,
    VM_ABI_X86_FASTCALL = 3,
    VM_ABI_X86_THISCALL = 4,
    VM_ABI_X86_AUTO = 5
} VM_CALL_ABI;

typedef enum VM_MICRO_CALL_KIND {
    VM_MICRO_CALL_NATIVE_RVA = 0,
    VM_MICRO_CALL_IMPORT_SLOT = 1,
    VM_MICRO_CALL_INDIRECT = 2
} VM_MICRO_CALL_KIND;

typedef enum VM_FLAG_UPDATE_OPERATION {
    VM_FLAG_UPDATE_CLEAR = 0,
    VM_FLAG_UPDATE_SET = 1,
    VM_FLAG_UPDATE_TOGGLE = 2
} VM_FLAG_UPDATE_OPERATION;

#define VM_CALL_AUX_ENCODE(abi, stackBytes) \
    ((((uint32_t)(abi)) & VM_CALL_AUX_ABI_MASK) | \
     ((((uint32_t)(stackBytes)) << VM_CALL_AUX_STACK_BYTES_SHIFT) & VM_CALL_AUX_STACK_BYTES_MASK))
#define VM_CALL_AUX_ABI(value) ((uint32_t)(value) & VM_CALL_AUX_ABI_MASK)
#define VM_CALL_AUX_STACK_BYTES(value) \
    (((uint32_t)(value) & VM_CALL_AUX_STACK_BYTES_MASK) >> VM_CALL_AUX_STACK_BYTES_SHIFT)

#define VM_MICRO_BRIDGE_HIDDEN_REGISTER_MASK 0x0000000Fu
#define VM_MICRO_BRIDGE_AVX                  0x00000100u
#define VM_MICRO_BRIDGE_X87                  0x00000200u
#define VM_MICRO_BRIDGE_LINKED               0x80000000u
#define VM_MICRO_BRIDGE_KNOWN_MASK \
    (VM_MICRO_BRIDGE_HIDDEN_REGISTER_MASK | VM_MICRO_BRIDGE_AVX | \
     VM_MICRO_BRIDGE_X87 | VM_MICRO_BRIDGE_LINKED)

enum {
    VM_FLAG_CF = 0x0001,
    VM_FLAG_FIXED_1 = 0x0002,
    VM_FLAG_PF = 0x0004,
    VM_FLAG_AF = 0x0010,
    VM_FLAG_ZF = 0x0040,
    VM_FLAG_SF = 0x0080,
    VM_FLAG_TF = 0x0100,
    VM_FLAG_IF = 0x0200,
    VM_FLAG_DF = 0x0400,
    VM_FLAG_OF = 0x0800,
    VM_FLAG_IOPL = 0x3000,
    VM_FLAG_NT = 0x4000,
    VM_FLAG_RF = 0x00010000,
    VM_FLAG_VM = 0x00020000,
    VM_FLAG_AC = 0x00040000,
    VM_FLAG_VIF = 0x00080000,
    VM_FLAG_VIP = 0x00100000,
    VM_FLAG_ID = 0x00200000
};

#define VM_FLAG_STATUS_MASK \
    (VM_FLAG_CF | VM_FLAG_PF | VM_FLAG_AF | VM_FLAG_ZF | VM_FLAG_SF | VM_FLAG_OF)
#define VM_FLAG_CONTROL_SYSTEM_MASK \
    (VM_FLAG_TF | VM_FLAG_IF | VM_FLAG_DF | VM_FLAG_IOPL | VM_FLAG_NT | \
     VM_FLAG_RF | VM_FLAG_VM | VM_FLAG_AC | VM_FLAG_VIF | VM_FLAG_VIP | VM_FLAG_ID)
#define VM_FLAG_PUSH_CLEARED_MASK (VM_FLAG_RF | VM_FLAG_VM)
#define VM_FLAG_ARCHITECTURAL_MASK \
    (VM_FLAG_FIXED_1 | VM_FLAG_STATUS_MASK | VM_FLAG_CONTROL_SYSTEM_MASK)

/* Pure POD codec state reconstructed from layoutSeed + functionRVA. */
#pragma pack(push, 1)
typedef struct VM_OPERAND_CODEC {
    uint64_t seed;
    uint64_t fieldKey;
    uint32_t functionRva;
    uint8_t affineMultiplier;
    uint8_t affineInverse;
    uint8_t affineAddend;
    uint8_t rotate;
    uint8_t varintKey;
    uint8_t reserved[3];
} VM_OPERAND_CODEC;

typedef struct VM_RUNTIME_OPERAND_DECODE_PLAN {
    uint8_t kind;
    uint8_t canonicalIndex;
    uint8_t fixedWidth;
    uint8_t u8Bias;
    uint8_t u8Xor;
    uint8_t u8Rotate;
    uint8_t reserved[2];
    uint8_t byteOrder[8];
    uint8_t byteXor[8];
    uint8_t varintXor[10];
    uint8_t varintRotate[10];
} VM_RUNTIME_OPERAND_DECODE_PLAN;

typedef struct VM_RUNTIME_DECODE_PLAN {
    uint8_t semantic;
    uint8_t semanticComplete;
    uint8_t operandCount;
    uint8_t fieldOrder[VM_MICRO_MAX_OPERANDS];
    VM_RUNTIME_OPERAND_DECODE_PLAN variant;
    VM_RUNTIME_OPERAND_DECODE_PLAN operands[VM_MICRO_MAX_OPERANDS];
} VM_RUNTIME_DECODE_PLAN;
#pragma pack(pop)

/*
 * Runtime-only state carried between handlers.  It is never serialized into
 * bytecode.  Every ALU uop overwrites lastAlu; FLAGS_LAZY is the sole operation
 * that copies it to pendingFlags.  Consumers materialize requested bits into
 * architecturalFlags without using native arithmetic flags.
 */
#pragma pack(push, 1)
typedef struct VM_LAZY_FLAGS_RECORD {
    uint64_t a;
    uint64_t b;
    uint64_t result;
    uint64_t auxiliary;
    uint32_t definedMask;
    uint32_t preserveMask;
    uint8_t operation;
    uint8_t width;
    uint8_t valid;
    uint8_t reserved;
} VM_LAZY_FLAGS_RECORD;
#pragma pack(pop)

#ifdef __cplusplus
}
static_assert(VM_UOP_COUNT < 0xFE, "micro opcode space exceeds handler map");
static_assert(sizeof(VM_OPERAND_CODEC) == 28,
              "operand codec ABI mismatch");
static_assert(sizeof(VM_RUNTIME_OPERAND_DECODE_PLAN) == 44,
              "runtime operand decode plan ABI mismatch");
static_assert(sizeof(VM_RUNTIME_DECODE_PLAN) == 227,
              "runtime semantic decode plan ABI mismatch");
static_assert(sizeof(VM_LAZY_FLAGS_RECORD) == 44,
              "lazy flag record ABI mismatch");
#endif

#endif // CS_RUNTIME_VM_ISA_H
