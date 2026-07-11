#ifndef CS_RUNTIME_VM_ISA_H
#define CS_RUNTIME_VM_ISA_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VM_SCHEMA_VERSION 0x00030003u
#define VM_INSTRUCTION_SIZE 48u
#define VM_REGISTER_INVALID 0xFFu
#define VM_CALL_AUX_ABI_MASK 0x000000FFu
#define VM_CALL_AUX_STACK_BYTES_SHIFT 8u
#define VM_CALL_AUX_STACK_BYTES_MASK 0x00FFFF00u
#define VM_NATIVE_MAX_STACK_ARGUMENT_BYTES 512u
#define VM_MAX_INTERNAL_CALL_DEPTH 256u

typedef enum VM_OPCODE {
    VM_NOP              = 0x00,
    VM_MOV_RR           = 0x01,
    VM_MOV_RC           = 0x02,
    VM_MOV_RM           = 0x03,
    VM_MOV_MR           = 0x04,
    VM_MOV_RM8          = 0x05,
    VM_MOV_MR8          = 0x06,
    VM_MOV_RM16         = 0x07,
    VM_MOV_MR16         = 0x08,
    VM_LEA              = 0x09,
    VM_XCHG             = 0x0A,

    VM_PUSH_R           = 0x10,
    VM_PUSH_C           = 0x11,
    VM_PUSH_MEM         = 0x12,
    VM_POP_R            = 0x13,
    VM_POP_MEM          = 0x14,
    VM_PUSHAD           = 0x15,
    VM_POPAD            = 0x16,
    VM_PUSHF            = 0x17,
    VM_POPF             = 0x18,

    VM_ADD_RR           = 0x20,
    VM_ADD_RC           = 0x21,
    VM_SUB_RR           = 0x22,
    VM_SUB_RC           = 0x23,
    VM_MUL_RR           = 0x24,
    VM_IMUL_RR          = 0x25,
    VM_IMUL_RRC         = 0x26,
    VM_DIV_RR           = 0x27,
    VM_IDIV_RR          = 0x28,
    VM_NEG_R            = 0x29,
    VM_INC_R            = 0x2A,
    VM_DEC_R            = 0x2B,
    VM_ADC_RR           = 0x2C,
    VM_SBB_RR           = 0x2D,
    VM_ADD_RM           = 0x2E,
    VM_ADD_MR           = 0x2F,

    VM_AND_RR           = 0x30,
    VM_AND_RC           = 0x31,
    VM_OR_RR            = 0x32,
    VM_OR_RC            = 0x33,
    VM_XOR_RR           = 0x34,
    VM_XOR_RC           = 0x35,
    VM_NOT_R            = 0x36,
    VM_SHL_RR           = 0x37,
    VM_SHL_RC           = 0x38,
    VM_SHR_RR           = 0x39,
    VM_SHR_RC           = 0x3A,
    VM_SAR_RR           = 0x3B,
    VM_SAR_RC           = 0x3C,
    VM_ROL_RR           = 0x3D,
    VM_ROR_RR           = 0x3E,
    VM_BT_RR            = 0x3F,
    VM_BTS_RR           = 0x40,
    VM_BTR_RR           = 0x41,
    VM_BSWAP            = 0x42,
    VM_ADC_RC           = 0x43,
    VM_SBB_RC           = 0x44,
    VM_NEG_M            = 0x45,
    VM_INC_M            = 0x46,
    VM_DEC_M            = 0x47,
    VM_SHL_MR           = 0x48,
    VM_SHL_MC           = 0x49,
    VM_SHR_MR           = 0x4A,
    VM_SHR_MC           = 0x4B,
    VM_SAR_MR           = 0x4C,
    VM_SAR_MC           = 0x4D,
    VM_ROL_RC           = 0x4E,
    VM_ROR_RC           = 0x4F,

    VM_CMP_RR           = 0x50,
    VM_CMP_RC           = 0x51,
    VM_TEST_RR          = 0x52,
    VM_TEST_RC          = 0x53,
    VM_CMP_RM           = 0x54,
    VM_CMP_MR           = 0x55,
    VM_TEST_RM          = 0x56,
    VM_TEST_MR          = 0x57,

    VM_JMP              = 0x60,
    VM_JZ               = 0x62,
    VM_JNZ              = 0x63,
    VM_JA               = 0x64,
    VM_JB               = 0x65,
    VM_JG               = 0x66,
    VM_JL               = 0x67,
    VM_JGE              = 0x68,
    VM_JLE              = 0x69,
    VM_JO               = 0x6A,
    VM_JNO              = 0x6B,
    VM_JS               = 0x6C,
    VM_JNS              = 0x6D,
    VM_CALL_VM          = 0x6E,
    VM_RET_VM           = 0x6F,
    VM_CALL_NATIVE      = 0x70,
    VM_VMENTER          = 0x71,
    VM_VMEXIT           = 0x72,
    VM_SYSCALL          = 0x73,
    VM_JAE              = 0x74,
    VM_JBE              = 0x75,
    VM_JP               = 0x76,
    VM_JNP              = 0x77,
    VM_CMOV_RR          = 0x78,
    VM_CMOV_RM          = 0x79,
    VM_SET_R            = 0x7A,
    VM_SET_M            = 0x7B,
    VM_CALL_IMPORT      = 0x7C,
    VM_CALL_INDIRECT_R  = 0x7D,
    VM_CALL_INDIRECT_M  = 0x7E,

    VM_ANTI_DEBUG       = 0x80,
    VM_CRC_CHECK        = 0x81,
    VM_RDTSC            = 0x82,
    VM_CPUID            = 0x83,
    VM_INT3             = 0x84,
    VM_MOVZX_RR         = 0x85,
    VM_MOVZX_RM         = 0x86,
    VM_MOVSX_RR         = 0x87,
    VM_MOVSX_RM         = 0x88,
    VM_MOVSXD_RR        = 0x89,
    VM_MOVSXD_RM        = 0x8A,
    VM_MOV_MC           = 0x8B,
    VM_XCHG_RM          = 0x8C,

    VM_SUB_RM           = 0x90,
    VM_SUB_MR           = 0x91,
    VM_ADC_RM           = 0x92,
    VM_ADC_MR           = 0x93,
    VM_SBB_RM           = 0x94,
    VM_SBB_MR           = 0x95,
    VM_AND_RM           = 0x96,
    VM_AND_MR           = 0x97,
    VM_OR_RM            = 0x98,
    VM_OR_MR            = 0x99,
    VM_XOR_RM           = 0x9A,
    VM_XOR_MR           = 0x9B,
    VM_BRIDGE_SIMD      = 0xA0,
    VM_BRIDGE_X87       = 0xA1,
    VM_ROL_MR           = 0xA2,
    VM_ROL_MC           = 0xA3,
    VM_ROR_MR           = 0xA4,
    VM_ROR_MC           = 0xA5,
    VM_SIGN_EXTEND_ACC  = 0xA6,
    VM_EXTEND_ACC       = 0xA7,
    VM_LEAVE            = 0xA8,
    VM_CLC              = 0xA9,
    VM_STC              = 0xAA,
    VM_CMC              = 0xAB,
    VM_LAHF             = 0xAC,
    VM_SAHF             = 0xAD
} VM_OPCODE;

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

#define VM_CALL_AUX_ENCODE(abi, stackBytes) \
    ((((uint32_t)(abi)) & VM_CALL_AUX_ABI_MASK) | \
     ((((uint32_t)(stackBytes)) << VM_CALL_AUX_STACK_BYTES_SHIFT) & VM_CALL_AUX_STACK_BYTES_MASK))
#define VM_CALL_AUX_ABI(value) ((uint32_t)(value) & VM_CALL_AUX_ABI_MASK)
#define VM_CALL_AUX_STACK_BYTES(value) \
    (((uint32_t)(value) & VM_CALL_AUX_STACK_BYTES_MASK) >> VM_CALL_AUX_STACK_BYTES_SHIFT)

#define VM_BRIDGE_AUX_HIDDEN_REGISTER_MASK 0x0000000Fu
#define VM_BRIDGE_AUX_AVX                  0x00000100u
#define VM_BRIDGE_AUX_X87                  0x00000200u
#define VM_BRIDGE_AUX_KNOWN_MASK \
    (VM_BRIDGE_AUX_HIDDEN_REGISTER_MASK | VM_BRIDGE_AUX_AVX | VM_BRIDGE_AUX_X87)

enum {
    VM_OPERAND_DST_ZERO_EXTEND = 0x0001,
    VM_OPERAND_SRC_SIGNED = 0x0002,
    VM_OPERAND_IMMEDIATE_SIGNED = 0x0004,
    VM_OPERAND_TARGET_IS_IMPORT = 0x0008,
    VM_OPERAND_NATIVE_BRIDGE = 0x0010,
    VM_OPERAND_SOURCE_IMMEDIATE = 0x0020,
    VM_OPERAND_SOURCE_MEMORY = 0x0040,
    VM_OPERAND_DEST_MEMORY = 0x0080,
    VM_OPERAND_IMPLICIT_ACCUMULATOR = 0x0100,
    VM_OPERAND_ATOMIC = 0x0200,
    VM_OPERAND_BRIDGE_LINKED = 0x0400
};

enum {
    VM_FLAG_CF = 0x0001,
    VM_FLAG_PF = 0x0004,
    VM_FLAG_AF = 0x0010,
    VM_FLAG_ZF = 0x0040,
    VM_FLAG_SF = 0x0080,
    VM_FLAG_TF = 0x0100,
    VM_FLAG_IF = 0x0200,
    VM_FLAG_DF = 0x0400,
    VM_FLAG_OF = 0x0800
};

#pragma pack(push, 1)
typedef struct VM_BYTECODE_INSTRUCTION {
    uint8_t opcode;
    uint8_t dst;
    uint8_t src;
    uint8_t extra;
    uint8_t dstBitOffset;
    uint8_t srcBitOffset;
    uint8_t extraBitOffset;
    uint8_t operandWidth;
    uint8_t memBase;
    uint8_t memIndex;
    uint8_t memScale;
    uint8_t memWidth;
    uint8_t memoryKind;
    uint8_t condition;
    uint16_t flags;
    uint64_t immediate;
    int64_t memDisp;
    uint32_t branchTargetOffset;
    uint32_t aux;
    uint64_t reserved;
} VM_BYTECODE_INSTRUCTION;
#pragma pack(pop)

#ifdef __cplusplus
}
static_assert(sizeof(VM_BYTECODE_INSTRUCTION) == VM_INSTRUCTION_SIZE,
              "VM bytecode schema size mismatch");
#endif

#endif // CS_RUNTIME_VM_ISA_H
