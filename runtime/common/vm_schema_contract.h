#ifndef CS_RUNTIME_VM_SCHEMA_CONTRACT_H
#define CS_RUNTIME_VM_SCHEMA_CONTRACT_H

#include "vm_isa.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum VM_SCHEMA_CONTRACT_ERROR {
    VM_SCHEMA_CONTRACT_OK = 0,
    VM_SCHEMA_CONTRACT_NULL = 1,
    VM_SCHEMA_CONTRACT_REGISTER_COUNT = 2,
    VM_SCHEMA_CONTRACT_REGISTER = 3,
    VM_SCHEMA_CONTRACT_WIDTH = 4,
    VM_SCHEMA_CONTRACT_MEMORY = 5,
    VM_SCHEMA_CONTRACT_CONDITION = 6,
    VM_SCHEMA_CONTRACT_REGISTER_LANE = 7,
    VM_SCHEMA_CONTRACT_FLAGS = 8,
    VM_SCHEMA_CONTRACT_OPERANDS = 9,
    VM_SCHEMA_CONTRACT_CALL = 10,
    VM_SCHEMA_CONTRACT_BRIDGE = 11,
    VM_SCHEMA_CONTRACT_OPCODE = 12
} VM_SCHEMA_CONTRACT_ERROR;

#if defined(_MSC_VER)
#define VM_SCHEMA_INLINE static __forceinline
#else
#define VM_SCHEMA_INLINE static inline
#endif

VM_SCHEMA_INLINE int vm_schema_width_valid(uint8_t width) {
    return width == 1 || width == 2 || width == 4 || width == 8;
}

VM_SCHEMA_INLINE int vm_schema_register_valid(uint8_t reg, uint32_t registerCount) {
    return reg == VM_REGISTER_INVALID || reg < registerCount;
}

VM_SCHEMA_INLINE int vm_schema_memory_valid(const VM_BYTECODE_INSTRUCTION* instruction) {
    if (!vm_schema_width_valid(instruction->memWidth)) return 0;
    if (instruction->memoryKind == VM_MEMORY_IMAGE_RVA) {
        return instruction->memDisp >= 0 &&
            instruction->memBase == VM_REGISTER_INVALID &&
            instruction->memIndex == VM_REGISTER_INVALID;
    }
    return instruction->memoryKind == VM_MEMORY_NATIVE;
}

VM_SCHEMA_INLINE int vm_schema_no_memory(const VM_BYTECODE_INSTRUCTION* instruction) {
    return (instruction->flags & (VM_OPERAND_SOURCE_MEMORY | VM_OPERAND_DEST_MEMORY)) == 0 &&
        instruction->memBase == VM_REGISTER_INVALID &&
        instruction->memIndex == VM_REGISTER_INVALID && instruction->memWidth == 0;
}

VM_SCHEMA_INLINE int vm_schema_address_valid(const VM_BYTECODE_INSTRUCTION* instruction) {
    if (instruction->memWidth != 0 ||
        (instruction->flags & (VM_OPERAND_SOURCE_MEMORY | VM_OPERAND_DEST_MEMORY |
            VM_OPERAND_SOURCE_IMMEDIATE)) != 0) {
        return 0;
    }
    if (instruction->memoryKind == VM_MEMORY_IMAGE_RVA) {
        return instruction->memDisp >= 0 &&
            instruction->memBase == VM_REGISTER_INVALID &&
            instruction->memIndex == VM_REGISTER_INVALID;
    }
    return instruction->memoryKind == VM_MEMORY_NATIVE;
}

VM_SCHEMA_INLINE int vm_schema_call_aux_valid(uint32_t aux) {
    return (aux & ~(VM_CALL_AUX_ABI_MASK | VM_CALL_AUX_STACK_BYTES_MASK)) == 0 &&
        VM_CALL_AUX_STACK_BYTES(aux) <= VM_NATIVE_MAX_STACK_ARGUMENT_BYTES &&
        VM_CALL_AUX_ABI(aux) <= VM_ABI_X86_AUTO;
}

VM_SCHEMA_INLINE int vm_schema_opcode_has_branch(uint8_t opcode) {
    switch (opcode) {
        case VM_JMP: case VM_JZ: case VM_JNZ: case VM_JA: case VM_JAE:
        case VM_JB: case VM_JBE: case VM_JG: case VM_JGE: case VM_JL:
        case VM_JLE: case VM_JO: case VM_JNO: case VM_JS: case VM_JNS:
        case VM_JP: case VM_JNP: case VM_CALL_VM:
            return 1;
        default:
            return 0;
    }
}

VM_SCHEMA_INLINE uint8_t vm_schema_expected_branch_condition(uint8_t opcode) {
    switch (opcode) {
        case VM_JMP: return VM_CONDITION_ALWAYS;
        case VM_JO: return VM_CONDITION_O;
        case VM_JNO: return VM_CONDITION_NO;
        case VM_JB: return VM_CONDITION_B;
        case VM_JAE: return VM_CONDITION_AE;
        case VM_JZ: return VM_CONDITION_E;
        case VM_JNZ: return VM_CONDITION_NE;
        case VM_JBE: return VM_CONDITION_BE;
        case VM_JA: return VM_CONDITION_A;
        case VM_JS: return VM_CONDITION_S;
        case VM_JNS: return VM_CONDITION_NS;
        case VM_JP: return VM_CONDITION_P;
        case VM_JNP: return VM_CONDITION_NP;
        case VM_JL: return VM_CONDITION_L;
        case VM_JGE: return VM_CONDITION_GE;
        case VM_JLE: return VM_CONDITION_LE;
        case VM_JG: return VM_CONDITION_G;
        default: return 0xFFu;
    }
}

VM_SCHEMA_INLINE VM_SCHEMA_CONTRACT_ERROR vm_schema_validate_instruction(
    const VM_BYTECODE_INSTRUCTION* instruction,
    uint32_t registerCount)
{
    const uint16_t knownFlags = VM_OPERAND_DST_ZERO_EXTEND |
        VM_OPERAND_SRC_SIGNED | VM_OPERAND_IMMEDIATE_SIGNED |
        VM_OPERAND_TARGET_IS_IMPORT | VM_OPERAND_NATIVE_BRIDGE |
        VM_OPERAND_SOURCE_IMMEDIATE | VM_OPERAND_SOURCE_MEMORY |
        VM_OPERAND_DEST_MEMORY | VM_OPERAND_IMPLICIT_ACCUMULATOR |
        VM_OPERAND_ATOMIC | VM_OPERAND_BRIDGE_LINKED;
    int hasDst;
    int hasSrc;
    int sourceMemory;
    int destinationMemory;
    int sourceImmediate;
    int scalarWidth;
    int noMemory;
    int memoryValid;

    if (!instruction) return VM_SCHEMA_CONTRACT_NULL;
    if (registerCount < 16 || registerCount > 32) return VM_SCHEMA_CONTRACT_REGISTER_COUNT;
    if (!vm_schema_register_valid(instruction->dst, registerCount) ||
        !vm_schema_register_valid(instruction->src, registerCount) ||
        !vm_schema_register_valid(instruction->extra, registerCount) ||
        !vm_schema_register_valid(instruction->memBase, registerCount) ||
        !vm_schema_register_valid(instruction->memIndex, registerCount)) {
        return VM_SCHEMA_CONTRACT_REGISTER;
    }
    if ((instruction->operandWidth && !vm_schema_width_valid(instruction->operandWidth)) ||
        (instruction->memWidth && !vm_schema_width_valid(instruction->memWidth))) {
        return VM_SCHEMA_CONTRACT_WIDTH;
    }
    if (!(instruction->memScale == 0 || instruction->memScale == 1 ||
          instruction->memScale == 2 || instruction->memScale == 4 ||
          instruction->memScale == 8) || instruction->memoryKind > VM_MEMORY_IMAGE_RVA) {
        return VM_SCHEMA_CONTRACT_MEMORY;
    }
    if (instruction->condition > VM_CONDITION_G) return VM_SCHEMA_CONTRACT_CONDITION;
    if (!vm_schema_opcode_has_branch(instruction->opcode) &&
        instruction->opcode != VM_CMOV_RR && instruction->opcode != VM_CMOV_RM &&
        instruction->opcode != VM_SET_R && instruction->opcode != VM_SET_M &&
        instruction->condition != VM_CONDITION_ALWAYS) {
        return VM_SCHEMA_CONTRACT_CONDITION;
    }
    if ((instruction->opcode == VM_CMOV_RR || instruction->opcode == VM_CMOV_RM ||
         instruction->opcode == VM_SET_R || instruction->opcode == VM_SET_M) &&
        instruction->condition == VM_CONDITION_ALWAYS) {
        return VM_SCHEMA_CONTRACT_CONDITION;
    }
    if ((instruction->dstBitOffset != 0 && instruction->dstBitOffset != 8) ||
        (instruction->srcBitOffset != 0 && instruction->srcBitOffset != 8) ||
        (instruction->extraBitOffset != 0 && instruction->extraBitOffset != 8)) {
        return VM_SCHEMA_CONTRACT_REGISTER_LANE;
    }
    if ((instruction->dstBitOffset == 8 && instruction->operandWidth != 1) ||
        (instruction->srcBitOffset == 8 &&
            ((instruction->opcode == VM_MOVZX_RR || instruction->opcode == VM_MOVSX_RR ||
              instruction->opcode == VM_MOVSXD_RR)
                ? (uint8_t)instruction->aux : instruction->operandWidth) != 1) ||
        instruction->extraBitOffset != 0) {
        return VM_SCHEMA_CONTRACT_REGISTER_LANE;
    }
    if ((instruction->flags & (uint16_t)~knownFlags) != 0 || instruction->reserved != 0) {
        return VM_SCHEMA_CONTRACT_FLAGS;
    }
    if (instruction->extra != VM_REGISTER_INVALID) return VM_SCHEMA_CONTRACT_OPERANDS;

    hasDst = instruction->dst != VM_REGISTER_INVALID;
    hasSrc = instruction->src != VM_REGISTER_INVALID;
    sourceMemory = (instruction->flags & VM_OPERAND_SOURCE_MEMORY) != 0;
    destinationMemory = (instruction->flags & VM_OPERAND_DEST_MEMORY) != 0;
    sourceImmediate = (instruction->flags & VM_OPERAND_SOURCE_IMMEDIATE) != 0;
    scalarWidth = vm_schema_width_valid(instruction->operandWidth);
    noMemory = vm_schema_no_memory(instruction);
    memoryValid = vm_schema_memory_valid(instruction);

    switch (instruction->opcode) {
        case VM_NOP:
            return !hasDst && !hasSrc && instruction->operandWidth == 0 &&
                instruction->flags == 0 && noMemory
                ? VM_SCHEMA_CONTRACT_OK : VM_SCHEMA_CONTRACT_OPERANDS;

        case VM_MOV_RR: case VM_XCHG:
        case VM_ADD_RR: case VM_ADC_RR: case VM_SUB_RR: case VM_SBB_RR:
        case VM_AND_RR: case VM_OR_RR: case VM_XOR_RR:
        case VM_CMP_RR: case VM_TEST_RR:
        case VM_SHL_RR: case VM_SHR_RR: case VM_SAR_RR:
        case VM_ROL_RR: case VM_ROR_RR: case VM_CMOV_RR:
            return hasDst && hasSrc && scalarWidth && noMemory && !sourceImmediate
                ? VM_SCHEMA_CONTRACT_OK : VM_SCHEMA_CONTRACT_OPERANDS;

        case VM_MOV_RC:
        case VM_ADD_RC: case VM_ADC_RC: case VM_SUB_RC: case VM_SBB_RC:
        case VM_AND_RC: case VM_OR_RC: case VM_XOR_RC:
        case VM_CMP_RC: case VM_TEST_RC:
        case VM_SHL_RC: case VM_SHR_RC: case VM_SAR_RC:
        case VM_ROL_RC: case VM_ROR_RC:
            return hasDst && !hasSrc && scalarWidth && noMemory && sourceImmediate
                ? VM_SCHEMA_CONTRACT_OK : VM_SCHEMA_CONTRACT_OPERANDS;

        case VM_MOV_RM: case VM_MOVZX_RM: case VM_MOVSX_RM: case VM_MOVSXD_RM:
        case VM_ADD_RM: case VM_ADC_RM: case VM_SUB_RM: case VM_SBB_RM:
        case VM_AND_RM: case VM_OR_RM: case VM_XOR_RM:
        case VM_CMP_RM: case VM_TEST_RM: case VM_CMOV_RM:
            return hasDst && !hasSrc && scalarWidth && sourceMemory &&
                !destinationMemory && !sourceImmediate && memoryValid
                ? VM_SCHEMA_CONTRACT_OK : VM_SCHEMA_CONTRACT_MEMORY;

        case VM_MOV_MR:
            return !hasDst && hasSrc && scalarWidth && destinationMemory &&
                !sourceImmediate && memoryValid
                ? VM_SCHEMA_CONTRACT_OK : VM_SCHEMA_CONTRACT_MEMORY;
        case VM_ADD_MR: case VM_ADC_MR: case VM_SUB_MR: case VM_SBB_MR:
        case VM_AND_MR: case VM_OR_MR: case VM_XOR_MR:
        case VM_CMP_MR: case VM_TEST_MR:
            return !hasDst && scalarWidth && destinationMemory && memoryValid &&
                ((hasSrc && !sourceImmediate) || (!hasSrc && sourceImmediate))
                ? VM_SCHEMA_CONTRACT_OK : VM_SCHEMA_CONTRACT_MEMORY;
        case VM_MOV_MC:
            return !hasDst && !hasSrc && scalarWidth && destinationMemory &&
                sourceImmediate && memoryValid
                ? VM_SCHEMA_CONTRACT_OK : VM_SCHEMA_CONTRACT_MEMORY;

        case VM_MOVZX_RR: case VM_MOVSX_RR: case VM_MOVSXD_RR:
            return hasDst && hasSrc && scalarWidth && noMemory &&
                vm_schema_width_valid((uint8_t)instruction->aux) &&
                instruction->aux < instruction->operandWidth
                ? VM_SCHEMA_CONTRACT_OK : VM_SCHEMA_CONTRACT_WIDTH;
        case VM_LEA:
            return hasDst && !hasSrc && scalarWidth &&
                (instruction->flags & (uint16_t)~VM_OPERAND_DST_ZERO_EXTEND) == 0 &&
                vm_schema_address_valid(instruction)
                ? VM_SCHEMA_CONTRACT_OK : VM_SCHEMA_CONTRACT_OPERANDS;
        case VM_XCHG_RM:
            return hasDst && !hasSrc && scalarWidth && sourceMemory &&
                !destinationMemory && memoryValid
                ? VM_SCHEMA_CONTRACT_OK : VM_SCHEMA_CONTRACT_MEMORY;

        case VM_NOT_R: case VM_NEG_R: case VM_INC_R: case VM_DEC_R:
            if (destinationMemory) {
                return !hasDst && scalarWidth && memoryValid
                    ? VM_SCHEMA_CONTRACT_OK : VM_SCHEMA_CONTRACT_MEMORY;
            }
            return hasDst && scalarWidth && noMemory
                ? VM_SCHEMA_CONTRACT_OK : VM_SCHEMA_CONTRACT_OPERANDS;
        case VM_NEG_M: case VM_INC_M: case VM_DEC_M:
            return !hasDst && scalarWidth && destinationMemory && memoryValid
                ? VM_SCHEMA_CONTRACT_OK : VM_SCHEMA_CONTRACT_MEMORY;

        case VM_SHL_MR: case VM_SHR_MR: case VM_SAR_MR:
        case VM_ROL_MR: case VM_ROR_MR:
            return !hasDst && hasSrc && scalarWidth && destinationMemory &&
                !sourceImmediate && memoryValid
                ? VM_SCHEMA_CONTRACT_OK : VM_SCHEMA_CONTRACT_MEMORY;
        case VM_SHL_MC: case VM_SHR_MC: case VM_SAR_MC:
        case VM_ROL_MC: case VM_ROR_MC:
            return !hasDst && !hasSrc && scalarWidth && destinationMemory &&
                sourceImmediate && memoryValid
                ? VM_SCHEMA_CONTRACT_OK : VM_SCHEMA_CONTRACT_MEMORY;

        case VM_MUL_RR: case VM_DIV_RR: case VM_IDIV_RR:
            return !hasDst && scalarWidth &&
                (instruction->flags & VM_OPERAND_IMPLICIT_ACCUMULATOR) != 0 &&
                ((hasSrc && noMemory) || (!hasSrc && sourceMemory && memoryValid))
                ? VM_SCHEMA_CONTRACT_OK : VM_SCHEMA_CONTRACT_OPERANDS;
        case VM_IMUL_RR:
            if (instruction->flags & VM_OPERAND_IMPLICIT_ACCUMULATOR) {
                return !hasDst && scalarWidth &&
                    ((hasSrc && noMemory) || (!hasSrc && sourceMemory && memoryValid))
                    ? VM_SCHEMA_CONTRACT_OK : VM_SCHEMA_CONTRACT_OPERANDS;
            }
            return hasDst && scalarWidth &&
                ((hasSrc && noMemory) || (!hasSrc && sourceMemory && memoryValid))
                ? VM_SCHEMA_CONTRACT_OK : VM_SCHEMA_CONTRACT_OPERANDS;
        case VM_IMUL_RRC:
            return hasDst && scalarWidth && !sourceImmediate &&
                ((hasSrc && noMemory) || (!hasSrc && sourceMemory && memoryValid))
                ? VM_SCHEMA_CONTRACT_OK : VM_SCHEMA_CONTRACT_OPERANDS;

        case VM_PUSH_R:
            return !hasDst && hasSrc && scalarWidth && noMemory
                ? VM_SCHEMA_CONTRACT_OK : VM_SCHEMA_CONTRACT_OPERANDS;
        case VM_PUSH_C:
            return !hasDst && !hasSrc && scalarWidth && noMemory && sourceImmediate
                ? VM_SCHEMA_CONTRACT_OK : VM_SCHEMA_CONTRACT_OPERANDS;
        case VM_PUSH_MEM:
            return !hasDst && !hasSrc && scalarWidth && sourceMemory && memoryValid
                ? VM_SCHEMA_CONTRACT_OK : VM_SCHEMA_CONTRACT_MEMORY;
        case VM_POP_R:
            return hasDst && !hasSrc && scalarWidth && noMemory
                ? VM_SCHEMA_CONTRACT_OK : VM_SCHEMA_CONTRACT_OPERANDS;
        case VM_POP_MEM:
            return !hasDst && !hasSrc && scalarWidth && destinationMemory && memoryValid
                ? VM_SCHEMA_CONTRACT_OK : VM_SCHEMA_CONTRACT_MEMORY;
        case VM_PUSHF: case VM_POPF:
            return !hasDst && !hasSrc &&
                (instruction->operandWidth == 2 || instruction->operandWidth == 4 ||
                 instruction->operandWidth == 8) && instruction->flags == 0 && noMemory
                ? VM_SCHEMA_CONTRACT_OK : VM_SCHEMA_CONTRACT_OPERANDS;
        case VM_LEAVE:
            return !hasDst && !hasSrc &&
                (instruction->operandWidth == 4 || instruction->operandWidth == 8) &&
                instruction->flags == 0 && noMemory
                ? VM_SCHEMA_CONTRACT_OK : VM_SCHEMA_CONTRACT_OPERANDS;

        case VM_BT_RR: case VM_BTS_RR: case VM_BTR_RR:
            return (hasDst || destinationMemory) && (hasSrc != sourceImmediate) &&
                (instruction->operandWidth == 2 || instruction->operandWidth == 4 ||
                 instruction->operandWidth == 8) &&
                (!destinationMemory || memoryValid) &&
                (!(instruction->flags & VM_OPERAND_ATOMIC) ||
                    (destinationMemory && instruction->opcode != VM_BT_RR))
                ? VM_SCHEMA_CONTRACT_OK : VM_SCHEMA_CONTRACT_OPERANDS;
        case VM_BSWAP:
            return hasDst && !hasSrc && noMemory &&
                (instruction->operandWidth == 4 || instruction->operandWidth == 8)
                ? VM_SCHEMA_CONTRACT_OK : VM_SCHEMA_CONTRACT_OPERANDS;
        case VM_SIGN_EXTEND_ACC: case VM_EXTEND_ACC:
            return !hasDst && !hasSrc && noMemory &&
                (instruction->operandWidth == 2 || instruction->operandWidth == 4 ||
                 instruction->operandWidth == 8)
                ? VM_SCHEMA_CONTRACT_OK : VM_SCHEMA_CONTRACT_OPERANDS;
        case VM_CLC: case VM_STC: case VM_CMC:
            return !hasDst && !hasSrc && instruction->operandWidth == 0 &&
                instruction->flags == 0 && noMemory
                ? VM_SCHEMA_CONTRACT_OK : VM_SCHEMA_CONTRACT_OPERANDS;
        case VM_LAHF: case VM_SAHF:
            return !hasDst && !hasSrc && instruction->operandWidth == 1 &&
                instruction->flags == 0 && noMemory
                ? VM_SCHEMA_CONTRACT_OK : VM_SCHEMA_CONTRACT_OPERANDS;

        case VM_JMP: case VM_JZ: case VM_JNZ: case VM_JA: case VM_JAE:
        case VM_JB: case VM_JBE: case VM_JG: case VM_JGE: case VM_JL:
        case VM_JLE: case VM_JO: case VM_JNO: case VM_JS: case VM_JNS:
        case VM_JP: case VM_JNP:
            return !hasDst && !hasSrc && instruction->operandWidth == 0 &&
                instruction->flags == 0 && noMemory &&
                instruction->condition == vm_schema_expected_branch_condition(instruction->opcode)
                ? VM_SCHEMA_CONTRACT_OK : VM_SCHEMA_CONTRACT_OPERANDS;
        case VM_CALL_VM:
            return !hasDst && !hasSrc && instruction->operandWidth == 0 &&
                instruction->flags == 0 && instruction->aux == 0 &&
                instruction->immediate != 0 && noMemory &&
                instruction->condition == VM_CONDITION_ALWAYS
                ? VM_SCHEMA_CONTRACT_OK : VM_SCHEMA_CONTRACT_CALL;
        case VM_SET_R:
            return hasDst && !hasSrc && instruction->operandWidth == 1 && noMemory &&
                instruction->condition != VM_CONDITION_ALWAYS
                ? VM_SCHEMA_CONTRACT_OK : VM_SCHEMA_CONTRACT_OPERANDS;
        case VM_SET_M:
            return !hasDst && !hasSrc && instruction->operandWidth == 1 &&
                destinationMemory && instruction->memWidth == 1 && memoryValid &&
                instruction->condition != VM_CONDITION_ALWAYS
                ? VM_SCHEMA_CONTRACT_OK : VM_SCHEMA_CONTRACT_MEMORY;

        case VM_CALL_NATIVE:
            return !hasDst && !hasSrc && noMemory && instruction->immediate != 0 &&
                instruction->flags == VM_OPERAND_NATIVE_BRIDGE &&
                vm_schema_call_aux_valid(instruction->aux)
                ? VM_SCHEMA_CONTRACT_OK : VM_SCHEMA_CONTRACT_CALL;
        case VM_CALL_IMPORT:
            return !hasDst && !hasSrc && noMemory && instruction->immediate != 0 &&
                instruction->flags ==
                    (VM_OPERAND_TARGET_IS_IMPORT | VM_OPERAND_NATIVE_BRIDGE) &&
                vm_schema_call_aux_valid(instruction->aux)
                ? VM_SCHEMA_CONTRACT_OK : VM_SCHEMA_CONTRACT_CALL;
        case VM_CALL_INDIRECT_R:
            return !hasDst && hasSrc && noMemory &&
                instruction->flags == VM_OPERAND_NATIVE_BRIDGE &&
                vm_schema_call_aux_valid(instruction->aux)
                ? VM_SCHEMA_CONTRACT_OK : VM_SCHEMA_CONTRACT_CALL;
        case VM_CALL_INDIRECT_M:
            return !hasDst && !hasSrc && sourceMemory && memoryValid &&
                instruction->flags ==
                    (VM_OPERAND_SOURCE_MEMORY | VM_OPERAND_NATIVE_BRIDGE) &&
                vm_schema_call_aux_valid(instruction->aux)
                ? VM_SCHEMA_CONTRACT_OK : VM_SCHEMA_CONTRACT_CALL;
        case VM_RET_VM:
            return !hasDst && !hasSrc && noMemory && instruction->flags == 0 &&
                instruction->aux <= 0xFFFFu
                ? VM_SCHEMA_CONTRACT_OK : VM_SCHEMA_CONTRACT_OPERANDS;
        case VM_VMEXIT:
            return !hasDst && !hasSrc && noMemory
                ? VM_SCHEMA_CONTRACT_OK : VM_SCHEMA_CONTRACT_OPERANDS;
        case VM_BRIDGE_SIMD: case VM_BRIDGE_X87: {
            const uint32_t expectedKind = instruction->opcode == VM_BRIDGE_X87
                ? VM_BRIDGE_AUX_X87 : 0u;
            return !hasDst && !hasSrc && instruction->operandWidth == 0 &&
                instruction->immediate != 0 &&
                instruction->flags == (VM_OPERAND_NATIVE_BRIDGE | VM_OPERAND_BRIDGE_LINKED) &&
                (instruction->aux & ~VM_BRIDGE_AUX_KNOWN_MASK) == 0 &&
                (instruction->aux & VM_BRIDGE_AUX_HIDDEN_REGISTER_MASK) < 16 &&
                (instruction->aux & VM_BRIDGE_AUX_X87) == expectedKind && noMemory
                ? VM_SCHEMA_CONTRACT_OK : VM_SCHEMA_CONTRACT_BRIDGE;
        }
        default:
            return VM_SCHEMA_CONTRACT_OPCODE;
    }
}

VM_SCHEMA_INLINE const char* vm_schema_contract_error_string(VM_SCHEMA_CONTRACT_ERROR error) {
    switch (error) {
        case VM_SCHEMA_CONTRACT_OK: return "ok";
        case VM_SCHEMA_CONTRACT_NULL: return "null instruction";
        case VM_SCHEMA_CONTRACT_REGISTER_COUNT: return "register count is outside 16..32";
        case VM_SCHEMA_CONTRACT_REGISTER: return "register id is outside the VM register file";
        case VM_SCHEMA_CONTRACT_WIDTH: return "operand width contract failed";
        case VM_SCHEMA_CONTRACT_MEMORY: return "memory operand contract failed";
        case VM_SCHEMA_CONTRACT_CONDITION: return "condition code contract failed";
        case VM_SCHEMA_CONTRACT_REGISTER_LANE: return "partial-register lane contract failed";
        case VM_SCHEMA_CONTRACT_FLAGS: return "instruction flags or reserved data contract failed";
        case VM_SCHEMA_CONTRACT_OPERANDS: return "opcode operand contract failed";
        case VM_SCHEMA_CONTRACT_CALL: return "native CALL contract failed";
        case VM_SCHEMA_CONTRACT_BRIDGE: return "extended-state bridge contract failed";
        case VM_SCHEMA_CONTRACT_OPCODE: return "opcode is outside the production VM schema";
        default: return "unknown VM schema contract error";
    }
}

#undef VM_SCHEMA_INLINE

#ifdef __cplusplus
}
#endif

#endif // CS_RUNTIME_VM_SCHEMA_CONTRACT_H
