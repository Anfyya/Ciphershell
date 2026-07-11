#include "vm_schema.h"

#include "../../runtime/common/vm_schema_contract.h"

#include <algorithm>
#include <cstring>

namespace CipherShell {
namespace {

#define VM_DESC(opcode, name, opcodeClass) \
    {opcode, name, opcodeClass, false, false, false, true, true}
#define VM_BRANCH(opcode, name, conditional) \
    {opcode, name, VMOpcodeClass::ControlFlow, true, conditional, false, true, true}

const std::vector<VMOpcodeDescriptor> kOpcodes = {
    VM_DESC(VM_NOP, "NOP", VMOpcodeClass::Data),
    VM_DESC(VM_MOV_RR, "MOV_RR", VMOpcodeClass::Data),
    VM_DESC(VM_MOV_RC, "MOV_RC", VMOpcodeClass::Data),
    VM_DESC(VM_MOV_RM, "MOV_RM", VMOpcodeClass::Data),
    VM_DESC(VM_MOV_MR, "MOV_MR", VMOpcodeClass::Data),
    VM_DESC(VM_MOV_MC, "MOV_MC", VMOpcodeClass::Data),
    VM_DESC(VM_LEA, "LEA", VMOpcodeClass::Data),
    VM_DESC(VM_XCHG, "XCHG", VMOpcodeClass::Data),
    VM_DESC(VM_XCHG_RM, "XCHG_RM", VMOpcodeClass::Data),
    VM_DESC(VM_MOVZX_RR, "MOVZX_RR", VMOpcodeClass::Data),
    VM_DESC(VM_MOVZX_RM, "MOVZX_RM", VMOpcodeClass::Data),
    VM_DESC(VM_MOVSX_RR, "MOVSX_RR", VMOpcodeClass::Data),
    VM_DESC(VM_MOVSX_RM, "MOVSX_RM", VMOpcodeClass::Data),
    VM_DESC(VM_MOVSXD_RR, "MOVSXD_RR", VMOpcodeClass::Data),
    VM_DESC(VM_MOVSXD_RM, "MOVSXD_RM", VMOpcodeClass::Data),

    VM_DESC(VM_PUSH_R, "PUSH_R", VMOpcodeClass::Stack),
    VM_DESC(VM_PUSH_C, "PUSH_C", VMOpcodeClass::Stack),
    VM_DESC(VM_PUSH_MEM, "PUSH_MEM", VMOpcodeClass::Stack),
    VM_DESC(VM_POP_R, "POP_R", VMOpcodeClass::Stack),
    VM_DESC(VM_POP_MEM, "POP_MEM", VMOpcodeClass::Stack),
    VM_DESC(VM_PUSHF, "PUSHF", VMOpcodeClass::Stack),
    VM_DESC(VM_POPF, "POPF", VMOpcodeClass::Stack),
    VM_DESC(VM_LEAVE, "LEAVE", VMOpcodeClass::Stack),

    VM_DESC(VM_ADD_RR, "ADD_RR", VMOpcodeClass::Arithmetic),
    VM_DESC(VM_ADD_RC, "ADD_RC", VMOpcodeClass::Arithmetic),
    VM_DESC(VM_ADD_RM, "ADD_RM", VMOpcodeClass::Arithmetic),
    VM_DESC(VM_ADD_MR, "ADD_MR", VMOpcodeClass::Arithmetic),
    VM_DESC(VM_SUB_RR, "SUB_RR", VMOpcodeClass::Arithmetic),
    VM_DESC(VM_SUB_RC, "SUB_RC", VMOpcodeClass::Arithmetic),
    VM_DESC(VM_SUB_RM, "SUB_RM", VMOpcodeClass::Arithmetic),
    VM_DESC(VM_SUB_MR, "SUB_MR", VMOpcodeClass::Arithmetic),
    VM_DESC(VM_ADC_RR, "ADC_RR", VMOpcodeClass::Arithmetic),
    VM_DESC(VM_ADC_RC, "ADC_RC", VMOpcodeClass::Arithmetic),
    VM_DESC(VM_ADC_RM, "ADC_RM", VMOpcodeClass::Arithmetic),
    VM_DESC(VM_ADC_MR, "ADC_MR", VMOpcodeClass::Arithmetic),
    VM_DESC(VM_SBB_RR, "SBB_RR", VMOpcodeClass::Arithmetic),
    VM_DESC(VM_SBB_RC, "SBB_RC", VMOpcodeClass::Arithmetic),
    VM_DESC(VM_SBB_RM, "SBB_RM", VMOpcodeClass::Arithmetic),
    VM_DESC(VM_SBB_MR, "SBB_MR", VMOpcodeClass::Arithmetic),
    VM_DESC(VM_NEG_R, "NEG_R", VMOpcodeClass::Arithmetic),
    VM_DESC(VM_NEG_M, "NEG_M", VMOpcodeClass::Arithmetic),
    VM_DESC(VM_INC_R, "INC_R", VMOpcodeClass::Arithmetic),
    VM_DESC(VM_INC_M, "INC_M", VMOpcodeClass::Arithmetic),
    VM_DESC(VM_DEC_R, "DEC_R", VMOpcodeClass::Arithmetic),
    VM_DESC(VM_DEC_M, "DEC_M", VMOpcodeClass::Arithmetic),
    VM_DESC(VM_MUL_RR, "MUL", VMOpcodeClass::Arithmetic),
    VM_DESC(VM_IMUL_RR, "IMUL_RR", VMOpcodeClass::Arithmetic),
    VM_DESC(VM_IMUL_RRC, "IMUL_RRC", VMOpcodeClass::Arithmetic),
    VM_DESC(VM_DIV_RR, "DIV", VMOpcodeClass::Arithmetic),
    VM_DESC(VM_IDIV_RR, "IDIV", VMOpcodeClass::Arithmetic),
    VM_DESC(VM_SIGN_EXTEND_ACC, "SIGN_EXTEND_ACC", VMOpcodeClass::Arithmetic),
    VM_DESC(VM_EXTEND_ACC, "EXTEND_ACC", VMOpcodeClass::Arithmetic),

    VM_DESC(VM_AND_RR, "AND_RR", VMOpcodeClass::Logical),
    VM_DESC(VM_AND_RC, "AND_RC", VMOpcodeClass::Logical),
    VM_DESC(VM_AND_RM, "AND_RM", VMOpcodeClass::Logical),
    VM_DESC(VM_AND_MR, "AND_MR", VMOpcodeClass::Logical),
    VM_DESC(VM_OR_RR, "OR_RR", VMOpcodeClass::Logical),
    VM_DESC(VM_OR_RC, "OR_RC", VMOpcodeClass::Logical),
    VM_DESC(VM_OR_RM, "OR_RM", VMOpcodeClass::Logical),
    VM_DESC(VM_OR_MR, "OR_MR", VMOpcodeClass::Logical),
    VM_DESC(VM_XOR_RR, "XOR_RR", VMOpcodeClass::Logical),
    VM_DESC(VM_XOR_RC, "XOR_RC", VMOpcodeClass::Logical),
    VM_DESC(VM_XOR_RM, "XOR_RM", VMOpcodeClass::Logical),
    VM_DESC(VM_XOR_MR, "XOR_MR", VMOpcodeClass::Logical),
    VM_DESC(VM_NOT_R, "NOT", VMOpcodeClass::Logical),
    VM_DESC(VM_SHL_RR, "SHL_RR", VMOpcodeClass::Logical),
    VM_DESC(VM_SHL_RC, "SHL_RC", VMOpcodeClass::Logical),
    VM_DESC(VM_SHR_RR, "SHR_RR", VMOpcodeClass::Logical),
    VM_DESC(VM_SHR_RC, "SHR_RC", VMOpcodeClass::Logical),
    VM_DESC(VM_SAR_RR, "SAR_RR", VMOpcodeClass::Logical),
    VM_DESC(VM_SAR_RC, "SAR_RC", VMOpcodeClass::Logical),
    VM_DESC(VM_ROL_RR, "ROL_RR", VMOpcodeClass::Logical),
    VM_DESC(VM_ROL_RC, "ROL_RC", VMOpcodeClass::Logical),
    VM_DESC(VM_ROR_RR, "ROR_RR", VMOpcodeClass::Logical),
    VM_DESC(VM_ROR_RC, "ROR_RC", VMOpcodeClass::Logical),
    VM_DESC(VM_SHL_MR, "SHL_MR", VMOpcodeClass::Logical),
    VM_DESC(VM_SHL_MC, "SHL_MC", VMOpcodeClass::Logical),
    VM_DESC(VM_SHR_MR, "SHR_MR", VMOpcodeClass::Logical),
    VM_DESC(VM_SHR_MC, "SHR_MC", VMOpcodeClass::Logical),
    VM_DESC(VM_SAR_MR, "SAR_MR", VMOpcodeClass::Logical),
    VM_DESC(VM_SAR_MC, "SAR_MC", VMOpcodeClass::Logical),
    VM_DESC(VM_ROL_MR, "ROL_MR", VMOpcodeClass::Logical),
    VM_DESC(VM_ROL_MC, "ROL_MC", VMOpcodeClass::Logical),
    VM_DESC(VM_ROR_MR, "ROR_MR", VMOpcodeClass::Logical),
    VM_DESC(VM_ROR_MC, "ROR_MC", VMOpcodeClass::Logical),
    VM_DESC(VM_BT_RR, "BT", VMOpcodeClass::Logical),
    VM_DESC(VM_BTS_RR, "BTS", VMOpcodeClass::Logical),
    VM_DESC(VM_BTR_RR, "BTR", VMOpcodeClass::Logical),
    VM_DESC(VM_CLC, "CLC", VMOpcodeClass::Logical),
    VM_DESC(VM_STC, "STC", VMOpcodeClass::Logical),
    VM_DESC(VM_CMC, "CMC", VMOpcodeClass::Logical),

    VM_DESC(VM_BSWAP, "BSWAP", VMOpcodeClass::Data),
    VM_DESC(VM_LAHF, "LAHF", VMOpcodeClass::Data),
    VM_DESC(VM_SAHF, "SAHF", VMOpcodeClass::Data),

    VM_DESC(VM_CMP_RR, "CMP_RR", VMOpcodeClass::Compare),
    VM_DESC(VM_CMP_RC, "CMP_RC", VMOpcodeClass::Compare),
    VM_DESC(VM_CMP_RM, "CMP_RM", VMOpcodeClass::Compare),
    VM_DESC(VM_CMP_MR, "CMP_MR", VMOpcodeClass::Compare),
    VM_DESC(VM_TEST_RR, "TEST_RR", VMOpcodeClass::Compare),
    VM_DESC(VM_TEST_RC, "TEST_RC", VMOpcodeClass::Compare),
    VM_DESC(VM_TEST_RM, "TEST_RM", VMOpcodeClass::Compare),
    VM_DESC(VM_TEST_MR, "TEST_MR", VMOpcodeClass::Compare),

    VM_BRANCH(VM_JMP, "JMP", false),
    VM_BRANCH(VM_JZ, "JZ", true), VM_BRANCH(VM_JNZ, "JNZ", true),
    VM_BRANCH(VM_JA, "JA", true), VM_BRANCH(VM_JAE, "JAE", true),
    VM_BRANCH(VM_JB, "JB", true), VM_BRANCH(VM_JBE, "JBE", true),
    VM_BRANCH(VM_JG, "JG", true), VM_BRANCH(VM_JGE, "JGE", true),
    VM_BRANCH(VM_JL, "JL", true), VM_BRANCH(VM_JLE, "JLE", true),
    VM_BRANCH(VM_JO, "JO", true), VM_BRANCH(VM_JNO, "JNO", true),
    VM_BRANCH(VM_JS, "JS", true), VM_BRANCH(VM_JNS, "JNS", true),
    VM_BRANCH(VM_JP, "JP", true), VM_BRANCH(VM_JNP, "JNP", true),
    VM_DESC(VM_CMOV_RR, "CMOV_RR", VMOpcodeClass::ControlFlow),
    VM_DESC(VM_CMOV_RM, "CMOV_RM", VMOpcodeClass::ControlFlow),
    VM_DESC(VM_SET_R, "SET_R", VMOpcodeClass::ControlFlow),
    VM_DESC(VM_SET_M, "SET_M", VMOpcodeClass::ControlFlow),
    {VM_CALL_VM, "CALL_VM", VMOpcodeClass::Call, true, false, false, true, true},
    VM_DESC(VM_CALL_NATIVE, "CALL_NATIVE", VMOpcodeClass::Call),
    VM_DESC(VM_CALL_IMPORT, "CALL_IMPORT", VMOpcodeClass::Call),
    VM_DESC(VM_CALL_INDIRECT_R, "CALL_INDIRECT_R", VMOpcodeClass::Call),
    VM_DESC(VM_CALL_INDIRECT_M, "CALL_INDIRECT_M", VMOpcodeClass::Call),
    {VM_RET_VM, "RET", VMOpcodeClass::ControlFlow, false, false, true, true, true},
    {VM_VMEXIT, "VMEXIT", VMOpcodeClass::ControlFlow, false, false, true, true, true},
    VM_DESC(VM_BRIDGE_SIMD, "BRIDGE_SIMD", VMOpcodeClass::Bridge),
    VM_DESC(VM_BRIDGE_X87, "BRIDGE_X87", VMOpcodeClass::Bridge)
};

#undef VM_DESC
#undef VM_BRANCH

} // namespace

uint32_t VMSchema::Version() { return VM_SCHEMA_VERSION; }
uint32_t VMSchema::InstructionSize() { return VM_INSTRUCTION_SIZE; }

const std::vector<VMOpcodeDescriptor>& VMSchema::Opcodes() { return kOpcodes; }

const VMOpcodeDescriptor* VMSchema::Lookup(uint8_t opcode) {
    const auto found = std::find_if(kOpcodes.begin(), kOpcodes.end(),
        [opcode](const VMOpcodeDescriptor& descriptor) {
            return descriptor.opcode == opcode;
        });
    return found == kOpcodes.end() ? nullptr : &*found;
}

bool VMSchema::ValidateInstruction(
    const BytecodeInstr& instruction,
    uint32_t registerCount,
    std::string& reason)
{
    const VM_SCHEMA_CONTRACT_ERROR error =
        vm_schema_validate_instruction(&instruction, registerCount);
    if (error != VM_SCHEMA_CONTRACT_OK) {
        reason = vm_schema_contract_error_string(error);
        return false;
    }
    return true;
}

void VMSchema::Encode(
    const BytecodeInstr& instruction,
    const std::unordered_map<uint8_t, uint8_t>& opcodeMap,
    std::vector<uint8_t>& output)
{
    BytecodeInstr encoded = instruction;
    const auto mapped = opcodeMap.find(instruction.opcode);
    if (mapped != opcodeMap.end()) encoded.opcode = mapped->second;
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&encoded);
    output.insert(output.end(), bytes, bytes + sizeof(encoded));
}

bool VMSchema::Decode(
    const uint8_t* bytes,
    size_t size,
    const uint8_t reverseOpcodeMap[256],
    BytecodeInstr& instruction,
    std::string& reason)
{
    if (!bytes || !reverseOpcodeMap || size < sizeof(instruction)) {
        reason = "truncated VM instruction";
        return false;
    }
    std::memcpy(&instruction, bytes, sizeof(instruction));
    instruction.opcode = reverseOpcodeMap[instruction.opcode];
    if (!Lookup(instruction.opcode)) {
        reason = "opcode has no production schema descriptor";
        return false;
    }
    return true;
}

} // namespace CipherShell
