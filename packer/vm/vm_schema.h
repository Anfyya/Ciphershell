#ifndef CS_VM_SCHEMA_H
#define CS_VM_SCHEMA_H

#include "../../runtime/common/vm_isa.h"
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace CipherShell {

using BytecodeInstr = VM_BYTECODE_INSTRUCTION;

enum class VMOpcodeClass : uint8_t {
    Invalid,
    Data,
    Arithmetic,
    Logical,
    Compare,
    Stack,
    ControlFlow,
    Call,
    Bridge,
    Special
};

struct VMOpcodeDescriptor {
    uint8_t opcode;
    const char* name;
    VMOpcodeClass opcodeClass;
    bool branch;
    bool conditional;
    bool terminal;
    bool runtimeSupportedX86;
    bool runtimeSupportedX64;
};

class VMSchema {
public:
    static uint32_t Version();
    static uint32_t InstructionSize();
    static const VMOpcodeDescriptor* Lookup(uint8_t opcode);
    static const std::vector<VMOpcodeDescriptor>& Opcodes();

    static bool ValidateInstruction(
        const BytecodeInstr& instruction,
        uint32_t registerCount,
        std::string& reason);

    static void Encode(
        const BytecodeInstr& instruction,
        const std::unordered_map<uint8_t, uint8_t>& opcodeMap,
        std::vector<uint8_t>& output);

    static bool Decode(
        const uint8_t* bytes,
        size_t size,
        const uint8_t reverseOpcodeMap[256],
        BytecodeInstr& instruction,
        std::string& reason);
};

} // namespace CipherShell

#endif // CS_VM_SCHEMA_H
