#ifndef CS_VM_SCHEMA_H
#define CS_VM_SCHEMA_H

#include "../../runtime/common/vm_isa.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace CipherShell {

enum class VMOpcodeClass : uint8_t {
    Invalid,
    Data,
    Stack,
    Memory,
    Arithmetic,
    Flags,
    ControlFlow,
    Call,
    Bridge,
    Special
};

struct VMOpcodeDescriptor {
    VM_MICRO_OPCODE opcode = VM_UOP_TRAP;
    const char* name = "TRAP";
    VMOpcodeClass opcodeClass = VMOpcodeClass::Invalid;
    uint8_t operandCount = 0;
    std::array<VM_MICRO_OPERAND_KIND, VM_MICRO_MAX_OPERANDS> operands{};
    int8_t stackPops = 0;
    int8_t stackPushes = 0;
    VM_MICRO_FLAG_EFFECT flagEffect = VM_MICRO_FLAGS_NONE;
    int8_t branchTargetOperand = -1;
    bool branch = false;
    bool conditional = false;
    bool terminal = false;
    bool runtimeSupportedX86 = true;
    bool runtimeSupportedX64 = true;
};

/* Pack-time decoded form only.  This object is never copied into the product. */
struct MicroInstruction {
    VM_MICRO_OPCODE opcode = VM_UOP_TRAP;
    uint8_t handlerVariant = 0;
    uint8_t operandCount = 0;
    std::array<uint64_t, VM_MICRO_MAX_OPERANDS> operands{};
    uint32_t sourceRva = 0;
};

struct DecodedMicroInstruction {
    MicroInstruction instruction{};
    uint32_t byteOffset = 0;
    uint32_t encodedSize = 0;
};

struct VMStreamValidation {
    bool success = false;
    uint32_t microOpCount = 0;
    uint32_t maxOperandStackDepth = 0;
    std::vector<DecodedMicroInstruction> decoded;
    std::string error;
};

class VMSchema {
public:
    static uint32_t Version();
    static const VMOpcodeDescriptor* Lookup(VM_MICRO_OPCODE opcode);
    static const VMOpcodeDescriptor* Lookup(uint8_t semanticOpcode);
    static const std::vector<VMOpcodeDescriptor>& Opcodes();

    static VM_OPERAND_CODEC DeriveOperandCodec(uint64_t buildSeed, uint32_t functionRva);
    static bool BuildRuntimeDecodePlans(
        const VM_OPERAND_CODEC& codec,
        VM_RUNTIME_DECODE_PLAN plans[VM_UOP_COUNT],
        std::string& reason);

    static bool ValidateInstruction(
        const MicroInstruction& instruction,
        uint32_t registerCount,
        std::string& reason);

    static bool Encode(
        const MicroInstruction& instruction,
        const std::unordered_map<uint8_t, uint8_t>& opcodeMap,
        const VM_OPERAND_CODEC& codec,
        std::vector<uint8_t>& output,
        std::string& reason);

    static bool DecodeOne(
        const uint8_t* bytes,
        size_t size,
        const uint8_t reverseOpcodeMap[256],
        const VM_OPERAND_CODEC& codec,
        MicroInstruction& instruction,
        uint32_t& consumed,
        std::string& reason);

    static bool DecodeStream(
        const uint8_t* bytes,
        size_t size,
        const uint8_t reverseOpcodeMap[256],
        const VM_OPERAND_CODEC& codec,
        std::vector<DecodedMicroInstruction>& decoded,
        std::string& reason);

    static VMStreamValidation ValidateStream(
        const uint8_t* bytes,
        size_t size,
        const uint8_t reverseOpcodeMap[256],
        const VM_OPERAND_CODEC& codec,
        uint32_t registerCount);

    static bool EncodedSize(
        const MicroInstruction& instruction,
        const VM_OPERAND_CODEC& codec,
        uint32_t& size,
        std::string& reason);
};

} // namespace CipherShell

#endif // CS_VM_SCHEMA_H
