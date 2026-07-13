#ifndef CS_VM_MICRO_SEMANTICS_H
#define CS_VM_MICRO_SEMANTICS_H

#include "vm_schema.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace CipherShell {

enum class VMMicroFault : uint8_t {
    None,
    Decode,
    OperandStack,
    Memory,
    DivideError,
    UnsupportedSemantic,
    ControlFlow,
    StepLimit,
    ExplicitTrap
};

struct VMMicroMemoryView {
    uint8_t* data = nullptr;
    size_t size = 0;
    uint64_t baseAddress = 0;
};

struct VMMicroMachineState {
    std::array<uint64_t, 32> gpr{};
    uint64_t rflags = 0;
    std::array<uint64_t, VM_MICRO_STACK_LIMIT> operandStack{};
    uint32_t operandStackDepth = 0;
    std::array<uint64_t, VM_MICRO_TEMP_COUNT> temporaries{};
    std::array<uint32_t, VM_MAX_INTERNAL_CALL_DEPTH> callStack{};
    uint32_t callDepth = 0;
    VM_LAZY_FLAGS_RECORD lastAlu{};
    VM_LAZY_FLAGS_RECORD pendingFlags{};
    uint32_t ip = 0;
    uint64_t imageBase = 0;
    bool finished = false;
    VMMicroFault fault = VMMicroFault::None;
    uint64_t faultAddress = 0;
};

struct VMMicroExecutionOptions {
    uint32_t registerCount = 32;
    uint32_t maxSteps = 1000000;
    uint8_t addressWidth = 8;
};

struct VMMicroSemanticPlan {
    std::vector<MicroInstruction> instructions;
    std::vector<uint32_t> encodedOffsets;
    uint32_t encodedSize = 0;
};

class VMMicroSemanticExecutor {
public:
    static bool Execute(
        const uint8_t* bytecode,
        size_t bytecodeSize,
        const uint8_t reverseOpcodeMap[256],
        const VM_OPERAND_CODEC& codec,
        VMMicroMachineState& state,
        VMMicroMemoryView memory,
        const VMMicroExecutionOptions& options,
        std::string& error);

    static bool Execute(
        const VMMicroSemanticPlan& plan,
        VMMicroMachineState& state,
        VMMicroMemoryView memory,
        const VMMicroExecutionOptions& options,
        std::string& error);

    static bool ExecuteOne(
        const MicroInstruction& instruction,
        uint32_t fallthroughIp,
        VMMicroMachineState& state,
        VMMicroMemoryView memory,
        const VMMicroExecutionOptions& options,
        std::string& error);

    static uint64_t MaterializeFlags(
        VMMicroMachineState& state,
        uint32_t requestedMask);
};

} // namespace CipherShell

#endif // CS_VM_MICRO_SEMANTICS_H
