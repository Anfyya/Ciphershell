#include "vm_verifier.h"

#include "../../runtime/common/vm_crypto.h"
#include "../pe_parser/pe_emitter.h"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <map>
#include <unordered_set>

namespace CipherShell {
namespace {

void DecodeMasterKey(
    const VM_METADATA_HEADER& header,
    const std::array<uint8_t, VM_RUNTIME_KEY_SHARE_SIZE>& runtimeKeyShare,
    uint8_t output[32]) {
    for (uint32_t i = 0; i < 32; ++i) {
        const uint8_t cookieByte = static_cast<uint8_t>(header.cookie >> ((i & 3u) * 8u));
        output[i] = header.encodedMasterKey[i] ^ runtimeKeyShare[i] ^
            header.buildId[i & 15u] ^
            cookieByte ^ static_cast<uint8_t>(i * 0x5Bu);
    }
}

bool BuildReverseMap(
    const std::unordered_map<uint8_t, uint8_t>& opcodeMap,
    uint8_t reverse[256],
    std::string& error)
{
    if (opcodeMap.size() != 256) {
        error = "opcode map is not a complete permutation";
        return false;
    }
    std::array<uint8_t, 256> seen{};
    for (const auto& item : opcodeMap) {
        if (seen[item.second]) {
            error = "opcode map is not injective";
            return false;
        }
        seen[item.second] = 1;
        reverse[item.second] = item.first;
    }
    return true;
}

bool OpcodeWritesRegisterDestination(uint8_t opcode) {
    switch (opcode) {
        case VM_MOV_RR: case VM_MOV_RC: case VM_MOV_RM:
        case VM_MOVZX_RR: case VM_MOVZX_RM: case VM_MOVSX_RR: case VM_MOVSX_RM:
        case VM_MOVSXD_RR: case VM_MOVSXD_RM: case VM_LEA: case VM_XCHG:
        case VM_XCHG_RM: case VM_ADD_RR: case VM_ADD_RC: case VM_ADD_RM:
        case VM_ADC_RR: case VM_ADC_RC: case VM_ADC_RM:
        case VM_SUB_RR: case VM_SUB_RC: case VM_SUB_RM:
        case VM_SBB_RR: case VM_SBB_RC: case VM_SBB_RM:
        case VM_AND_RR: case VM_AND_RC: case VM_AND_RM:
        case VM_OR_RR: case VM_OR_RC: case VM_OR_RM:
        case VM_XOR_RR: case VM_XOR_RC: case VM_XOR_RM:
        case VM_NOT_R: case VM_NEG_R: case VM_INC_R: case VM_DEC_R:
        case VM_SHL_RR: case VM_SHL_RC: case VM_SHR_RR: case VM_SHR_RC:
        case VM_SAR_RR: case VM_SAR_RC: case VM_ROL_RR: case VM_ROL_RC:
        case VM_ROR_RR: case VM_ROR_RC: case VM_IMUL_RR: case VM_IMUL_RRC:
        case VM_POP_R: case VM_CMOV_RR: case VM_CMOV_RM: case VM_SET_R:
        case VM_BTS_RR: case VM_BTR_RR: case VM_BSWAP:
            return true;
        default:
            return false;
    }
}

bool IsNativeCallOpcode(uint8_t opcode) {
    return opcode == VM_CALL_NATIVE || opcode == VM_CALL_IMPORT ||
        opcode == VM_CALL_INDIRECT_R || opcode == VM_CALL_INDIRECT_M;
}

uint32_t NativeStackWidth(bool is64Bit) { return is64Bit ? 8u : 4u; }

uint32_t StackInstructionWidth(const BytecodeInstr& instruction, bool is64Bit) {
    return instruction.operandWidth == 2 ? 2u : NativeStackWidth(is64Bit);
}

bool DecodeSignedImmediate(const BytecodeInstr& instruction, int64_t& value) {
    const uint8_t width = instruction.operandWidth;
    if (width == 8) {
        value = static_cast<int64_t>(instruction.immediate);
        return true;
    }
    if (width == 4) {
        value = (instruction.flags & VM_OPERAND_IMMEDIATE_SIGNED)
            ? static_cast<int32_t>(instruction.immediate)
            : static_cast<int64_t>(static_cast<uint32_t>(instruction.immediate));
        return true;
    }
    return false;
}

} // namespace

VMRecordVerification VMBytecodeVerifier::VerifyPlainRecord(
    const VMFunctionRecord& record,
    const std::vector<uint8_t>& bytecode,
    const std::unordered_map<uint8_t, uint8_t>& opcodeMap,
    const std::unordered_map<uint8_t, uint8_t>& registerMap,
    uint32_t registerCount,
    bool is64Bit)
{
    VMRecordVerification result{};
    if (record.bytecodeOffset > bytecode.size() ||
        record.bytecodeSize > bytecode.size() - record.bytecodeOffset ||
        record.bytecodeSize == 0 || record.bytecodeSize % VMSchema::InstructionSize() != 0) {
        result.error = "record bytecode range violates fixed schema";
        return result;
    }
    if (record.guestStackSize < 0x4000u || record.guestStackSize > 0x70000u ||
        (record.guestStackSize & 0x0FFFu) != 0) {
        result.error = "record guest stack reserve is invalid";
        return result;
    }
    uint8_t reverse[256]{};
    if (!BuildReverseMap(opcodeMap, reverse, result.error)) return result;
    const auto stackMapping = registerMap.find(4);
    const auto frameMapping = registerMap.find(5);
    if (stackMapping == registerMap.end() || frameMapping == registerMap.end() ||
        stackMapping->second >= registerCount || frameMapping->second >= registerCount ||
        stackMapping->second == frameMapping->second) {
        result.error = "RSP/RBP register mapping is missing or non-injective";
        return result;
    }
    const uint8_t stackRegister = stackMapping->second;
    const uint8_t frameRegister = frameMapping->second;

    const uint32_t count = record.bytecodeSize / VMSchema::InstructionSize();
    std::vector<BytecodeInstr> instructions(count);
    for (uint32_t i = 0; i < count; ++i) {
        const uint8_t* encoded = bytecode.data() + record.bytecodeOffset +
            static_cast<size_t>(i) * VMSchema::InstructionSize();
        std::string decodeError;
        if (!VMSchema::Decode(encoded, VMSchema::InstructionSize(), reverse,
                instructions[i], decodeError)) {
            result.error = "instruction decode failed at offset " +
                std::to_string(i * VMSchema::InstructionSize()) + ": " + decodeError;
            return result;
        }
        std::string schemaError;
        if (!VMSchema::ValidateInstruction(instructions[i], registerCount, schemaError)) {
            result.error = "instruction schema validation failed at offset " +
                std::to_string(i * VMSchema::InstructionSize()) + ": " + schemaError;
            return result;
        }
        const auto* descriptor = VMSchema::Lookup(instructions[i].opcode);
        if (!descriptor || (is64Bit ? !descriptor->runtimeSupportedX64 : !descriptor->runtimeSupportedX86)) {
            result.error = "runtime has no handler for opcode at offset " +
                std::to_string(i * VMSchema::InstructionSize());
            return result;
        }
        if (descriptor->branch) {
            const uint32_t target = instructions[i].branchTargetOffset;
            if (target >= record.bytecodeSize || target % VMSchema::InstructionSize() != 0) {
                result.error = "branch target is outside record or not an instruction boundary";
                return result;
            }
        }
        if (instructions[i].opcode == VM_CALL_VM) {
            const uint64_t functionEnd = static_cast<uint64_t>(record.functionRVA) +
                record.functionSize;
            if (instructions[i].immediate < record.functionRVA ||
                instructions[i].immediate >= functionEnd) {
                result.error = "CALL_VM native return RVA is outside the protected function";
                return result;
            }
        }
        if (is64Bit && instructions[i].opcode == VM_RET_VM && instructions[i].aux != 0) {
            result.error = "x64 RET uses stack cleanup outside the Windows x64 ABI";
            return result;
        }
    }

    struct FlowKey {
        uint32_t index = 0;
        std::vector<uint32_t> returns;
        int64_t stackOffset = 0;
        int64_t frameOffset = 0;
        bool frameKnown = false;
        bool abiAmbiguous = false;
        uint8_t entryStackModulo16 = 0;
        bool operator<(const FlowKey& other) const {
            if (index != other.index) return index < other.index;
            if (returns != other.returns) return returns < other.returns;
            if (stackOffset != other.stackOffset) return stackOffset < other.stackOffset;
            if (frameKnown != other.frameKnown) return frameKnown < other.frameKnown;
            if (frameOffset != other.frameOffset) return frameOffset < other.frameOffset;
            if (abiAmbiguous != other.abiAmbiguous) return abiAmbiguous < other.abiAmbiguous;
            return entryStackModulo16 < other.entryStackModulo16;
        }
    };
    std::vector<FlowKey> worklist;
    if (is64Bit) {
        FlowKey entry{};
        entry.entryStackModulo16 = 8;
        worklist.push_back(entry);
    } else {
        for (uint8_t residue = 0; residue < 16; residue += 4) {
            FlowKey entry{};
            entry.entryStackModulo16 = residue;
            worklist.push_back(entry);
        }
    }
    std::map<FlowKey, uint8_t> visited;
    bool reachableTerminal = false;
    bool sawUnbalancedTerminal = false;
    bool sawTerminalReturn = false;
    uint32_t terminalReturnStackCleanup = 0;
    uint32_t maxGuestStackUsage = 0;
    auto adjustStack = [&](FlowKey& flow, int64_t delta, const char* operation) {
        if ((delta > 0 && flow.stackOffset > INT64_MAX - delta) ||
            (delta < 0 && flow.stackOffset < INT64_MIN - delta)) {
            result.error = std::string(operation) + " overflows symbolic RSP";
            return false;
        }
        flow.stackOffset += delta;
        if (flow.stackOffset < -static_cast<int64_t>(record.guestStackSize)) {
            result.error = std::string(operation) + " exceeds the configured guest stack reserve";
            return false;
        }
        if (flow.stackOffset < 0) {
            maxGuestStackUsage = (std::max)(maxGuestStackUsage,
                static_cast<uint32_t>(-flow.stackOffset));
        }
        return true;
    };
    auto setStackOffset = [&](FlowKey& flow, int64_t replacement, const char* operation) {
        if (replacement < -static_cast<int64_t>(record.guestStackSize)) {
            result.error = std::string(operation) + " exceeds the configured guest stack reserve";
            return false;
        }
        flow.stackOffset = replacement;
        if (replacement < 0) {
            maxGuestStackUsage = (std::max)(maxGuestStackUsage,
                static_cast<uint32_t>(-replacement));
        }
        return true;
    };
    auto applyStackImmediate = [&](FlowKey& flow, int64_t immediate, bool subtract,
                                   const char* operation) {
        if (subtract && immediate == INT64_MIN) {
            result.error = std::string(operation) + " overflows symbolic RSP";
            return false;
        }
        return adjustStack(flow, subtract ? -immediate : immediate, operation);
    };
    auto adjustFrame = [&](FlowKey& flow, int64_t delta, const char* operation) {
        if ((delta > 0 && flow.frameOffset > INT64_MAX - delta) ||
            (delta < 0 && flow.frameOffset < INT64_MIN - delta)) {
            result.error = std::string(operation) + " overflows symbolic RBP";
            return false;
        }
        flow.frameOffset += delta;
        return true;
    };
    auto setStackFromAddress = [&](FlowKey& flow, const BytecodeInstr& instruction,
                                   const char* operation) {
        if (instruction.memoryKind != VM_MEMORY_NATIVE ||
            instruction.memIndex != VM_REGISTER_INVALID) {
            result.error = std::string(operation) + " uses a non-symbolic RSP address";
            return false;
        }
        int64_t base = 0;
        if (instruction.memBase == stackRegister) base = flow.stackOffset;
        else if (instruction.memBase == frameRegister && flow.frameKnown) base = flow.frameOffset;
        else {
            result.error = std::string(operation) + " has an unknown RSP base";
            return false;
        }
        if ((instruction.memDisp > 0 && base > INT64_MAX - instruction.memDisp) ||
            (instruction.memDisp < 0 && base < INT64_MIN - instruction.memDisp)) {
            result.error = std::string(operation) + " overflows symbolic RSP";
            return false;
        }
        return setStackOffset(flow, base + instruction.memDisp, operation);
    };
    auto verifyStackMemory = [&](const FlowKey& flow, const BytecodeInstr& instruction) {
        const bool accessesMemory = (instruction.flags &
            (VM_OPERAND_SOURCE_MEMORY | VM_OPERAND_DEST_MEMORY)) != 0;
        if (!accessesMemory || instruction.memoryKind != VM_MEMORY_NATIVE) return true;
        if (instruction.memIndex == stackRegister || instruction.memIndex == frameRegister) {
            result.error = "stack/frame register used as an unbounded memory index";
            return false;
        }
        bool stackRelative = false;
        int64_t base = 0;
        if (instruction.memBase == stackRegister) {
            stackRelative = true;
            base = flow.stackOffset;
        } else if (instruction.memBase == frameRegister && flow.frameKnown) {
            stackRelative = true;
            base = flow.frameOffset;
        }
        if (!stackRelative) return true;
        if (instruction.memIndex != VM_REGISTER_INVALID) {
            result.error = "indexed stack memory access is not statically bounded";
            return false;
        }
        if ((instruction.memDisp > 0 && base > INT64_MAX - instruction.memDisp) ||
            (instruction.memDisp < 0 && base < INT64_MIN - instruction.memDisp)) {
            result.error = "stack memory address overflows symbolic range";
            return false;
        }
        const int64_t addressOffset = base + instruction.memDisp;
        if (addressOffset < -static_cast<int64_t>(record.guestStackSize)) {
            result.error = "stack memory access exceeds the configured guest stack reserve";
            return false;
        }
        if (addressOffset < 0) {
            maxGuestStackUsage = (std::max)(maxGuestStackUsage,
                static_cast<uint32_t>(-addressOffset));
        }
        if (instruction.memWidth > 0 && addressOffset > INT64_MAX - instruction.memWidth) {
            result.error = "stack memory access end overflows symbolic range";
            return false;
        }
        return true;
    };
    while (!worklist.empty()) {
        FlowKey state = std::move(worklist.back());
        worklist.pop_back();
        if (state.index >= count ||
            !visited.emplace(state, static_cast<uint8_t>(1)).second) continue;
        const BytecodeInstr& instruction = instructions[state.index];
        const auto* descriptor = VMSchema::Lookup(instruction.opcode);
        if (!descriptor) {
            result.error = "reachable opcode descriptor disappeared";
            return result;
        }
        const bool stackDestination = instruction.dst == stackRegister &&
            OpcodeWritesRegisterDestination(instruction.opcode);
        const bool frameDestination = instruction.dst == frameRegister &&
            OpcodeWritesRegisterDestination(instruction.opcode);
        bool destinationHandled = false;
        if (instruction.opcode != VM_POP_MEM &&
            !verifyStackMemory(state, instruction)) return result;

        switch (instruction.opcode) {
            case VM_PUSH_R: case VM_PUSH_C: case VM_PUSH_MEM:
            case VM_PUSHF:
                if (!adjustStack(state,
                        -static_cast<int64_t>(StackInstructionWidth(instruction, is64Bit)),
                        "PUSH")) return result;
                break;
            case VM_POP_R: case VM_POP_MEM: case VM_POPF:
                if (!adjustStack(state,
                        static_cast<int64_t>(StackInstructionWidth(instruction, is64Bit)),
                        "POP")) return result;
                if (instruction.opcode == VM_POP_R && instruction.dst == stackRegister) {
                    result.error = "POP into RSP/ESP is not statically bounded";
                    return result;
                }
                if (instruction.opcode == VM_POP_R && instruction.dst == frameRegister) {
                    state.frameKnown = false;
                    destinationHandled = true;
                }
                break;
            case VM_LEAVE:
                if (!state.frameKnown) {
                    result.error = "LEAVE reached with an unknown RBP/EBP relation";
                    return result;
                }
                if (state.frameOffset > INT64_MAX - instruction.operandWidth) {
                    result.error = "LEAVE overflows symbolic RSP";
                    return result;
                }
                if (!setStackOffset(state,
                        state.frameOffset + static_cast<int64_t>(instruction.operandWidth),
                        "LEAVE")) return result;
                state.frameKnown = false;
                destinationHandled = true;
                break;
            default:
                break;
        }
        if (instruction.opcode == VM_POP_MEM &&
            !verifyStackMemory(state, instruction)) return result;

        if (instruction.opcode == VM_XCHG &&
            (instruction.src == stackRegister || instruction.dst == stackRegister)) {
            result.error = "XCHG involving RSP/ESP is not statically bounded";
            return result;
        }
        if (instruction.opcode == VM_XCHG &&
            (instruction.src == frameRegister || instruction.dst == frameRegister)) {
            state.frameKnown = false;
        }

        if (stackDestination && !destinationHandled) {
            int64_t immediate = 0;
            switch (instruction.opcode) {
                case VM_MOV_RR:
                    if (instruction.src == stackRegister) {
                        destinationHandled = true;
                    } else if (instruction.src == frameRegister && state.frameKnown) {
                        if (!setStackOffset(state, state.frameOffset, "MOV RSP,RBP")) {
                            return result;
                        }
                        destinationHandled = true;
                    }
                    break;
                case VM_LEA:
                    if (!setStackFromAddress(state, instruction, "LEA RSP")) return result;
                    destinationHandled = true;
                    break;
                case VM_ADD_RC: case VM_SUB_RC:
                    if (!DecodeSignedImmediate(instruction, immediate)) break;
                    if (!applyStackImmediate(state, immediate,
                            instruction.opcode == VM_SUB_RC,
                            instruction.opcode == VM_ADD_RC ? "ADD RSP" : "SUB RSP")) {
                        return result;
                    }
                    destinationHandled = true;
                    break;
                case VM_INC_R:
                    if (!adjustStack(state, 1, "INC RSP")) return result;
                    destinationHandled = true;
                    break;
                case VM_DEC_R:
                    if (!adjustStack(state, -1, "DEC RSP")) return result;
                    destinationHandled = true;
                    break;
                case VM_AND_RC: {
                    const uint64_t widthMask = instruction.operandWidth == 8
                        ? UINT64_MAX : 0xFFFFFFFFULL;
                    const uint64_t mask = instruction.immediate & widthMask;
                    const uint64_t lowMask = (~mask) & widthMask;
                    const uint64_t alignment = lowMask + 1u;
                    if (alignment == 0 || alignment > 16 ||
                        (alignment & (alignment - 1u)) != 0) break;
                    const int64_t residue = (state.entryStackModulo16 + state.stackOffset) &
                        static_cast<int64_t>(alignment - 1u);
                    if (!adjustStack(state, -residue, "AND RSP")) return result;
                    destinationHandled = true;
                    break;
                }
                default:
                    break;
            }
            if (!destinationHandled) {
                result.error = "reachable instruction writes RSP/ESP with an unbounded expression";
                return result;
            }
        }

        if (frameDestination && !destinationHandled) {
            int64_t immediate = 0;
            switch (instruction.opcode) {
                case VM_MOV_RR:
                    if (instruction.src == stackRegister) {
                        state.frameOffset = state.stackOffset;
                        state.frameKnown = true;
                    } else if (instruction.src != frameRegister) {
                        state.frameKnown = false;
                    }
                    break;
                case VM_LEA:
                    if (instruction.memoryKind == VM_MEMORY_NATIVE &&
                        instruction.memIndex == VM_REGISTER_INVALID &&
                        (instruction.memBase == stackRegister ||
                         (instruction.memBase == frameRegister && state.frameKnown))) {
                        const int64_t base = instruction.memBase == stackRegister
                            ? state.stackOffset : state.frameOffset;
                        if ((instruction.memDisp > 0 && base > INT64_MAX - instruction.memDisp) ||
                            (instruction.memDisp < 0 && base < INT64_MIN - instruction.memDisp)) {
                            result.error = "LEA RBP overflows symbolic frame state";
                            return result;
                        }
                        state.frameOffset = base + instruction.memDisp;
                        state.frameKnown = true;
                    } else state.frameKnown = false;
                    break;
                case VM_ADD_RC: case VM_SUB_RC:
                    if (state.frameKnown && DecodeSignedImmediate(instruction, immediate)) {
                        if (instruction.opcode == VM_SUB_RC && immediate == INT64_MIN) {
                            result.error = "SUB RBP overflows symbolic frame state";
                            return result;
                        }
                        if (!adjustFrame(state,
                                instruction.opcode == VM_ADD_RC ? immediate : -immediate,
                                instruction.opcode == VM_ADD_RC ? "ADD RBP" : "SUB RBP")) {
                            return result;
                        }
                    } else state.frameKnown = false;
                    break;
                case VM_INC_R:
                    if (state.frameKnown && !adjustFrame(state, 1, "INC RBP")) return result;
                    break;
                case VM_DEC_R:
                    if (state.frameKnown && !adjustFrame(state, -1, "DEC RBP")) return result;
                    break;
                default:
                    state.frameKnown = false;
                    break;
            }
        }

        if (instruction.opcode == VM_RET_VM) {
            if (state.returns.empty()) {
                if (state.stackOffset != 0) {
                    if (!state.abiAmbiguous) {
                        result.error = "reachable terminal RET has an unbalanced guest stack";
                        return result;
                    }
                    sawUnbalancedTerminal = true;
                    continue;
                }
                reachableTerminal = true;
                if (!sawTerminalReturn) {
                    terminalReturnStackCleanup = instruction.aux;
                    sawTerminalReturn = true;
                } else if (terminalReturnStackCleanup != instruction.aux) {
                    result.error = "reachable terminal RET paths use inconsistent stack cleanup";
                    return result;
                }
            }
            else {
                if (!adjustStack(state,
                        static_cast<int64_t>(NativeStackWidth(is64Bit) + instruction.aux),
                        "internal RET")) return result;
                state.index = state.returns.back();
                state.returns.pop_back();
                worklist.push_back(std::move(state));
            }
            continue;
        }
        if (instruction.opcode == VM_VMEXIT) {
            if (!state.returns.empty()) {
                result.error = "VMEXIT is reachable with a nonempty VM CALL stack";
                return result;
            }
            if (state.stackOffset != 0) {
                if (!state.abiAmbiguous) {
                    result.error = "reachable VMEXIT has an unbalanced guest stack";
                    return result;
                }
                sawUnbalancedTerminal = true;
                continue;
            }
            reachableTerminal = true;
            continue;
        }
        if (instruction.opcode == VM_CALL_VM) {
            if (state.returns.size() >= VM_MAX_INTERNAL_CALL_DEPTH) {
                result.error = "VM CALL stack exceeds the runtime depth bound";
                return result;
            }
            if (state.index + 1 >= count) {
                result.error = "CALL_VM return address falls off record";
                return result;
            }
            if (!adjustStack(state, -static_cast<int64_t>(NativeStackWidth(is64Bit)),
                    "internal CALL")) return result;
            state.returns.push_back(state.index + 1);
            state.index = instruction.branchTargetOffset / VMSchema::InstructionSize();
            worklist.push_back(std::move(state));
        } else if (IsNativeCallOpcode(instruction.opcode)) {
            if (state.index + 1 >= count) {
                result.error = "native CALL return address falls off record";
                return result;
            }
            const uint32_t abi = VM_CALL_AUX_ABI(instruction.aux);
            const uint32_t cleanup = VM_CALL_AUX_STACK_BYTES(instruction.aux);
            if (!is64Bit && abi == VM_ABI_X86_AUTO && cleanup != 0) {
                state.abiAmbiguous = true;
                FlowKey calleeCleanup = state;
                if (!adjustStack(calleeCleanup, cleanup, "x86 automatic callee cleanup")) {
                    return result;
                }
                calleeCleanup.index++;
                worklist.push_back(std::move(calleeCleanup));
            } else if (!is64Bit && abi != VM_ABI_X86_CDECL && abi != VM_ABI_X86_AUTO) {
                if (!adjustStack(state, cleanup, "x86 callee cleanup")) return result;
            }
            ++state.index;
            worklist.push_back(std::move(state));
        } else if (descriptor->branch) {
            FlowKey branch = state;
            branch.index = instruction.branchTargetOffset / VMSchema::InstructionSize();
            worklist.push_back(std::move(branch));
            if (descriptor->conditional) {
                if (state.index + 1 >= count) {
                    result.error = "conditional branch falls off record";
                    return result;
                }
                ++state.index;
                worklist.push_back(std::move(state));
            }
        } else {
            if (state.index + 1 >= count) {
                result.error = "reachable control flow falls off record without RET/VMEXIT";
                return result;
            }
            ++state.index;
            worklist.push_back(std::move(state));
        }
        if (visited.size() > 1000000u) {
            result.error = "VM control-flow state space exceeds the static verifier bound";
            return result;
        }
    }
    if (!reachableTerminal) {
        result.error = sawUnbalancedTerminal
            ? "all reachable terminal paths have an unbalanced guest stack"
            : "record has no reachable RET/VMEXIT";
        return result;
    }
    if (!sawTerminalReturn || record.returnStackCleanup != terminalReturnStackCleanup) {
        result.error = "record RET cleanup does not match reachable terminal RET semantics";
        return result;
    }
    result.success = true;
    result.instructionCount = count;
    result.maxGuestStackUsage = maxGuestStackUsage;
    return result;
}

bool VMBytecodeVerifier::VerifyEmittedMetadataAndBytecode(
    CS_PE_IMAGE* image,
    uint32_t metadataRVA,
    const std::vector<VMFunctionRecord>& expectedRecords,
    const std::vector<uint8_t>& expectedPlaintext,
    const std::array<uint8_t, VM_RUNTIME_KEY_SHARE_SIZE>& runtimeKeyShare,
    const std::array<uint8_t, VM_HANDLER_TABLE_SIZE>& expectedSemanticToSlot,
    const std::array<uint8_t, VM_HANDLER_TABLE_SIZE>& expectedSlotToSemantic,
    const std::array<uint8_t, VM_HANDLER_TABLE_SIZE>& expectedVariants,
    uint32_t expectedJunkHandlerCount,
    bool expectedHandlerMutation,
    bool expectedJunkHandlers,
    std::string& error)
{
    PEEmitter emitter(image);
    if (!emitter.IsValid()) {
        error = "invalid PE image";
        return false;
    }
    const uint32_t offset = emitter.RvaToOffset(metadataRVA);
    if (offset == 0 || offset + sizeof(VM_METADATA_HEADER) > image->rawSize) {
        error = "metadata RVA is outside output image";
        return false;
    }
    VM_METADATA_HEADER header{};
    std::memcpy(&header, image->rawData + offset, sizeof(header));
    if (header.totalSize > image->rawSize - offset) {
        error = "metadata total size is outside output image";
        return false;
    }
    const uint8_t* metadata = image->rawData + offset;
    if (!VMSectionEmitter::VerifyMetadata(
            metadata, header.totalSize, runtimeKeyShare, error)) return false;
    if (header.recordCount != expectedRecords.size() ||
        header.bytecodeSize != expectedPlaintext.size()) {
        error = "emitted record or bytecode count differs from build graph";
        return false;
    }
    const uint32_t requiredFlags = VM_METADATA_FLAG_AUTHENTICATED |
        VM_METADATA_FLAG_BYTECODE_CHACHA20 |
        VM_METADATA_FLAG_NATIVE_BODY_DESTROYED |
        VM_METADATA_FLAG_CFG_VERIFIED;
    if ((header.flags & requiredFlags) != requiredFlags ||
        (header.architecture == VM_ARCH_X64 &&
            !(header.flags & VM_METADATA_FLAG_UNWIND_VERIFIED)) ||
        header.runtimeBaseRVA == 0 || header.runtimeEntryRVA < header.runtimeBaseRVA ||
        header.runtimeSize == 0 || header.imageSize == 0 ||
        header.runtimeBaseRVA >= header.imageSize ||
        header.runtimeSize > header.imageSize - header.runtimeBaseRVA ||
        header.runtimeEntryRVA - header.runtimeBaseRVA >= header.runtimeSize) {
        error = "emitted metadata linkage flags or runtime range are incomplete";
        return false;
    }
    if ((header.flags & VM_METADATA_FLAG_CFG_ENABLED) &&
        ((header.architecture == VM_ARCH_X64 && header.guardCFDispatchPointerRVA == 0) ||
         (header.architecture == VM_ARCH_X86 && header.guardCFCheckPointerRVA == 0))) {
        error = "CFG-enabled metadata has no architecture-specific Guard pointer";
        return false;
    }
    if (header.handlerTableSize != VM_HANDLER_TABLE_SIZE ||
        header.handlerVariantCount != VM_HANDLER_VARIANT_COUNT ||
        header.junkHandlerCount != expectedJunkHandlerCount ||
        expectedJunkHandlerCount > VM_HANDLER_USABLE_SLOT_COUNT) {
        error = "emitted handler metadata differs from the build graph";
        return false;
    }
    const auto rangeInsideMetadata = [&](uint32_t offset, uint32_t size) {
        return offset <= header.totalSize && size <= header.totalSize - offset;
    };
    if (!rangeInsideMetadata(header.handlerSemanticMapOffset, VM_HANDLER_TABLE_SIZE) ||
        !rangeInsideMetadata(header.handlerDescriptorOffset, VM_HANDLER_TABLE_SIZE) ||
        !rangeInsideMetadata(header.handlerVariantOffset, VM_HANDLER_TABLE_SIZE)) {
        error = "emitted handler tables are outside authenticated metadata";
        return false;
    }
    const uint8_t* emittedSemanticToSlot = metadata + header.handlerSemanticMapOffset;
    const uint8_t* emittedSlotToSemantic = metadata + header.handlerDescriptorOffset;
    const uint8_t* emittedVariants = metadata + header.handlerVariantOffset;
    if (!std::equal(expectedSemanticToSlot.begin(), expectedSemanticToSlot.end(), emittedSemanticToSlot) ||
        !std::equal(expectedSlotToSemantic.begin(), expectedSlotToSemantic.end(), emittedSlotToSemantic) ||
        !std::equal(expectedVariants.begin(), expectedVariants.end(), emittedVariants)) {
        error = "emitted handler tables differ from MutationEngine output";
        return false;
    }
    if (((header.flags & VM_METADATA_FLAG_HANDLER_MUTATED) != 0) != expectedHandlerMutation ||
        ((header.flags & VM_METADATA_FLAG_JUNK_HANDLERS) != 0) != expectedJunkHandlers ||
        expectedJunkHandlers != (expectedJunkHandlerCount != 0)) {
        error = "emitted handler flags differ from the build graph";
        return false;
    }

    uint8_t masterKey[32]{};
    DecodeMasterKey(header, runtimeKeyShare, masterKey);
    const auto* records = reinterpret_cast<const VM_FUNCTION_RECORD*>(metadata + header.recordOffset);
    std::vector<uint8_t> recovered(expectedPlaintext.size(), 0);
    for (uint32_t i = 0; i < header.recordCount; ++i) {
        const VM_FUNCTION_RECORD& record = records[i];
        auto expected = std::find_if(expectedRecords.begin(), expectedRecords.end(),
            [&](const VMFunctionRecord& value) { return value.functionRVA == record.functionRVA; });
        if (expected == expectedRecords.end() ||
            record.bytecodeOffset != expected->bytecodeOffset ||
            record.bytecodeSize != expected->bytecodeSize ||
            record.returnStackCleanup != expected->returnStackCleanup ||
            record.guestStackSize != expected->guestStackSize ||
            record.trampolineRVA == 0 || record.trampolineSize == 0 ||
            (record.flags & (VM_RECORD_FLAG_NATIVE_BODY_DESTROYED |
                VM_RECORD_FLAG_CFG_VERIFIED)) !=
                (VM_RECORD_FLAG_NATIVE_BODY_DESTROYED | VM_RECORD_FLAG_CFG_VERIFIED) ||
            (header.architecture == VM_ARCH_X64 &&
                !(record.flags & VM_RECORD_FLAG_UNWIND_VERIFIED))) {
            std::memset(masterKey, 0, sizeof(masterKey));
            error = "emitted record linkage differs from build graph";
            return false;
        }
        if (record.bytecodeOffset > header.bytecodeSize ||
            record.bytecodeSize > header.bytecodeSize - record.bytecodeOffset) {
            std::memset(masterKey, 0, sizeof(masterKey));
            error = "emitted record bytecode range is invalid";
            return false;
        }
        uint8_t recordKey[32]{};
        vm_derive_record_key(masterKey, header.buildId, record.functionRVA, recordKey);
        const uint8_t* ciphertext = metadata + header.bytecodeOffset + record.bytecodeOffset;
        const uint64_t tag = vm_siphash24(ciphertext, record.bytecodeSize, recordKey + 16);
        if (!vm_constant_time_equal64(tag, record.bytecodeTag)) {
            std::memset(recordKey, 0, sizeof(recordKey));
            std::memset(masterKey, 0, sizeof(masterKey));
            error = "emitted bytecode authentication tag mismatch";
            return false;
        }
        vm_chacha20_xor(ciphertext, recovered.data() + record.bytecodeOffset,
            record.bytecodeSize, recordKey, record.nonce, 1, 0);
        std::memset(recordKey, 0, sizeof(recordKey));
    }
    std::memset(masterKey, 0, sizeof(masterKey));
    if (recovered != expectedPlaintext) {
        error = "decrypted emitted bytecode differs from Translator output";
        return false;
    }
    return true;
}

} // namespace CipherShell
