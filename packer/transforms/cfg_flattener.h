/**
 * CipherShell native CFG flattening.
 *
 * This module is deliberately independent from the VM translator/runtime.  It
 * copies verified native basic blocks into a new RX section, relocates every
 * PC-relative operand, replaces native edges with an encrypted-state
 * dispatcher, duplicates base relocations for copied absolute operands and
 * destroys the old native body only after the complete PE plan validates.
 */

#ifndef CS_CFG_FLATTENER_H
#define CS_CFG_FLATTENER_H

#include "../analysis/instruction_ir.h"
#include "../pe_parser/pe_parser.h"
#include "function_trampoline_patcher.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace CipherShell {

struct FlatteningConfig {
    bool enableStateEncryption = true;
    bool enableStateRandomization = true;
    bool enableDispatcherMutation = true;
    uint32_t junkCaseCount = 5;
    uint32_t stateKeyRotation = 16;
    uint64_t buildSeed = 0;
};

enum class CFGCodeRelocationKind : uint8_t {
    RelativeCall = 1,
    RipRelativeMemory = 2
};

struct CFGCodeRelocation {
    CFGCodeRelocationKind kind = CFGCodeRelocationKind::RelativeCall;
    uint32_t instructionOffset = 0;
    uint32_t fieldOffset = 0;
    uint8_t fieldSize = 0;
    uint32_t targetRVA = 0;
};

struct CFGCopiedInstructionRange {
    uint32_t originalRVA = 0;
    uint32_t generatedOffset = 0;
    uint8_t size = 0;
};

struct CFGFlattenedBlockRecord {
    uint32_t originalRVA = 0;
    uint32_t generatedOffset = 0;
    uint32_t generatedSize = 0;
    uint32_t encodedState = 0;
    bool conditional = false;
    bool terminalReturn = false;
};

struct CFGDispatchCaseRecord {
    uint32_t encodedState = 0;
    uint32_t targetOffset = 0;
    bool junk = false;
};

struct CFGTransitionRecord {
    uint32_t callOffset = 0;
    uint32_t tokenOffset = 0;
    uint32_t encodedState = 0;
    uint32_t targetOffset = 0;
};

struct CFGFlattenedFunction {
    bool success = false;
    bool is64Bit = false;
    uint32_t originalFunctionRVA = 0;
    uint32_t originalFunctionSize = 0;
    uint32_t codeRVA = 0;
    uint32_t entryOffset = 0;
    uint32_t dispatcherOffset = 0;
    uint32_t dispatcherSize = 0;
    uint32_t stateEncryptionKey = 0;
    std::vector<uint8_t> code;
    std::vector<uint8_t> dispatcherUnwindInfo;
    std::vector<CFGFlattenedBlockRecord> blocks;
    std::vector<CFGDispatchCaseRecord> dispatchCases;
    std::vector<CFGTransitionRecord> transitions;
    std::vector<CFGCodeRelocation> codeRelocations;
    std::vector<CFGCopiedInstructionRange> copiedInstructions;
    std::string error;
};

struct CFGProtectedFunctionRecord {
    uint32_t sectionOffset = 0;
    CFGFlattenedFunction flattened;
};

struct CFGProtectionResult {
    bool success = false;
    bool is64Bit = false;
    uint32_t codeSectionRVA = 0;
    uint32_t codeSectionRawOffset = 0;
    uint32_t codeSectionSize = 0;
    std::vector<uint8_t> expectedCodeSection;
    std::vector<CFGProtectedFunctionRecord> functions;
    std::vector<CS_RELOC_ENTRY> duplicatedRelocations;
    std::vector<CS_RUNTIME_FUNCTION> dispatcherRuntimeFunctions;
    std::vector<FunctionPatchResult> patchResults;
    std::string error;
};

class CFGFlattener {
public:
    /** Generate one position-aware flattened native function image. */
    CFGFlattenedFunction Generate(
        const Function& function,
        bool is64Bit,
        uint32_t codeRVA,
        const FlatteningConfig& config) const;

    /**
     * Apply a complete CFG-only protection transaction to the in-memory PE.
     * VM metadata, bytecode and runtime objects are not consulted.
     */
    CFGProtectionResult Protect(
        CS_PE_IMAGE* image,
        const std::vector<Function>& functions,
        const FlatteningConfig& config,
        const char codeSectionName[8],
        const char unwindSectionName[8],
        const char exceptionSectionName[8],
        const char relocationSectionName[8]) const;

    static bool ValidateGeneratedFunction(
        const CFGFlattenedFunction& function,
        std::string& error);

    static bool VerifyAppliedProtection(
        const CS_PE_IMAGE* image,
        const CFGProtectionResult& result,
        std::string& error);
};

} // namespace CipherShell

#endif // CS_CFG_FLATTENER_H
