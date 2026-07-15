#ifndef CS_FUNCTION_TRAMPOLINE_PATCHER_H
#define CS_FUNCTION_TRAMPOLINE_PATCHER_H

#include "vm_runtime_builder.h"
#include "../analysis/instruction_ir.h"
#include "../pe_parser/pe_parser.h"
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace CipherShell {

enum class FunctionPatchKind {
    None,
    NearRel32,
    X64AbsoluteIndirect
};

struct FunctionPatchResult {
    bool success = false;
    uint32_t functionRVA = 0;
    uint32_t patchRVA = 0;
    uint32_t trampolineRVA = 0;
    uint32_t patchedBytes = 0;
    uint32_t entryPatchBytes = 0;
    FunctionPatchKind patchKind = FunctionPatchKind::None;
    bool verified = false;
    bool preservedEndbr = false;
    bool nativeBodyDestroyed = false;
    uint32_t destroyedBytes = 0;
    std::vector<std::pair<uint32_t, uint32_t>> destroyedRanges;
    std::string error;
};

struct FunctionPatchTarget {
    uint32_t functionRVA = 0;
    uint32_t trampolineRVA = 0;
    uint32_t functionSize = 0;
};

class FunctionTrampolinePatcher {
public:
    std::vector<FunctionPatchResult> PatchNativeFunctions(
        CS_PE_IMAGE* image,
        const std::vector<FunctionPatchTarget>& targets,
        const std::vector<Function>& functions,
        bool destroyNativeBody);

    std::vector<FunctionPatchResult> PatchFunctions(
        CS_PE_IMAGE* image,
        const std::vector<VMTrampolineRecord>& trampolines,
        const std::vector<VMFunctionRecord>& records,
        const std::vector<Function>& functions,
        bool destroyNativeBody);
    static bool VerifyAppliedPatch(
        const CS_PE_IMAGE* image,
        const FunctionPatchResult& result,
        std::string& error);

private:
    static bool BuildEntryPatch(
        const CS_PE_IMAGE* image,
        uint32_t sourceRVA,
        uint32_t targetRVA,
        uint32_t availableSize,
        std::vector<uint8_t>& patch,
        FunctionPatchKind& kind,
        std::string& error);
    static bool BuildNearJump(uint32_t sourceRVA, uint32_t targetRVA, std::vector<uint8_t>& patch);
    static std::vector<uint8_t> BuildX64AbsoluteJump(uint64_t targetVA);
    static bool VerifyPatch(
        const CS_PE_IMAGE* image,
        uint32_t functionRVA,
        uint32_t trampolineRVA,
        FunctionPatchKind kind,
        const std::vector<uint8_t>& patch,
        std::string& error);
};

} // namespace CipherShell

#endif // CS_FUNCTION_TRAMPOLINE_PATCHER_H
