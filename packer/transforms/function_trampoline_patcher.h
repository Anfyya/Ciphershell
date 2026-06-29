#ifndef CS_FUNCTION_TRAMPOLINE_PATCHER_H
#define CS_FUNCTION_TRAMPOLINE_PATCHER_H

#include "vm_runtime_builder.h"
#include "../pe_parser/pe_parser.h"
#include <cstdint>
#include <string>
#include <vector>

namespace CipherShell {

struct FunctionPatchResult {
    bool success = false;
    uint32_t functionRVA = 0;
    uint32_t trampolineRVA = 0;
    uint32_t patchedBytes = 0;
    std::string error;
};

class FunctionTrampolinePatcher {
public:
    std::vector<FunctionPatchResult> PatchFunctions(
        CS_PE_IMAGE* image,
        const std::vector<VMTrampolineRecord>& trampolines,
        const std::vector<VMFunctionRecord>& records,
        bool destroyNativeBody);

private:
    static std::vector<uint8_t> BuildNearJump(uint32_t sourceRVA, uint32_t targetRVA);
};

} // namespace CipherShell

#endif // CS_FUNCTION_TRAMPOLINE_PATCHER_H
