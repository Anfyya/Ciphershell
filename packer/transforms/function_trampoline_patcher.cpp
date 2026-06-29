#include "function_trampoline_patcher.h"
#include "../pe_parser/pe_emitter.h"
#include <unordered_map>

namespace CipherShell {

std::vector<uint8_t> FunctionTrampolinePatcher::BuildNearJump(uint32_t sourceRVA, uint32_t targetRVA) {
    std::vector<uint8_t> jmp;
    jmp.push_back(0xE9);
    int32_t rel = static_cast<int32_t>(static_cast<int64_t>(targetRVA) - static_cast<int64_t>(sourceRVA + 5));
    for (int i = 0; i < 4; i++) jmp.push_back(static_cast<uint8_t>(rel >> (i * 8)));
    return jmp;
}

std::vector<FunctionPatchResult> FunctionTrampolinePatcher::PatchFunctions(
    CS_PE_IMAGE* image,
    const std::vector<VMTrampolineRecord>& trampolines,
    const std::vector<VMFunctionRecord>& records,
    bool destroyNativeBody)
{
    std::vector<FunctionPatchResult> results;
    PEEmitter emitter(image);
    if (!emitter.IsValid()) return results;

    std::unordered_map<uint32_t, VMFunctionRecord> byRva;
    for (const auto& record : records) byRva[record.functionRVA] = record;

    for (const auto& tr : trampolines) {
        FunctionPatchResult r;
        r.functionRVA = tr.functionRVA;
        r.trampolineRVA = tr.trampolineRVA;

        auto it = byRva.find(tr.functionRVA);
        if (it == byRva.end()) {
            r.error = "missing VM function record";
            results.push_back(r);
            continue;
        }
        if (it->second.functionSize < 5) {
            r.error = "function too small for near jump";
            results.push_back(r);
            continue;
        }

        std::string error;
        auto patch = BuildNearJump(tr.functionRVA, tr.trampolineRVA);
        if (!emitter.PatchBytes(tr.functionRVA, patch, &error)) {
            r.error = error;
            results.push_back(r);
            continue;
        }
        r.patchedBytes = 5;

        if (destroyNativeBody && it->second.functionSize > 5) {
            uint32_t bodySize = it->second.functionSize - 5;
            if (!emitter.FillBytes(tr.functionRVA + 5, bodySize, 0xCC, &error)) {
                r.error = "entry patched, but native body destroy failed: " + error;
                results.push_back(r);
                continue;
            }
            r.patchedBytes += bodySize;
        }

        r.success = true;
        results.push_back(r);
    }
    return results;
}

} // namespace CipherShell
