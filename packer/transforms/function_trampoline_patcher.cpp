#include "function_trampoline_patcher.h"
#include "../pe_parser/pe_emitter.h"
#include "../pe_parser/pe_utils.h"
#include "../analysis/disassembler.h"
#include <cstring>
#include <limits>
#include <unordered_map>

namespace CipherShell {

namespace {
uint64_t GetImageBase(const CS_PE_IMAGE* image) {
    if (!image) return 0;
    return image->is64Bit ? image->ntHeaders64->OptionalHeader.ImageBase
                          : image->ntHeaders32->OptionalHeader.ImageBase;
}

bool Rel32Fits(uint32_t sourceRVA, uint32_t targetRVA) {
    int64_t rel = static_cast<int64_t>(targetRVA) - static_cast<int64_t>(sourceRVA + 5u);
    return rel >= static_cast<int64_t>((std::numeric_limits<int32_t>::min)()) &&
           rel <= static_cast<int64_t>((std::numeric_limits<int32_t>::max)());
}

uint32_t ReadU32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

uint64_t ReadU64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= static_cast<uint64_t>(p[i]) << (i * 8);
    return v;
}

bool HasEndbrPrefix(const CS_PE_IMAGE* image, uint32_t offset) {
    if (!image || !image->rawData || offset > image->rawSize || 4u > image->rawSize - offset) return false;
    const uint8_t* bytes = image->rawData + offset;
    return bytes[0] == 0xF3 && bytes[1] == 0x0F && bytes[2] == 0x1E &&
        bytes[3] == (image->is64Bit ? 0xFA : 0xFB);
}
}

bool FunctionTrampolinePatcher::BuildNearJump(
    uint32_t sourceRVA,
    uint32_t targetRVA,
    std::vector<uint8_t>& patch)
{
    if (!Rel32Fits(sourceRVA, targetRVA)) return false;
    patch.clear();
    patch.push_back(0xE9);
    int32_t rel = static_cast<int32_t>(static_cast<int64_t>(targetRVA) - static_cast<int64_t>(sourceRVA + 5u));
    for (int i = 0; i < 4; i++) patch.push_back(static_cast<uint8_t>(static_cast<uint32_t>(rel) >> (i * 8)));
    return true;
}

std::vector<uint8_t> FunctionTrampolinePatcher::BuildX64AbsoluteJump(uint64_t targetVA) {
    std::vector<uint8_t> patch;
    patch.reserve(14);
    patch.push_back(0xFF); // jmp qword ptr [rip]
    patch.push_back(0x25);
    patch.insert(patch.end(), {0x00, 0x00, 0x00, 0x00});
    for (int i = 0; i < 8; i++) patch.push_back(static_cast<uint8_t>(targetVA >> (i * 8)));
    return patch;
}

bool FunctionTrampolinePatcher::BuildEntryPatch(
    const CS_PE_IMAGE* image,
    uint32_t sourceRVA,
    uint32_t targetRVA,
    uint32_t availableSize,
    std::vector<uint8_t>& patch,
    FunctionPatchKind& kind,
    std::string& error)
{
    kind = FunctionPatchKind::None;
    patch.clear();

    if (availableSize >= 5 && BuildNearJump(sourceRVA, targetRVA, patch)) {
        kind = FunctionPatchKind::NearRel32;
        return true;
    }

    if (!image || !image->is64Bit) {
        error = "near rel32 trampoline is out of range and non-x64 far patch is not supported";
        return false;
    }

    if (availableSize < 14) {
        error = "function too small for x64 absolute trampoline patch";
        return false;
    }

    patch = BuildX64AbsoluteJump(GetImageBase(image) + targetRVA);
    kind = FunctionPatchKind::X64AbsoluteIndirect;
    return true;
}

bool FunctionTrampolinePatcher::VerifyPatch(
    const CS_PE_IMAGE* image,
    uint32_t functionRVA,
    uint32_t trampolineRVA,
    FunctionPatchKind kind,
    const std::vector<uint8_t>& patch,
    std::string& error)
{
    if (!image || !image->rawData || patch.empty()) {
        error = "invalid image or empty patch while verifying trampoline";
        return false;
    }

    PEEmitter emitter(const_cast<CS_PE_IMAGE*>(image));
    uint32_t offset = emitter.RvaToOffset(functionRVA);
    if (offset == 0 || offset + patch.size() > image->rawSize) {
        error = "patched function RVA is outside file while verifying trampoline";
        return false;
    }

    const uint8_t* bytes = image->rawData + offset;
    if (std::memcmp(bytes, patch.data(), patch.size()) != 0) {
        error = "patched bytes do not match requested trampoline bytes";
        return false;
    }

    if (kind == FunctionPatchKind::NearRel32) {
        int32_t rel = static_cast<int32_t>(ReadU32(bytes + 1));
        uint32_t actualTarget = static_cast<uint32_t>(static_cast<int64_t>(functionRVA + 5u) + rel);
        if (bytes[0] != 0xE9 || actualTarget != trampolineRVA) {
            error = "near trampoline target verification failed";
            return false;
        }
        return true;
    }

    if (kind == FunctionPatchKind::X64AbsoluteIndirect) {
        uint64_t targetVA = ReadU64(bytes + 6);
        if (bytes[0] != 0xFF || bytes[1] != 0x25 ||
            ReadU32(bytes + 2) != 0 ||
            targetVA != GetImageBase(image) + trampolineRVA) {
            error = "x64 absolute trampoline target verification failed";
            return false;
        }
        return true;
    }

    error = "unknown trampoline patch kind";
    return false;
}

bool FunctionTrampolinePatcher::VerifyAppliedPatch(
    const CS_PE_IMAGE* image,
    const FunctionPatchResult& result,
    std::string& error)
{
    if (!image || !image->isValid || !result.success || !result.verified ||
        result.patchRVA == 0 || result.trampolineRVA == 0 ||
        result.entryPatchBytes == 0) {
        error = "patch result is incomplete";
        return false;
    }
    if (result.preservedEndbr) {
        const uint32_t functionOffset = PEUtils::RvaToOffset(image, result.functionRVA);
        if (functionOffset == 0 || !HasEndbrPrefix(image, functionOffset)) {
            error = "preserved ENDBR prefix is missing";
            return false;
        }
    }
    std::vector<uint8_t> expected;
    if (result.patchKind == FunctionPatchKind::NearRel32) {
        if (!BuildNearJump(result.patchRVA, result.trampolineRVA, expected)) {
            error = "recorded near patch target is out of range";
            return false;
        }
    } else if (result.patchKind == FunctionPatchKind::X64AbsoluteIndirect) {
        expected = BuildX64AbsoluteJump(GetImageBase(image) + result.trampolineRVA);
    } else {
        error = "recorded patch kind is invalid";
        return false;
    }
    if (expected.size() > result.entryPatchBytes) {
        error = "recorded entry patch span is shorter than its jump";
        return false;
    }
    expected.resize(result.entryPatchBytes, 0x90);
    if (!VerifyPatch(image, result.patchRVA, result.trampolineRVA,
            result.patchKind, expected, error)) return false;

    uint64_t destroyedTotal = 0;
    for (const auto& range : result.destroyedRanges) {
        if (range.first >= range.second || range.second - range.first > image->rawSize) {
            error = "recorded destroyed range is invalid";
            return false;
        }
        const uint32_t offset = PEUtils::RvaToOffset(image, range.first);
        const uint32_t size = range.second - range.first;
        if (offset == 0 || size > image->rawSize - offset) {
            error = "recorded destroyed range is outside the image";
            return false;
        }
        for (uint32_t i = 0; i < size; ++i) {
            if (image->rawData[offset + i] != 0xCC) {
                error = "recorded native body destruction is no longer present";
                return false;
            }
        }
        destroyedTotal += size;
    }
    if (!result.nativeBodyDestroyed || destroyedTotal != result.destroyedBytes ||
        static_cast<uint64_t>(result.entryPatchBytes) + destroyedTotal != result.patchedBytes) {
        error = "recorded patch byte counts are inconsistent";
        return false;
    }
    return true;
}

std::vector<FunctionPatchResult> FunctionTrampolinePatcher::PatchFunctions(
    CS_PE_IMAGE* image,
    const std::vector<VMTrampolineRecord>& trampolines,
    const std::vector<VMFunctionRecord>& records,
    const std::vector<Function>& functions,
    bool destroyNativeBody)
{
    std::vector<FunctionPatchResult> results;
    PEEmitter emitter(image);
    if (!emitter.IsValid()) return results;

    std::unordered_map<uint32_t, VMFunctionRecord> byRva;
    for (const auto& record : records) byRva[record.functionRVA] = record;
    std::unordered_map<uint32_t, const Function*> functionByRva;
    for (const auto& function : functions) {
        functionByRva[static_cast<uint32_t>(function.entryAddress)] = &function;
    }

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
        auto functionIt = functionByRva.find(tr.functionRVA);
        if (functionIt == functionByRva.end() || !functionIt->second ||
            !functionIt->second->boundaryTrusted) {
            r.error = "missing trusted decoded function plan";
            results.push_back(r);
            continue;
        }

        std::vector<uint8_t> patch;
        std::string error;
        const uint32_t functionOffset = emitter.RvaToOffset(tr.functionRVA);
        if (functionOffset == 0 || functionOffset >= image->rawSize) {
            r.error = "function RVA is outside file while measuring patch span";
            results.push_back(r);
            continue;
        }
        const uint32_t entryPrefixSize = HasEndbrPrefix(image, functionOffset) ? 4u : 0u;
        r.preservedEndbr = entryPrefixSize != 0;
        r.patchRVA = tr.functionRVA + entryPrefixSize;

        patch.clear();
        if (it->second.functionSize <= entryPrefixSize ||
            !BuildEntryPatch(image, r.patchRVA, tr.trampolineRVA,
                it->second.functionSize - entryPrefixSize, patch, r.patchKind, error)) {
            r.error = error.empty() ? "function is too small after preserving ENDBR" : error;
            results.push_back(r);
            continue;
        }
        Disassembler decoder;
        decoder.Initialize(image->is64Bit != 0, GetImageBase(image));
        uint32_t overwriteSpan = 0;
        const uint32_t patchOffset = functionOffset + entryPrefixSize;
        const uint32_t available = (std::min)(
            static_cast<uint32_t>(it->second.functionSize - entryPrefixSize),
            static_cast<uint32_t>(image->rawSize - patchOffset));
        if (!decoder.MeasureInstructionSpan(image->rawData + patchOffset,
                available, r.patchRVA, static_cast<uint32_t>(patch.size()), overwriteSpan)) {
            r.error = "Zydis patch-boundary validation failed: " + decoder.GetLastError();
            results.push_back(r);
            continue;
        }
        std::unordered_map<uint32_t, uint8_t> decodedBytes;
        for (const auto& block : functionIt->second->blocks) {
            for (const auto& instruction : block.instructions) {
                for (uint32_t byte = 0; byte < instruction.length; ++byte) {
                    decodedBytes[instruction.rva + byte] = 1;
                }
            }
        }
        bool entryRangeDecoded = true;
        for (uint32_t byte = 0; byte < overwriteSpan; ++byte) {
            if (decodedBytes.count(r.patchRVA + byte) == 0) {
                entryRangeDecoded = false;
                break;
            }
        }
        if (!entryRangeDecoded) {
            r.error = "entry patch span crosses bytes not owned by decoded instructions";
            results.push_back(r);
            continue;
        }
        patch.resize(overwriteSpan, 0x90);

        if (!emitter.PatchBytes(r.patchRVA, patch, &error)) {
            r.error = error;
            results.push_back(r);
            continue;
        }
        r.patchedBytes = overwriteSpan;
        r.entryPatchBytes = overwriteSpan;

        if (!VerifyPatch(image, r.patchRVA, tr.trampolineRVA, r.patchKind, patch, error)) {
            r.error = error;
            results.push_back(r);
            continue;
        }
        r.verified = true;

        if (destroyNativeBody) {
            std::vector<std::pair<uint32_t, uint32_t>> ranges;
            bool rangeFailure = false;
            for (const auto& block : functionIt->second->blocks) {
                for (const auto& instruction : block.instructions) {
                    const uint32_t begin = instruction.rva;
                    const uint32_t end = begin + instruction.length;
                    if (begin < tr.functionRVA || end < begin ||
                        end > tr.functionRVA + it->second.functionSize) {
                        r.error = "decoded instruction is outside the trusted function envelope";
                        rangeFailure = true;
                        break;
                    }
                    if (!ranges.empty() && ranges.back().second == begin) ranges.back().second = end;
                    else ranges.push_back({begin, end});
                }
                if (rangeFailure) break;
            }
            if (rangeFailure || ranges.empty()) {
                if (r.error.empty()) r.error = "trusted function plan has no decoded instruction ranges";
                results.push_back(r);
                continue;
            }
            const uint32_t patchEnd = r.patchRVA + overwriteSpan;
            for (const auto& range : ranges) {
                uint32_t begin = range.first;
                const uint32_t end = range.second;
                if (begin < patchEnd) begin = patchEnd;
                if (begin >= end) continue;
                if (!emitter.FillBytes(begin, end - begin, 0xCC, &error)) {
                    r.error = "entry patched, but decoded native body destroy failed: " + error;
                    rangeFailure = true;
                    break;
                }
                r.destroyedRanges.push_back({begin, end});
                r.destroyedBytes += end - begin;
            }
            if (rangeFailure) {
                results.push_back(r);
                continue;
            }
            for (const auto& range : ranges) {
                uint32_t begin = range.first < patchEnd ? patchEnd : range.first;
                if (begin >= range.second) continue;
                const uint32_t offset = emitter.RvaToOffset(begin);
                if (offset == 0 || range.second - begin > image->rawSize - offset) {
                    r.error = "destroyed native range is outside the PE image";
                    rangeFailure = true;
                    break;
                }
                for (uint32_t byte = 0; byte < range.second - begin; ++byte) {
                    if (image->rawData[offset + byte] != 0xCC) {
                        r.error = "destroyed native range verification failed";
                        rangeFailure = true;
                        break;
                    }
                }
                if (rangeFailure) break;
            }
            if (rangeFailure) {
                results.push_back(r);
                continue;
            }
            r.nativeBodyDestroyed = true;
            r.patchedBytes += r.destroyedBytes;
        }

        r.success = true;
        results.push_back(r);
    }
    return results;
}

} // namespace CipherShell
