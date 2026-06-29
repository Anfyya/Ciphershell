#include "function_trampoline_patcher.h"
#include "../pe_parser/pe_emitter.h"
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
    patch.reserve(13);
    patch.push_back(0x49); // mov r11, imm64
    patch.push_back(0xBB);
    for (int i = 0; i < 8; i++) patch.push_back(static_cast<uint8_t>(targetVA >> (i * 8)));
    patch.push_back(0x41); // jmp r11
    patch.push_back(0xFF);
    patch.push_back(0xE3);
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

    if (availableSize < 13) {
        error = "function too small for x64 absolute trampoline patch";
        return false;
    }

    patch = BuildX64AbsoluteJump(GetImageBase(image) + targetRVA);
    kind = FunctionPatchKind::X64AbsoluteR11;
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

    if (kind == FunctionPatchKind::X64AbsoluteR11) {
        uint64_t targetVA = ReadU64(bytes + 2);
        if (bytes[0] != 0x49 || bytes[1] != 0xBB ||
            bytes[10] != 0x41 || bytes[11] != 0xFF || bytes[12] != 0xE3 ||
            targetVA != GetImageBase(image) + trampolineRVA) {
            error = "x64 absolute trampoline target verification failed";
            return false;
        }
        return true;
    }

    error = "unknown trampoline patch kind";
    return false;
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

        std::vector<uint8_t> patch;
        std::string error;
        if (!BuildEntryPatch(image, tr.functionRVA, tr.trampolineRVA,
                it->second.functionSize, patch, r.patchKind, error)) {
            r.error = error;
            results.push_back(r);
            continue;
        }

        if (!emitter.PatchBytes(tr.functionRVA, patch, &error)) {
            r.error = error;
            results.push_back(r);
            continue;
        }
        r.patchedBytes = static_cast<uint32_t>(patch.size());

        if (!VerifyPatch(image, tr.functionRVA, tr.trampolineRVA, r.patchKind, patch, error)) {
            r.error = error;
            results.push_back(r);
            continue;
        }
        r.verified = true;

        if (destroyNativeBody && it->second.functionSize > patch.size()) {
            uint32_t bodySize = it->second.functionSize - static_cast<uint32_t>(patch.size());
            if (!emitter.FillBytes(tr.functionRVA + static_cast<uint32_t>(patch.size()), bodySize, 0xCC, &error)) {
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
