#include "vm_runtime_builder.h"

#include "../pe_parser/pe_emitter.h"
#include "../pe_parser/pe_utils.h"
#include "../vm/vm_schema.h"
#include "../../runtime/common/vm_metadata.h"
#include "../../runtime/common/vm_micro_runtime_abi.h"
#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <set>
#include <unordered_set>

namespace CipherShell {
namespace {

struct RuntimeRelocation {
    uint32_t offset = 0;
    uint16_t type = 0;
};

struct MappedRuntimeImage {
    std::vector<uint8_t> bytes;
    std::vector<RuntimeRelocation> relocations;
    std::vector<VMRuntimeFunctionEntry> unwindEntries;
    uint64_t preferredBase = 0;
    uint32_t entryRVA = 0;
    uint32_t headersSize = 0;
    bool is64Bit = false;
};

bool RangeValid(size_t offset, size_t size, size_t total) {
    return offset <= total && size <= total - offset;
}

constexpr uint64_t kRuntimeSectionDigestDomain = 0x4353564D53454354ULL;
constexpr uint64_t kRuntimeImageDigestDomain = 0x4353564D494D4147ULL;
constexpr uint64_t kEncryptedHandlerDigestDomain = 0x4353564D48444C52ULL;
constexpr uint64_t kDispatchTableDigestDomain = 0x4353564D44535054ULL;
constexpr uint64_t kSemanticPlaintextEvidenceDomain = 0x4353564D504C4E33ULL;
constexpr uint64_t kRecordBytecodeEvidenceDomain = 0x4353564D52454332ULL;
constexpr uint64_t kDispatchKeyDomain = 0x4449535041544348ULL;

struct ReferenceRuntimeFingerprint {
    uint32_t size = 0;
    uint64_t rollingHash = 0;
    uint64_t leadingPower = 0;
    std::array<uint8_t, 32> sha256{};
    const char* name = nullptr;
    const char* provenanceId = nullptr;
};

/*
 * SHA-256 fingerprints of the file-backed .text bytes from every retired
 * runtime image that was previously accepted as a production interpreter.
 * Keeping only digests (never the old machine-code bytes) lets the final PE
 * gate reject an exact embedded legacy interpreter without recreating a
 * fixed-runtime-blob source path.  Every tuple's source/capture commit, build
 * recipe and byte-range limitation is bound by its provenanceId in
 * docs/reference_runtime_fingerprints.md and checked by the static gate.
 */
constexpr std::array<ReferenceRuntimeFingerprint, 4> kReferenceRuntimes = {{
    {23552u, 0x2C5FC69EE2383E78ULL, 0xE6224086755CFF01ULL,
        {0xFA,0x0C,0x6F,0x3E,0x27,0x5F,0x62,0x0B,
         0xF5,0x1F,0x19,0xAF,0x5F,0x1C,0xD3,0xA4,
         0x6E,0xC1,0x04,0x31,0x17,0x6D,0x53,0xEB,
         0x42,0x96,0x63,0x7A,0xCC,0x5A,0x26,0xDC},
        "retired-x64-runtime-text", "legacy-msvc-x64-full-bb01871"},
    {24064u, 0xA15835EC2011743AULL, 0xA9A6C919725EFF01ULL,
        {0xBB,0x84,0x3D,0x65,0x55,0xCF,0x8D,0xFC,
         0x53,0x1A,0xE4,0x04,0xC7,0x97,0x4C,0x21,
         0xD1,0xBF,0xEA,0xC3,0x6F,0xC6,0x36,0x29,
         0x86,0x56,0x57,0x24,0xA3,0xD3,0x43,0x98},
        "retired-x86-runtime-text", "legacy-msvc-x86-full-bb01871"},
    {11776u, 0x72544B6CBFEC2E4FULL, 0xC3455FA1BA2EFF01ULL,
        {0x0B,0xCA,0x07,0x48,0xCC,0x32,0xC7,0x13,
         0xF4,0x15,0x56,0x3C,0xC8,0x2E,0xD9,0x3D,
         0x62,0x1C,0x53,0xE5,0x9B,0xA9,0xF6,0x79,
         0x98,0xAF,0x98,0xDA,0x36,0xDB,0xFD,0xD0},
        "retired-x64-runtime-probe-text", "legacy-msvc-x64-probe-bb01871"},
    {11776u, 0xB58E1DFE08EE6C7EULL, 0xC3455FA1BA2EFF01ULL,
        {0x2B,0x25,0xCE,0x27,0x79,0xB5,0x0E,0x4D,
         0x4E,0x43,0x40,0xF6,0x38,0x77,0x3E,0x5C,
         0x76,0xCD,0xBD,0xCB,0x3C,0x93,0xD9,0xF7,
         0x68,0xFE,0x49,0x11,0xB3,0x6A,0xF7,0xFF},
        "retired-x86-runtime-probe-text", "legacy-msvc-x86-probe-bb01871"}
}};

uint32_t RotateRight32(uint32_t value, uint32_t count) {
    return (value >> count) | (value << (32u - count));
}

void Sha256Transform(
    std::array<uint32_t, 8>& state,
    const uint8_t block[64])
{
    static constexpr std::array<uint32_t, 64> constants = {
        0x428A2F98u,0x71374491u,0xB5C0FBCFu,0xE9B5DBA5u,
        0x3956C25Bu,0x59F111F1u,0x923F82A4u,0xAB1C5ED5u,
        0xD807AA98u,0x12835B01u,0x243185BEu,0x550C7DC3u,
        0x72BE5D74u,0x80DEB1FEu,0x9BDC06A7u,0xC19BF174u,
        0xE49B69C1u,0xEFBE4786u,0x0FC19DC6u,0x240CA1CCu,
        0x2DE92C6Fu,0x4A7484AAu,0x5CB0A9DCu,0x76F988DAu,
        0x983E5152u,0xA831C66Du,0xB00327C8u,0xBF597FC7u,
        0xC6E00BF3u,0xD5A79147u,0x06CA6351u,0x14292967u,
        0x27B70A85u,0x2E1B2138u,0x4D2C6DFCu,0x53380D13u,
        0x650A7354u,0x766A0ABBu,0x81C2C92Eu,0x92722C85u,
        0xA2BFE8A1u,0xA81A664Bu,0xC24B8B70u,0xC76C51A3u,
        0xD192E819u,0xD6990624u,0xF40E3585u,0x106AA070u,
        0x19A4C116u,0x1E376C08u,0x2748774Cu,0x34B0BCB5u,
        0x391C0CB3u,0x4ED8AA4Au,0x5B9CCA4Fu,0x682E6FF3u,
        0x748F82EEu,0x78A5636Fu,0x84C87814u,0x8CC70208u,
        0x90BEFFFAu,0xA4506CEBu,0xBEF9A3F7u,0xC67178F2u
    };
    std::array<uint32_t, 64> words{};
    for (size_t index = 0; index < 16u; ++index) {
        const size_t offset = index * 4u;
        words[index] = (static_cast<uint32_t>(block[offset]) << 24u) |
            (static_cast<uint32_t>(block[offset + 1u]) << 16u) |
            (static_cast<uint32_t>(block[offset + 2u]) << 8u) |
            static_cast<uint32_t>(block[offset + 3u]);
    }
    for (size_t index = 16u; index < words.size(); ++index) {
        const uint32_t s0 = RotateRight32(words[index - 15u], 7u) ^
            RotateRight32(words[index - 15u], 18u) ^
            (words[index - 15u] >> 3u);
        const uint32_t s1 = RotateRight32(words[index - 2u], 17u) ^
            RotateRight32(words[index - 2u], 19u) ^
            (words[index - 2u] >> 10u);
        words[index] = words[index - 16u] + s0 + words[index - 7u] + s1;
    }

    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    uint32_t f = state[5];
    uint32_t g = state[6];
    uint32_t h = state[7];
    for (size_t index = 0; index < words.size(); ++index) {
        const uint32_t big1 = RotateRight32(e, 6u) ^
            RotateRight32(e, 11u) ^ RotateRight32(e, 25u);
        const uint32_t choose = (e & f) ^ ((~e) & g);
        const uint32_t temp1 = h + big1 + choose + constants[index] + words[index];
        const uint32_t big0 = RotateRight32(a, 2u) ^
            RotateRight32(a, 13u) ^ RotateRight32(a, 22u);
        const uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        const uint32_t temp2 = big0 + majority;
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

std::array<uint8_t, 32> Sha256Digest(const uint8_t* bytes, size_t size) {
    std::array<uint32_t, 8> state = {
        0x6A09E667u,0xBB67AE85u,0x3C6EF372u,0xA54FF53Au,
        0x510E527Fu,0x9B05688Cu,0x1F83D9ABu,0x5BE0CD19u
    };
    const size_t fullBlocks = size / 64u;
    for (size_t index = 0; index < fullBlocks; ++index)
        Sha256Transform(state, bytes + index * 64u);

    std::array<uint8_t, 128> tail{};
    const size_t remainder = size % 64u;
    if (remainder != 0)
        std::memcpy(tail.data(), bytes + fullBlocks * 64u, remainder);
    tail[remainder] = 0x80u;
    const size_t tailSize = remainder < 56u ? 64u : 128u;
    const uint64_t bitLength = static_cast<uint64_t>(size) * 8u;
    for (size_t index = 0; index < 8u; ++index) {
        tail[tailSize - 1u - index] =
            static_cast<uint8_t>(bitLength >> (index * 8u));
    }
    Sha256Transform(state, tail.data());
    if (tailSize == 128u) Sha256Transform(state, tail.data() + 64u);

    std::array<uint8_t, 32> digest{};
    for (size_t index = 0; index < state.size(); ++index) {
        digest[index * 4u] = static_cast<uint8_t>(state[index] >> 24u);
        digest[index * 4u + 1u] = static_cast<uint8_t>(state[index] >> 16u);
        digest[index * 4u + 2u] = static_cast<uint8_t>(state[index] >> 8u);
        digest[index * 4u + 3u] = static_cast<uint8_t>(state[index]);
    }
    return digest;
}

bool VerifyNoReferenceRuntimeBlob(
    const uint8_t* bytes,
    size_t size,
    std::string& error)
{
    static constexpr std::array<uint8_t, 32> emptyDigest = {
        0xE3,0xB0,0xC4,0x42,0x98,0xFC,0x1C,0x14,
        0x9A,0xFB,0xF4,0xC8,0x99,0x6F,0xB9,0x24,
        0x27,0xAE,0x41,0xE4,0x64,0x9B,0x93,0x4C,
        0xA4,0x95,0x99,0x1B,0x78,0x52,0xB8,0x55
    };
    if (Sha256Digest(nullptr, 0) != emptyDigest) {
        error = "reference-runtime SHA-256 self-test failed";
        return false;
    }
    if (!bytes && size != 0) {
        error = "reference-runtime scan received a null image";
        return false;
    }
    for (const ReferenceRuntimeFingerprint& reference : kReferenceRuntimes) {
        if (!reference.name || !reference.provenanceId ||
            reference.name[0] == '\0' || reference.provenanceId[0] == '\0') {
            error = "reference-runtime fingerprint has no provenance identity";
            return false;
        }
        if (reference.size == 0 || reference.size > size) continue;
        uint64_t rolling = 0;
        for (size_t index = 0; index < reference.size; ++index)
            rolling = rolling * 257u + bytes[index];
        const size_t last = size - reference.size;
        for (size_t offset = 0; offset <= last; ++offset) {
            if (rolling == reference.rollingHash &&
                Sha256Digest(bytes + offset, reference.size) == reference.sha256) {
                error = std::string("final PE contains exact reference runtime blob: ") +
                    reference.name;
                return false;
            }
            if (offset == last) break;
            rolling -= static_cast<uint64_t>(bytes[offset]) * reference.leadingPower;
            rolling = rolling * 257u + bytes[offset + reference.size];
        }
    }
    return true;
}

uint64_t HashRuntimeBytes(const uint8_t* bytes, size_t size, uint64_t domain) {
    uint64_t hash = 1469598103934665603ULL ^ domain;
    for (size_t index = 0; index < size; ++index) {
        hash ^= bytes[index];
        hash *= 1099511628211ULL;
        hash ^= hash >> 29u;
    }
    return hash ? hash : (domain | 1ULL);
}

bool RuntimeRangeValid(
    const VMRuntimeContentRange& range,
    size_t total)
{
    return range.size != 0 && range.digest != 0 &&
        RangeValid(range.offset, range.size, total);
}

constexpr std::array<uint8_t, VM_RUNTIME_KEY_SHARE_SIZE> kRuntimeKeyMarker = {
    0x43,0x53,0x56,0x4D,0x4B,0x45,0x59,0x33,
    0x91,0x2D,0xE7,0x54,0xA8,0x6B,0xC0,0x1F,
    0x37,0xD2,0x4A,0xB9,0x65,0x0E,0x83,0xFC,
    0x18,0xA1,0x5D,0x72,0xCE,0x39,0xB4,0x06
};

bool PatchRuntimeKeyShare(
    MappedRuntimeImage& runtime,
    const std::array<uint8_t, VM_RUNTIME_KEY_SHARE_SIZE>& runtimeKeyShare,
    std::string& error)
{
    size_t match = 0;
    uint32_t matches = 0;
    for (size_t offset = 0; offset + kRuntimeKeyMarker.size() <= runtime.bytes.size(); ++offset) {
        if (std::memcmp(runtime.bytes.data() + offset,
                kRuntimeKeyMarker.data(), kRuntimeKeyMarker.size()) == 0) {
            match = offset;
            ++matches;
        }
    }
    if (matches != 1) {
        error = "runtime key-share marker is missing or not unique";
        return false;
    }
    const bool allZero = std::all_of(runtimeKeyShare.begin(), runtimeKeyShare.end(),
        [](uint8_t value) { return value == 0; });
    if (allZero) {
        error = "runtime key share is all zero";
        return false;
    }
    std::copy(runtimeKeyShare.begin(), runtimeKeyShare.end(), runtime.bytes.begin() + match);
    return true;
}

uint32_t AlignUp(uint32_t value, uint32_t alignment) {
    if (alignment == 0) return value;
    return (value + alignment - 1u) & ~(alignment - 1u);
}

class CodeBuffer {
public:
    std::vector<uint8_t> bytes;

    void U8(uint8_t value) { bytes.push_back(value); }
    void U16(uint16_t value) { U8(static_cast<uint8_t>(value)); U8(static_cast<uint8_t>(value >> 8)); }
    void U32(uint32_t value) {
        for (unsigned i = 0; i < 4; ++i) U8(static_cast<uint8_t>(value >> (i * 8)));
    }
    void Raw(std::initializer_list<uint8_t> values) { bytes.insert(bytes.end(), values.begin(), values.end()); }
    size_t Offset() const { return bytes.size(); }
};

class X64TrampolineAssembler : public CodeBuffer {
public:
    struct ImageBasePatch {
        uint32_t immediateOffset = 0;
        uint32_t anchorOffset = 0;
    };

    void Endbr() { Raw({0xF3, 0x0F, 0x1E, 0xFA}); }
    void PushFlags() { U8(0x9C); }
    void PopFlags() { U8(0x9D); }
    void PushReg(uint8_t reg) {
        if (reg >= 8) U8(0x41);
        U8(static_cast<uint8_t>(0x50 + (reg & 7u)));
    }
    void PopReg(uint8_t reg) {
        if (reg >= 8) U8(0x41);
        U8(static_cast<uint8_t>(0x58 + (reg & 7u)));
    }
    void SubRsp(uint32_t value) { Raw({0x48, 0x81, 0xEC}); U32(value); }
    void AddRsp(uint32_t value) { Raw({0x48, 0x81, 0xC4}); U32(value); }
    void MovRbpRsp() { Raw({0x48, 0x89, 0xE5}); }
    void LeaRspRbp(uint32_t displacement) {
        Raw({0x48, 0x8D, 0xA5});
        U32(displacement);
    }
    void ProbeStack(uint32_t value) {
        // The caller-provided x64 shadow space remains addressable while RSP is
        // unchanged.  Keep the probe unwind-neutral so a guard-page exception
        // cannot expose transient pushes to the system unwinder.
        Raw({0x48, 0x89, 0x44, 0x24, 0x08});
        Raw({0x48, 0x89, 0x4C, 0x24, 0x10});
        PushFlags();
        PopReg(0);
        Raw({0x48, 0x89, 0x44, 0x24, 0x18});
        Raw({0x48, 0x89, 0xE0});
        Raw({0x48, 0x2D}); U32(value);
        Raw({0x48, 0x89, 0xE1});
        const size_t loop = Offset();
        Raw({0x48, 0x81, 0xE9}); U32(0x1000u);
        Raw({0xF6, 0x01, 0x00});
        Raw({0x48, 0x39, 0xC1});
        U8(0x77);
        const size_t branch = Offset();
        U8(static_cast<uint8_t>(static_cast<int8_t>(
            static_cast<int64_t>(loop) - static_cast<int64_t>(branch + 1))));
    }
    void StoreReg(uint8_t reg, int32_t displacement) {
        U8(static_cast<uint8_t>(0x48 | (reg >= 8 ? 0x04 : 0x00)));
        U8(0x89);
        U8(static_cast<uint8_t>(0x84 | ((reg & 7u) << 3)));
        U8(0x24);
        U32(static_cast<uint32_t>(displacement));
    }
    void LoadReg(uint8_t reg, int32_t displacement) {
        U8(static_cast<uint8_t>(0x48 | (reg >= 8 ? 0x04 : 0x00)));
        U8(0x8B);
        U8(static_cast<uint8_t>(0x84 | ((reg & 7u) << 3)));
        U8(0x24);
        U32(static_cast<uint32_t>(displacement));
    }
    void StoreXmm(uint8_t xmm, uint32_t displacement) {
        U8(0xF3);
        if (xmm >= 8) U8(0x44);
        Raw({0x0F, 0x7F});
        U8(static_cast<uint8_t>(0x84 | ((xmm & 7u) << 3)));
        U8(0x24);
        U32(displacement);
    }
    void LoadXmm(uint8_t xmm, uint32_t displacement) {
        U8(0xF3);
        if (xmm >= 8) U8(0x44);
        Raw({0x0F, 0x6F});
        U8(static_cast<uint8_t>(0x84 | ((xmm & 7u) << 3)));
        U8(0x24);
        U32(displacement);
    }
    void LeaRcxRsp(uint32_t displacement) { Raw({0x48, 0x8D, 0x8C, 0x24}); U32(displacement); }
    void LeaRaxRsp(uint32_t displacement) { Raw({0x48, 0x8D, 0x84, 0x24}); U32(displacement); }
    void LeaR10Rsp(uint32_t displacement) { Raw({0x4C, 0x8D, 0x94, 0x24}); U32(displacement); }
    void AddRaxImm(uint32_t value) { Raw({0x48, 0x05}); U32(value); }
    void AndRaxImm(uint32_t value) { Raw({0x48, 0x25}); U32(value); }
    void MovEaxImm(uint32_t value) { U8(0xB8); U32(value); }
    void XorEdxEdx() { Raw({0x31, 0xD2}); }
    void MovEdxImm(uint32_t value) { U8(0xBA); U32(value); }
    void MovR8dImm(uint32_t value) { Raw({0x41, 0xB8}); U32(value); }
    ImageBasePatch LoadOwnImageBaseR9() {
        // RIP belongs to the protected module even when it is a DLL.  PEB.ImageBaseAddress
        // names the host EXE and therefore cannot be used by an injected DLL trampoline.
        // Capture the address after LEA, then subtract that instruction's patched RVA.
        const uint32_t anchorOffset = static_cast<uint32_t>(Offset()) + 7u;
        Raw({0x4C, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00}); // lea r9,[rip]
        U8(0xB8);                                         // mov eax, anchor RVA
        const uint32_t immediateOffset = static_cast<uint32_t>(Offset());
        U32(0);
        Raw({0x49, 0x29, 0xC1});                         // sub r9,rax
        return {immediateOffset, anchorOffset};
    }
    void AddR8R9() { Raw({0x4D, 0x01, 0xC8}); }
    void StoreRaxRsp(uint32_t displacement) { Raw({0x48, 0x89, 0x84, 0x24}); U32(displacement); }
    void LoadRaxRsp(uint32_t displacement) { Raw({0x48, 0x8B, 0x84, 0x24}); U32(displacement); }
    void LoadR10Rsp(uint32_t displacement) { Raw({0x4C, 0x8B, 0x94, 0x24}); U32(displacement); }
    void StoreImm32Rax(uint32_t displacement, uint32_t value) {
        Raw({0xC7, 0x80}); U32(displacement); U32(value);
    }
    void FxsaveRax() { Raw({0x48, 0x0F, 0xAE, 0x00}); }
    void FxrstorR10() { Raw({0x49, 0x0F, 0xAE, 0x0A}); }
    void XsaveR10() { Raw({0x49, 0x0F, 0xAE, 0x22}); }
    void XrstorR10() { Raw({0x49, 0x0F, 0xAE, 0x2A}); }
    void PushFlagsToRax() { Raw({0x9C, 0x58}); }
    void PushMemoryRsp(int32_t displacement) {
        Raw({0xFF, 0xB4, 0x24});
        U32(static_cast<uint32_t>(displacement));
    }
    void CallRelative(uint32_t instructionRVA, uint32_t targetRVA) {
        U8(0xE8);
        const int64_t relative = static_cast<int64_t>(targetRVA) -
            static_cast<int64_t>(instructionRVA + bytes.size() + 4);
        U32(static_cast<uint32_t>(static_cast<int32_t>(relative)));
    }
    void FailHardIfEaxNonZero() { Raw({0x85, 0xC0, 0x74, 0x03, 0xCC, 0x0F, 0x0B}); }
    void Ret() { U8(0xC3); }
};

struct UnwindOperation {
    uint8_t codeOffset = 0;
    uint8_t unwindOp = 0;
    uint8_t opInfo = 0;
    uint16_t extra = 0;
};

struct BuiltX64Trampoline {
    std::vector<uint8_t> code;
    std::vector<uint8_t> unwindInfo;
    X64TrampolineAssembler::ImageBasePatch imageBasePatch{};
};

struct SavedRegister {
    uint8_t number;
    uint32_t offset;
};

std::vector<uint8_t> BuildUnwindInfo(
    uint8_t prologSize,
    const std::vector<UnwindOperation>& operations,
    uint8_t frameRegister = 0,
    uint8_t frameOffset = 0)
{
    const auto slotCount = [](const UnwindOperation& operation) -> uint8_t {
        switch (operation.unwindOp) {
            case 0: // UWOP_PUSH_NONVOL
            case 2: // UWOP_ALLOC_SMALL
            case 3: // UWOP_SET_FPREG
                return 1;
            case 1: // UWOP_ALLOC_LARGE, OpInfo 0 in this builder
            case 4: // UWOP_SAVE_NONVOL
            case 8: // UWOP_SAVE_XMM128
                return operation.unwindOp == 1 && operation.opInfo != 0 ? 3 : 2;
            case 5: // UWOP_SAVE_NONVOL_FAR
            case 9: // UWOP_SAVE_XMM128_FAR
                return 3;
            default:
                return 0;
        }
    };
    uint32_t unwindSlots = 0;
    for (const auto& operation : operations) {
        const uint8_t slots = slotCount(operation);
        if (slots == 0 || unwindSlots > 0xFFu - slots) return {};
        unwindSlots += slots;
    }
    if (frameRegister > 15u || frameOffset > 15u) return {};
    CodeBuffer output;
    output.U8(0x01); // UNW_VERSION=1, no handler flags.
    output.U8(prologSize);
    output.U8(static_cast<uint8_t>(unwindSlots));
    output.U8(static_cast<uint8_t>((frameOffset << 4u) | frameRegister));
    for (auto it = operations.rbegin(); it != operations.rend(); ++it) {
        const uint8_t slots = slotCount(*it);
        output.U8(it->codeOffset);
        output.U8(static_cast<uint8_t>((it->opInfo << 4) | (it->unwindOp & 0x0F)));
        if (slots >= 2u) output.U16(it->extra);
        if (slots == 3u) output.U16(0u);
    }
    while (output.bytes.size() % 4 != 0) output.U8(0);
    return output.bytes;
}

class X86TrampolineAssembler : public CodeBuffer {
public:
    struct ImageBasePatch {
        uint32_t immediateOffset = 0;
        uint32_t anchorOffset = 0;
    };

    void Endbr() { Raw({0xF3, 0x0F, 0x1E, 0xFB}); }
    void PushFlags() { U8(0x9C); }
    void PopFlags() { U8(0x9D); }
    void PushAll() { U8(0x60); }
    void PopAll() { U8(0x61); }
    void SubEsp(uint32_t value) { Raw({0x81, 0xEC}); U32(value); }
    void AddEsp(uint32_t value) { Raw({0x81, 0xC4}); U32(value); }
    void ProbeStack(uint32_t value) {
        PushFlags();
        PushReg(0);
        PushReg(1);
        Raw({0x8B, 0xC4});
        U8(0x2D); U32(value);
        Raw({0x8B, 0xCC});
        const size_t loop = Offset();
        Raw({0x81, 0xE9}); U32(0x1000u);
        Raw({0xF6, 0x01, 0x00});
        Raw({0x3B, 0xC8});
        U8(0x77);
        const size_t branch = Offset();
        U8(static_cast<uint8_t>(static_cast<int8_t>(
            static_cast<int64_t>(loop) - static_cast<int64_t>(branch + 1))));
        PopReg(1);
        PopReg(0);
        PopFlags();
    }
    void LoadEaxRsp(uint32_t displacement) { Raw({0x8B, 0x84, 0x24}); U32(displacement); }
    void StoreEaxRsp(uint32_t displacement) { Raw({0x89, 0x84, 0x24}); U32(displacement); }
    void StoreXmm(uint8_t xmm, uint32_t displacement) {
        Raw({0xF3, 0x0F, 0x7F});
        U8(static_cast<uint8_t>(0x84 | ((xmm & 7u) << 3)));
        U8(0x24);
        U32(displacement);
    }
    void LoadXmm(uint8_t xmm, uint32_t displacement) {
        Raw({0xF3, 0x0F, 0x6F});
        U8(static_cast<uint8_t>(0x84 | ((xmm & 7u) << 3)));
        U8(0x24);
        U32(displacement);
    }
    void MovEdxEsp() { Raw({0x8B, 0xD4}); }
    void MovEcxEsp() { Raw({0x8B, 0xCC}); }
    void AddEcxImm(uint32_t value) { Raw({0x81, 0xC1}); U32(value); }
    void AndEcxImm(uint32_t value) { Raw({0x81, 0xE1}); U32(value); }
    void AddEdxImm(uint32_t value) { Raw({0x81, 0xC2}); U32(value); }
    void AndEdxImm(uint32_t value) { Raw({0x81, 0xE2}); U32(value); }
    void MovEaxImm(uint32_t value) { U8(0xB8); U32(value); }
    void XorEdxEdx() { Raw({0x31, 0xD2}); }
    void StoreImm32Ecx(uint32_t displacement, uint32_t value) {
        Raw({0xC7, 0x81}); U32(displacement); U32(value);
    }
    void FxsaveEcx() { Raw({0x0F, 0xAE, 0x01}); }
    void FxrstorEcx() { Raw({0x0F, 0xAE, 0x09}); }
    void XsaveEcx() { Raw({0x0F, 0xAE, 0x21}); }
    void XrstorEcx() { Raw({0x0F, 0xAE, 0x29}); }
    void LeaEaxEsp(uint32_t displacement) { Raw({0x8D, 0x84, 0x24}); U32(displacement); }
    ImageBasePatch LoadOwnImageBaseEcx() {
        // A balanced CALL/helper/RET obtains a PE32 code address without reading
        // PEB.ImageBaseAddress (which names the host EXE for a DLL). Do not use
        // the traditional call-next/pop idiom here: POP would leave CET shadow
        // stack state unmatched and make the trampoline's final RET raise #CP.
        const uint32_t anchorOffset = static_cast<uint32_t>(Offset()) + 5u;
        Raw({0xE8, 0x02, 0x00, 0x00, 0x00}); // call get_pc
        Raw({0xEB, 0x04});                    // anchor: jmp after_helper
        Raw({0x8B, 0x0C, 0x24});              // get_pc: mov ecx,[esp]
        U8(0xC3);                             // ret (balances normal + shadow stacks)
        Raw({0x81, 0xE9});                    // after_helper: sub ecx, anchor RVA
        const uint32_t immediateOffset = static_cast<uint32_t>(Offset());
        U32(0);
        return {immediateOffset, anchorOffset};
    }
    void MovEbxImm(uint32_t value) { U8(0xBB); U32(value); }
    void AddEbxEcx() { Raw({0x03, 0xD9}); }
    void PushReg(uint8_t reg) { U8(static_cast<uint8_t>(0x50 + (reg & 7u))); }
    void PopReg(uint8_t reg) { U8(static_cast<uint8_t>(0x58 + (reg & 7u))); }
    void PushImm(uint32_t value) { U8(0x68); U32(value); }
    void CallRelative(uint32_t instructionRVA, uint32_t targetRVA) {
        U8(0xE8);
        const int64_t relative = static_cast<int64_t>(targetRVA) -
            static_cast<int64_t>(instructionRVA + bytes.size() + 4);
        U32(static_cast<uint32_t>(static_cast<int32_t>(relative)));
    }
    void FailHardIfEaxNonZero() { Raw({0x85, 0xC0, 0x74, 0x03, 0xCC, 0x0F, 0x0B}); }
    void Ret(uint16_t cleanup) { if (cleanup) { U8(0xC2); U16(cleanup); } else U8(0xC3); }
};

bool ParseRuntimeImage(
    const uint8_t* file,
    size_t fileSize,
    bool expect64Bit,
    MappedRuntimeImage& output,
    std::string& error)
{
    if (!file || fileSize < sizeof(IMAGE_DOS_HEADER)) {
        error = "runtime blob DOS header is truncated";
        return false;
    }
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(file);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 ||
        !RangeValid(static_cast<size_t>(dos->e_lfanew), sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER), fileSize)) {
        error = "runtime blob has invalid DOS/NT header";
        return false;
    }
    const uint8_t* ntBase = file + dos->e_lfanew;
    if (*reinterpret_cast<const DWORD*>(ntBase) != IMAGE_NT_SIGNATURE) {
        error = "runtime blob NT signature mismatch";
        return false;
    }
    const auto* fileHeader = reinterpret_cast<const IMAGE_FILE_HEADER*>(ntBase + sizeof(DWORD));
    const uint8_t* optionalBase = reinterpret_cast<const uint8_t*>(fileHeader + 1);
    if (!RangeValid(static_cast<size_t>(optionalBase - file), fileHeader->SizeOfOptionalHeader, fileSize)) {
        error = "runtime optional header is truncated";
        return false;
    }
    const WORD magic = *reinterpret_cast<const WORD*>(optionalBase);
    output.is64Bit = magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    if (output.is64Bit != expect64Bit ||
        (!output.is64Bit && magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)) {
        error = "runtime blob architecture mismatch";
        return false;
    }

    uint32_t sizeOfImage = 0;
    uint32_t sizeOfHeaders = 0;
    IMAGE_DATA_DIRECTORY importDirectory{};
    IMAGE_DATA_DIRECTORY relocationDirectory{};
    IMAGE_DATA_DIRECTORY exceptionDirectory{};
    if (output.is64Bit) {
        const auto* optional = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(optionalBase);
        sizeOfImage = optional->SizeOfImage;
        sizeOfHeaders = optional->SizeOfHeaders;
        output.preferredBase = optional->ImageBase;
        output.entryRVA = optional->AddressOfEntryPoint;
        importDirectory = optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        relocationDirectory = optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        exceptionDirectory = optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    } else {
        const auto* optional = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(optionalBase);
        sizeOfImage = optional->SizeOfImage;
        sizeOfHeaders = optional->SizeOfHeaders;
        output.preferredBase = optional->ImageBase;
        output.entryRVA = optional->AddressOfEntryPoint;
        importDirectory = optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        relocationDirectory = optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    }
    if (sizeOfImage == 0 || sizeOfImage > 16u * 1024u * 1024u || output.entryRVA >= sizeOfImage) {
        error = "runtime mapped image size or entry RVA is invalid";
        return false;
    }
    if (importDirectory.VirtualAddress != 0 || importDirectory.Size != 0) {
        error = "runtime blob unexpectedly contains imports";
        return false;
    }

    output.bytes.assign(sizeOfImage, 0);
    output.headersSize = sizeOfHeaders;
    const size_t headerBytes = (std::min)(static_cast<size_t>(sizeOfHeaders), fileSize);
    std::memcpy(output.bytes.data(), file, headerBytes);
    const uint8_t* sectionBase = optionalBase + fileHeader->SizeOfOptionalHeader;
    if (!RangeValid(static_cast<size_t>(sectionBase - file),
        static_cast<size_t>(fileHeader->NumberOfSections) * sizeof(IMAGE_SECTION_HEADER), fileSize)) {
        error = "runtime section table is truncated";
        return false;
    }
    const auto* sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(sectionBase);
    for (WORD i = 0; i < fileHeader->NumberOfSections; ++i) {
        const auto& section = sections[i];
        const uint32_t virtualSize = section.Misc.VirtualSize ? section.Misc.VirtualSize : section.SizeOfRawData;
        if (section.VirtualAddress > sizeOfImage || virtualSize > sizeOfImage - section.VirtualAddress ||
            !RangeValid(section.PointerToRawData, section.SizeOfRawData, fileSize)) {
            error = "runtime section range is invalid";
            return false;
        }
        if ((section.Characteristics & IMAGE_SCN_MEM_WRITE) && virtualSize != 0) {
            error = "runtime blob contains writable static state";
            return false;
        }
        const uint32_t copySize = (std::min)(static_cast<uint32_t>(section.SizeOfRawData), virtualSize);
        if (copySize) std::memcpy(output.bytes.data() + section.VirtualAddress,
            file + section.PointerToRawData, copySize);
    }

    if (relocationDirectory.VirtualAddress && relocationDirectory.Size) {
        if (relocationDirectory.VirtualAddress > output.bytes.size() ||
            relocationDirectory.Size > output.bytes.size() - relocationDirectory.VirtualAddress) {
            error = "runtime relocation directory is outside mapped image";
            return false;
        }
        uint32_t cursor = relocationDirectory.VirtualAddress;
        const uint32_t end = cursor + relocationDirectory.Size;
        while (cursor < end) {
            if (end - cursor < sizeof(IMAGE_BASE_RELOCATION)) {
                error = "runtime relocation block is truncated";
                return false;
            }
            const auto* block = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(output.bytes.data() + cursor);
            if (block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) || block->SizeOfBlock > end - cursor) {
                error = "runtime relocation block size is invalid";
                return false;
            }
            const uint32_t entryCount = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            const WORD* entries = reinterpret_cast<const WORD*>(block + 1);
            for (uint32_t i = 0; i < entryCount; ++i) {
                RuntimeRelocation relocation{};
                relocation.type = entries[i] >> 12;
                relocation.offset = block->VirtualAddress + (entries[i] & 0x0FFFu);
                if (relocation.type != IMAGE_REL_BASED_ABSOLUTE) output.relocations.push_back(relocation);
            }
            cursor += block->SizeOfBlock;
        }
    }

    if (output.is64Bit && exceptionDirectory.VirtualAddress && exceptionDirectory.Size) {
        if (exceptionDirectory.VirtualAddress > output.bytes.size() ||
            exceptionDirectory.Size > output.bytes.size() - exceptionDirectory.VirtualAddress ||
            exceptionDirectory.Size % sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY) != 0) {
            error = "runtime exception directory is invalid";
            return false;
        }
        const auto* entries = reinterpret_cast<const IMAGE_RUNTIME_FUNCTION_ENTRY*>(
            output.bytes.data() + exceptionDirectory.VirtualAddress);
        const uint32_t count = exceptionDirectory.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
        for (uint32_t i = 0; i < count; ++i) {
            VMRuntimeFunctionEntry entry{};
            entry.beginRVA = entries[i].BeginAddress;
            entry.endRVA = entries[i].EndAddress;
            entry.unwindRVA = entries[i].UnwindData;
            if (entry.beginRVA >= entry.endRVA || entry.endRVA > output.bytes.size() ||
                entry.unwindRVA >= output.bytes.size()) {
                error = "runtime unwind entry is outside mapped image";
                return false;
            }
            output.unwindEntries.push_back(entry);
        }
    }
    if (output.headersSize > output.bytes.size()) {
        error = "runtime mapped header size exceeds image size";
        return false;
    }
    std::fill(output.bytes.begin(), output.bytes.begin() + output.headersSize,
        static_cast<uint8_t>(0));
    return true;
}

bool ApplyRuntimeRelocations(
    MappedRuntimeImage& runtime,
    uint64_t newBase,
    std::string& error)
{
    const int64_t delta = static_cast<int64_t>(newBase - runtime.preferredBase);
    for (const auto& relocation : runtime.relocations) {
        if (runtime.is64Bit && relocation.type == IMAGE_REL_BASED_DIR64) {
            if (!RangeValid(relocation.offset, sizeof(uint64_t), runtime.bytes.size())) {
                error = "x64 runtime relocation target is outside mapped image";
                return false;
            }
            uint64_t value = 0;
            std::memcpy(&value, runtime.bytes.data() + relocation.offset, sizeof(value));
            value = static_cast<uint64_t>(static_cast<int64_t>(value) + delta);
            std::memcpy(runtime.bytes.data() + relocation.offset, &value, sizeof(value));
        } else if (!runtime.is64Bit && relocation.type == IMAGE_REL_BASED_HIGHLOW) {
            if (!RangeValid(relocation.offset, sizeof(uint32_t), runtime.bytes.size())) {
                error = "x86 runtime relocation target is outside mapped image";
                return false;
            }
            uint32_t value = 0;
            std::memcpy(&value, runtime.bytes.data() + relocation.offset, sizeof(value));
            value = static_cast<uint32_t>(static_cast<int64_t>(value) + delta);
            std::memcpy(runtime.bytes.data() + relocation.offset, &value, sizeof(value));
        } else {
            error = "runtime relocation type is unsupported for target architecture";
            return false;
        }
    }
    return true;
}

BuiltX64Trampoline BuildX64Trampoline(
    uint32_t trampolineOffset,
    uint32_t runtimeEntryOffset,
    uint32_t functionRVA,
    uint32_t metadataRVA,
    uint32_t guestStackSize,
    bool usesAvx)
{
    constexpr uint32_t kFrameOffset = 0x40;
    constexpr uint32_t kXmmOffset = 0xD0;
    constexpr uint32_t kExtendedStorageOffset = 0x200;
    constexpr uint32_t kExtendedPointerSlot = 0x30;
    constexpr uint32_t kHostStackAllocation =
        kFrameOffset + VM_RUNTIME_X64_FRAME_TO_SCRATCH;
    // A pushed RBP supplies a real frame pointer for the Win64 epilog.  Add
    // eight bytes to the old allocation so RSP remains 16-byte aligned before
    // every CALL (entry RSP is 8 mod 16, PUSH RBP makes it 0 mod 16).
    const uint32_t kStackAllocation =
        kHostStackAllocation + guestStackSize + 8u;
    constexpr uint32_t kFrameR15 = kFrameOffset + 0;
    constexpr uint32_t kFrameR14 = kFrameOffset + 8;
    constexpr uint32_t kFrameR13 = kFrameOffset + 16;
    constexpr uint32_t kFrameR12 = kFrameOffset + 24;
    constexpr uint32_t kFrameR11 = kFrameOffset + 32;
    constexpr uint32_t kFrameR10 = kFrameOffset + 40;
    constexpr uint32_t kFrameR9 = kFrameOffset + 48;
    constexpr uint32_t kFrameR8 = kFrameOffset + 56;
    constexpr uint32_t kFrameRdi = kFrameOffset + 64;
    constexpr uint32_t kFrameRsi = kFrameOffset + 72;
    constexpr uint32_t kFrameRbp = kFrameOffset + 80;
    constexpr uint32_t kFrameRbx = kFrameOffset + 88;
    constexpr uint32_t kFrameRdx = kFrameOffset + 96;
    constexpr uint32_t kFrameRcx = kFrameOffset + 104;
    constexpr uint32_t kFrameRax = kFrameOffset + 112;
    constexpr uint32_t kFrameRflags = kFrameOffset + 120;
    constexpr uint32_t kFrameReturnAddress = kFrameOffset + 128;
    constexpr uint32_t kFrameOriginalRsp = kFrameOffset + 136;

    X64TrampolineAssembler assembler;
    std::vector<UnwindOperation> unwindOperations;

    assembler.Endbr();
    // ProbeStack is unwind-neutral and restores entry flags/registers.  Probe
    // through the pushed frame-pointer slot as well as the fixed allocation.
    assembler.ProbeStack(kStackAllocation + 8u);
    assembler.PushReg(5);
    unwindOperations.push_back({
        static_cast<uint8_t>(assembler.Offset()), 0, 5, 0
    });
    assembler.SubRsp(kStackAllocation);
    unwindOperations.push_back({
        static_cast<uint8_t>(assembler.Offset()), 1, 0,
        static_cast<uint16_t>(kStackAllocation / 8)
    });
    assembler.MovRbpRsp();
    unwindOperations.push_back({
        static_cast<uint8_t>(assembler.Offset()), 3, 0, 0
    });

    const SavedRegister nonvolatileGprs[] = {
        {15, kFrameR15}, {14, kFrameR14}, {13, kFrameR13}, {12, kFrameR12},
        {7, kFrameRdi}, {6, kFrameRsi}, {3, kFrameRbx}
    };
    for (const auto& saved : nonvolatileGprs) {
        assembler.StoreReg(saved.number, static_cast<int32_t>(saved.offset));
        unwindOperations.push_back({
            static_cast<uint8_t>(assembler.Offset()), 4, saved.number,
            static_cast<uint16_t>(saved.offset / 8)
        });
    }
    for (uint8_t xmm = 6; xmm < 16; ++xmm) {
        const uint32_t offset = kXmmOffset + xmm * 16;
        assembler.StoreXmm(xmm, offset);
        unwindOperations.push_back({
            static_cast<uint8_t>(assembler.Offset()), 8, xmm,
            static_cast<uint16_t>(offset / 16)
        });
    }
    if (assembler.Offset() > 0xFFu) return {};
    const uint8_t prologSize = static_cast<uint8_t>(assembler.Offset());

    const SavedRegister volatileGprs[] = {
        {11, kFrameR11}, {10, kFrameR10}, {9, kFrameR9}, {8, kFrameR8},
        {2, kFrameRdx}
    };
    for (const auto& saved : volatileGprs) {
        assembler.StoreReg(saved.number, static_cast<int32_t>(saved.offset));
    }
    // ProbeStack saved entry RAX/RCX/RFLAGS in the caller home area before
    // PUSH RBP.  The pushed RBP adds one slot to every positive entry offset.
    assembler.LoadReg(1, static_cast<int32_t>(kStackAllocation + 0x18u));
    assembler.StoreReg(1, static_cast<int32_t>(kFrameRcx));
    assembler.LoadReg(0, static_cast<int32_t>(kStackAllocation + 0x10u));
    assembler.StoreReg(0, static_cast<int32_t>(kFrameRax));
    assembler.LoadReg(0, static_cast<int32_t>(kStackAllocation + 0x20u));
    assembler.StoreReg(0, static_cast<int32_t>(kFrameRflags));
    assembler.LoadReg(0, static_cast<int32_t>(kStackAllocation + 0x08u));
    assembler.StoreReg(0, static_cast<int32_t>(kFrameReturnAddress));
    // The original RBP is the slot immediately above the fixed allocation.
    assembler.LoadReg(0, static_cast<int32_t>(kStackAllocation));
    assembler.StoreReg(0, static_cast<int32_t>(kFrameRbp));
    assembler.LeaRaxRsp(kStackAllocation + 0x08u);
    assembler.StoreReg(0, static_cast<int32_t>(kFrameOriginalRsp));
    assembler.LeaRaxRsp(kExtendedStorageOffset);
    assembler.AddRaxImm(63);
    assembler.AndRaxImm(0xFFFFFFC0u);
    assembler.StoreRaxRsp(kExtendedPointerSlot);
    assembler.StoreImm32Rax(VM_XSAVE_AREA_SIZE,
        usesAvx ? VM_EXTENDED_STATE_FLAG_AVX : 0u);
    if (usesAvx) {
        assembler.LoadR10Rsp(kExtendedPointerSlot);
        assembler.MovEaxImm(7);
        assembler.XorEdxEdx();
        assembler.XsaveR10();
    } else {
        assembler.FxsaveRax();
    }

    assembler.LeaRcxRsp(kFrameOffset);
    assembler.MovEdxImm(functionRVA);
    const auto imageBasePatch = assembler.LoadOwnImageBaseR9();
    assembler.MovR8dImm(metadataRVA);
    assembler.AddR8R9();
    assembler.LoadRaxRsp(kExtendedPointerSlot);
    assembler.StoreRaxRsp(0x20);
    assembler.CallRelative(trampolineOffset, runtimeEntryOffset);
    assembler.FailHardIfEaxNonZero();

    assembler.LoadR10Rsp(kExtendedPointerSlot);
    if (usesAvx) {
        assembler.MovEaxImm(7);
        assembler.XorEdxEdx();
        assembler.XrstorR10();
    } else {
        assembler.FxrstorR10();
    }
    assembler.PushMemoryRsp(static_cast<int32_t>(kFrameRflags));
    assembler.PopFlags();
    const SavedRegister restoreGprs[] = {
        {15, kFrameR15}, {14, kFrameR14}, {13, kFrameR13}, {12, kFrameR12},
        {11, kFrameR11}, {10, kFrameR10}, {9, kFrameR9}, {8, kFrameR8},
        {7, kFrameRdi}, {6, kFrameRsi}, {3, kFrameRbx},
        {2, kFrameRdx}, {1, kFrameRcx}, {0, kFrameRax}
    };
    for (const auto& restored : restoreGprs) {
        assembler.LoadReg(restored.number, static_cast<int32_t>(restored.offset));
    }
    // LEA through the declared frame register is a canonical Win64 epilog and
    // does not overwrite the VM's returned status flags.  POP RBP and RET are
    // the only following instructions, exactly matching the V1 epilog grammar.
    assembler.LeaRspRbp(kStackAllocation);
    assembler.PopReg(5);
    assembler.Ret();

    BuiltX64Trampoline result;
    result.code = std::move(assembler.bytes);
    result.unwindInfo = BuildUnwindInfo(
        prologSize, unwindOperations, 5u, 0u);
    result.imageBasePatch = imageBasePatch;
    return result;
}

struct BuiltX86Trampoline {
    std::vector<uint8_t> code;
    X86TrampolineAssembler::ImageBasePatch imageBasePatch{};
};

BuiltX86Trampoline BuildX86Trampoline(
    uint32_t trampolineOffset,
    uint32_t runtimeEntryOffset,
    uint32_t functionRVA,
    uint32_t metadataRVA,
    uint16_t returnCleanup,
    uint32_t guestStackSize,
    bool usesAvx)
{
    constexpr uint32_t kFrameOffset = 0x40;
    constexpr uint32_t kHostAllocation =
        kFrameOffset + VM_RUNTIME_X86_FRAME_TO_SCRATCH;
    constexpr uint32_t kExtendedStorageOffset = 0x100;
    const uint32_t kStackAllocation = kHostAllocation + guestStackSize;
    X86TrampolineAssembler assembler;
    assembler.Endbr();
    assembler.ProbeStack(kStackAllocation + sizeof(VM_NATIVE_FRAME_X86));
    assembler.PushFlags();
    assembler.PushAll();
    assembler.SubEsp(kStackAllocation);
    for (uint32_t offset = 0; offset < sizeof(VM_NATIVE_FRAME_X86); offset += 4) {
        assembler.LoadEaxRsp(kStackAllocation + offset);
        assembler.StoreEaxRsp(kFrameOffset + offset);
    }
    assembler.MovEcxEsp();
    assembler.AddEcxImm(kExtendedStorageOffset + 63);
    assembler.AndEcxImm(0xFFFFFFC0u);
    assembler.StoreImm32Ecx(VM_XSAVE_AREA_SIZE,
        usesAvx ? VM_EXTENDED_STATE_FLAG_AVX : 0u);
    if (usesAvx) {
        assembler.MovEaxImm(7);
        assembler.XorEdxEdx();
        assembler.XsaveEcx();
    } else {
        assembler.FxsaveEcx();
    }
    assembler.MovEdxEsp();
    assembler.AddEdxImm(kExtendedStorageOffset + 63);
    assembler.AndEdxImm(0xFFFFFFC0u);
    assembler.LeaEaxEsp(kFrameOffset);
    const auto imageBasePatch = assembler.LoadOwnImageBaseEcx();
    assembler.MovEbxImm(metadataRVA);
    assembler.AddEbxEcx();
    assembler.PushReg(2); // Extended processor-state pointer in EDX.
    assembler.PushReg(1); // Image base in ECX.
    assembler.PushReg(3); // Metadata VA in EBX.
    assembler.PushImm(functionRVA);
    assembler.PushReg(0); // Native frame pointer in EAX.
    assembler.CallRelative(trampolineOffset, runtimeEntryOffset);
    assembler.AddEsp(20);
    assembler.FailHardIfEaxNonZero();
    assembler.MovEcxEsp();
    assembler.AddEcxImm(kExtendedStorageOffset + 63);
    assembler.AndEcxImm(0xFFFFFFC0u);
    if (usesAvx) {
        assembler.MovEaxImm(7);
        assembler.XorEdxEdx();
        assembler.XrstorEcx();
    } else {
        assembler.FxrstorEcx();
    }
    for (uint32_t offset = 0; offset < sizeof(VM_NATIVE_FRAME_X86); offset += 4) {
        assembler.LoadEaxRsp(kFrameOffset + offset);
        assembler.StoreEaxRsp(kStackAllocation + offset);
    }
    assembler.AddEsp(kStackAllocation);
    assembler.PopAll();
    assembler.PopFlags();
    assembler.Ret(returnCleanup);
    BuiltX86Trampoline result;
    result.code = std::move(assembler.bytes);
    result.imageBasePatch = imageBasePatch;
    return result;
}

uint64_t GetImageBase(const CS_PE_IMAGE* image) {
    return image->is64Bit ? image->ntHeaders64->OptionalHeader.ImageBase
                          : image->ntHeaders32->OptionalHeader.ImageBase;
}

bool ReadMetadataHeader(
    const CS_PE_IMAGE* image,
    uint32_t metadataRVA,
    VM_METADATA_HEADER& header)
{
    if (!image || !image->rawData || metadataRVA == 0) return false;
    uint32_t rawOffset = 0;
    bool found = false;
    const uint32_t headersSize = image->is64Bit
        ? image->ntHeaders64->OptionalHeader.SizeOfHeaders
        : image->ntHeaders32->OptionalHeader.SizeOfHeaders;
    if (metadataRVA < headersSize) {
        rawOffset = metadataRVA;
        found = true;
    } else {
        for (WORD i = 0; i < image->numSections; ++i) {
            const auto& section = image->sections[i];
            const uint32_t span = (std::max)(section.Misc.VirtualSize, section.SizeOfRawData);
            if (metadataRVA >= section.VirtualAddress &&
                metadataRVA - section.VirtualAddress < span) {
                rawOffset = section.PointerToRawData + metadataRVA - section.VirtualAddress;
                found = true;
                break;
            }
        }
    }
    if (!found || rawOffset > image->rawSize ||
        sizeof(header) > image->rawSize - rawOffset) return false;
    std::memcpy(&header, image->rawData + rawOffset, sizeof(header));
    return header.headerSize == sizeof(VM_METADATA_HEADER) &&
        header.layoutSeed != 0 && header.operandCodecSeed != 0 &&
        header.schemaVersion == VM_SCHEMA_VERSION;
}

} // namespace

bool VMRuntimeBuilder::VerifyRuntimeContents(
    const CS_PE_IMAGE* image,
    const VMRuntimeBuildResult& result,
    std::string& error)
{
    error.clear();
    const auto fail = [&](const char* message) -> bool {
        error = message;
        return false;
    };

    if (!image || !image->isValid || !image->rawData || !image->sections ||
        image->numSections == 0) {
        return fail("runtime integrity verification requires a valid parsed PE");
    }
    if ((image->is64Bit && image->ntHeaders64 == nullptr) ||
        (!image->is64Bit && image->ntHeaders32 == nullptr)) {
        return fail("runtime integrity verification requires parsed NT headers");
    }
    const bool expected64 = result.architecture == VM_ARCH_X64;
    if ((result.architecture != VM_ARCH_X64 && result.architecture != VM_ARCH_X86) ||
        expected64 != (image->is64Bit != 0)) {
        return fail("runtime integrity architecture does not match the current PE");
    }
    if (result.sectionRVA == 0 || result.sectionSize == 0 ||
        result.runtimeImageSize == 0 || result.runtimeEntryRVA < result.sectionRVA) {
        return fail("runtime integrity linkage range is incomplete");
    }

    const VMRuntimeIntegrityExpectation& expectation = result.integrityExpectation;
    if (expectation.version != VM_RUNTIME_INTEGRITY_EXPECTATION_VERSION ||
        expectation.expectedSectionBytes.size() != result.sectionSize ||
        expectation.sectionContentSize < result.runtimeImageSize ||
        expectation.sectionContentSize > expectation.expectedSectionBytes.size()) {
        return fail("runtime integrity expectation is missing or malformed");
    }
    if ((expectation.dispatchTableCodec.encoding !=
                VMDispatchTableEncoding::XorKeyedTable &&
            expectation.dispatchTableCodec.encoding !=
                VMDispatchTableEncoding::AddRotateKeyedTable) ||
        expectation.dispatchTableCodec.key == 0u ||
        expectation.dispatchTableCodec.key > 0x7FFFFFFFu ||
        expectation.dispatchTableCodec.rotate == 0u ||
        expectation.dispatchTableCodec.rotate > 31u) {
        return fail("runtime integrity dispatch-table codec is invalid");
    }
    if (expectation.synthesizedImage.offset != 0 ||
        expectation.synthesizedImage.size != result.runtimeImageSize ||
        !RuntimeRangeValid(expectation.synthesizedImage,
            expectation.sectionContentSize) ||
        !RuntimeRangeValid(expectation.encryptedHandlers,
            expectation.synthesizedImage.size) ||
        !RuntimeRangeValid(expectation.dispatchTable,
            expectation.synthesizedImage.size)) {
        return fail("runtime integrity synthesized subrange is invalid");
    }
    const uint64_t dispatchEnd = static_cast<uint64_t>(
        expectation.dispatchTable.offset) + expectation.dispatchTable.size;
    if (dispatchEnd > expectation.encryptedHandlers.offset) {
        return fail("runtime integrity dispatch and encrypted-handler ranges overlap");
    }
    const uint32_t entryOffset = result.runtimeEntryRVA - result.sectionRVA;
    if (entryOffset >= expectation.synthesizedImage.size) {
        return fail("runtime entry lies outside the synthesized image");
    }
    if (expectation.sectionDigest == 0 || expectation.dispatchDigestDomain == 0 ||
        result.opcodeMapDigest == 0 || result.handlerBodyDigest == 0 ||
        result.dispatchKeyDigest == 0 || result.variantSelectorDigest == 0 ||
        expectation.opcodeMapDigest != result.opcodeMapDigest ||
        expectation.handlerBodyDigest != result.handlerBodyDigest ||
        expectation.dispatchKeyDigest != result.dispatchKeyDigest ||
        expectation.variantSelectorDigest != result.variantSelectorDigest) {
        return fail("runtime diversity digest contract is inconsistent");
    }

    const uint8_t* expected = expectation.expectedSectionBytes.data();
    if (HashRuntimeBytes(expected, expectation.expectedSectionBytes.size(),
            kRuntimeSectionDigestDomain) != expectation.sectionDigest ||
        HashRuntimeBytes(expected + expectation.synthesizedImage.offset,
            expectation.synthesizedImage.size, kRuntimeImageDigestDomain) !=
                expectation.synthesizedImage.digest ||
        HashRuntimeBytes(expected + expectation.encryptedHandlers.offset,
            expectation.encryptedHandlers.size, kEncryptedHandlerDigestDomain) !=
                expectation.encryptedHandlers.digest ||
        HashRuntimeBytes(expected + expectation.dispatchTable.offset,
            expectation.dispatchTable.size, kDispatchTableDigestDomain) !=
                expectation.dispatchTable.digest) {
        return fail("runtime integrity expectation digest does not match expected bytes");
    }
    if (!std::all_of(
            expectation.expectedSectionBytes.begin() + expectation.sectionContentSize,
            expectation.expectedSectionBytes.end(),
            [](uint8_t value) { return value == 0; })) {
        return fail("runtime integrity expected section padding is non-zero");
    }

    const IMAGE_SECTION_HEADER* runtimeSection = nullptr;
    for (WORD index = 0; index < image->numSections; ++index) {
        const IMAGE_SECTION_HEADER& section = image->sections[index];
        if (section.VirtualAddress != result.sectionRVA) continue;
        if (runtimeSection != nullptr) {
            return fail("runtime integrity section RVA is duplicated");
        }
        runtimeSection = &section;
    }
    if (!runtimeSection || runtimeSection->SizeOfRawData != result.sectionSize ||
        runtimeSection->Misc.VirtualSize < expectation.sectionContentSize ||
        (runtimeSection->Characteristics &
            (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ)) !=
                (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ) ||
        (runtimeSection->Characteristics & IMAGE_SCN_MEM_WRITE) != 0 ||
        !PEUtils::CheckRawBounds(image, runtimeSection->PointerToRawData,
            runtimeSection->SizeOfRawData)) {
        return fail("runtime integrity section layout or permissions changed");
    }

    const uint8_t* current = image->rawData + runtimeSection->PointerToRawData;
    const auto verifyRange = [&](const VMRuntimeContentRange& range,
                                 uint64_t domain,
                                 const char* digestError,
                                 const char* byteError) -> bool {
        if (HashRuntimeBytes(current + range.offset, range.size, domain) != range.digest) {
            error = digestError;
            return false;
        }
        if (std::memcmp(current + range.offset, expected + range.offset,
                range.size) != 0) {
            error = byteError;
            return false;
        }
        return true;
    };
    if (!verifyRange(expectation.encryptedHandlers,
            kEncryptedHandlerDigestDomain,
            "runtime encrypted-handler digest mismatch",
            "runtime encrypted-handler bytes mismatch") ||
        !verifyRange(expectation.dispatchTable,
            kDispatchTableDigestDomain,
            "runtime dispatch-table digest mismatch",
            "runtime dispatch-table bytes mismatch") ||
        !verifyRange(expectation.synthesizedImage,
            kRuntimeImageDigestDomain,
            "runtime synthesized-image digest mismatch",
            "runtime synthesized-image bytes mismatch")) {
        return false;
    }
    if (HashRuntimeBytes(current, expectation.expectedSectionBytes.size(),
            kRuntimeSectionDigestDomain) != expectation.sectionDigest) {
        return fail("runtime section digest mismatch");
    }
    if (std::memcmp(current, expected,
            expectation.expectedSectionBytes.size()) != 0) {
        return fail("runtime section bytes mismatch");
    }

    const uint32_t pointerSize = expected64 ? 8u : 4u;
    if (expectation.dispatchTable.size % pointerSize != 0) {
        return fail("runtime dispatch-table width is invalid");
    }
    for (uint32_t offset = 0; offset < expectation.dispatchTable.size;
         offset += pointerSize) {
        uint64_t encodedTarget = 0;
        std::memcpy(&encodedTarget,
            current + expectation.dispatchTable.offset + offset, pointerSize);
        if (pointerSize == 4u) encodedTarget &= 0xFFFFFFFFULL;
        const uint64_t relative = DecodeVMDispatchTableTarget(
            encodedTarget, pointerSize, expectation.dispatchTableCodec);
        if (relative == 0u) continue;
        const uint64_t handlerEnd = static_cast<uint64_t>(
            expectation.encryptedHandlers.offset) +
            expectation.encryptedHandlers.size;
        if (relative < expectation.encryptedHandlers.offset ||
            relative >= handlerEnd ||
            relative > (std::numeric_limits<uint32_t>::max)()) {
            return fail("runtime dispatch target is outside encrypted handlers");
        }
    }
    if (HashRuntimeBytes(
            current + expectation.dispatchTable.offset,
            expectation.dispatchTable.size,
            expectation.dispatchDigestDomain) != result.dispatchKeyDigest) {
        return fail("runtime dispatch-key digest does not match encoded targets");
    }
    if (!VerifyNoReferenceRuntimeBlob(image->rawData, image->rawSize, error)) {
        return false;
    }
    return true;
}

VMRuntimeBuildResult VMRuntimeBuilder::Build(
    CS_PE_IMAGE* image,
    const std::vector<VMFunctionRecord>& records,
    const std::vector<uint8_t>& plaintextBytecode,
    const std::unordered_map<uint8_t, uint8_t>& opcodeMap,
    uint32_t metadataRVA,
    const std::array<uint8_t, VM_RUNTIME_KEY_SHARE_SIZE>& runtimeKeyShare,
    const VMHandlerSynthesisConfig& requestedSynthesisConfig,
    const char sectionName[8],
    const char unwindSectionName[8],
    const char relocationSectionName[8],
    const VMRuntimeTraceBinding* traceBinding)
{
    VMRuntimeBuildResult result{};
    if (!image || !image->isValid || !image->rawData || records.empty() ||
        plaintextBytecode.empty() || opcodeMap.empty() || metadataRVA == 0) {
        result.error = "VM_RUNTIME: invalid image, metadata, bytecode, or record table";
        return result;
    }
    if (traceBinding != nullptr) {
        if (traceBinding->traceRVA == 0 || traceBinding->capacity == 0 ||
            traceBinding->capacity > VM_TRACE_MAX_CAPACITY ||
            traceBinding->groupId >= 64u ||
            (traceBinding->architecture != VM_ARCH_X86 &&
             traceBinding->architecture != VM_ARCH_X64) ||
            ((traceBinding->architecture == VM_ARCH_X64) !=
                (image->is64Bit != 0))) {
            result.error = "VM_RUNTIME: invalid runtime trace evidence binding";
            return result;
        }
        VM_METADATA_HEADER traceMetadata{};
        if (!ReadMetadataHeader(image, metadataRVA, traceMetadata) ||
            traceMetadata.architecture != traceBinding->architecture ||
            std::memcmp(traceMetadata.buildId, traceBinding->buildId.data(),
                traceBinding->buildId.size()) != 0) {
            result.error =
                "VM_RUNTIME: trace build id/architecture is not bound to metadata";
            return result;
        }
        result.traceBinding = *traceBinding;
    }

    VMHandlerSynthesisConfig synthesisConfig = requestedSynthesisConfig;
    if (requestedSynthesisConfig.runtimeTraceEnabled !=
            (traceBinding != nullptr)) {
        result.error = "VM_RUNTIME: trace codegen and evidence binding disagree";
        return result;
    }
    synthesisConfig.architecture = image->is64Bit
        ? VMHandlerArchitecture::X64 : VMHandlerArchitecture::X86;
    if (synthesisConfig.virtualProtectIatRVA == 0 ||
        synthesisConfig.flushInstructionCacheIatRVA == 0) {
        result.error = "VM_RUNTIME: handler RX decryption API IAT RVAs are missing";
        return result;
    }
    if (synthesisConfig.functionDecodePlans.empty()) {
        VM_METADATA_HEADER metadataHeader{};
        if (!ReadMetadataHeader(image, metadataRVA, metadataHeader)) {
            result.error = "VM_RUNTIME: micro metadata header cannot seed operand decode plans";
            return result;
        }
        synthesisConfig.functionDecodePlans.reserve(records.size());
        for (const auto& record : records) {
            VMHandlerFunctionDecodePlans plans{};
            plans.functionRVA = record.functionRVA;
            plans.codec = VMSchema::DeriveOperandCodec(
                metadataHeader.operandCodecSeed, record.functionRVA);
            std::string planError;
            if (!VMSchema::BuildRuntimeDecodePlans(
                    plans.codec, plans.plans.data(), planError)) {
                result.error = "VM_RUNTIME: operand decode plan failed for function: " + planError;
                return result;
            }
            synthesisConfig.functionDecodePlans.push_back(std::move(plans));
        }
    }

    std::array<uint8_t, 256> reverseOpcodeMap{};
    reverseOpcodeMap.fill(VM_HANDLER_INVALID);
    for (const auto& mapping : opcodeMap) {
        if (mapping.first >= VM_UOP_COUNT) continue;
        if (reverseOpcodeMap[mapping.second] != VM_HANDLER_INVALID) {
            result.error = "VM_RUNTIME: plaintext evidence opcode map is invalid";
            return result;
        }
        reverseOpcodeMap[mapping.second] = mapping.first;
    }

    std::set<std::pair<uint8_t, uint8_t>> referencedHandlers;
    std::set<uint8_t> referencedSemantics;
    std::unordered_set<uint32_t> evidenceFunctionRVAs;
    result.handlerReferences.reserve(records.size());
    for (const auto& record : records) {
        if (!evidenceFunctionRVAs.insert(record.functionRVA).second ||
            record.bytecodeSize == 0 ||
            record.bytecodeOffset > plaintextBytecode.size() ||
            record.bytecodeSize >
                plaintextBytecode.size() - record.bytecodeOffset) {
            result.error = "VM_RUNTIME: plaintext evidence record range is invalid";
            return result;
        }
        const auto plans = std::find_if(
            synthesisConfig.functionDecodePlans.begin(),
            synthesisConfig.functionDecodePlans.end(),
            [&](const VMHandlerFunctionDecodePlans& candidate) {
                return candidate.functionRVA == record.functionRVA;
            });
        if (plans == synthesisConfig.functionDecodePlans.end()) {
            result.error = "VM_RUNTIME: plaintext evidence lacks a function decode plan";
            return result;
        }
        std::vector<DecodedMicroInstruction> decoded;
        std::string decodeError;
        const uint8_t* recordBytes = plaintextBytecode.data() +
            record.bytecodeOffset;
        if (!VMSchema::DecodeStream(recordBytes, record.bytecodeSize,
                reverseOpcodeMap.data(), plans->codec, decoded, decodeError) ||
            decoded.empty()) {
            result.error = "VM_RUNTIME: plaintext evidence bytecode decode failed: " +
                decodeError;
            return result;
        }
        VMRecordHandlerReferences recordEvidence{};
        recordEvidence.functionRVA = record.functionRVA;
        recordEvidence.bytecodeOffset = record.bytecodeOffset;
        recordEvidence.bytecodeSize = record.bytecodeSize;
        recordEvidence.bytecodeDigest = HashRuntimeBytes(
            recordBytes, record.bytecodeSize,
            kRecordBytecodeEvidenceDomain ^ record.functionRVA);
        recordEvidence.bytecode.assign(
            recordBytes, recordBytes + record.bytecodeSize);
        recordEvidence.references.reserve(decoded.size());
        for (const auto& item : decoded) {
            const uint8_t semantic =
                static_cast<uint8_t>(item.instruction.opcode);
            const uint8_t variant = item.instruction.handlerVariant;
            if (semantic >= VM_UOP_COUNT || variant >= synthesisConfig.variantCount ||
                synthesisConfig.handlerSemanticToSlot[semantic] ==
                    VM_HANDLER_INVALID || item.encodedSize == 0 ||
                item.byteOffset > record.bytecodeSize ||
                item.encodedSize > record.bytecodeSize - item.byteOffset) {
                result.error = "VM_RUNTIME: bytecode references an unavailable handler";
                return result;
            }
            recordEvidence.references.push_back({
                item.byteOffset, item.encodedSize, semantic, variant});
            referencedHandlers.emplace(semantic, variant);
            referencedSemantics.emplace(semantic);
        }
        result.handlerReferences.push_back(std::move(recordEvidence));
    }
    std::sort(result.handlerReferences.begin(), result.handlerReferences.end(),
        [](const auto& left, const auto& right) {
            return left.functionRVA < right.functionRVA;
        });
    if (referencedHandlers.empty()) {
        result.error = "VM_RUNTIME: bytecode references no synthesized handlers";
        return result;
    }

    VMHandlerSynthesizer synthesizer;
    VMHandlerSynthesisResult synthesized = synthesizer.Synthesize(synthesisConfig);
    if (!synthesized.success) {
        result.error = "VM_RUNTIME: handler synthesis failed: " + synthesized.error;
        return result;
    }
    std::string synthesisError;
    if (!VMHandlerSynthesizer::Validate(synthesisConfig, synthesized, synthesisError)) {
        result.error = "VM_RUNTIME: synthesized handler validation failed: " + synthesisError;
        return result;
    }
    if (!synthesized.directThreaded || !synthesized.handlerBodiesEncrypted ||
        synthesized.fixedRuntimeBlobUsed || !synthesized.usesTemporaryPageWrite ||
        !synthesized.restoresExecuteRead || !synthesized.publicEntryReady ||
        !synthesized.validationEntryReady) {
        result.error = "VM_RUNTIME: synthesized handler security contract is incomplete";
        return result;
    }

    MappedRuntimeImage runtime;
    runtime.bytes = synthesized.image;
    runtime.preferredBase = 0;
    runtime.entryRVA = synthesized.entryOffset;
    runtime.headersSize = 0;
    runtime.is64Bit = image->is64Bit != 0;
    runtime.relocations.reserve(synthesized.relocations.size());
    for (const auto& relocation : synthesized.relocations) {
        runtime.relocations.push_back({relocation.offset, relocation.type});
    }
    runtime.unwindEntries.reserve(synthesized.unwindEntries.size());
    for (const auto& unwind : synthesized.unwindEntries) {
        runtime.unwindEntries.push_back({
            unwind.beginOffset, unwind.endOffset, unwind.unwindOffset});
    }
    if (!PatchRuntimeKeyShare(runtime, runtimeKeyShare, result.error)) {
        result.error = "VM_RUNTIME: " + result.error;
        return result;
    }
    result.keySharePatched = true;
    result.handlerSynthesisVerified = true;
    result.directThreadedVerified = true;
    result.handlerEncryptionVerified = true;
    result.opcodeMapDigest = synthesized.opcodeMapDigest;
    result.handlerBodyDigest = synthesized.microSelectionDigest;
    result.dispatchKeyDigest = synthesized.dispatchKeyDigest;
    result.variantSelectorDigest = synthesized.variantSelectorDigest;
    // Keep handlerReferences bound to the K values selected by the real
    // bytecode, but close the plaintext sidecar over every synthesized K for
    // each referenced semantic.  This makes same-(semantic,K) cross-build
    // comparisons possible without changing runtime dispatch selection.
    if (synthesisConfig.variantCount == 0 ||
        referencedSemantics.size() >
            (std::numeric_limits<size_t>::max)() /
                synthesisConfig.variantCount ||
        referencedSemantics.size() >
            (std::numeric_limits<uint32_t>::max)() /
                synthesisConfig.variantCount) {
        result.error =
            "VM_RUNTIME: plaintext handler evidence count is invalid";
        return result;
    }
    const size_t expectedPlaintextHandlerCount =
        referencedSemantics.size() * synthesisConfig.variantCount;
    result.plaintextHandlers.reserve(expectedPlaintextHandlerCount);
    for (const auto& handler : synthesized.handlers) {
        if (referencedSemantics.count(handler.semantic) == 0)
            continue;
        if (handler.semantic == VM_HANDLER_INVALID ||
            handler.slot == VM_HANDLER_INVALID ||
            handler.variant >= synthesisConfig.variantCount ||
            handler.plaintextBody.empty() ||
            handler.plaintextBody.size() >
                (std::numeric_limits<uint32_t>::max)() ||
            handler.semanticCoreSize == 0 ||
            handler.semanticCoreOffset > handler.plaintextBody.size() ||
            handler.semanticCoreSize >
                handler.plaintextBody.size() - handler.semanticCoreOffset ||
            handler.semanticCoreOffset > handler.dispatchTailOffset ||
            handler.semanticCoreSize >
                handler.dispatchTailOffset - handler.semanticCoreOffset ||
            ((handler.semanticCoreVariantSize == 0) !=
                (handler.semanticCoreVariantOffset == 0)) ||
            (handler.semanticCoreVariantSize != 0 &&
                (handler.semanticCoreVariantOffset < handler.semanticCoreOffset ||
                 handler.semanticCoreVariantSize > handler.semanticCoreSize -
                    (handler.semanticCoreVariantOffset -
                        handler.semanticCoreOffset)))) {
            result.error = "VM_RUNTIME: synthesized plaintext handler evidence is invalid";
            return result;
        }
        uint32_t previousCodecEnd = handler.semanticCoreOffset;
        for (const auto& range : handler.valueCodecRanges) {
            if (range.size < 32u || range.offset < previousCodecEnd ||
                range.offset < handler.semanticCoreOffset ||
                range.size > handler.semanticCoreSize -
                    (range.offset - handler.semanticCoreOffset)) {
                result.error = "VM_RUNTIME: value-codec evidence range is invalid";
                return result;
            }
            previousCodecEnd = range.offset + range.size;
        }
        const auto semanticBegin = handler.plaintextBody.begin() +
            handler.semanticCoreOffset;
        result.plaintextHandlers.push_back({
            handler.semantic, handler.slot, handler.variant,
            static_cast<uint32_t>(handler.plaintextBody.size()),
            handler.semanticCoreOffset,
            handler.semanticCoreVariantOffset,
            handler.semanticCoreVariantSize,
            std::vector<uint8_t>(semanticBegin,
                semanticBegin + handler.semanticCoreSize),
            handler.valueCodecRanges});
    }
    std::sort(result.plaintextHandlers.begin(), result.plaintextHandlers.end(),
        [](const auto& left, const auto& right) {
            if (left.semantic != right.semantic)
                return left.semantic < right.semantic;
            return left.variant < right.variant;
        });
    if (result.plaintextHandlers.empty()) {
        result.error = "VM_RUNTIME: synthesized plaintext handler evidence is empty";
        return result;
    }
    if (result.plaintextHandlers.size() != expectedPlaintextHandlerCount) {
        result.error =
            "VM_RUNTIME: referenced semantic handler evidence set is incomplete";
        return result;
    }
    size_t evidenceIndex = 0;
    for (const uint8_t semantic : referencedSemantics) {
        for (uint32_t variant = 0; variant < synthesisConfig.variantCount;
             ++variant, ++evidenceIndex) {
            if (evidenceIndex >= result.plaintextHandlers.size() ||
                result.plaintextHandlers[evidenceIndex].semantic != semantic ||
                result.plaintextHandlers[evidenceIndex].variant != variant) {
                result.error =
                    "VM_RUNTIME: referenced semantic handler evidence K set "
                    "is missing, duplicated, or out of order";
                return result;
            }
        }
    }
    if (evidenceIndex != result.plaintextHandlers.size()) {
        result.error =
            "VM_RUNTIME: plaintext handler evidence contains an unexpected key";
        return result;
    }
    for (const auto& referenced : referencedHandlers) {
        const auto found = std::lower_bound(result.plaintextHandlers.begin(),
            result.plaintextHandlers.end(), referenced,
            [](const VMHandlerPlaintextEvidence& handler,
               const std::pair<uint8_t, uint8_t>& key) {
                return std::pair<uint8_t, uint8_t>{
                           handler.semantic, handler.variant} < key;
            });
        if (found == result.plaintextHandlers.end() ||
            found->semantic != referenced.first ||
            found->variant != referenced.second) {
            result.error =
                "VM_RUNTIME: bytecode-selected handler evidence is missing";
            return result;
        }
    }
    std::vector<uint8_t> semanticEvidenceMaterial;
    const auto appendU32 = [&](uint32_t value) {
        for (uint32_t shift = 0; shift < 32; shift += 8) {
            semanticEvidenceMaterial.push_back(
                static_cast<uint8_t>(value >> shift));
        }
    };
    const auto appendU64 = [&](uint64_t value) {
        for (uint32_t shift = 0; shift < 64; shift += 8) {
            semanticEvidenceMaterial.push_back(
                static_cast<uint8_t>(value >> shift));
        }
    };
    appendU32(result.traceBinding.architecture);
    appendU32(result.traceBinding.groupId);
    appendU32(result.traceBinding.traceRVA);
    appendU32(result.traceBinding.capacity);
    semanticEvidenceMaterial.insert(semanticEvidenceMaterial.end(),
        result.traceBinding.buildId.begin(), result.traceBinding.buildId.end());
    appendU32(static_cast<uint32_t>(result.plaintextHandlers.size()));
    appendU32(static_cast<uint32_t>(result.handlerReferences.size()));
    for (const auto& handler : result.plaintextHandlers) {
        semanticEvidenceMaterial.push_back(handler.semantic);
        semanticEvidenceMaterial.push_back(handler.slot);
        semanticEvidenceMaterial.push_back(handler.variant);
        semanticEvidenceMaterial.push_back(0);
        appendU32(handler.handlerBodySize);
        appendU32(handler.semanticCoreOffset);
        appendU32(static_cast<uint32_t>(handler.core.size()));
        appendU32(handler.semanticCoreVariantOffset);
        appendU32(handler.semanticCoreVariantSize);
        appendU32(static_cast<uint32_t>(handler.valueCodecRanges.size()));
        semanticEvidenceMaterial.insert(semanticEvidenceMaterial.end(),
            handler.core.begin(), handler.core.end());
        for (const auto& range : handler.valueCodecRanges) {
            appendU32(range.offset);
            appendU32(range.size);
        }
    }
    for (const auto& record : result.handlerReferences) {
        appendU32(record.functionRVA);
        appendU32(record.bytecodeOffset);
        appendU32(record.bytecodeSize);
        appendU64(record.bytecodeDigest);
        appendU32(static_cast<uint32_t>(record.references.size()));
        semanticEvidenceMaterial.insert(semanticEvidenceMaterial.end(),
            record.bytecode.begin(), record.bytecode.end());
        for (const auto& reference : record.references) {
            appendU32(reference.bytecodeOffset);
            appendU32(reference.encodedSize);
            semanticEvidenceMaterial.push_back(reference.semantic);
            semanticEvidenceMaterial.push_back(reference.variant);
            semanticEvidenceMaterial.push_back(0);
            semanticEvidenceMaterial.push_back(0);
        }
    }
    result.semanticPlaintextEvidenceDigest = HashRuntimeBytes(
        semanticEvidenceMaterial.data(), semanticEvidenceMaterial.size(),
        kSemanticPlaintextEvidenceDomain);
    if (image->loadConfig.hasCFG) {
        if (!image->loadConfig.valid ||
            (image->is64Bit && image->loadConfig.guardCFDispatchFunctionPointer == 0) ||
            (!image->is64Bit && image->loadConfig.guardCFCheckFunctionPointer == 0) ||
            (image->loadConfig.guardCFFunctionCount !=
                image->loadConfig.guardFunctionRVAs.size())) {
            result.error = "VM_RUNTIME: CFG Load Config or Guard function table is incomplete";
            return result;
        }
    }
    result.cfgVerified = true;

    std::vector<uint8_t> blob = runtime.bytes;
    struct TrampolineImageBasePatch {
        uint32_t immediateOffset = 0;
        uint32_t anchorOffset = 0;
    };
    std::vector<TrampolineImageBasePatch> imageBasePatches;
    const uint32_t runtimeImageSize = static_cast<uint32_t>(runtime.bytes.size());
    std::unordered_set<uint32_t> functionRVAs;
    constexpr uint32_t kRuntimeContextReserve =
        (static_cast<uint32_t>(sizeof(VM_MICRO_EXECUTION_CONTEXT)) + 15u) & ~15u;
    for (const auto& record : records) {
        if (!functionRVAs.insert(record.functionRVA).second || record.functionSize < 5 ||
            record.guestStackSize < 0x4000u || record.guestStackSize > 0x70000u ||
            (record.guestStackSize & 0x0FFFu) != 0 ||
            record.guestStackSize +
                (0x40u + VM_RUNTIME_X64_FRAME_TO_SCRATCH) > 0x7FFF8u ||
            record.bytecodeSize == 0 ||
            kRuntimeContextReserve > record.guestStackSize ||
            record.bytecodeSize > record.guestStackSize - kRuntimeContextReserve) {
            result.error = "VM_RUNTIME: function record or guest stack reserve is invalid";
            return result;
        }
        const uint32_t trampolineOffset = AlignUp(static_cast<uint32_t>(blob.size()), 16);
        blob.resize(trampolineOffset, 0x90);
        std::vector<uint8_t> trampoline;
        VMRuntimeFunctionEntry trampolineUnwind{};
        if (image->is64Bit) {
            BuiltX64Trampoline built = BuildX64Trampoline(trampolineOffset, runtime.entryRVA,
                record.functionRVA, metadataRVA,
                record.guestStackSize,
                (record.flags & VM_RECORD_FLAG_USES_AVX) != 0);
            if (built.code.empty() || built.unwindInfo.empty()) {
                result.error = "VM_RUNTIME: x64 trampoline prolog exceeds unwind encoding limits";
                return result;
            }
            trampoline = std::move(built.code);
            imageBasePatches.push_back({
                trampolineOffset + built.imageBasePatch.immediateOffset,
                trampolineOffset + built.imageBasePatch.anchorOffset});
            const uint32_t unwindOffset = AlignUp(
                trampolineOffset + static_cast<uint32_t>(trampoline.size()), 4);
            blob.resize(unwindOffset, 0);
            trampolineUnwind.beginRVA = trampolineOffset;
            trampolineUnwind.endRVA = trampolineOffset + static_cast<uint32_t>(trampoline.size());
            trampolineUnwind.unwindRVA = unwindOffset;
            blob.insert(blob.end(), built.unwindInfo.begin(), built.unwindInfo.end());
        } else {
            if (record.returnStackCleanup > 0xFFFFu) {
                result.error = "VM_RUNTIME: x86 RET cleanup exceeds uint16";
                return result;
            }
            BuiltX86Trampoline built = BuildX86Trampoline(trampolineOffset, runtime.entryRVA,
                record.functionRVA, metadataRVA,
                static_cast<uint16_t>(record.returnStackCleanup),
                record.guestStackSize,
                (record.flags & VM_RECORD_FLAG_USES_AVX) != 0);
            trampoline = std::move(built.code);
            imageBasePatches.push_back({
                trampolineOffset + built.imageBasePatch.immediateOffset,
                trampolineOffset + built.imageBasePatch.anchorOffset});
        }
        VMTrampolineRecord link{};
        link.functionRVA = record.functionRVA;
        link.trampolineRVA = trampolineOffset;
        link.trampolineSize = static_cast<uint32_t>(trampoline.size());
        result.trampolines.push_back(link);
        if (image->is64Bit) {
            std::copy(trampoline.begin(), trampoline.end(), blob.begin() + trampolineOffset);
            result.unwindEntries.push_back(trampolineUnwind);
        } else {
            blob.insert(blob.end(), trampoline.begin(), trampoline.end());
        }
    }

    char name[8] = {'.', 'c', 's', 'v', 'r', 't', 0, 0};
    if (sectionName) std::memcpy(name, sectionName, sizeof(name));
    PEEmitter emitter(image);
    auto appended = emitter.AppendSection(name, blob,
        IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ);
    if (!appended.success) {
        result.error = "VM_RUNTIME: " + appended.error;
        return result;
    }

    const uint64_t mappedBase = GetImageBase(image) + appended.rva;
    if (!image->is64Bit && mappedBase > (std::numeric_limits<uint32_t>::max)()) {
        result.error = "VM_RUNTIME: x86 runtime mapping exceeds the 32-bit address range";
        return result;
    }
    if (!ApplyRuntimeRelocations(runtime, mappedBase, result.error)) {
        result.error = "VM_RUNTIME: " + result.error;
        return result;
    }
    std::copy(runtime.bytes.begin(), runtime.bytes.end(), blob.begin());
    for (const auto& patch : imageBasePatches) {
        if (!RangeValid(patch.immediateOffset, sizeof(uint32_t), blob.size()) ||
            patch.anchorOffset > (std::numeric_limits<uint32_t>::max)() - appended.rva) {
            result.error = "VM_RUNTIME: trampoline image-base patch is outside the emitted section";
            return result;
        }
        const uint32_t anchorRVA = appended.rva + patch.anchorOffset;
        std::memcpy(blob.data() + patch.immediateOffset, &anchorRVA, sizeof(anchorRVA));
    }
    if (!emitter.PatchBytes(appended.rva, blob, &result.error)) {
        result.error = "VM_RUNTIME: unable to commit relocated blob: " + result.error;
        return result;
    }

    if (!relocationSectionName) {
        result.error = "VM_RUNTIME: relocation section name is missing";
        return result;
    }
    std::vector<CS_RELOC_ENTRY> targetRelocations;
    targetRelocations.reserve(runtime.relocations.size());
    for (const auto& relocation : runtime.relocations) {
        CS_RELOC_ENTRY target{};
        target.type = relocation.type;
        target.fullRVA = static_cast<uint64_t>(appended.rva) + relocation.offset;
        target.pageRVA = static_cast<uint32_t>(target.fullRVA) & ~0xFFFu;
        target.offset = static_cast<uint16_t>(target.fullRVA & 0x0FFFu);
        targetRelocations.push_back(target);
    }
    // Rebuild even when this PIC runtime contributes no new fixups: VM native
    // bodies may have consumed original HIGHLOW/DIR64 fields, and merely
    // pruning the parsed vector would leave the old on-disk directory active.
    if (!emitter.RebuildBaseRelocationDirectory(targetRelocations,
            relocationSectionName, nullptr, &result.error)) {
        result.error = "VM_RUNTIME: unable to rebuild target relocation directory: " + result.error;
        return result;
    }
    for (const auto& target : targetRelocations) {
        const auto found = std::find_if(image->relocs.entries.begin(), image->relocs.entries.end(),
            [&](const CS_RELOC_ENTRY& entry) {
                return entry.fullRVA == target.fullRVA && entry.type == target.type;
            });
        if (found == image->relocs.entries.end()) {
            result.error = "VM_RUNTIME: target relocation verification failed";
            return result;
        }
    }
    result.relocationsVerified = true;

    result.sectionRVA = appended.rva;
    result.sectionRawOffset = image->sections[appended.sectionIndex].PointerToRawData;
    result.sectionSize = image->sections[appended.sectionIndex].SizeOfRawData;
    result.runtimeEntryRVA = appended.rva + runtime.entryRVA;
    result.runtimeImageSize = runtimeImageSize;
    result.architecture = image->is64Bit ? VM_ARCH_X64 : VM_ARCH_X86;
    for (auto& trampoline : result.trampolines) trampoline.trampolineRVA += appended.rva;
    for (auto& unwind : result.unwindEntries) {
        unwind.beginRVA += appended.rva;
        unwind.endRVA += appended.rva;
        unwind.unwindRVA += appended.rva;
    }
    for (const auto& unwind : runtime.unwindEntries) {
        VMRuntimeFunctionEntry adjusted = unwind;
        adjusted.beginRVA += appended.rva;
        adjusted.endRVA += appended.rva;
        adjusted.unwindRVA += appended.rva;
        result.unwindEntries.push_back(adjusted);
    }

    if (image->is64Bit) {
        if (!unwindSectionName || result.unwindEntries.empty()) {
            result.error = "VM_RUNTIME: x64 unwind section name or function entries are missing";
            return result;
        }
        std::vector<CS_RUNTIME_FUNCTION> exceptionEntries;
        exceptionEntries.reserve(result.unwindEntries.size());
        for (const auto& unwind : result.unwindEntries) {
            exceptionEntries.push_back({unwind.beginRVA, unwind.endRVA, unwind.unwindRVA});
        }
        if (!emitter.RebuildExceptionDirectory(
                exceptionEntries, unwindSectionName, nullptr, &result.error)) {
            result.error = "VM_RUNTIME: unable to rebuild x64 exception directory: " + result.error;
            return result;
        }
    }

    result.sectionRawOffset = image->sections[appended.sectionIndex].PointerToRawData;
    result.sectionSize = image->sections[appended.sectionIndex].SizeOfRawData;

    if (blob.size() > result.sectionSize) {
        result.error = "VM_RUNTIME: emitted runtime content exceeds its raw section";
        return result;
    }
    VMRuntimeIntegrityExpectation& expectation = result.integrityExpectation;
    expectation.version = VM_RUNTIME_INTEGRITY_EXPECTATION_VERSION;
    expectation.sectionContentSize = static_cast<uint32_t>(blob.size());
    expectation.dispatchDigestDomain = HashRuntimeBytes(
        synthesisConfig.buildSeed.data(), synthesisConfig.buildSeed.size(),
        kDispatchKeyDomain);
    expectation.opcodeMapDigest = result.opcodeMapDigest;
    expectation.handlerBodyDigest = result.handlerBodyDigest;
    expectation.dispatchKeyDigest = result.dispatchKeyDigest;
    expectation.variantSelectorDigest = result.variantSelectorDigest;
    expectation.dispatchTableCodec = synthesized.dispatchTableCodec;
    expectation.expectedSectionBytes.assign(result.sectionSize, 0);
    std::copy(blob.begin(), blob.end(), expectation.expectedSectionBytes.begin());
    expectation.synthesizedImage.offset = 0;
    expectation.synthesizedImage.size = result.runtimeImageSize;
    expectation.synthesizedImage.digest = HashRuntimeBytes(
        expectation.expectedSectionBytes.data(), result.runtimeImageSize,
        kRuntimeImageDigestDomain);
    expectation.encryptedHandlers.offset = synthesized.encryptedHandlerOffset;
    expectation.encryptedHandlers.size = synthesized.encryptedHandlerSize;
    expectation.encryptedHandlers.digest = HashRuntimeBytes(
        expectation.expectedSectionBytes.data() + synthesized.encryptedHandlerOffset,
        synthesized.encryptedHandlerSize, kEncryptedHandlerDigestDomain);
    expectation.dispatchTable.offset = synthesized.dispatchTableOffset;
    expectation.dispatchTable.size = synthesized.dispatchTableSize;
    expectation.dispatchTable.digest = HashRuntimeBytes(
        expectation.expectedSectionBytes.data() + synthesized.dispatchTableOffset,
        synthesized.dispatchTableSize, kDispatchTableDigestDomain);
    expectation.sectionDigest = HashRuntimeBytes(
        expectation.expectedSectionBytes.data(),
        expectation.expectedSectionBytes.size(), kRuntimeSectionDigestDomain);

    std::string integrityError;
    if (!VerifyRuntimeContents(image, result, integrityError)) {
        result.error = "VM_RUNTIME: emitted runtime integrity verification failed: " +
            integrityError;
        return result;
    }
    result.runtimeContentVerified = true;
    result.referenceRuntimeBlobFreeVerified = true;

    result.unwindVerified = true;
    result.executionReady = true;
    result.success = true;
    return result;
}

} // namespace CipherShell
