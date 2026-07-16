#include "vm_abi_unwind_gate.h"

#include <windows.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>

#include "../../runtime/common/vm_metadata.h"

namespace {

#if defined(_M_X64)
#pragma pack(push, 1)
struct VmAbiSnapshot {
    uint64_t stackBefore;
    uint64_t stackAfter;
    uint64_t gpr[8];
    uint8_t xmm[10][16];
    int32_t returnedValue;
    uint32_t reserved;
};
#pragma pack(pop)

static_assert(offsetof(VmAbiSnapshot, stackAfter) == 8);
static_assert(offsetof(VmAbiSnapshot, gpr) == 16);
static_assert(offsetof(VmAbiSnapshot, xmm) == 80);
static_assert(offsetof(VmAbiSnapshot, returnedValue) == 240);
static_assert(sizeof(VmAbiSnapshot) == 248);

extern "C" int CaptureBinaryFunctionAbi(
    VmProtectedSubFunction function,
    int left,
    int right,
    VmAbiSnapshot* snapshot);

constexpr std::array<uint64_t, 8> kExpectedGpr = {
    0x1122334455667788ULL, // RBX
    0x8877665544332211ULL, // RBP
    0x0F1E2D3C4B5A6978ULL, // RSI
    0x89ABCDEF01234567ULL, // RDI
    0x13579BDF2468ACE0ULL, // R12
    0xFEDCBA9876543210ULL, // R13
    0x55AA55AAAA55AA55ULL, // R14
    0xC3C3F00D5A5AA5A5ULL, // R15
};

constexpr std::array<std::array<uint8_t, 16>, 10> kExpectedXmm = {{
    {{0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6A,0x6B,0x6C,0x6D,0x6E,0x6F}},
    {{0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7A,0x7B,0x7C,0x7D,0x7E,0x7F}},
    {{0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8A,0x8B,0x8C,0x8D,0x8E,0x8F}},
    {{0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9A,0x9B,0x9C,0x9D,0x9E,0x9F}},
    {{0xA0,0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF}},
    {{0xB0,0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,0xB8,0xB9,0xBA,0xBB,0xBC,0xBD,0xBE,0xBF}},
    {{0xC0,0xC1,0xC2,0xC3,0xC4,0xC5,0xC6,0xC7,0xC8,0xC9,0xCA,0xCB,0xCC,0xCD,0xCE,0xCF}},
    {{0xD0,0xD1,0xD2,0xD3,0xD4,0xD5,0xD6,0xD7,0xD8,0xD9,0xDA,0xDB,0xDC,0xDD,0xDE,0xDF}},
    {{0xE0,0xE1,0xE2,0xE3,0xE4,0xE5,0xE6,0xE7,0xE8,0xE9,0xEA,0xEB,0xEC,0xED,0xEE,0xEF}},
    {{0xF0,0xF1,0xF2,0xF3,0xF4,0xF5,0xF6,0xF7,0xF8,0xF9,0xFA,0xFB,0xFC,0xFD,0xFE,0xFF}},
}};
#else
#pragma pack(push, 1)
struct VmAbiSnapshot {
    uint32_t stackBefore;
    uint32_t stackAfter;
    uint32_t gpr[4];
    int32_t returnedValue;
};
#pragma pack(pop)

static_assert(offsetof(VmAbiSnapshot, stackAfter) == 4);
static_assert(offsetof(VmAbiSnapshot, gpr) == 8);
static_assert(offsetof(VmAbiSnapshot, returnedValue) == 24);
static_assert(sizeof(VmAbiSnapshot) == 28);

extern "C" int __cdecl CaptureBinaryFunctionAbi(
    VmProtectedSubFunction function,
    int left,
    int right,
    VmAbiSnapshot* snapshot);

constexpr std::array<uint32_t, 4> kExpectedGpr = {
    0xB16B00B5u, // EBX
    0xE8B0F00Du, // EBP
    0x51A5C0DEu, // ESI
    0xD1A1FACEu, // EDI
};
#endif

struct LoadedImage {
    HMODULE module = nullptr;
    uint8_t* base = nullptr;
    uint32_t imageSize = 0;
    IMAGE_NT_HEADERS* nt = nullptr;
};

bool GetLoadedImage(const void* address, LoadedImage& image) {
    image = {};
    HMODULE module = nullptr;
    if (!GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(address), &module) || !module) {
        return false;
    }
    auto* base = reinterpret_cast<uint8_t*>(module);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0 ||
        static_cast<uint32_t>(dos->e_lfanew) > 0x100000u) {
        return false;
    }
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(
        base + static_cast<uint32_t>(dos->e_lfanew));
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.SizeOfImage < 0x1000u ||
        nt->FileHeader.NumberOfSections == 0) {
        return false;
    }
#if defined(_M_X64)
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return false;
#else
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) return false;
#endif
    image.module = module;
    image.base = base;
    image.imageSize = nt->OptionalHeader.SizeOfImage;
    image.nt = nt;
    return true;
}

bool RangeInImage(const LoadedImage& image, uint32_t rva, uint64_t size) {
    return rva < image.imageSize && size <= image.imageSize - rva;
}

bool ResolveEntryJump(const LoadedImage& image, const void* function,
                      uint8_t*& target) {
    target = nullptr;
    auto* entry = reinterpret_cast<uint8_t*>(const_cast<void*>(function));
    if (entry < image.base ||
        static_cast<uint64_t>(entry - image.base) + 16u > image.imageSize) {
        return false;
    }
    if (entry[0] == 0xF3u && entry[1] == 0x0Fu &&
        entry[2] == 0x1Eu &&
        (entry[3] == 0xFAu || entry[3] == 0xFBu)) {
        entry += 4;
    }
    if (entry[0] == 0xE9u) {
        int32_t displacement = 0;
        std::memcpy(&displacement, entry + 1, sizeof(displacement));
        target = entry + 5 + displacement;
    }
#if defined(_M_X64)
    else if (entry[0] == 0xFFu && entry[1] == 0x25u) {
        int32_t displacement = 0;
        std::memcpy(&displacement, entry + 2, sizeof(displacement));
        auto** slot = reinterpret_cast<uint8_t**>(entry + 6 + displacement);
        if (reinterpret_cast<uint8_t*>(slot) < image.base ||
            static_cast<uint64_t>(reinterpret_cast<uint8_t*>(slot) - image.base) +
                    sizeof(*slot) >
                image.imageSize) {
            return false;
        }
        target = *slot;
    }
#endif
    if (!target || target < image.base || target >= image.base + image.imageSize) {
        target = nullptr;
        return false;
    }
    return true;
}

bool FindPackedRecord(const LoadedImage& image, const void* function,
                      VM_FUNCTION_RECORD& foundRecord) {
    foundRecord = {};
    const auto functionAddress = reinterpret_cast<const uint8_t*>(function);
    if (functionAddress < image.base || functionAddress >= image.base + image.imageSize)
        return false;
    const uint32_t functionRva = static_cast<uint32_t>(functionAddress - image.base);
    const IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(image.nt);
    uint32_t matches = 0;
    for (uint16_t sectionIndex = 0;
         sectionIndex < image.nt->FileHeader.NumberOfSections; ++sectionIndex) {
        const auto& section = sections[sectionIndex];
        const uint32_t span = (std::max)(
            section.Misc.VirtualSize, section.SizeOfRawData);
        if (!RangeInImage(image, section.VirtualAddress, span) ||
            span < sizeof(VM_METADATA_HEADER)) {
            continue;
        }
        const auto* metadata = reinterpret_cast<const VM_METADATA_HEADER*>(
            image.base + section.VirtualAddress);
#if defined(_M_X64)
        constexpr uint32_t expectedArchitecture = VM_ARCH_X64;
        constexpr uint32_t architectureFlags =
            VM_METADATA_FLAG_UNWIND_VERIFIED;
#else
        constexpr uint32_t expectedArchitecture = VM_ARCH_X86;
        constexpr uint32_t architectureFlags = 0u;
#endif
        constexpr uint32_t requiredFlags =
            VM_METADATA_FLAG_AUTHENTICATED |
            VM_METADATA_FLAG_NATIVE_BODY_DESTROYED |
            VM_METADATA_FLAG_HANDLER_SYNTHESIZED |
            VM_METADATA_FLAG_DIRECT_THREADED |
            VM_METADATA_FLAG_HANDLER_ENCRYPTED |
            VM_METADATA_FLAG_RUNTIME_TRACE;
        const bool nonzeroBuildId = std::any_of(
            std::begin(metadata->buildId), std::end(metadata->buildId),
            [](uint8_t value) { return value != 0; });
        if (metadata->metadataVersion != VM_METADATA_VERSION ||
            metadata->runtimeVersion != VM_RUNTIME_VERSION ||
            metadata->schemaVersion != VM_SCHEMA_VERSION ||
            metadata->headerSize != sizeof(VM_METADATA_HEADER) ||
            metadata->recordSize != sizeof(VM_FUNCTION_RECORD) ||
            metadata->architecture != expectedArchitecture ||
            metadata->cookie == 0 || metadata->metadataTag == 0 ||
            metadata->layoutSeed == 0 || metadata->operandCodecSeed == 0 ||
            !nonzeroBuildId ||
            (metadata->flags & (requiredFlags | architectureFlags)) !=
                (requiredFlags | architectureFlags) ||
            metadata->recordCount == 0 ||
            metadata->recordCount > 0x10000u ||
            metadata->recordOffset < sizeof(VM_METADATA_HEADER) ||
            metadata->totalSize > span ||
            metadata->recordOffset > metadata->totalSize ||
            static_cast<uint64_t>(metadata->recordCount) *
                    sizeof(VM_FUNCTION_RECORD) >
                metadata->totalSize - metadata->recordOffset) {
            continue;
        }
        const auto* records = reinterpret_cast<const VM_FUNCTION_RECORD*>(
            reinterpret_cast<const uint8_t*>(metadata) + metadata->recordOffset);
        for (uint32_t index = 0; index < metadata->recordCount; ++index) {
            if (records[index].functionRVA != functionRva) continue;
            if (records[index].trampolineRVA == 0 ||
                records[index].trampolineSize == 0 ||
                !RangeInImage(image, records[index].trampolineRVA,
                    records[index].trampolineSize)) {
                return false;
            }
            foundRecord = records[index];
            ++matches;
        }
    }
    return matches == 1;
}

bool ResolveMetadataBoundTrampoline(const LoadedImage& image,
                                    const void* function,
                                    VM_FUNCTION_RECORD& record,
                                    uint8_t*& trampoline) {
    trampoline = nullptr;
    uint8_t* entryTarget = nullptr;
    if (!FindPackedRecord(image, function, record) ||
        !ResolveEntryJump(image, function, entryTarget)) {
        return false;
    }
    trampoline = image.base + record.trampolineRVA;
    return entryTarget == trampoline;
}

#if defined(_M_X64)
M128A* ContextXmm(CONTEXT& context, unsigned reg) {
    switch (reg) {
    case 6: return &context.Xmm6;
    case 7: return &context.Xmm7;
    case 8: return &context.Xmm8;
    case 9: return &context.Xmm9;
    case 10: return &context.Xmm10;
    case 11: return &context.Xmm11;
    case 12: return &context.Xmm12;
    case 13: return &context.Xmm13;
    case 14: return &context.Xmm14;
    case 15: return &context.Xmm15;
    default: return nullptr;
    }
}

void SetContextGpr(CONTEXT& context, unsigned reg, uint64_t value) {
    switch (reg) {
    case 3: context.Rbx = value; break;
    case 5: context.Rbp = value; break;
    case 6: context.Rsi = value; break;
    case 7: context.Rdi = value; break;
    case 12: context.R12 = value; break;
    case 13: context.R13 = value; break;
    case 14: context.R14 = value; break;
    case 15: context.R15 = value; break;
    default: break;
    }
}

uint64_t ExpectedGpr(unsigned reg) {
    switch (reg) {
    case 3: return kExpectedGpr[0];
    case 5: return kExpectedGpr[1];
    case 6: return kExpectedGpr[2];
    case 7: return kExpectedGpr[3];
    case 12: return kExpectedGpr[4];
    case 13: return kExpectedGpr[5];
    case 14: return kExpectedGpr[6];
    case 15: return kExpectedGpr[7];
    default: return 0;
    }
}

bool ContextMatchesNonvolatile(const CONTEXT& context) {
    if (context.Rbx != kExpectedGpr[0] ||
        context.Rbp != kExpectedGpr[1] ||
        context.Rsi != kExpectedGpr[2] ||
        context.Rdi != kExpectedGpr[3] ||
        context.R12 != kExpectedGpr[4] ||
        context.R13 != kExpectedGpr[5] ||
        context.R14 != kExpectedGpr[6] ||
        context.R15 != kExpectedGpr[7]) {
        return false;
    }
    auto& writable = const_cast<CONTEXT&>(context);
    for (unsigned reg = 6; reg < 16; ++reg) {
        const M128A* value = ContextXmm(writable, reg);
        if (!value || std::memcmp(value, kExpectedXmm[reg - 6].data(), 16) != 0)
            return false;
    }
    return true;
}

bool VerifyLoadedX64Unwind(VmProtectedSubFunction function) {
    constexpr uint8_t kUwopPushNonvol = 0u;
    constexpr uint8_t kUwopAllocLarge = 1u;
    constexpr uint8_t kUwopSetFpreg = 3u;
    constexpr uint8_t kUwopSaveNonvol = 4u;
    constexpr uint8_t kUwopSaveXmm128 = 8u;
    LoadedImage image;
    VM_FUNCTION_RECORD record{};
    uint8_t* trampoline = nullptr;
    if (!GetLoadedImage(reinterpret_cast<const void*>(function), image) ||
        !ResolveMetadataBoundTrampoline(image,
            reinterpret_cast<const void*>(function), record, trampoline) ||
        (record.flags & (VM_RECORD_FLAG_X64 |
                         VM_RECORD_FLAG_NATIVE_BODY_DESTROYED |
                         VM_RECORD_FLAG_UNWIND_VERIFIED)) !=
            (VM_RECORD_FLAG_X64 | VM_RECORD_FLAG_NATIVE_BODY_DESTROYED |
             VM_RECORD_FLAG_UNWIND_VERIFIED)) {
        return false;
    }

    DWORD64 lookupImageBase = 0;
    PRUNTIME_FUNCTION runtimeFunction = RtlLookupFunctionEntry(
        reinterpret_cast<DWORD64>(trampoline), &lookupImageBase, nullptr);
    if (!runtimeFunction || lookupImageBase !=
            reinterpret_cast<DWORD64>(image.base) ||
        runtimeFunction->BeginAddress != record.trampolineRVA ||
        runtimeFunction->EndAddress !=
            record.trampolineRVA + record.trampolineSize ||
        !RangeInImage(image, runtimeFunction->UnwindData, 4)) {
        return false;
    }
    const auto* unwind = image.base + runtimeFunction->UnwindData;
    const uint8_t version = unwind[0] & 0x07u;
    const uint8_t flags = unwind[0] >> 3u;
    const uint8_t prologSize = unwind[1];
    const uint8_t codeSlots = unwind[2];
    if (version != 1u || flags != 0u || (unwind[3] & 0x0Fu) != 5u ||
        (unwind[3] >> 4u) != 0u || codeSlots == 0 ||
        !RangeInImage(image, runtimeFunction->UnwindData,
            4u + static_cast<uint64_t>(codeSlots) * 2u)) {
        return false;
    }

    size_t epilogOffset = record.trampolineSize;
    uint32_t stackAllocation = 0;
    for (size_t offset = 0; offset + 9u <= record.trampolineSize; ++offset) {
        const uint8_t* code = trampoline + offset;
        if (code[0] == 0x48u && code[1] == 0x8Du && code[2] == 0xA5u &&
            code[7] == 0x5Du && code[8] == 0xC3u) {
            std::memcpy(&stackAllocation, code + 3, sizeof(stackAllocation));
            epilogOffset = offset;
        }
    }
    if (epilogOffset + 9u != record.trampolineSize ||
        prologSize >= epilogOffset || stackAllocation < 0x4000u ||
        (stackAllocation & 0x0Fu) != 0u) {
        return false;
    }

    const size_t stackBytes = static_cast<size_t>(stackAllocation) + 0x6000u;
    auto* stack = static_cast<uint8_t*>(VirtualAlloc(
        nullptr, stackBytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!stack) return false;
    uintptr_t frameRsp = reinterpret_cast<uintptr_t>(stack + 0x2000u);
    frameRsp = (frameRsp + 15u) & ~static_cast<uintptr_t>(15u);
    const uintptr_t entryRsp = frameRsp + stackAllocation + 8u;
    if (entryRsp + sizeof(uint64_t) >
        reinterpret_cast<uintptr_t>(stack + stackBytes)) {
        VirtualFree(stack, 0, MEM_RELEASE);
        return false;
    }

    constexpr uint64_t callerRip = 0x00007FF612345678ULL;
    const auto store64 = [](uintptr_t address, uint64_t value) {
        std::memcpy(reinterpret_cast<void*>(address), &value, sizeof(value));
    };
    store64(entryRsp, callerRip);
    store64(entryRsp - 8u, kExpectedGpr[1]);

    std::array<bool, 16> savedGpr{};
    std::array<bool, 16> savedXmm{};
    bool sawRbpPush = false;
    uint32_t unwindAllocation = 0;
    const uint8_t* codes = unwind + 4;
    for (uint32_t slot = 0; slot < codeSlots;) {
        const uint8_t operation = codes[slot * 2u + 1u] & 0x0Fu;
        const uint8_t info = codes[slot * 2u + 1u] >> 4u;
        if (operation == kUwopPushNonvol) {
            if (info != 5u) {
                VirtualFree(stack, 0, MEM_RELEASE);
                return false;
            }
            sawRbpPush = true;
            savedGpr[info] = true;
            ++slot;
        } else if (operation == kUwopAllocLarge) {
            if (info == 0u && slot + 1u < codeSlots) {
                uint16_t scaled = 0;
                std::memcpy(&scaled, codes + (slot + 1u) * 2u, sizeof(scaled));
                unwindAllocation = static_cast<uint32_t>(scaled) * 8u;
                slot += 2u;
            } else if (info == 1u && slot + 2u < codeSlots) {
                std::memcpy(&unwindAllocation,
                    codes + (slot + 1u) * 2u, sizeof(unwindAllocation));
                slot += 3u;
            } else {
                VirtualFree(stack, 0, MEM_RELEASE);
                return false;
            }
        } else if (operation == kUwopSetFpreg) {
            ++slot;
        } else if (operation == kUwopSaveNonvol && slot + 1u < codeSlots) {
            uint16_t scaled = 0;
            std::memcpy(&scaled, codes + (slot + 1u) * 2u, sizeof(scaled));
            const uint32_t offset = static_cast<uint32_t>(scaled) * 8u;
            if (info >= savedGpr.size() ||
                offset > stackAllocation - sizeof(uint64_t)) {
                VirtualFree(stack, 0, MEM_RELEASE);
                return false;
            }
            store64(frameRsp + offset, ExpectedGpr(info));
            savedGpr[info] = true;
            slot += 2u;
        } else if (operation == kUwopSaveXmm128 && slot + 1u < codeSlots) {
            uint16_t scaled = 0;
            std::memcpy(&scaled, codes + (slot + 1u) * 2u, sizeof(scaled));
            const uint32_t offset = static_cast<uint32_t>(scaled) * 16u;
            if (info < 6u || info >= 16u ||
                offset > stackAllocation - 16u) {
                VirtualFree(stack, 0, MEM_RELEASE);
                return false;
            }
            std::memcpy(reinterpret_cast<void*>(frameRsp + offset),
                kExpectedXmm[info - 6u].data(), 16u);
            savedXmm[info] = true;
            slot += 2u;
        } else {
            VirtualFree(stack, 0, MEM_RELEASE);
            return false;
        }
    }
    const bool completeSaveSet = sawRbpPush &&
        savedGpr[3] && savedGpr[5] && savedGpr[6] && savedGpr[7] &&
        savedGpr[12] && savedGpr[13] && savedGpr[14] && savedGpr[15] &&
        std::all_of(savedXmm.begin() + 6, savedXmm.end(),
            [](bool value) { return value; });
    if (!completeSaveSet || unwindAllocation != stackAllocation) {
        VirtualFree(stack, 0, MEM_RELEASE);
        return false;
    }

    const std::array<uint32_t, 4> controlOffsets = {
        prologSize,
        static_cast<uint32_t>(epilogOffset),
        static_cast<uint32_t>(epilogOffset + 7u),
        static_cast<uint32_t>(epilogOffset + 8u),
    };
    const std::array<uintptr_t, 4> controlRsp = {
        frameRsp, frameRsp, entryRsp - 8u, entryRsp,
    };
    const std::array<uint64_t, 4> controlRbp = {
        frameRsp, frameRsp, frameRsp, kExpectedGpr[1],
    };
    bool ok = true;
    for (size_t index = 0; index < controlOffsets.size() && ok; ++index) {
        const DWORD64 controlPc = reinterpret_cast<DWORD64>(trampoline) +
            controlOffsets[index];
        DWORD64 pointImageBase = 0;
        PRUNTIME_FUNCTION pointFunction = RtlLookupFunctionEntry(
            controlPc, &pointImageBase, nullptr);
        if (!pointFunction || pointImageBase != lookupImageBase ||
            pointFunction->BeginAddress != runtimeFunction->BeginAddress ||
            pointFunction->EndAddress != runtimeFunction->EndAddress ||
            pointFunction->UnwindData != runtimeFunction->UnwindData) {
            ok = false;
            break;
        }
        CONTEXT context{};
        context.ContextFlags = CONTEXT_FULL | CONTEXT_FLOATING_POINT;
        context.Rip = controlPc;
        context.Rsp = controlRsp[index];
        if (index != 0u) {
            for (unsigned reg : {3u,5u,6u,7u,12u,13u,14u,15u})
                SetContextGpr(context, reg, ExpectedGpr(reg));
            for (unsigned reg = 6; reg < 16; ++reg) {
                std::memcpy(ContextXmm(context, reg),
                    kExpectedXmm[reg - 6u].data(), 16u);
            }
        }
        // LEA and POP are entered before RBP itself has been popped.  Apply
        // the control-point-specific frame value after seeding the remaining
        // already-restored nonvolatiles so the generic seed loop cannot
        // accidentally replace frameRsp with the caller's RBP sentinel.
        context.Rbp = controlRbp[index];
        PVOID handlerData = nullptr;
        DWORD64 establisherFrame = 0;
        RtlVirtualUnwind(UNW_FLAG_NHANDLER, lookupImageBase, controlPc,
            pointFunction, &context, &handlerData, &establisherFrame, nullptr);
        ok = context.Rip == callerRip &&
            context.Rsp == entryRsp + sizeof(uint64_t) &&
            ContextMatchesNonvolatile(context);
    }
    VirtualFree(stack, 0, MEM_RELEASE);
    if (ok) {
        std::printf(
            "VM_UNWIND_RESULT architecture=64 metadata=1 lookup=4/4 "
            "body=1 lea=1 pop=1 ret=1 gpr=8/8 xmm=10/10\n");
    }
    return ok;
}
#else
bool ContainsStdcallRet8(const LoadedImage& image, const uint8_t* code,
                        uint32_t maximumBytes) {
    if (!code || code < image.base || code >= image.base + image.imageSize)
        return false;
    const uint32_t rva = static_cast<uint32_t>(code - image.base);
    const uint32_t available = (std::min)(maximumBytes, image.imageSize - rva);
    for (uint32_t offset = 0; offset + 3u <= available; ++offset) {
        if (code[offset] == 0xC2u && code[offset + 1u] == 0x08u &&
            code[offset + 2u] == 0x00u) {
            return true;
        }
    }
    return false;
}

bool VerifyLoadedX86Stdcall(VmProtectedSubFunction function, bool expectPacked) {
    LoadedImage image;
    if (!GetLoadedImage(reinterpret_cast<const void*>(function), image))
        return false;
    const uint8_t* code = reinterpret_cast<const uint8_t*>(function);
    bool metadataBound = false;
    if (expectPacked) {
        VM_FUNCTION_RECORD record{};
        uint8_t* trampoline = nullptr;
        if (!ResolveMetadataBoundTrampoline(image,
                reinterpret_cast<const void*>(function), record, trampoline) ||
            record.returnStackCleanup != 8u ||
            (record.flags & (VM_RECORD_FLAG_NATIVE_BODY_DESTROYED |
                             VM_RECORD_FLAG_CFG_VERIFIED)) !=
                (VM_RECORD_FLAG_NATIVE_BODY_DESTROYED |
                 VM_RECORD_FLAG_CFG_VERIFIED)) {
            return false;
        }
        code = trampoline;
        metadataBound = true;
        if (record.trampolineSize < 3u ||
            code[record.trampolineSize - 3u] != 0xC2u ||
            code[record.trampolineSize - 2u] != 0x08u ||
            code[record.trampolineSize - 1u] != 0x00u) {
            return false;
        }
    } else if (!ContainsStdcallRet8(image, code, 128u)) {
        return false;
    }
    std::printf(
        "VM_X86_STDCALL_RESULT packed=%u metadata=%u ret_imm16=8\n",
        expectPacked ? 1u : 0u, metadataBound ? 1u : 0u);
    return true;
}
#endif

} // namespace

bool VerifyVmProtectedAbi(VmProtectedSubFunction function, bool expectPacked,
                          int left, int right) {
    if (!function) return false;
    VmAbiSnapshot snapshot{};
    const int returned = CaptureBinaryFunctionAbi(
        function, left, right, &snapshot);
    const bool stackOk = snapshot.stackBefore == snapshot.stackAfter;
    const bool returnOk = returned == left - right &&
        snapshot.returnedValue == returned;
    const bool gprOk = std::equal(
        kExpectedGpr.begin(), kExpectedGpr.end(), std::begin(snapshot.gpr));
#if defined(_M_X64)
    bool xmmOk = true;
    for (size_t index = 0; index < kExpectedXmm.size(); ++index) {
        if (std::memcmp(snapshot.xmm[index], kExpectedXmm[index].data(), 16) != 0) {
            xmmOk = false;
            break;
        }
    }
    std::printf(
        "VM_ABI_RESULT architecture=64 packed=%u stack_delta=%lld "
        "gpr=%u/8 xmm=%u/10 return=%d\n",
        expectPacked ? 1u : 0u,
        static_cast<long long>(snapshot.stackAfter - snapshot.stackBefore),
        gprOk ? 8u : 0u, xmmOk ? 10u : 0u, returned);
    return stackOk && returnOk && gprOk && xmmOk;
#else
    std::printf(
        "VM_ABI_RESULT architecture=32 packed=%u stack_delta=%ld "
        "gpr=%u/4 xmm=0/0 return=%d\n",
        expectPacked ? 1u : 0u,
        static_cast<long>(snapshot.stackAfter - snapshot.stackBefore),
        gprOk ? 4u : 0u, returned);
    return stackOk && returnOk && gprOk;
#endif
}

bool VerifyVmPackedUnwindOrStdcall(VmProtectedSubFunction function,
                                   bool expectPacked) {
#if defined(_M_X64)
    if (!expectPacked) return true;
    return VerifyLoadedX64Unwind(function);
#else
    return VerifyLoadedX86Stdcall(function, expectPacked);
#endif
}
