#include "vm_runtime_builder.h"

#include "../pe_parser/pe_emitter.h"
#include "../../runtime/common/vm_metadata.h"
#include "../../runtime/common/vm_runtime_core.h"
#include "vm_runtime_x64_image.h"
#include "vm_runtime_x86_image.h"
#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
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
    void LoadImageBaseR9() {
        Raw({0x65, 0x4C, 0x8B, 0x0C, 0x25, 0x60, 0x00, 0x00, 0x00});
        Raw({0x4D, 0x8B, 0x49, 0x10});
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
};

struct SavedRegister {
    uint8_t number;
    uint32_t offset;
};

std::vector<uint8_t> BuildUnwindInfo(
    uint8_t prologSize,
    const std::vector<UnwindOperation>& operations)
{
    CodeBuffer output;
    output.U8(0x01); // UNW_VERSION=1, no handler flags.
    output.U8(prologSize);
    output.U8(static_cast<uint8_t>(operations.size() * 2));
    output.U8(0x00); // No frame register.
    for (auto it = operations.rbegin(); it != operations.rend(); ++it) {
        output.U8(it->codeOffset);
        output.U8(static_cast<uint8_t>((it->opInfo << 4) | (it->unwindOp & 0x0F)));
        output.U16(it->extra);
    }
    while (output.bytes.size() % 4 != 0) output.U8(0);
    return output.bytes;
}

class X86TrampolineAssembler : public CodeBuffer {
public:
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
    void LoadImageBaseEcx() {
        Raw({0x64, 0x8B, 0x0D, 0x30, 0x00, 0x00, 0x00});
        Raw({0x8B, 0x49, 0x08});
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
    constexpr uint32_t kHostStackAllocation = 0x598;
    const uint32_t kStackAllocation = kHostStackAllocation + guestStackSize;
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
    assembler.ProbeStack(kStackAllocation);
    assembler.SubRsp(kStackAllocation);
    unwindOperations.push_back({
        static_cast<uint8_t>(assembler.Offset()), 1, 0,
        static_cast<uint16_t>(kStackAllocation / 8)
    });

    const SavedRegister nonvolatileGprs[] = {
        {15, kFrameR15}, {14, kFrameR14}, {13, kFrameR13}, {12, kFrameR12},
        {7, kFrameRdi}, {6, kFrameRsi}, {5, kFrameRbp}, {3, kFrameRbx}
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
    assembler.LoadReg(1, static_cast<int32_t>(kStackAllocation + 0x10u));
    assembler.StoreReg(1, static_cast<int32_t>(kFrameRcx));
    assembler.LoadReg(0, static_cast<int32_t>(kStackAllocation + 0x08u));
    assembler.StoreReg(0, static_cast<int32_t>(kFrameRax));
    assembler.LoadReg(0, static_cast<int32_t>(kStackAllocation + 0x18u));
    assembler.StoreReg(0, static_cast<int32_t>(kFrameRflags));
    assembler.LoadReg(0, static_cast<int32_t>(kStackAllocation));
    assembler.StoreReg(0, static_cast<int32_t>(kFrameReturnAddress));
    assembler.LeaRaxRsp(kStackAllocation);
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
    assembler.LoadImageBaseR9();
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
        {7, kFrameRdi}, {6, kFrameRsi}, {5, kFrameRbp}, {3, kFrameRbx},
        {2, kFrameRdx}, {1, kFrameRcx}, {0, kFrameRax}
    };
    for (const auto& restored : restoreGprs) {
        assembler.LoadReg(restored.number, static_cast<int32_t>(restored.offset));
    }
    assembler.AddRsp(kStackAllocation);
    assembler.Ret();

    BuiltX64Trampoline result;
    result.code = std::move(assembler.bytes);
    result.unwindInfo = BuildUnwindInfo(prologSize, unwindOperations);
    return result;
}

std::vector<uint8_t> BuildX86Trampoline(
    uint32_t trampolineOffset,
    uint32_t runtimeEntryOffset,
    uint32_t functionRVA,
    uint32_t metadataRVA,
    uint16_t returnCleanup,
    uint32_t guestStackSize,
    bool usesAvx)
{
    constexpr uint32_t kHostAllocation = 0x500;
    constexpr uint32_t kFrameOffset = 0x40;
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
    assembler.LoadImageBaseEcx();
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
    return assembler.bytes;
}

uint64_t GetImageBase(const CS_PE_IMAGE* image) {
    return image->is64Bit ? image->ntHeaders64->OptionalHeader.ImageBase
                          : image->ntHeaders32->OptionalHeader.ImageBase;
}

} // namespace

VMRuntimeBuildResult VMRuntimeBuilder::Build(
    CS_PE_IMAGE* image,
    const std::vector<VMFunctionRecord>& records,
    uint32_t metadataRVA,
    const std::array<uint8_t, VM_RUNTIME_KEY_SHARE_SIZE>& runtimeKeyShare,
    const char sectionName[8],
    const char unwindSectionName[8],
    const char relocationSectionName[8])
{
    VMRuntimeBuildResult result{};
    if (!image || !image->isValid || !image->rawData || records.empty() || metadataRVA == 0) {
        result.error = "VM_RUNTIME: invalid image, metadata, or record table";
        return result;
    }

    MappedRuntimeImage runtime;
    const uint8_t* embedded = image->is64Bit ? kVMRuntimeX64Image : kVMRuntimeX86Image;
    const size_t embeddedSize = image->is64Bit ? kVMRuntimeX64ImageSize : kVMRuntimeX86ImageSize;
    if (!ParseRuntimeImage(embedded, embeddedSize, image->is64Bit != 0, runtime, result.error)) {
        result.error = "VM_RUNTIME: " + result.error;
        return result;
    }
    if (!PatchRuntimeKeyShare(runtime, runtimeKeyShare, result.error)) {
        result.error = "VM_RUNTIME: " + result.error;
        return result;
    }
    result.keySharePatched = true;
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
    const uint32_t runtimeImageSize = static_cast<uint32_t>(runtime.bytes.size());
    std::unordered_set<uint32_t> functionRVAs;
    for (const auto& record : records) {
        if (!functionRVAs.insert(record.functionRVA).second || record.functionSize < 5 ||
            record.guestStackSize < 0x4000u || record.guestStackSize > 0x70000u ||
            (record.guestStackSize & 0x0FFFu) != 0 ||
            record.guestStackSize + 0x598u > 0x7FFF8u) {
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
            trampoline = BuildX86Trampoline(trampolineOffset, runtime.entryRVA,
                record.functionRVA, metadataRVA,
                static_cast<uint16_t>(record.returnStackCleanup),
                record.guestStackSize,
                (record.flags & VM_RECORD_FLAG_USES_AVX) != 0);
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
    if (!image->is64Bit && mappedBase > std::numeric_limits<uint32_t>::max()) {
        result.error = "VM_RUNTIME: x86 runtime mapping exceeds the 32-bit address range";
        return result;
    }
    if (!ApplyRuntimeRelocations(runtime, mappedBase, result.error)) {
        result.error = "VM_RUNTIME: " + result.error;
        return result;
    }
    std::copy(runtime.bytes.begin(), runtime.bytes.end(), blob.begin());
    if (!emitter.PatchBytes(appended.rva, blob, &result.error)) {
        result.error = "VM_RUNTIME: unable to commit relocated blob: " + result.error;
        return result;
    }

    if (!runtime.relocations.empty()) {
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

    result.unwindVerified = true;
    result.executionReady = true;
    result.success = true;
    return result;
}

} // namespace CipherShell
