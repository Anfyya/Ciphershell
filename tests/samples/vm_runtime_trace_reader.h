#pragma once

#include <windows.h>

#include "../../runtime/common/vm_metadata.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>

inline bool EmitVmRuntimeTrace(HMODULE module, bool requireTrace) {
    if (!module) return false;
    const auto* base = reinterpret_cast<const uint8_t*>(module);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0 ||
        static_cast<uint32_t>(dos->e_lfanew) > 0x100000u) return false;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        base + static_cast<uint32_t>(dos->e_lfanew));
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
#if defined(_WIN64)
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return false;
    constexpr uint32_t expectedArchitecture = VM_ARCH_X64;
#else
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) return false;
    constexpr uint32_t expectedArchitecture = VM_ARCH_X86;
#endif
    const uint32_t imageSize = nt->OptionalHeader.SizeOfImage;
    if (imageSize < 0x1000u || nt->FileHeader.NumberOfSections == 0) return false;
    const IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
    uint32_t traceGroups = 0;
    for (uint16_t sectionIndex = 0;
         sectionIndex < nt->FileHeader.NumberOfSections; ++sectionIndex) {
        const auto& section = sections[sectionIndex];
        const uint32_t sectionSpan = (std::max)(
            section.Misc.VirtualSize, section.SizeOfRawData);
        if (section.VirtualAddress >= imageSize ||
            sectionSpan < sizeof(VM_METADATA_HEADER) ||
            sectionSpan > imageSize - section.VirtualAddress) continue;
        const auto* metadata = reinterpret_cast<const VM_METADATA_HEADER*>(
            base + section.VirtualAddress);
        if (metadata->metadataVersion != VM_METADATA_VERSION ||
            metadata->runtimeVersion != VM_RUNTIME_VERSION ||
            metadata->headerSize != sizeof(VM_METADATA_HEADER) ||
            metadata->recordSize != sizeof(VM_FUNCTION_RECORD) ||
            metadata->architecture != expectedArchitecture ||
            metadata->totalSize < sizeof(VM_METADATA_HEADER) ||
            metadata->totalSize > sectionSpan ||
            (metadata->flags & VM_METADATA_FLAG_RUNTIME_TRACE) == 0) continue;
        if (metadata->traceRVA == 0 ||
            metadata->traceRVA >= imageSize ||
            metadata->traceCapacity == 0 ||
            metadata->traceCapacity > VM_TRACE_MAX_CAPACITY ||
            metadata->traceGroup >= 64u) return false;
        const uint64_t traceBytes = sizeof(VM_TRACE_HEADER) +
            static_cast<uint64_t>(metadata->traceCapacity) *
                sizeof(VM_TRACE_EVENT);
        if (traceBytes > imageSize - metadata->traceRVA) return false;

        const IMAGE_SECTION_HEADER* traceSection = nullptr;
        for (uint16_t candidate = 0;
             candidate < nt->FileHeader.NumberOfSections; ++candidate) {
            const uint32_t candidateSpan = (std::max)(
                sections[candidate].Misc.VirtualSize,
                sections[candidate].SizeOfRawData);
            if (metadata->traceRVA < sections[candidate].VirtualAddress)
                continue;
            const uint32_t delta = metadata->traceRVA -
                sections[candidate].VirtualAddress;
            if (delta <= candidateSpan &&
                traceBytes <= static_cast<uint64_t>(candidateSpan - delta)) {
                if (traceSection != nullptr) return false;
                traceSection = &sections[candidate];
            }
        }
        constexpr uint32_t executeMask = IMAGE_SCN_MEM_EXECUTE |
            IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_DISCARDABLE;
        if (!traceSection ||
            traceSection->VirtualAddress != metadata->traceRVA ||
            traceSection->Misc.VirtualSize != traceBytes ||
            traceSection->PointerToRawData == 0 ||
            traceSection->SizeOfRawData < traceBytes ||
            (traceSection->Characteristics & IMAGE_SCN_MEM_READ) == 0 ||
            (traceSection->Characteristics & IMAGE_SCN_MEM_WRITE) == 0 ||
            (traceSection->Characteristics & executeMask) != 0) return false;

        const auto* header = reinterpret_cast<const VM_TRACE_HEADER*>(
            base + metadata->traceRVA);
        if (header->magic != VM_TRACE_MAGIC ||
            header->version != VM_TRACE_VERSION ||
            header->headerSize != sizeof(VM_TRACE_HEADER) ||
            header->eventSize != sizeof(VM_TRACE_EVENT) ||
            header->capacity != metadata->traceCapacity ||
            header->architecture != metadata->architecture ||
            header->groupId != metadata->traceGroup ||
            header->reserved[0] != 0 || header->reserved[1] != 0 ||
            std::memcmp(header->buildId, metadata->buildId,
                sizeof(header->buildId)) != 0) return false;
        MemoryBarrier();
        const uint32_t next = header->nextSequence;
        const uint32_t committed = header->committedCount;
        const uint32_t overflow = header->overflow;
        if (overflow != 0 || committed == 0 || committed != next ||
            committed > header->capacity) return false;

        char buildId[33]{};
        for (size_t index = 0; index < sizeof(header->buildId); ++index) {
            std::snprintf(buildId + index * 2u, 3u, "%02x",
                static_cast<unsigned>(header->buildId[index]));
        }
        std::printf(
            "VM_RUNTIME_TRACE_HEADER group=%u architecture=%u "
            "trace_rva=0x%x capacity=%u count=%u overflow=%u build_id=%s\n",
            header->groupId,
            header->architecture == VM_ARCH_X64 ? 64u : 32u,
            metadata->traceRVA, header->capacity, committed, overflow, buildId);
        const auto* events = reinterpret_cast<const VM_TRACE_EVENT*>(
            reinterpret_cast<const uint8_t*>(header) + header->headerSize);
        for (uint32_t index = 0; index < committed; ++index) {
            const uint32_t sequence = events[index].sequence;
            if (sequence != index + 1u || events[index].functionRVA == 0 ||
                events[index].bytecodeEndOffset == 0 ||
                events[index].semantic == VM_HANDLER_INVALID ||
                events[index].variant >= VM_HANDLER_VARIANT_COUNT ||
                events[index].reserved != 0) return false;
            std::printf(
                "VM_RUNTIME_TRACE_EVENT group=%u sequence=%u "
                "function_rva=0x%x bytecode_end=0x%x semantic=%u variant=%u\n",
                header->groupId, sequence, events[index].functionRVA,
                events[index].bytecodeEndOffset,
                static_cast<unsigned>(events[index].semantic),
                static_cast<unsigned>(events[index].variant));
        }
        ++traceGroups;
    }
    if (requireTrace && traceGroups == 0) return false;
    if (!requireTrace && traceGroups != 0) return false;
    return true;
}
