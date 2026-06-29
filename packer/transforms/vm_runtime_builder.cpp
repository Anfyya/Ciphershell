#include "vm_runtime_builder.h"
#include "../pe_parser/pe_emitter.h"
#include <cstring>

namespace CipherShell {

void VMRuntimeBuilder::Emit8(std::vector<uint8_t>& out, uint8_t value) { out.push_back(value); }
void VMRuntimeBuilder::Emit32(std::vector<uint8_t>& out, uint32_t value) {
    out.push_back(static_cast<uint8_t>(value));
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value >> 16));
    out.push_back(static_cast<uint8_t>(value >> 24));
}
size_t VMRuntimeBuilder::Emit32Placeholder(std::vector<uint8_t>& out) {
    size_t pos = out.size();
    Emit32(out, 0);
    return pos;
}
void VMRuntimeBuilder::Patch32(std::vector<uint8_t>& out, size_t pos, uint32_t value) {
    for (int i = 0; i < 4; i++) out[pos + i] = static_cast<uint8_t>(value >> (i * 8));
}
void VMRuntimeBuilder::PatchRel32(std::vector<uint8_t>& out, size_t immPos, size_t target) {
    int32_t disp = static_cast<int32_t>(static_cast<int64_t>(target) - static_cast<int64_t>(immPos + 4));
    Patch32(out, immPos, static_cast<uint32_t>(disp));
}

std::vector<uint8_t> VMRuntimeBuilder::BuildX64RuntimeSkeleton(uint32_t metadataRVA) {
    std::vector<uint8_t> c;
    c.reserve(96);

    // Strict ABI-preserving shell. This is still marked non-execution-ready by
    // Build(); it must never be treated as a working interpreter by the main pipeline.
    Emit8(c, 0x9C);                                      // pushfq
    Emit8(c, 0x50);                                      // push rax
    Emit8(c, 0x51);                                      // push rcx
    Emit8(c, 0x52);                                      // push rdx
    Emit8(c, 0x53);                                      // push rbx
    Emit8(c, 0x55);                                      // push rbp
    Emit8(c, 0x56);                                      // push rsi
    Emit8(c, 0x57);                                      // push rdi
    Emit8(c, 0x41); Emit8(c, 0x50);                      // push r8
    Emit8(c, 0x41); Emit8(c, 0x51);                      // push r9
    Emit8(c, 0x41); Emit8(c, 0x52);                      // push r10
    Emit8(c, 0x41); Emit8(c, 0x53);                      // push r11
    Emit8(c, 0x41); Emit8(c, 0x54);                      // push r12
    Emit8(c, 0x41); Emit8(c, 0x55);                      // push r13
    Emit8(c, 0x41); Emit8(c, 0x56);                      // push r14
    Emit8(c, 0x41); Emit8(c, 0x57);                      // push r15
    Emit8(c, 0x48); Emit8(c, 0x83); Emit8(c, 0xEC); Emit8(c, 0x28); // shadow space + align

    // mov r11d, metadataRVA. The actual trampoline also passes metadata in r11d;
    // this immediate binding is kept for static validation while the runtime is fail-closed.
    Emit8(c, 0x41); Emit8(c, 0xBB); Emit32(c, metadataRVA);

    // No crash sentinel is emitted on the normal path. The packer refuses
    // to write an L4 output until a real interpreter replaces this no-op body.
    Emit8(c, 0x90);

    Emit8(c, 0x48); Emit8(c, 0x83); Emit8(c, 0xC4); Emit8(c, 0x28);
    Emit8(c, 0x41); Emit8(c, 0x5F);
    Emit8(c, 0x41); Emit8(c, 0x5E);
    Emit8(c, 0x41); Emit8(c, 0x5D);
    Emit8(c, 0x41); Emit8(c, 0x5C);
    Emit8(c, 0x41); Emit8(c, 0x5B);
    Emit8(c, 0x41); Emit8(c, 0x5A);
    Emit8(c, 0x41); Emit8(c, 0x59);
    Emit8(c, 0x41); Emit8(c, 0x58);
    Emit8(c, 0x5F);
    Emit8(c, 0x5E);
    Emit8(c, 0x5D);
    Emit8(c, 0x5B);
    Emit8(c, 0x5A);
    Emit8(c, 0x59);
    Emit8(c, 0x58);
    Emit8(c, 0x9D);                                      // popfq
    Emit8(c, 0xC3);                                      // ret
    return c;
}

std::vector<uint8_t> VMRuntimeBuilder::BuildX64Trampoline(uint32_t functionRVA, uint32_t metadataRVA) {
    std::vector<uint8_t> c;
    c.reserve(32);
    Emit8(c, 0x41); Emit8(c, 0xBA); Emit32(c, functionRVA); // mov r10d, functionRVA
    Emit8(c, 0x41); Emit8(c, 0xBB); Emit32(c, metadataRVA); // mov r11d, metadataRVA
    Emit8(c, 0xE9); Emit32(c, 0);                        // jmp runtime, patched after layout
    return c;
}

VMRuntimeBuildResult VMRuntimeBuilder::Build(
    CS_PE_IMAGE* image,
    const std::vector<VMFunctionRecord>& records,
    uint32_t metadataRVA,
    const char sectionName[8])
{
    VMRuntimeBuildResult result;
    if (!image || !image->isValid) {
        result.error = "invalid PE image";
        return result;
    }
    if (!image->is64Bit) {
        result.error = "VM runtime builder currently supports x64 only";
        return result;
    }
    if (records.empty()) {
        result.error = "no VM function records";
        return result;
    }

    std::vector<uint8_t> blob = BuildX64RuntimeSkeleton(metadataRVA);
    uint32_t runtimeOffset = 0;
    std::vector<uint32_t> trampolineOffsets;
    trampolineOffsets.reserve(records.size());

    for (const auto& record : records) {
        while ((blob.size() & 0x0F) != 0) blob.push_back(0x90);
        uint32_t trampOffset = static_cast<uint32_t>(blob.size());
        auto tramp = BuildX64Trampoline(record.functionRVA, metadataRVA);
        size_t relPos = tramp.size() - 4;
        int32_t rel = static_cast<int32_t>(static_cast<int64_t>(runtimeOffset) - static_cast<int64_t>(trampOffset + tramp.size()));
        Patch32(tramp, relPos, static_cast<uint32_t>(rel));
        blob.insert(blob.end(), tramp.begin(), tramp.end());
        trampolineOffsets.push_back(trampOffset);
    }

    char name[8] = {'.','c','s','v','x',0,0,0};
    if (sectionName) memcpy(name, sectionName, 8);

    PEEmitter emitter(image);
    auto append = emitter.AppendSection(name, blob, IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ);
    if (!append.success) {
        result.error = append.error;
        return result;
    }

    result.success = true;
    result.executionReady = false;
    result.sectionRVA = append.rva;
    result.runtimeEntryRVA = append.rva + runtimeOffset;
    for (size_t i = 0; i < records.size(); i++) {
        VMTrampolineRecord tr;
        tr.functionRVA = records[i].functionRVA;
        tr.trampolineRVA = append.rva + trampolineOffsets[i];
        tr.trampolineSize = 17;
        result.trampolines.push_back(tr);
    }
    result.error = "VM interpreter body is not execution-ready; generated runtime is a non-crashing fail-closed shell";
    return result;
}

} // namespace CipherShell
