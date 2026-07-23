#include "packer/transforms/vm_runtime_builder.h"
#include "packer/mutation/mutation_engine.h"
#include "packer/pe_parser/pe_emitter.h"
#include "packer/pe_parser/pe_parser.h"
#include "packer/vm/vm_schema.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace {

using CipherShell::CS_PE_IMAGE;
using CipherShell::MutationConfig;
using CipherShell::MutationEngine;
using CipherShell::PEEmitter;
using CipherShell::PEParser;
using CipherShell::EncodeVMDispatchTableTarget;
using CipherShell::VMDispatchTableEncoding;
using CipherShell::VMFunctionRecord;
using CipherShell::VMHandlerArchitecture;
using CipherShell::VMHandlerFunctionDecodePlans;
using CipherShell::VMHandlerSynthesisConfig;
using CipherShell::VMRuntimeBuildResult;
using CipherShell::VMRuntimeBuilder;
using CipherShell::VMSchema;

constexpr uint32_t kRuntimeSectionRVA = 0x3000u;
constexpr uint32_t kRuntimeSectionSize = 0x200u;
constexpr uint32_t kRuntimeContentSize = 0x1A0u;
constexpr uint32_t kRuntimeImageSize = 0x180u;
constexpr uint32_t kDispatchOffset = 0x40u;
constexpr uint32_t kDispatchSize = 0x10u;
constexpr uint32_t kHandlerOffset = 0x100u;
constexpr uint32_t kHandlerSize = 0x80u;
constexpr uint64_t kImageBase64 = 0x140000000ULL;
constexpr uint64_t kImageBase32 = 0x10000000ULL;

constexpr uint64_t kRuntimeSectionDigestDomain = 0x4353564D53454354ULL;
constexpr uint64_t kRuntimeImageDigestDomain = 0x4353564D494D4147ULL;
constexpr uint64_t kEncryptedHandlerDigestDomain = 0x4353564D48444C52ULL;
constexpr uint64_t kDispatchTableDigestDomain = 0x4353564D44535054ULL;

class TestFailure final : public std::runtime_error {
public:
    explicit TestFailure(const std::string& message) : std::runtime_error(message) {}
};

void Require(bool condition, const std::string& message) {
    if (!condition) throw TestFailure(message);
}

uint64_t HashBytes(const uint8_t* bytes, size_t size, uint64_t domain) {
    uint64_t hash = 1469598103934665603ULL ^ domain;
    for (size_t index = 0; index < size; ++index) {
        hash ^= bytes[index];
        hash *= 1099511628211ULL;
        hash ^= hash >> 29u;
    }
    return hash ? hash : (domain | 1ULL);
}

struct TestImage {
    TestImage(uint32_t rawOffset, bool is64Bit)
        : bytes(static_cast<size_t>(rawOffset) + kRuntimeSectionSize, 0),
          runtimeRawOffset(rawOffset)
    {
        ntHeaders64.OptionalHeader.ImageBase = kImageBase64;
        ntHeaders32.OptionalHeader.ImageBase = static_cast<DWORD>(kImageBase32);
        section.VirtualAddress = kRuntimeSectionRVA;
        section.Misc.VirtualSize = kRuntimeSectionSize;
        section.SizeOfRawData = kRuntimeSectionSize;
        section.PointerToRawData = runtimeRawOffset;
        section.Characteristics = IMAGE_SCN_CNT_CODE |
            IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

        image.rawData = bytes.data();
        image.rawSize = static_cast<DWORD>(bytes.size());
        image.ntHeaders64 = &ntHeaders64;
        image.ntHeaders32 = &ntHeaders32;
        image.sections = &section;
        image.numSections = 1;
        image.is64Bit = is64Bit ? TRUE : FALSE;
        image.isValid = TRUE;
    }

    void Install(const std::vector<uint8_t>& sectionBytes) {
        Require(sectionBytes.size() == kRuntimeSectionSize,
            "测试 runtime section 长度错误");
        std::copy(sectionBytes.begin(), sectionBytes.end(),
            bytes.begin() + runtimeRawOffset);
    }

    std::vector<uint8_t> bytes;
    uint32_t runtimeRawOffset = 0;
    IMAGE_NT_HEADERS64 ntHeaders64{};
    IMAGE_NT_HEADERS32 ntHeaders32{};
    IMAGE_SECTION_HEADER section{};
    CS_PE_IMAGE image{};
};

void RefreshPhysicalDigests(VMRuntimeBuildResult& result) {
    auto& expectation = result.integrityExpectation;
    const uint8_t* bytes = expectation.expectedSectionBytes.data();
    expectation.sectionDigest = HashBytes(bytes,
        expectation.expectedSectionBytes.size(), kRuntimeSectionDigestDomain);
    expectation.synthesizedImage.digest = HashBytes(
        bytes + expectation.synthesizedImage.offset,
        expectation.synthesizedImage.size, kRuntimeImageDigestDomain);
    expectation.encryptedHandlers.digest = HashBytes(
        bytes + expectation.encryptedHandlers.offset,
        expectation.encryptedHandlers.size, kEncryptedHandlerDigestDomain);
    expectation.dispatchTable.digest = HashBytes(
        bytes + expectation.dispatchTable.offset,
        expectation.dispatchTable.size, kDispatchTableDigestDomain);
}

void WritePointer(std::vector<uint8_t>& bytes,
                  uint32_t offset,
                  uint32_t pointerSize,
                  uint64_t value) {
    std::memcpy(bytes.data() + offset, &value, pointerSize);
}

VMRuntimeBuildResult MakeExpectedRuntime(bool is64Bit) {
    VMRuntimeBuildResult result{};
    result.success = true;
    result.executionReady = true;
    result.runtimeContentVerified = true;
    result.sectionRVA = kRuntimeSectionRVA;
    result.sectionSize = kRuntimeSectionSize;
    result.runtimeEntryRVA = kRuntimeSectionRVA + 0x10u;
    result.runtimeImageSize = kRuntimeImageSize;
    result.architecture = is64Bit ? VM_ARCH_X64 : VM_ARCH_X86;
    result.opcodeMapDigest = 0x0102030405060708ULL;
    result.handlerBodyDigest = 0x1112131415161718ULL;
    result.variantSelectorDigest = 0x2122232425262728ULL;

    auto& expectation = result.integrityExpectation;
    expectation.version = CipherShell::VM_RUNTIME_INTEGRITY_EXPECTATION_VERSION;
    expectation.sectionContentSize = kRuntimeContentSize;
    expectation.dispatchDigestDomain = 0xA5B6C7D8E9F01122ULL;
    expectation.opcodeMapDigest = result.opcodeMapDigest;
    expectation.handlerBodyDigest = result.handlerBodyDigest;
    expectation.variantSelectorDigest = result.variantSelectorDigest;
    expectation.dispatchTableCodec.encoding = is64Bit
        ? VMDispatchTableEncoding::AddRotateKeyedTable
        : VMDispatchTableEncoding::XorKeyedTable;
    expectation.dispatchTableCodec.key = is64Bit
        ? 0x13579BDFu : 0x2468ACE1u;
    expectation.dispatchTableCodec.rotate = is64Bit ? 19u : 11u;
    expectation.synthesizedImage = {0, kRuntimeImageSize, 0};
    expectation.encryptedHandlers = {kHandlerOffset, kHandlerSize, 0};
    expectation.dispatchTable = {kDispatchOffset, kDispatchSize, 0};
    expectation.expectedSectionBytes.assign(kRuntimeSectionSize, 0);

    for (uint32_t offset = 0; offset < kRuntimeContentSize; ++offset) {
        expectation.expectedSectionBytes[offset] = static_cast<uint8_t>(
            (offset * 37u + 0x5Bu) & 0xFFu);
    }

    const uint32_t pointerSize = is64Bit ? 8u : 4u;
    const uint32_t cellCount = kDispatchSize / pointerSize;
    for (uint32_t cell = 0; cell < cellCount; ++cell) {
        uint64_t relative = 0;
        if (cell == 0u) relative = kHandlerOffset;
        else if (cell == 1u) relative = kHandlerOffset + 0x20u;
        const uint64_t encoded = EncodeVMDispatchTableTarget(
            relative, pointerSize, expectation.dispatchTableCodec);
        WritePointer(expectation.expectedSectionBytes,
            kDispatchOffset + cell * pointerSize, pointerSize, encoded);
    }
    result.dispatchKeyDigest = HashBytes(
        expectation.expectedSectionBytes.data() + kDispatchOffset,
        kDispatchSize, expectation.dispatchDigestDomain);
    expectation.dispatchKeyDigest = result.dispatchKeyDigest;
    RefreshPhysicalDigests(result);
    return result;
}

void RequireVerified(const TestImage& testImage,
                     const VMRuntimeBuildResult& result,
                     const std::string& context) {
    std::string error;
    // 函数实参求值顺序未定义：不能在同一次调用里既求值 VerifyRuntimeContents(...)
    // 又用它写入的 error 拼接消息，否则消息可能在调用发生前就已求值完毕，
    // 永远看到空字符串。先落地布尔结果，再拼接消息。
    const bool verified = VMRuntimeBuilder::VerifyRuntimeContents(
        &testImage.image, result, error);
    Require(verified, context + ": " + error);
}

void RequireRejected(const TestImage& testImage,
                     const VMRuntimeBuildResult& result,
                     const std::string& expectedReason) {
    std::string error;
    Require(!VMRuntimeBuilder::VerifyRuntimeContents(
            &testImage.image, result, error),
        "被篡改的 runtime 产物被错误接受");
    Require(error.find(expectedReason) != std::string::npos,
        "runtime 篡改拒绝原因不精确: " + error);
}

void TestValidAndRelocatedRawOffset() {
    for (const bool is64Bit : {false, true}) {
        const VMRuntimeBuildResult result = MakeExpectedRuntime(is64Bit);
        TestImage original(0x200u, is64Bit);
        original.Install(result.integrityExpectation.expectedSectionBytes);
        RequireVerified(original, result, "原始 runtime section 校验失败");

        // 模拟后续追加 PE section 导致原始文件偏移移动；RVA 与字节不变时必须通过。
        TestImage shifted(0x600u, is64Bit);
        shifted.Install(result.integrityExpectation.expectedSectionBytes);
        RequireVerified(shifted, result, "runtime section 原始偏移移动后校验失败");
    }
}

void TestPhysicalTamperRejection() {
    const VMRuntimeBuildResult result = MakeExpectedRuntime(true);

    TestImage handlerTamper(0x200u, true);
    handlerTamper.Install(result.integrityExpectation.expectedSectionBytes);
    handlerTamper.bytes[handlerTamper.runtimeRawOffset + kHandlerOffset + 3u] ^= 0x80u;
    RequireRejected(handlerTamper, result, "encrypted-handler");

    TestImage dispatchTamper(0x200u, true);
    dispatchTamper.Install(result.integrityExpectation.expectedSectionBytes);
    dispatchTamper.bytes[dispatchTamper.runtimeRawOffset + kDispatchOffset] ^= 0x01u;
    RequireRejected(dispatchTamper, result, "dispatch-table");

    TestImage synthTamper(0x200u, true);
    synthTamper.Install(result.integrityExpectation.expectedSectionBytes);
    synthTamper.bytes[synthTamper.runtimeRawOffset + 0x80u] ^= 0x20u;
    RequireRejected(synthTamper, result, "synthesized-image");

    TestImage trampolineTamper(0x200u, true);
    trampolineTamper.Install(result.integrityExpectation.expectedSectionBytes);
    trampolineTamper.bytes[trampolineTamper.runtimeRawOffset + 0x190u] ^= 0x08u;
    RequireRejected(trampolineTamper, result, "section digest");

    TestImage paddingTamper(0x200u, true);
    paddingTamper.Install(result.integrityExpectation.expectedSectionBytes);
    paddingTamper.bytes[paddingTamper.runtimeRawOffset + 0x1F0u] = 0xCCu;
    RequireRejected(paddingTamper, result, "section digest");
}

void TestDigestAndDispatchTargetRejection() {
    for (const bool is64Bit : {false, true}) {
        const VMRuntimeBuildResult result = MakeExpectedRuntime(is64Bit);
        TestImage image(0x200u, is64Bit);
        image.Install(result.integrityExpectation.expectedSectionBytes);

        VMRuntimeBuildResult digestTamper = result;
        digestTamper.variantSelectorDigest ^= 1u;
        RequireRejected(image, digestTamper, "diversity digest");

        // 即使攻击者同步伪造整段期望字节与物理摘要，编码后的 dispatch 表
        // 仍必须与 pack-time dispatch-key digest 一致。
        VMRuntimeBuildResult forgedDispatch = result;
        const uint32_t pointerSize = is64Bit ? 8u : 4u;
        const uint64_t forgedTarget = EncodeVMDispatchTableTarget(
            kHandlerOffset + 0x10u, pointerSize,
            forgedDispatch.integrityExpectation.dispatchTableCodec);
        WritePointer(forgedDispatch.integrityExpectation.expectedSectionBytes,
            kDispatchOffset, pointerSize, forgedTarget);
        RefreshPhysicalDigests(forgedDispatch);
        TestImage forgedImage(0x200u, is64Bit);
        forgedImage.Install(forgedDispatch.integrityExpectation.expectedSectionBytes);
        RequireRejected(forgedImage, forgedDispatch, "dispatch-key digest");
    }
}

class OwnedBuilderImage final {
public:
    explicit OwnedBuilderImage(bool is64Bit = true) {
        constexpr uint32_t headersSize = 0x400u;
        constexpr uint32_t textRawOffset = headersSize;
        constexpr uint32_t textRawSize = 0x400u;
        constexpr uint32_t totalSize = textRawOffset + textRawSize;
        image.rawData = new BYTE[totalSize]{};
        image.rawSize = totalSize;

        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image.rawData);
        dos->e_magic = IMAGE_DOS_SIGNATURE;
        dos->e_lfanew = 0x80;
        IMAGE_SECTION_HEADER* section = nullptr;
        if (is64Bit) {
            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(
                image.rawData + dos->e_lfanew);
            nt->Signature = IMAGE_NT_SIGNATURE;
            nt->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
            nt->FileHeader.NumberOfSections = 1;
            nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
            nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
            nt->OptionalHeader.ImageBase = kImageBase64;
            nt->OptionalHeader.AddressOfEntryPoint = 0x1000u;
            nt->OptionalHeader.BaseOfCode = 0x1000u;
            nt->OptionalHeader.SectionAlignment = 0x1000u;
            nt->OptionalHeader.FileAlignment = 0x200u;
            nt->OptionalHeader.SizeOfHeaders = headersSize;
            nt->OptionalHeader.SizeOfImage = 0x2000u;
            nt->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
            image.ntHeaders64 = nt;
            section = IMAGE_FIRST_SECTION(nt);
        } else {
            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(
                image.rawData + dos->e_lfanew);
            nt->Signature = IMAGE_NT_SIGNATURE;
            nt->FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
            nt->FileHeader.NumberOfSections = 1;
            nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);
            nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
            nt->OptionalHeader.ImageBase = static_cast<DWORD>(kImageBase32);
            nt->OptionalHeader.AddressOfEntryPoint = 0x1000u;
            nt->OptionalHeader.BaseOfCode = 0x1000u;
            nt->OptionalHeader.BaseOfData = 0x2000u;
            nt->OptionalHeader.SectionAlignment = 0x1000u;
            nt->OptionalHeader.FileAlignment = 0x200u;
            nt->OptionalHeader.SizeOfHeaders = headersSize;
            nt->OptionalHeader.SizeOfImage = 0x2000u;
            nt->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
            image.ntHeaders32 = nt;
            section = IMAGE_FIRST_SECTION(nt);
        }
        std::memcpy(section->Name, ".text", 5);
        section->Misc.VirtualSize = textRawSize;
        section->VirtualAddress = 0x1000u;
        section->SizeOfRawData = textRawSize;
        section->PointerToRawData = textRawOffset;
        section->Characteristics = IMAGE_SCN_CNT_CODE |
            IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
        std::fill(image.rawData + textRawOffset,
            image.rawData + textRawOffset + textRawSize,
            static_cast<BYTE>(0x90));

        image.dosHeader = dos;
        image.sections = section;
        image.numSections = 1;
        image.is64Bit = is64Bit ? TRUE : FALSE;
        image.isValid = TRUE;
    }

    ~OwnedBuilderImage() {
        delete[] image.rawData;
        image.rawData = nullptr;
    }

    OwnedBuilderImage(const OwnedBuilderImage&) = delete;
    OwnedBuilderImage& operator=(const OwnedBuilderImage&) = delete;

    CS_PE_IMAGE image{};
};

std::array<uint8_t, 32> MakeBuildSeed() {
    std::array<uint8_t, 32> seed{};
    uint32_t state = 0xC001D00Du;
    for (size_t index = 0; index < seed.size(); ++index) {
        state ^= state << 13u;
        state ^= state >> 17u;
        state ^= state << 5u;
        seed[index] = static_cast<uint8_t>(state >> ((index & 3u) * 8u));
    }
    return seed;
}

VMHandlerSynthesisConfig MakeBuilderConfig(
    uint32_t functionRVA,
    std::unordered_map<uint8_t, uint8_t>& opcodeMap,
    bool is64Bit = true)
{
    const std::array<uint8_t, 32> seed = MakeBuildSeed();
    MutationConfig mutation{};
    mutation.seed = seed;
    mutation.registerCount = 24;
    mutation.randomizeOpcodeMap = true;
    mutation.randomizeRegisterMap = true;
    mutation.mutateHandlers = true;
    mutation.embedJunkHandlers = true;
    mutation.requestedJunkHandlerCount = 4;
    for (const auto& descriptor : VMSchema::Opcodes()) {
        if (is64Bit ? descriptor.runtimeSupportedX64 :
                descriptor.runtimeSupportedX86) {
            mutation.validOpcodes.push_back(
                static_cast<uint8_t>(descriptor.opcode));
        }
    }
    MutationEngine engine;
    Require(engine.Initialize(mutation),
        "runtime builder 集成测试无法初始化 MutationEngine");
    const auto isa = engine.GenerateMutatedISA();
    opcodeMap = isa.opcodeMap;

    VMHandlerSynthesisConfig config{};
    config.architecture = is64Bit ? VMHandlerArchitecture::X64 :
        VMHandlerArchitecture::X86;
    config.buildSeed = seed;
    config.handlerSemanticToSlot = isa.handlerSemanticToSlot;
    config.handlerSlotToSemantic = isa.handlerSlotToSemantic;
    config.handlerVariants = isa.handlerVariants;
    config.operandCodec.opcodeXor = static_cast<uint8_t>(seed[3] | 1u);
    config.operandCodec.opcodeAdd = static_cast<uint8_t>(seed[7] | 1u);
    config.operandCodec.opcodeRotate = static_cast<uint8_t>((seed[11] % 7u) + 1u);
    config.variantCount = VM_HANDLER_VARIANT_COUNT;
    config.minimumJunkBytesPerHandler = 96;
    config.virtualProtectIatRVA = 0x1100u;
    config.flushInstructionCacheIatRVA = 0x1108u;
    config.encryptHandlerBodies = true;
    config.emitCetLandingPads = true;

    VMHandlerFunctionDecodePlans plans{};
    plans.functionRVA = functionRVA;
    plans.codec = VMSchema::DeriveOperandCodec(
        0x8899AABBCCDDEEFFULL, functionRVA);
    std::string planError;
    Require(VMSchema::BuildRuntimeDecodePlans(
            plans.codec, plans.plans.data(), planError),
        "runtime builder 集成测试无法生成 decode plan: " + planError);
    config.functionDecodePlans.push_back(plans);
    return config;
}

std::vector<uint8_t> MakeBuilderBytecode(
    const VMHandlerSynthesisConfig& config,
    const std::unordered_map<uint8_t, uint8_t>& opcodeMap,
    uint8_t variant)
{
    CipherShell::MicroInstruction instruction{};
    instruction.opcode = VM_UOP_RET;
    instruction.handlerVariant = variant;
    instruction.operandCount = 1u;
    instruction.operands[0] = 0u;
    std::vector<uint8_t> bytecode;
    std::string error;
    Require(!config.functionDecodePlans.empty() &&
            VMSchema::Encode(instruction, opcodeMap,
                config.functionDecodePlans.front().codec, bytecode, error) &&
            !bytecode.empty(),
        "runtime builder integration could not encode evidence bytecode: " + error);
    return bytecode;
}

#if defined(_M_X64)
void VerifyX64TrampolineVirtualUnwind(const VMRuntimeBuildResult& result) {
    Require(result.trampolines.size() == 1u,
        "RtlVirtualUnwind regression requires exactly one trampoline");
    const auto& trampoline = result.trampolines.front();
    const auto unwind = std::find_if(
        result.unwindEntries.begin(), result.unwindEntries.end(),
        [&](const auto& candidate) {
            return candidate.beginRVA == trampoline.trampolineRVA;
        });
    Require(unwind != result.unwindEntries.end() &&
            unwind->endRVA == trampoline.trampolineRVA +
                trampoline.trampolineSize,
        "x64 trampoline RUNTIME_FUNCTION range is missing or truncated");

    const auto& emitted = result.integrityExpectation.expectedSectionBytes;
    Require(trampoline.trampolineRVA >= result.sectionRVA &&
            unwind->unwindRVA >= result.sectionRVA,
        "x64 trampoline unwind RVAs precede the runtime section");
    const uint32_t codeOffset = trampoline.trampolineRVA - result.sectionRVA;
    const uint32_t unwindOffset = unwind->unwindRVA - result.sectionRVA;
    Require(static_cast<uint64_t>(codeOffset) + trampoline.trampolineSize <=
                emitted.size() &&
            static_cast<uint64_t>(unwindOffset) + 4u <= emitted.size(),
        "x64 trampoline code/unwind bytes exceed the emitted section");
    const uint8_t* code = emitted.data() + codeOffset;
    const uint8_t* unwindInfo = emitted.data() + unwindOffset;
    Require((unwindInfo[0] & 0x07u) == 1u &&
            (unwindInfo[0] & 0xF8u) == 0u &&
            (unwindInfo[3] & 0x0Fu) == 5u &&
            (unwindInfo[3] >> 4u) == 0u,
        "x64 trampoline unwind header does not declare a V1 RBP frame");

    size_t epilogOffset = trampoline.trampolineSize;
    uint32_t stackAllocation = 0;
    for (size_t offset = 0; offset + 9u <= trampoline.trampolineSize; ++offset) {
        if (code[offset] != 0x48u || code[offset + 1u] != 0x8Du ||
            code[offset + 2u] != 0xA5u || code[offset + 7u] != 0x5Du ||
            code[offset + 8u] != 0xC3u) {
            continue;
        }
        std::memcpy(&stackAllocation, code + offset + 3u,
            sizeof(stackAllocation));
        epilogOffset = offset;
        break;
    }
    Require(epilogOffset < trampoline.trampolineSize &&
            stackAllocation >= 0x4000u &&
            (stackAllocation & 0x0Fu) == 0u &&
            unwindInfo[1] < epilogOffset,
        "x64 trampoline lacks its canonical LEA/POP/RET epilog");

    auto* mapped = static_cast<uint8_t*>(VirtualAlloc(
        nullptr, emitted.size(), MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE));
    Require(mapped != nullptr,
        "VirtualAlloc failed for RtlVirtualUnwind trampoline image");
    std::memcpy(mapped, emitted.data(), emitted.size());
    DWORD oldProtection = 0;
    Require(VirtualProtect(mapped, emitted.size(), PAGE_EXECUTE_READ,
                &oldProtection) != FALSE,
        "VirtualProtect failed for RtlVirtualUnwind trampoline image");

    const DWORD64 imageBase = reinterpret_cast<DWORD64>(mapped) -
        result.sectionRVA;
    RUNTIME_FUNCTION nativeFunction{};
    nativeFunction.BeginAddress = unwind->beginRVA;
    nativeFunction.EndAddress = unwind->endRVA;
    nativeFunction.UnwindData = unwind->unwindRVA;

    std::vector<uint8_t> stack(
        static_cast<size_t>(stackAllocation) + 0x4000u, 0);
    uintptr_t entryRsp = reinterpret_cast<uintptr_t>(
        stack.data() + stack.size() - 0x100u);
    entryRsp = (entryRsp & ~static_cast<uintptr_t>(0x0Fu)) + 8u;
    const uintptr_t frameRsp = entryRsp - 8u - stackAllocation;
    Require(frameRsp >= reinterpret_cast<uintptr_t>(stack.data()) &&
            entryRsp + sizeof(uint64_t) <=
                reinterpret_cast<uintptr_t>(stack.data() + stack.size()),
        "synthetic unwind stack range is invalid");

    const auto store64 = [](uintptr_t address, uint64_t value) {
        std::memcpy(reinterpret_cast<void*>(address), &value, sizeof(value));
    };
    constexpr uint64_t returnAddress = 0x00007FF612345678ULL;
    constexpr uint64_t originalRbp = 0x0000000013579BDFULL;
    constexpr uint64_t expectedRbx = 0x0102030405060708ULL;
    constexpr uint64_t expectedRsi = 0x1112131415161718ULL;
    constexpr uint64_t expectedRdi = 0x2122232425262728ULL;
    constexpr uint64_t expectedR12 = 0x3132333435363738ULL;
    constexpr uint64_t expectedR13 = 0x4142434445464748ULL;
    constexpr uint64_t expectedR14 = 0x5152535455565758ULL;
    constexpr uint64_t expectedR15 = 0x6162636465666768ULL;
    store64(entryRsp, returnAddress);
    store64(entryRsp - 8u, originalRbp);
    store64(frameRsp + 0x40u, expectedR15);
    store64(frameRsp + 0x48u, expectedR14);
    store64(frameRsp + 0x50u, expectedR13);
    store64(frameRsp + 0x58u, expectedR12);
    store64(frameRsp + 0x80u, expectedRdi);
    store64(frameRsp + 0x88u, expectedRsi);
    store64(frameRsp + 0x98u, expectedRbx);

    const auto unwindAt = [&](uint32_t relativeOffset, uintptr_t rsp,
                              uint64_t rbp, bool restoreSavedRegisters) {
        CONTEXT context{};
        context.ContextFlags = CONTEXT_FULL | CONTEXT_FLOATING_POINT;
        context.Rip = imageBase + trampoline.trampolineRVA + relativeOffset;
        context.Rsp = rsp;
        context.Rbp = rbp;
        if (!restoreSavedRegisters) {
            context.Rbx = expectedRbx;
            context.Rsi = expectedRsi;
            context.Rdi = expectedRdi;
            context.R12 = expectedR12;
            context.R13 = expectedR13;
            context.R14 = expectedR14;
            context.R15 = expectedR15;
        }
        PVOID handlerData = nullptr;
        DWORD64 establisherFrame = 0;
        RtlVirtualUnwind(UNW_FLAG_NHANDLER, imageBase, context.Rip,
            &nativeFunction, &context, &handlerData, &establisherFrame,
            nullptr);
        Require(context.Rip == returnAddress &&
                context.Rsp == entryRsp + sizeof(uint64_t) &&
                context.Rbp == originalRbp &&
                context.Rbx == expectedRbx && context.Rsi == expectedRsi &&
                context.Rdi == expectedRdi && context.R12 == expectedR12 &&
                context.R13 == expectedR13 && context.R14 == expectedR14 &&
                context.R15 == expectedR15,
            "RtlVirtualUnwind did not reconstruct the x64 trampoline caller");
    };

    // SizeOfProlog is the first instruction boundary after the prolog. Use
    // that exact boundary so RtlVirtualUnwind is never handed a PC in the
    // middle of the function body's first instruction.
    const uint32_t bodyOffset = static_cast<uint32_t>(unwindInfo[1]);
    Require(bodyOffset < epilogOffset,
        "x64 trampoline has no function-body byte after its prolog");
    unwindAt(bodyOffset, frameRsp, frameRsp, true);
    unwindAt(static_cast<uint32_t>(epilogOffset), frameRsp, frameRsp, false);
    unwindAt(static_cast<uint32_t>(epilogOffset + 7u), entryRsp - 8u,
        frameRsp, false);
    unwindAt(static_cast<uint32_t>(epilogOffset + 8u), entryRsp,
        originalRbp, false);

    VirtualFree(mapped, 0, MEM_RELEASE);
}
#endif

void TestBuilderAndReparseIntegration() {
    constexpr uint32_t functionRVA = 0x1000u;
    OwnedBuilderImage owned;
    VMFunctionRecord record{};
    record.functionRVA = functionRVA;
    record.functionSize = 0x20u;
    record.guestStackSize = 0x4000u;

    std::array<uint8_t, VM_RUNTIME_KEY_SHARE_SIZE> runtimeKeyShare{};
    for (size_t index = 0; index < runtimeKeyShare.size(); ++index) {
        runtimeKeyShare[index] = static_cast<uint8_t>(0x41u + index);
    }
    std::unordered_map<uint8_t, uint8_t> opcodeMap;
    const VMHandlerSynthesisConfig config = MakeBuilderConfig(
        functionRVA, opcodeMap);
    const std::vector<uint8_t> bytecode = MakeBuilderBytecode(
        config, opcodeMap, 1u);
    record.bytecodeSize = static_cast<uint32_t>(bytecode.size());
    const char runtimeSection[8] = {'.','t','v','m','r','t',0,0};
    const char unwindSection[8] = {'.','t','v','m','u','w',0,0};
    const char relocationSection[8] = {'.','t','v','m','r','l',0,0};
    const char safeSehSection[8] = {'.','t','v','m','s','h',0,0};

    VMRuntimeBuilder builder;
    const VMRuntimeBuildResult result = builder.Build(
        &owned.image, {record}, bytecode, opcodeMap,
        0x1080u, runtimeKeyShare, config,
        runtimeSection, unwindSection, relocationSection, safeSehSection);
    Require(result.success && result.executionReady &&
            result.runtimeContentVerified &&
            result.referenceRuntimeBlobFreeVerified,
        "VMRuntimeBuilder 未通过自身产物完整性门禁: " + result.error);
    Require(result.trampolines.size() == 1,
        "VMRuntimeBuilder 集成测试没有生成唯一 trampoline");
    Require(result.plaintextHandlers.size() == config.variantCount &&
            result.handlerReferences.size() == 1u &&
            result.handlerReferences.front().references.size() == 1u &&
            result.handlerReferences.front().references.front().semantic ==
                VM_UOP_RET &&
            result.handlerReferences.front().references.front().variant == 1u,
        "VMRuntimeBuilder evidence did not preserve the selected RET reference");
    for (uint32_t variant = 0; variant < config.variantCount; ++variant) {
        Require(result.plaintextHandlers[variant].semantic == VM_UOP_RET &&
                result.plaintextHandlers[variant].variant == variant,
            "VMRuntimeBuilder evidence did not contain the complete, sorted RET K set");
    }
    const auto& trampoline = result.trampolines.front();
    Require(trampoline.trampolineRVA >= result.sectionRVA,
        "trampoline RVA 位于 runtime section 之前");
    const uint32_t trampolineOffset = trampoline.trampolineRVA - result.sectionRVA;
    const auto& emitted = result.integrityExpectation.expectedSectionBytes;
#if defined(_M_X64)
    VerifyX64TrampolineVirtualUnwind(result);
#endif
    Require(static_cast<uint64_t>(trampolineOffset) + trampoline.trampolineSize <=
            emitted.size(),
        "x64 trampoline range exceeds emitted runtime section");
    const std::array<uint8_t, 13> forbiddenPebImageBase = {
        0x65,0x4C,0x8B,0x0C,0x25,0x60,0x00,0x00,0x00,0x4D,0x8B,0x49,0x10
    };
    const auto pebUse = std::search(
        emitted.begin() + trampolineOffset,
        emitted.begin() + trampolineOffset + trampoline.trampolineSize,
        forbiddenPebImageBase.begin(), forbiddenPebImageBase.end());
    Require(pebUse == emitted.begin() + trampolineOffset + trampoline.trampolineSize,
        "DLL trampoline 仍错误读取宿主 EXE 的 PEB.ImageBaseAddress");

    bool foundSelfBase = false;
    for (uint32_t offset = 0; offset + 15u <= trampoline.trampolineSize; ++offset) {
        const uint8_t* code = emitted.data() + trampolineOffset + offset;
        if (std::memcmp(code, "\x4c\x8d\x0d\x00\x00\x00\x00\xb8", 8) != 0 ||
            std::memcmp(code + 12, "\x49\x29\xc1", 3) != 0) {
            continue;
        }
        uint32_t patchedAnchorRVA = 0;
        std::memcpy(&patchedAnchorRVA, code + 8, sizeof(patchedAnchorRVA));
        Require(patchedAnchorRVA == trampoline.trampolineRVA + offset + 7u,
            "trampoline 自身 RIP anchor RVA 回填错误");
        foundSelfBase = true;
        break;
    }
    Require(foundSelfBase,
        "trampoline 未生成可用于 DLL/EXE 的 position-independent image base");
    std::string error;
    // 见 RequireVerified 注释：先落地布尔结果，避免实参求值顺序把消息拼接在
    // VerifyRuntimeContents 写入 error 之前完成。
    bool verified = VMRuntimeBuilder::VerifyRuntimeContents(
        &owned.image, result, error);
    Require(verified, "VMRuntimeBuilder 构建后复验失败: " + error);

    PEEmitter emitter(&owned.image);
    const char laterSection[8] = {'.','t','l','a','t','e',0,0};
    const auto appended = emitter.AppendSection(laterSection,
        std::vector<uint8_t>(0x30u, 0xA5u),
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ);
    Require(appended.success, "后续 PE section 追加失败: " + appended.error);
    verified = VMRuntimeBuilder::VerifyRuntimeContents(
        &owned.image, result, error);
    Require(verified, "后续 PE section 追加后 runtime 复验失败: " + error);

    BYTE* reparsedBytes = new BYTE[owned.image.rawSize];
    std::memcpy(reparsedBytes, owned.image.rawData, owned.image.rawSize);
    PEParser parser;
    CS_PE_IMAGE* reparsed = parser.LoadFromBuffer(
        reparsedBytes, owned.image.rawSize);
    Require(reparsed != nullptr && reparsed->isValid,
        "最终 PE 字节无法重新解析");
    verified = VMRuntimeBuilder::VerifyRuntimeContents(
        reparsed, result, error);
    Require(verified, "最终 PE 重解析后的 runtime 复验失败: " + error);
    parser.FreeImage(reparsed);
}

void TestBuilderX86SelfBaseAndCetBalance() {
    constexpr uint32_t functionRVA = 0x1000u;
    OwnedBuilderImage owned(false);
    VMFunctionRecord record{};
    record.functionRVA = functionRVA;
    record.functionSize = 0x20u;
    record.guestStackSize = 0x4000u;

    std::array<uint8_t, VM_RUNTIME_KEY_SHARE_SIZE> runtimeKeyShare{};
    for (size_t index = 0; index < runtimeKeyShare.size(); ++index) {
        runtimeKeyShare[index] = static_cast<uint8_t>(0x71u + index);
    }
    std::unordered_map<uint8_t, uint8_t> opcodeMap;
    const VMHandlerSynthesisConfig config = MakeBuilderConfig(
        functionRVA, opcodeMap, false);
    const std::vector<uint8_t> bytecode = MakeBuilderBytecode(
        config, opcodeMap, 2u);
    record.bytecodeSize = static_cast<uint32_t>(bytecode.size());
    const char runtimeSection[8] = {'.','x','v','m','r','t',0,0};
    const char unwindSection[8] = {'.','x','v','m','u','w',0,0};
    const char relocationSection[8] = {'.','x','v','m','r','l',0,0};
    const char safeSehSection[8] = {'.','x','v','m','s','h',0,0};

    VMRuntimeBuilder builder;
    const VMRuntimeBuildResult result = builder.Build(
        &owned.image, {record}, bytecode, opcodeMap,
        0x1080u, runtimeKeyShare, config,
        runtimeSection, unwindSection, relocationSection, safeSehSection);
    Require(result.success && result.executionReady &&
            result.architecture == VM_ARCH_X86,
        "x86 VMRuntimeBuilder integration failed: " + result.error);
    Require(result.trampolines.size() == 1u,
        "x86 VMRuntimeBuilder did not emit exactly one trampoline");

    const auto& trampoline = result.trampolines.front();
    Require(trampoline.trampolineRVA >= result.sectionRVA,
        "x86 trampoline RVA precedes runtime section");
    const uint32_t trampolineOffset = trampoline.trampolineRVA - result.sectionRVA;
    const auto& emitted = result.integrityExpectation.expectedSectionBytes;
    Require(static_cast<uint64_t>(trampolineOffset) + trampoline.trampolineSize <=
            emitted.size(),
        "x86 trampoline range exceeds emitted runtime section");
    const auto begin = emitted.begin() + trampolineOffset;
    const auto end = begin + trampoline.trampolineSize;

    const std::array<uint8_t, 10> forbiddenPebImageBase = {
        0x64,0x8B,0x0D,0x30,0x00,0x00,0x00,0x8B,0x49,0x08
    };
    Require(std::search(begin, end, forbiddenPebImageBase.begin(),
                forbiddenPebImageBase.end()) == end,
        "x86 DLL trampoline still reads host EXE PEB.ImageBaseAddress");
    const std::array<uint8_t, 6> forbiddenUnbalancedGetPc = {
        0xE8,0x00,0x00,0x00,0x00,0x59
    };
    Require(std::search(begin, end, forbiddenUnbalancedGetPc.begin(),
                forbiddenUnbalancedGetPc.end()) == end,
        "x86 trampoline contains CET-unbalanced call-next/pop get-PC sequence");

    const std::array<uint8_t, 13> balancedPrefix = {
        0xE8,0x02,0x00,0x00,0x00,
        0xEB,0x04,
        0x8B,0x0C,0x24,
        0xC3,
        0x81,0xE9
    };
    const auto selfBase = std::search(
        begin, end, balancedPrefix.begin(), balancedPrefix.end());
    Require(selfBase != end &&
            static_cast<size_t>(end - selfBase) >= balancedPrefix.size() + 4u,
        "x86 trampoline lacks balanced position-independent image-base sequence");
    uint32_t patchedAnchorRVA = 0;
    std::memcpy(&patchedAnchorRVA,
        &*(selfBase + balancedPrefix.size()), sizeof(patchedAnchorRVA));
    const uint32_t sequenceOffset = static_cast<uint32_t>(selfBase - begin);
    Require(patchedAnchorRVA == trampoline.trampolineRVA + sequenceOffset + 5u,
        "x86 trampoline self-address anchor RVA was patched incorrectly");

    std::string error;
    const bool verified = VMRuntimeBuilder::VerifyRuntimeContents(
        &owned.image, result, error);
    Require(verified, "x86 VMRuntimeBuilder post-build verification failed: " + error);
}

} // namespace

int main() {
    try {
        TestValidAndRelocatedRawOffset();
        TestPhysicalTamperRejection();
        TestDigestAndDispatchTargetRejection();
        TestBuilderAndReparseIntegration();
        TestBuilderX86SelfBaseAndCetBalance();
        std::cout << "VM runtime 产物完整性测试通过" << std::endl;
        return 0;
    } catch (const std::exception& exception) {
        std::cerr << "VM runtime 产物完整性测试失败: "
                  << exception.what() << std::endl;
        return 1;
    }
}
