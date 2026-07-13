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
#include <vector>

namespace {

using CipherShell::CS_PE_IMAGE;
using CipherShell::MutationConfig;
using CipherShell::MutationEngine;
using CipherShell::PEEmitter;
using CipherShell::PEParser;
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
    expectation.synthesizedImage = {0, kRuntimeImageSize, 0};
    expectation.encryptedHandlers = {kHandlerOffset, kHandlerSize, 0};
    expectation.dispatchTable = {kDispatchOffset, kDispatchSize, 0};
    expectation.expectedSectionBytes.assign(kRuntimeSectionSize, 0);

    for (uint32_t offset = 0; offset < kRuntimeContentSize; ++offset) {
        expectation.expectedSectionBytes[offset] = static_cast<uint8_t>(
            (offset * 37u + 0x5Bu) & 0xFFu);
    }

    const uint32_t pointerSize = is64Bit ? 8u : 4u;
    const uint64_t imageBase = is64Bit ? kImageBase64 : kImageBase32;
    const uint64_t mappedBase = imageBase + kRuntimeSectionRVA;
    const uint64_t firstTarget = mappedBase + kHandlerOffset;
    const uint64_t secondTarget = mappedBase + kHandlerOffset + 0x20u;
    WritePointer(expectation.expectedSectionBytes, kDispatchOffset,
        pointerSize, firstTarget);
    WritePointer(expectation.expectedSectionBytes,
        kDispatchOffset + pointerSize, pointerSize, secondTarget);

    std::vector<uint8_t> normalizedDispatch(kDispatchSize, 0);
    const uint64_t firstRelative = kHandlerOffset;
    const uint64_t secondRelative = kHandlerOffset + 0x20u;
    WritePointer(normalizedDispatch, 0, pointerSize, firstRelative);
    WritePointer(normalizedDispatch, pointerSize, pointerSize, secondRelative);
    result.dispatchKeyDigest = HashBytes(normalizedDispatch.data(),
        normalizedDispatch.size(), expectation.dispatchDigestDomain);
    expectation.dispatchKeyDigest = result.dispatchKeyDigest;
    RefreshPhysicalDigests(result);
    return result;
}

void RequireVerified(const TestImage& testImage,
                     const VMRuntimeBuildResult& result,
                     const std::string& context) {
    std::string error;
    Require(VMRuntimeBuilder::VerifyRuntimeContents(
            &testImage.image, result, error),
        context + ": " + error);
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

        // 即使攻击者同步伪造整段期望字节与物理摘要，dispatch 目标反归一化后
        // 仍必须与 pack-time dispatch-key digest 一致。
        VMRuntimeBuildResult forgedDispatch = result;
        const uint32_t pointerSize = is64Bit ? 8u : 4u;
        const uint64_t imageBase = is64Bit ? kImageBase64 : kImageBase32;
        const uint64_t forgedTarget = imageBase + kRuntimeSectionRVA +
            kHandlerOffset + 0x10u;
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
    OwnedBuilderImage() {
        constexpr uint32_t headersSize = 0x400u;
        constexpr uint32_t textRawOffset = headersSize;
        constexpr uint32_t textRawSize = 0x400u;
        constexpr uint32_t totalSize = textRawOffset + textRawSize;
        image.rawData = new BYTE[totalSize]{};
        image.rawSize = totalSize;

        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image.rawData);
        dos->e_magic = IMAGE_DOS_SIGNATURE;
        dos->e_lfanew = 0x80;
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

        IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt);
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
        image.ntHeaders64 = nt;
        image.ntHeaders32 = nullptr;
        image.sections = section;
        image.numSections = 1;
        image.is64Bit = TRUE;
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

VMHandlerSynthesisConfig MakeBuilderConfig(uint32_t functionRVA) {
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
        if (descriptor.runtimeSupportedX64) {
            mutation.validOpcodes.push_back(
                static_cast<uint8_t>(descriptor.opcode));
        }
    }
    MutationEngine engine;
    Require(engine.Initialize(mutation),
        "runtime builder 集成测试无法初始化 MutationEngine");
    const auto isa = engine.GenerateMutatedISA();

    VMHandlerSynthesisConfig config{};
    config.architecture = VMHandlerArchitecture::X64;
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

void TestBuilderAndReparseIntegration() {
    constexpr uint32_t functionRVA = 0x1000u;
    OwnedBuilderImage owned;
    VMFunctionRecord record{};
    record.functionRVA = functionRVA;
    record.functionSize = 0x20u;
    record.bytecodeSize = 1;
    record.guestStackSize = 0x4000u;

    std::array<uint8_t, VM_RUNTIME_KEY_SHARE_SIZE> runtimeKeyShare{};
    for (size_t index = 0; index < runtimeKeyShare.size(); ++index) {
        runtimeKeyShare[index] = static_cast<uint8_t>(0x41u + index);
    }
    const VMHandlerSynthesisConfig config = MakeBuilderConfig(functionRVA);
    const char runtimeSection[8] = {'.','t','v','m','r','t',0,0};
    const char unwindSection[8] = {'.','t','v','m','u','w',0,0};
    const char relocationSection[8] = {'.','t','v','m','r','l',0,0};

    VMRuntimeBuilder builder;
    const VMRuntimeBuildResult result = builder.Build(
        &owned.image, {record}, 0x1080u, runtimeKeyShare, config,
        runtimeSection, unwindSection, relocationSection);
    Require(result.success && result.executionReady &&
            result.runtimeContentVerified &&
            result.referenceRuntimeBlobFreeVerified,
        "VMRuntimeBuilder 未通过自身产物完整性门禁: " + result.error);
    std::string error;
    Require(VMRuntimeBuilder::VerifyRuntimeContents(
            &owned.image, result, error),
        "VMRuntimeBuilder 构建后复验失败: " + error);

    PEEmitter emitter(&owned.image);
    const char laterSection[8] = {'.','t','l','a','t','e',0,0};
    const auto appended = emitter.AppendSection(laterSection,
        std::vector<uint8_t>(0x30u, 0xA5u),
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ);
    Require(appended.success, "后续 PE section 追加失败: " + appended.error);
    Require(VMRuntimeBuilder::VerifyRuntimeContents(
            &owned.image, result, error),
        "后续 PE section 追加后 runtime 复验失败: " + error);

    BYTE* reparsedBytes = new BYTE[owned.image.rawSize];
    std::memcpy(reparsedBytes, owned.image.rawData, owned.image.rawSize);
    PEParser parser;
    CS_PE_IMAGE* reparsed = parser.LoadFromBuffer(
        reparsedBytes, owned.image.rawSize);
    Require(reparsed != nullptr && reparsed->isValid,
        "最终 PE 字节无法重新解析");
    Require(VMRuntimeBuilder::VerifyRuntimeContents(
            reparsed, result, error),
        "最终 PE 重解析后的 runtime 复验失败: " + error);
    parser.FreeImage(reparsed);
}

} // namespace

int main() {
    try {
        TestValidAndRelocatedRawOffset();
        TestPhysicalTamperRejection();
        TestDigestAndDispatchTargetRejection();
        TestBuilderAndReparseIntegration();
        std::cout << "VM runtime 产物完整性测试通过" << std::endl;
        return 0;
    } catch (const std::exception& exception) {
        std::cerr << "VM runtime 产物完整性测试失败: "
                  << exception.what() << std::endl;
        return 1;
    }
}
