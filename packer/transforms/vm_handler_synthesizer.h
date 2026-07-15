#ifndef CS_VM_HANDLER_SYNTHESIZER_H
#define CS_VM_HANDLER_SYNTHESIZER_H

#include "../../runtime/common/vm_micro_runtime_abi.h"
#include "vm_dispatch_table_codec.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace CipherShell {

enum class VMHandlerArchitecture : uint32_t {
    X86 = VM_ARCH_X86,
    X64 = VM_ARCH_X64
};

enum class VMHandlerEntryABI : uint8_t {
    X86CdeclContext = 1,
    X64FastcallContext = 2
};

struct VMHandlerOperandCodecConfig {
    uint32_t version = VM_OPERAND_CODEC_VERSION;
    uint64_t domain = VM_OPERAND_CODEC_DOMAIN;
    uint8_t opcodeXor = 0;
    uint8_t opcodeAdd = 0;
    uint8_t opcodeRotate = 1;
    uint8_t reserved = 0;
};

struct VMHandlerFunctionDecodePlans {
    uint32_t functionRVA = 0;
    VM_OPERAND_CODEC codec{};
    std::array<VM_RUNTIME_DECODE_PLAN, VM_UOP_COUNT> plans{};
};

struct VMHandlerSynthesisConfig {
    VMHandlerArchitecture architecture = VMHandlerArchitecture::X64;
    std::array<uint8_t, 32> buildSeed{};
    std::array<uint8_t, VM_HANDLER_TABLE_SIZE> handlerSemanticToSlot{};
    std::array<uint8_t, VM_HANDLER_TABLE_SIZE> handlerSlotToSemantic{};
    std::array<uint8_t, VM_HANDLER_TABLE_SIZE> handlerVariants{};
    VMHandlerOperandCodecConfig operandCodec{};
    std::vector<VMHandlerFunctionDecodePlans> functionDecodePlans;
    uint32_t variantCount = VM_HANDLER_VARIANT_COUNT;
    uint32_t minimumJunkBytesPerHandler = 96;
    uint32_t virtualProtectIatRVA = 0;
    uint32_t flushInstructionCacheIatRVA = 0;
    bool encryptHandlerBodies = true;
    bool emitCetLandingPads = true;
};

struct VMHandlerRelocation {
    uint32_t offset = 0;
    uint16_t type = 0;
    uint16_t reserved = 0;
};

enum class VMSynthesizedUnwindKind : uint8_t {
    StackAllocation = 1,
    PushNonvolatile = 2
};

struct VMSynthesizedStackFunclet {
    uint32_t offset = 0;
    uint32_t size = 0;
    uint32_t stackBytes = 0;
    VMSynthesizedUnwindKind kind =
        VMSynthesizedUnwindKind::StackAllocation;
    uint8_t prologSize = 0;
    uint8_t nonvolatileRegister = 0;
};

struct VMSynthesizedHandler {
    uint8_t semantic = VM_HANDLER_INVALID;
    uint8_t slot = VM_HANDLER_INVALID;
    uint8_t variant = 0;
    uint32_t storageOffset = 0;
    uint32_t storageSize = 0;
    uint32_t dispatchTailOffset = 0;
    uint32_t dispatchTailSize = 0;
    /*
     * x64 only: body-relative funclet range whose live stack state contains
     * the direct-tail 0x28-byte Win64 call frame.  The range ends immediately
     * after the restoring ADD RSP, before the final JMP/RET leaf instructions.
     */
    uint32_t dispatchUnwindOffset = 0;
    uint32_t dispatchUnwindSize = 0;
    uint32_t operandBytesConsumed = 0;
    uint64_t bodyDigest = 0;
    uint64_t dispatchTailDigest = 0;
    std::array<uint8_t, 4> registerAssignment{};
    bool semanticComplete = false;
    std::vector<VMSynthesizedStackFunclet> semanticStackFunclets;
    std::vector<uint8_t> plaintextBody;
    std::vector<uint8_t> ciphertextBody;
};

struct VMHandlerDispatchEntry {
    uint8_t slot = VM_HANDLER_INVALID;
    uint8_t semantic = VM_HANDLER_INVALID;
    uint8_t variant = 0;
    uint8_t reserved = 0;
    uint32_t targetOffset = 0;
};

struct VMSynthesizedUnwindEntry {
    uint32_t beginOffset = 0;
    uint32_t endOffset = 0;
    uint32_t unwindOffset = 0;
};

struct VMHandlerSynthesisResult {
    bool success = false;
    bool directThreaded = false;
    bool handlerBodiesEncrypted = false;
    bool fixedRuntimeBlobUsed = false;
    bool publicEntryReady = false;
    bool validationEntryReady = false;
    bool usesTemporaryPageWrite = false;
    bool restoresExecuteRead = false;
    uint32_t architecture = 0;
    uint32_t entryOffset = 0;
    uint32_t contextEntryOffset = 0;
    uint32_t validationEntryOffset = 0;
    VMHandlerEntryABI contextEntryABI = VMHandlerEntryABI::X64FastcallContext;
    uint32_t decryptorOffset = 0;
    uint32_t decryptorSize = 0;
    uint32_t decryptorLoopOffset = 0;
    uint32_t decryptorLoopSize = 0;
    uint32_t decryptorMutationPlan = 0;
    uint64_t decryptorLogicDigest = 0;
    uint32_t operandDecoderOffset = 0;
    uint32_t operandDecoderSize = 0;
    uint32_t flagMaterializerOffset = 0;
    uint32_t flagMaterializerSize = 0;
    uint32_t dispatchTableOffset = 0;
    uint32_t dispatchTableSize = 0;
    VMDispatchTableCodec dispatchTableCodec{};
    uint32_t decodePlanTableOffset = 0;
    uint32_t decodePlanTableSize = 0;
    uint32_t encryptedHandlerOffset = 0;
    uint32_t encryptedHandlerSize = 0;
    uint32_t keyMarkerOffset = 0;
    uint64_t opcodeMapDigest = 0;
    uint64_t dispatchKeyDigest = 0;
    uint64_t microSelectionDigest = 0;
    uint64_t variantSelectorDigest = 0;
    std::vector<uint8_t> image;
    std::vector<VMHandlerRelocation> relocations;
    std::vector<VMSynthesizedHandler> handlers;
    std::vector<VMSynthesizedHandler> junkHandlers;
    std::vector<VMHandlerDispatchEntry> dispatchEntries;
    std::vector<VMHandlerDispatchEntry> junkDispatchEntries;
    std::vector<VMSynthesizedUnwindEntry> unwindEntries;
    std::string error;
};

class VMHandlerSynthesizer {
public:
    VMHandlerSynthesisResult Synthesize(const VMHandlerSynthesisConfig& config) const;

    static bool Validate(
        const VMHandlerSynthesisConfig& config,
        const VMHandlerSynthesisResult& result,
        std::string& error);

    static std::vector<uint8_t> ExtractPlaintextBodies(
        const VMHandlerSynthesisResult& result);
};

VMDispatchTableCodec DeriveVMDispatchTableCodec(
    const std::array<uint8_t, 32>& buildSeed);
uint64_t EncodeVMDispatchTableTarget(
    uint64_t targetOffset,
    uint32_t pointerSize,
    const VMDispatchTableCodec& codec);
uint64_t DecodeVMDispatchTableTarget(
    uint64_t encodedTarget,
    uint32_t pointerSize,
    const VMDispatchTableCodec& codec);

} // namespace CipherShell

#endif // CS_VM_HANDLER_SYNTHESIZER_H
