#ifndef CS_VM_NATIVE_DIFFERENTIAL_PROVIDER_H
#define CS_VM_NATIVE_DIFFERENTIAL_PROVIDER_H

#include "../transforms/translator.h"
#include "../transforms/vm_handler_synthesizer.h"

#include <array>
#include <cstdint>
#include <memory>
#include <string>

namespace CipherShell {

/*
 * Concrete, Windows-only VMNativeDifferentialEvidenceProvider.
 *
 * The synthesized handler's operand decode-plan table is keyed by function
 * RVA (exactly like VMRuntimeBuilder builds it for the real shipped image,
 * see vm_runtime_builder.cpp), so a single handler image cannot serve every
 * future candidate function decided a priori: Initialize() only stashes the
 * per-build config (architecture, seed, handler slot/variant assignment,
 * worker path); PrepareForFunction() must be called once per candidate
 * function, with that function's own TranslationResult::operandCodec,
 * before running any of its corpus cases -- it (re)synthesizes a handler
 * image whose decode-plan table matches this one function, exactly as
 * VMRuntimeBuilder will when it later builds the real per-build image
 * covering every accepted function.  A missing worker binary, a spawn
 * failure, or a timeout all fail closed: this class never fabricates
 * evidence and never falls back to a software model.
 */
class VMWindowsNativeDifferentialEvidenceProvider final
    : public VMNativeDifferentialEvidenceProvider {
public:
    VMWindowsNativeDifferentialEvidenceProvider();
    ~VMWindowsNativeDifferentialEvidenceProvider() override;

    bool Initialize(
        VMHandlerArchitecture architecture,
        const std::array<uint8_t, 32>& buildSeed,
        const std::array<uint8_t, VM_HANDLER_TABLE_SIZE>& handlerSemanticToSlot,
        const std::array<uint8_t, VM_HANDLER_TABLE_SIZE>& handlerSlotToSemantic,
        const std::array<uint8_t, VM_HANDLER_TABLE_SIZE>& handlerVariants,
        const VMHandlerOperandCodecConfig& operandCodec,
        uint32_t memorySize,
        std::string& error);

    bool PrepareForFunction(
        uint32_t functionRVA,
        const VM_OPERAND_CODEC& functionOperandCodec,
        std::string& error);

    uint64_t SemanticIdentityDigest() const { return m_semanticDigest; }

    bool ExecuteCase(
        const Function& function,
        const TranslationResult& translation,
        const std::unordered_map<uint8_t, uint8_t>& opcodeMap,
        const std::unordered_map<uint8_t, uint8_t>& registerMap,
        const VMNativeDifferentialCaseRequest& request,
        VMNativeDifferentialCaseEvidence& evidence,
        std::string& error) const override;

private:
    struct SharedConfig;
    struct Impl;
    std::unique_ptr<SharedConfig> m_config;
    std::unique_ptr<Impl> m_impl;
    uint64_t m_semanticDigest = 0;
};

} // namespace CipherShell

#endif // CS_VM_NATIVE_DIFFERENTIAL_PROVIDER_H
