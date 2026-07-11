/**
 * CipherShell 变异引擎
 * 每次加壳时重新生成 ISA、寄存器映射和 handler 入口布局。
 */

#ifndef CS_MUTATION_ENGINE_H
#define CS_MUTATION_ENGINE_H

#include "../../runtime/common/vm_metadata.h"
#include <array>
#include <cstdint>
#include <unordered_map>
#include <vector>

namespace CipherShell {

struct MutationConfig {
    std::array<uint8_t, 32> seed{};
    uint32_t registerCount;
    bool randomizeOpcodeMap;
    bool randomizeRegisterMap;
    bool mutateHandlers;
    bool embedJunkHandlers;
    uint32_t requestedJunkHandlerCount;
    std::vector<uint8_t> validOpcodes;

    MutationConfig()
        : registerCount(24),
          randomizeOpcodeMap(true),
          randomizeRegisterMap(true),
          mutateHandlers(true),
          embedJunkHandlers(true),
          requestedJunkHandlerCount(16) {}
};

struct MutatedISA {
    std::unordered_map<uint8_t, uint8_t> opcodeMap;
    std::unordered_map<uint8_t, uint8_t> registerMap;
    std::array<uint8_t, VM_HANDLER_TABLE_SIZE> handlerSemanticToSlot{};
    std::array<uint8_t, VM_HANDLER_TABLE_SIZE> handlerSlotToSemantic{};
    std::array<uint8_t, VM_HANDLER_TABLE_SIZE> handlerVariants{};
    uint32_t junkHandlerCount = 0;
    bool handlerMutationEnabled = false;
    bool junkHandlersEnabled = false;
};

class MutationEngine {
public:
    MutationEngine();
    ~MutationEngine();

    bool Initialize(const MutationConfig& config);
    MutatedISA GenerateMutatedISA();
    uint64_t GetSeedFingerprint() const;

private:
    std::unordered_map<uint8_t, uint8_t> RandomizeOpcodeMap();
    std::unordered_map<uint8_t, uint8_t> RandomizeRegisterMap();
    bool BuildHandlerLayout(MutatedISA& isa);
    uint32_t NextRandom();
    uint32_t RandomBelow(uint32_t upperBound);

    MutationConfig m_config;
    uint64_t m_streamOffset;
    bool m_initialized;
};

} // namespace CipherShell

#endif // CS_MUTATION_ENGINE_H
