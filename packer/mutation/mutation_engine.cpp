#include "mutation_engine.h"

#include "../../runtime/common/vm_crypto.h"

#include <algorithm>
#include <array>
#include <vector>
#include <unordered_set>

namespace CipherShell {

MutationEngine::MutationEngine()
    : m_streamOffset(0)
    , m_initialized(false) {
}

MutationEngine::~MutationEngine() {
    std::fill(m_config.seed.begin(), m_config.seed.end(), static_cast<uint8_t>(0));
    m_streamOffset = 0;
}

bool MutationEngine::Initialize(const MutationConfig& config) {
    if (config.registerCount < 16 || config.registerCount > 32) {
        m_initialized = false;
        return false;
    }

    m_config = config;
    m_streamOffset = 0;
    m_initialized = true;
    return true;
}

MutatedISA MutationEngine::GenerateMutatedISA() {
    MutatedISA isa;
    if (!m_initialized) {
        return isa;
    }

    if (m_config.randomizeOpcodeMap) {
        isa.opcodeMap = RandomizeOpcodeMap();
    } else {
        for (uint32_t i = 0; i < 256; ++i) {
            isa.opcodeMap[static_cast<uint8_t>(i)] = static_cast<uint8_t>(i);
        }
    }

    if (m_config.randomizeRegisterMap) {
        isa.registerMap = RandomizeRegisterMap();
    } else {
        for (uint8_t i = 0; i < 16; ++i) {
            isa.registerMap[i] = i;
        }
    }

    if (!BuildHandlerLayout(isa)) {
        isa.opcodeMap.clear();
        isa.registerMap.clear();
    }
    return isa;
}

uint64_t MutationEngine::GetSeedFingerprint() const {
    return vm_siphash24(m_config.seed.data() + 16, 16, m_config.seed.data());
}

std::unordered_map<uint8_t, uint8_t> MutationEngine::RandomizeOpcodeMap() {
    std::unordered_map<uint8_t, uint8_t> map;
    std::vector<uint8_t> permutation(256);
    for (uint32_t i = 0; i < permutation.size(); ++i) {
        permutation[i] = static_cast<uint8_t>(i);
    }

    for (uint32_t i = static_cast<uint32_t>(permutation.size() - 1); i > 0; --i) {
        const uint32_t j = RandomBelow(i + 1);
        std::swap(permutation[i], permutation[j]);
    }

    for (uint32_t i = 0; i < permutation.size(); ++i) {
        map[static_cast<uint8_t>(i)] = permutation[i];
    }
    return map;
}

std::unordered_map<uint8_t, uint8_t> MutationEngine::RandomizeRegisterMap() {
    std::unordered_map<uint8_t, uint8_t> map;
    std::vector<uint8_t> available(m_config.registerCount);
    for (uint32_t i = 0; i < available.size(); ++i) {
        available[i] = static_cast<uint8_t>(i);
    }

    for (uint32_t i = static_cast<uint32_t>(available.size() - 1); i > 0; --i) {
        const uint32_t j = RandomBelow(i + 1);
        std::swap(available[i], available[j]);
    }
    for (uint8_t i = 0; i < 16; ++i) {
        map[i] = available[i];
    }
    return map;
}

bool MutationEngine::BuildHandlerLayout(MutatedISA& isa) {
    isa.handlerSemanticToSlot.fill(VM_HANDLER_INVALID);
    isa.handlerSlotToSemantic.fill(VM_HANDLER_INVALID);
    isa.handlerVariants.fill(0);

    std::vector<uint8_t> valid;
    std::unordered_set<uint8_t> seen;
    for (uint8_t opcode : m_config.validOpcodes) {
        if (opcode == VM_HANDLER_INVALID || opcode == VM_HANDLER_JUNK ||
            !seen.insert(opcode).second) continue;
        valid.push_back(opcode);
    }
    if (valid.empty() || valid.size() > VM_HANDLER_USABLE_SLOT_COUNT) return false;

    // 0xFF is the invalid sentinel stored in semanticToSlot, so slot 255 is
    // intentionally reserved and can never be assigned to a real or junk handler.
    std::vector<uint8_t> slots(VM_HANDLER_USABLE_SLOT_COUNT);
    for (uint32_t i = 0; i < slots.size(); ++i) slots[i] = static_cast<uint8_t>(i);
    if (m_config.mutateHandlers) {
        for (uint32_t i = static_cast<uint32_t>(slots.size() - 1); i > 0; --i) {
            const uint32_t j = RandomBelow(i + 1u);
            std::swap(slots[i], slots[j]);
        }
    }

    size_t cursor = 0;
    for (uint8_t opcode : valid) {
        uint8_t slot;
        if (!m_config.mutateHandlers && isa.handlerSlotToSemantic[opcode] == VM_HANDLER_INVALID) {
            slot = opcode;
        } else {
            while (cursor < slots.size() &&
                   isa.handlerSlotToSemantic[slots[cursor]] != VM_HANDLER_INVALID) ++cursor;
            if (cursor >= slots.size()) return false;
            slot = slots[cursor++];
        }
        isa.handlerSemanticToSlot[opcode] = slot;
        isa.handlerSlotToSemantic[slot] = opcode;
        isa.handlerVariants[slot] = m_config.mutateHandlers
            ? static_cast<uint8_t>(RandomBelow(VM_HANDLER_VARIANT_COUNT))
            : 0;
    }

    if (m_config.mutateHandlers) {
        bool anyMoved = false;
        for (uint8_t opcode : valid) {
            if (isa.handlerSemanticToSlot[opcode] != opcode) {
                anyMoved = true;
                break;
            }
        }
        if (!anyMoved && valid.size() >= 2) {
            const uint8_t first = valid[0];
            const uint8_t second = valid[1];
            const uint8_t firstSlot = isa.handlerSemanticToSlot[first];
            const uint8_t secondSlot = isa.handlerSemanticToSlot[second];
            isa.handlerSemanticToSlot[first] = secondSlot;
            isa.handlerSemanticToSlot[second] = firstSlot;
            isa.handlerSlotToSemantic[firstSlot] = second;
            isa.handlerSlotToSemantic[secondSlot] = first;
            std::swap(isa.handlerVariants[firstSlot], isa.handlerVariants[secondSlot]);
        }
    }

    if (m_config.embedJunkHandlers) {
        const uint32_t available = static_cast<uint32_t>(VM_HANDLER_USABLE_SLOT_COUNT - valid.size());
        const uint32_t requested = (std::min)(m_config.requestedJunkHandlerCount, available);
        for (uint32_t i = 0; i < requested; ++i) {
            while (cursor < slots.size() &&
                   isa.handlerSlotToSemantic[slots[cursor]] != VM_HANDLER_INVALID) ++cursor;
            if (cursor >= slots.size()) break;
            const uint8_t slot = slots[cursor++];
            isa.handlerSlotToSemantic[slot] = VM_HANDLER_JUNK;
            isa.handlerVariants[slot] = static_cast<uint8_t>(RandomBelow(VM_HANDLER_VARIANT_COUNT));
            ++isa.junkHandlerCount;
        }
    }
    isa.handlerMutationEnabled = m_config.mutateHandlers;
    isa.junkHandlersEnabled = isa.junkHandlerCount != 0;
    return true;
}

uint32_t MutationEngine::NextRandom() {
    static constexpr uint8_t nonce[12] = {
        'C', 'S', 'I', 'S', 'A', 'P', 'R', 'N', 'G', 3, 0, 1
    };
    std::array<uint8_t, sizeof(uint32_t)> input{};
    std::array<uint8_t, sizeof(uint32_t)> output{};
    vm_chacha20_xor(input.data(), output.data(), output.size(), m_config.seed.data(),
        nonce, 1, m_streamOffset);
    m_streamOffset += output.size();
    return static_cast<uint32_t>(output[0]) |
        (static_cast<uint32_t>(output[1]) << 8) |
        (static_cast<uint32_t>(output[2]) << 16) |
        (static_cast<uint32_t>(output[3]) << 24);
}

uint32_t MutationEngine::RandomBelow(uint32_t upperBound) {
    if (upperBound <= 1) return 0;
    const uint32_t threshold = (0u - upperBound) % upperBound;
    for (;;) {
        const uint32_t value = NextRandom();
        if (value >= threshold) return value % upperBound;
    }
}

} // namespace CipherShell
