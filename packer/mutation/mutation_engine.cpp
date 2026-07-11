#include "mutation_engine.h"

#include "../../runtime/common/vm_crypto.h"

#include <algorithm>
#include <array>
#include <vector>

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
