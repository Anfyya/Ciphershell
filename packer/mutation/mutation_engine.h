/**
 * CipherShell 变异引擎
 * 每次加壳时重新生成 ISA、随机化 opcode、变异 handler
 */

#ifndef CS_MUTATION_ENGINE_H
#define CS_MUTATION_ENGINE_H

#include <array>
#include <cstdint>
#include <unordered_map>

namespace CipherShell {

// ============================================================================
// ISA 变异配置
// ============================================================================

struct MutationConfig {
    std::array<uint8_t, 32> seed{};     // 256 位构建种子
    uint32_t    registerCount;          // 寄存器数量
    bool        randomizeOpcodeMap;     // 随机化 opcode 映射
    bool        randomizeRegisterMap;   // 随机化寄存器映射

    MutationConfig() :
        registerCount(24),
        randomizeOpcodeMap(true),
        randomizeRegisterMap(true)
    {}
};

// ============================================================================
// 变异后的 ISA 描述
// ============================================================================

struct MutatedISA {
    std::unordered_map<uint8_t, uint8_t>   opcodeMap;      // 标准 opcode → 变异 opcode
    std::unordered_map<uint8_t, uint8_t>   registerMap;    // x86 reg → vReg
};

// ============================================================================
// 变异引擎类
// ============================================================================

class MutationEngine {
public:
    MutationEngine();
    ~MutationEngine();

    /**
     * 初始化变异引擎
     * @param config 变异配置
     * @return 是否成功
     */
    bool Initialize(const MutationConfig& config);

    /**
     * 生成变异后的 ISA
     * @return 变异后的 ISA 描述
     */
    MutatedISA GenerateMutatedISA();

    /**
     * 获取变异种子（用于记录/重放）
     * @return 种子值
     */
    uint64_t GetSeedFingerprint() const;

private:
    // Opcode 随机化
    std::unordered_map<uint8_t, uint8_t> RandomizeOpcodeMap();

    // 寄存器随机化
    std::unordered_map<uint8_t, uint8_t> RandomizeRegisterMap();

    // 辅助函数
    uint32_t NextRandom();
    uint32_t RandomBelow(uint32_t upperBound);

    // 成员变量
    MutationConfig m_config;
    uint64_t m_streamOffset;
    bool m_initialized;
};

} // namespace CipherShell

#endif // CS_MUTATION_ENGINE_H
