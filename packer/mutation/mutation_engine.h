/**
 * CipherShell 变异引擎
 * 每次加壳时重新生成 ISA、随机化 opcode、变异 handler
 */

#ifndef CS_MUTATION_ENGINE_H
#define CS_MUTATION_ENGINE_H

#include <cstdint>
#include <ctime>
#include <vector>
#include <unordered_map>

namespace CipherShell {

// ============================================================================
// ISA 变异配置
// ============================================================================

struct MutationConfig {
    uint32_t    seed;                   // 随机种子
    uint32_t    registerCount;          // 寄存器数量
    bool        randomizeOpcodeMap;     // 随机化 opcode 映射
    bool        randomizeRegisterMap;   // 随机化寄存器映射
    bool        mutateHandlers;         // 变异 handler 代码
    bool        insertJunkHandlers;     // 插入假 handler
    uint32_t    junkHandlerCount;       // 假 handler 数量
    bool        randomizeDispatchMode;  // 随机化 dispatch 模式
    bool        randomizeStackLayout;   // 随机化栈布局

    MutationConfig() :
        seed(0),
        registerCount(24),
        randomizeOpcodeMap(true),
        randomizeRegisterMap(true),
        mutateHandlers(true),
        insertJunkHandlers(true),
        junkHandlerCount(20),
        randomizeDispatchMode(true),
        randomizeStackLayout(true)
    {
        seed = (uint32_t)time(nullptr);
    }
};

// ============================================================================
// 变异后的 ISA 描述
// ============================================================================

struct MutatedISA {
    std::unordered_map<uint8_t, uint8_t>   opcodeMap;      // 标准 opcode → 变异 opcode
    std::unordered_map<uint8_t, uint8_t>   registerMap;    // x86 reg → vReg
    std::vector<uint8_t>                    handlerOrder;   // handler 排列顺序
    std::vector<uint8_t>                    junkOpcodes;    // 假 handler 的 opcode
    uint32_t                                dispatchMode;   // dispatch 模式
    uint32_t                                stackBase;      // 栈基址
    uint32_t                                stackSize;      // 栈大小
};

// ============================================================================
// Handler 变异信息
// ============================================================================

struct MutatedHandler {
    uint8_t     originalOpcode;         // 原始 opcode
    uint8_t     mutatedOpcode;          // 变异后的 opcode
    std::vector<uint8_t>   code;        // 变异后的 handler 代码
    uint32_t    codeSize;               // 代码大小
    bool        isJunk;                 // 是否是假 handler
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
     * 变异 handler 代码
     * @param originalHandler 原始 handler 代码
     * @param originalSize 原始大小
     * @return 变异后的 handler
     */
    MutatedHandler MutateHandler(const uint8_t* originalHandler, uint32_t originalSize);

    /**
     * 生成假 handler
     * @return 假 handler
     */
    MutatedHandler GenerateJunkHandler();

    /**
     * 生成变异后的 handler 表
     * @param isa 变异后的 ISA
     * @return handler 表数据
     */
    std::vector<MutatedHandler> GenerateHandlerTable(const MutatedISA& isa);

    /**
     * 获取变异种子（用于记录/重放）
     * @return 种子值
     */
    uint32_t GetSeed() const;

private:
    // Opcode 随机化
    std::unordered_map<uint8_t, uint8_t> RandomizeOpcodeMap();

    // 寄存器随机化
    std::unordered_map<uint8_t, uint8_t> RandomizeRegisterMap();

    // Handler 排列随机化
    std::vector<uint8_t> RandomizeHandlerOrder();

    // Handler 代码变异
    void MutateCode(std::vector<uint8_t>& code);
    void InsertJunkInstructions(std::vector<uint8_t>& code);
    void RemapRegisters(std::vector<uint8_t>& code);
    void RearrangeCode(std::vector<uint8_t>& code);

    // 辅助函数
    uint32_t NextRandom();
    uint8_t NextRandomByte();

    // 成员变量
    MutationConfig m_config;
    uint32_t m_randomState;
    bool m_initialized;
};

} // namespace CipherShell

#endif // CS_MUTATION_ENGINE_H
