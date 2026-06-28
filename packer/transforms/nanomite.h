/**
 * CipherShell Nanomite 技术
 * 将条件跳转替换为 INT3，通过异常处理器决定跳转目标
 */

#ifndef CS_NANOMITE_H
#define CS_NANOMITE_H

#include <windows.h>
#include "../analysis/disassembler.h"
#include <cstdint>
#include <vector>
#include <unordered_map>

namespace CipherShell {

// ============================================================================
// Nanomite 条目
// ============================================================================

struct NanomiteEntry {
    uint64_t    address;            // INT3 地址
    uint64_t    targetTrue;         // 条件为真时的目标
    uint64_t    targetFalse;        // 条件为假时的目标
    uint8_t     conditionType;      // 条件类型 (ZF, CF, SF, OF 组合)
    uint8_t     originalOpcode;     // 原始条件跳转 opcode
    bool        isConditional;      // 是否条件跳转
    uint32_t    id;                 // 唯一 ID
};

// ============================================================================
// Nanomite 配置
// ============================================================================

struct NanomiteConfig {
    bool    replaceConditionalJumps;    // 替换条件跳转
    bool    replaceUnconditionalJumps;  // 替换无条件跳转
    bool    encryptJumpTable;           // 加密跳转表
    bool    randomizeTableOrder;        // 随机化表顺序
    uint32_t    minJumpDistance;         // 最小跳转距离（避免短跳转）

    NanomiteConfig() :
        replaceConditionalJumps(true),
        replaceUnconditionalJumps(false),
        encryptJumpTable(true),
        randomizeTableOrder(true),
        minJumpDistance(2) {}
};

// ============================================================================
// Nanomite 结果
// ============================================================================

struct NanomiteResult {
    std::vector<NanomiteEntry>  entries;            // Nanomite 条目
    std::unordered_map<uint64_t, uint32_t> addrMap; // 地址 → 条目索引
    BYTE*   jumpTableData;                          // 跳转表数据
    DWORD   jumpTableSize;                          // 跳转表大小
    BYTE*   vehHandlerCode;                         // VEH 处理器代码
    DWORD   vehHandlerSize;                         // 处理器大小
};

// ============================================================================
// Nanomite 注入器类
// ============================================================================

class NanomiteInjector {
public:
    NanomiteInjector();
    ~NanomiteInjector();

    /**
     * 注入 Nanomite
     * @param blocks 基本块列表
     * @param config 配置
     * @return 注入结果
     */
    NanomiteResult Inject(
        const std::vector<BasicBlock>& blocks,
        const NanomiteConfig& config
    );

    /**
     * 生成 VEH 处理器代码
     * @param entries Nanomite 条目
     * @param is64Bit 是否 64 位
     * @param handlerSize 输出大小
     * @return VEH 处理器代码
     */
    BYTE* GenerateVEHHandler(
        const std::vector<NanomiteEntry>& entries,
        bool is64Bit,
        DWORD* handlerSize
    );

    /**
     * 生成跳转表
     * @param entries Nanomite 条目
     * @param encrypt 是否加密
     * @param tableSize 输出大小
     * @return 跳转表数据
     */
    BYTE* GenerateJumpTable(
        const std::vector<NanomiteEntry>& entries,
        bool encrypt,
        DWORD* tableSize
    );

    /**
     * 清理资源
     * @param result 结果
     */
    void Cleanup(NanomiteResult& result);

private:
    // 条件分析
    uint8_t AnalyzeCondition(const Instruction& instr);
    bool ShouldReplace(const Instruction& instr, const NanomiteConfig& config);

    // 辅助函数
    uint32_t GenerateId();
    uint32_t EncryptEntryId(uint32_t id, uint32_t key);

    // 成员变量
    uint32_t m_nextId;
    uint32_t m_encryptionKey;
};

} // namespace CipherShell

#endif // CS_NANOMITE_H
