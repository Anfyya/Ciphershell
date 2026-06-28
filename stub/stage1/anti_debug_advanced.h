/**
 * CipherShell 高级反调试技术
 * 扩展检测方法和隐式响应机制
 */

#ifndef CS_ANTI_DEBUG_ADVANCED_H
#define CS_ANTI_DEBUG_ADVANCED_H

#include "anti_debug.h"
#include <cstdint>
#include <vector>

namespace CipherShell {

// ============================================================================
// 高级检测方法
// ============================================================================

enum class AdvancedAntiDebugMethod : uint32_t {
    // 时序交叉验证
    Timing_CrossValidation      = 0x00010000,
    
    // 内存完整性
    Memory_CodeCRC              = 0x00020000,
    Memory_HandlerChecksum      = 0x00040000,
    Memory_GuardPages           = 0x00080000,
    
    // 异常处理
    Exception_SingleStep        = 0x00100000,
    Exception_Int3Fingerprint   = 0x00200000,
    Exception_VEHChain          = 0x00400000,
    
    // 行为分析
    Behavior_BreakpointPattern  = 0x00800000,
    Behavior_MemoryAccess       = 0x01000000,
    Behavior_InstructionCount   = 0x02000000,
    
    // 环境指纹
    Env_CPUIDHypervisor         = 0x04000000,
    Env_MACAddress              = 0x08000000,
    Env_DiskSize                = 0x10000000,
    Env_RecentFiles             = 0x20000000,
    
    // 主动陷阱
    Trap_SelfModifyingCode      = 0x40000000,
    Trap_InterruptHook          = 0x80000000,
};

// ============================================================================
// 检测结果扩展
// ============================================================================

struct AdvancedAntiDebugResult : AntiDebugResult {
    uint64_t    timingDelta;        // 时序差值
    uint32_t    memoryChecksum;     // 内存校验和
    bool        isVirtualMachine;   // 是否在虚拟机中
    bool        isSandbox;          // 是否在沙箱中
    char        debuggerName[64];   // 检测到的调试器名称
};

// ============================================================================
// 延迟投毒上下文
// ============================================================================

struct PoisonContext {
    bool        active;             // 投毒是否激活
    uint32_t    countdown;          // 倒计时（指令数）
    uint32_t    poisonValue;        // 投毒值
    uint64_t    triggerTimestamp;   // 触发时间戳
    uint32_t    triggerMethod;      // 触发的检测方法
};

// ============================================================================
// 高级反调试类
// ============================================================================

class AntiDebugAdvanced : public AntiDebug {
public:
    AntiDebugAdvanced();
    ~AntiDebugAdvanced();

    /**
     * 初始化高级反调试
     * @param config 配置
     * @return 是否成功
     */
    bool InitializeAdvanced(const AntiDebugConfig& config);

    /**
     * 执行高级检测
     * @return 高级检测结果
     */
    AdvancedAntiDebugResult PerformAdvancedCheck();

    /**
     * 执行时序交叉验证
     * @return 是否检测到调试器
     */
    bool TimingCrossValidation();

    /**
     * 计算代码段 CRC
     * @param imageBase 映像基址
     * @return CRC 值
     */
    uint32_t CalculateCodeCRC(void* imageBase);

    /**
     * 检测虚拟机/沙箱
     * @return 是否在虚拟环境中
     */
    bool DetectVirtualEnvironment();

    /**
     * 设置延迟投毒
     * @param context 投毒上下文
     * @param delay 延迟指令数
     * @param poisonValue 投毒值
     */
    void SetupDelayedPoison(PoisonContext& context, uint32_t delay, uint32_t poisonValue);

    /**
     * 检查投毒是否应该触发
     * @param context 投毒上下文
     * @return 是否触发
     */
    bool CheckPoisonTrigger(PoisonContext& context);

    /**
     * 生成反调试检测 shellcode（用于嵌入 VM handler）
     * @param is64Bit 是否 64 位
     * @param handlerIndex handler 索引
     * @param codeSize 输出代码大小
     * @return 检测代码
     */
    BYTE* GenerateInlineCheckCode(bool is64Bit, uint32_t handlerIndex, DWORD* codeSize);

private:
    // 高级检测实现
    bool CheckTimingWithJitter();
    bool CheckMemoryIntegrity();
    bool CheckExceptionHandler();
    bool CheckCPUIDHypervisor();
    bool CheckMACAddress();
    bool CheckDiskSize();
    bool CheckRecentFiles();

    // 陷阱实现
    void SetupSelfModifyingCodeTrap();
    bool CheckSelfModifyingCodeTrap();

    // 辅助函数
    uint32_t Fletcher32(const uint16_t* data, size_t len);
    uint64_t MeasureInstructionTiming(void* code);
    bool IsKnownDebuggerProcess(const char* processName);

    // 成员变量
    PoisonContext m_poisonContext;
    uint32_t m_originalCodeCRC;
    bool m_trapActive;
};

} // namespace CipherShell

#endif // CS_ANTI_DEBUG_ADVANCED_H
