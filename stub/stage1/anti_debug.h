/**
 * CipherShell 反调试系统
 * 实现多种反调试技术和隐式响应机制
 */

#ifndef CS_ANTI_DEBUG_H
#define CS_ANTI_DEBUG_H

#include <windows.h>
#include <cstdint>

namespace CipherShell {

// ============================================================================
// 反调试检测类型
// ============================================================================

enum class AntiDebugMethod : uint32_t {
    // 时序检测
    Timing_RDTSC            = 0x0001,
    Timing_QPC              = 0x0002,
    Timing_GetTickCount     = 0x0004,
    Timing_ThreadCycle      = 0x0008,

    // 状态检测
    State_PEB_BeingDebugged = 0x0010,
    State_PEB_NtGlobalFlag  = 0x0020,
    State_HeapFlags         = 0x0040,
    State_HardwareBP        = 0x0080,
    State_KdDebugger        = 0x0100,

    // 完整性检测
    Integrity_CodeCRC       = 0x0200,
    Integrity_APIScan       = 0x0400,

    // 环境检测
    Env_ParentProcess       = 0x0800,
    Env_DebuggerWindow      = 0x1000,
    Env_ModuleScan          = 0x2000,

    // 主动对抗
    Active_ThreadHide       = 0x4000,
    Active_ExceptionChain   = 0x8000,
};

// ============================================================================
// 检测结果
// ============================================================================

struct AntiDebugResult {
    bool        detected;       // 是否检测到调试器
    uint32_t    method;         // 检测到的方法
    uint32_t    confidence;     // 置信度 (0-100)
    uint64_t    timestamp;      // 检测时间戳
};

// ============================================================================
// 反调试配置
// ============================================================================

struct AntiDebugConfig {
    uint32_t    enabledMethods;     // 启用的检测方法
    bool        implicitResponse;   // 隐式响应（不退出，投毒）
    uint32_t    poisonDelay;        // 投毒延迟（指令数）
    bool        multiLayerCheck;    // 多层交叉验证

    AntiDebugConfig() :
        enabledMethods(0xFFFFFFFF),  // 全部启用
        implicitResponse(true),
        poisonDelay(500),
        multiLayerCheck(true) {}
};

// ============================================================================
// 反调试类
// ============================================================================

class AntiDebug {
public:
    AntiDebug();
    ~AntiDebug();

    /**
     * 初始化反调试系统
     * @param config 配置
     * @return 是否成功
     */
    bool Initialize(const AntiDebugConfig& config);

    /**
     * 执行所有检测
     * @return 检测结果
     */
    AntiDebugResult PerformCheck();

    /**
     * 执行特定检测
     * @param method 检测方法
     * @return 检测结果
     */
    AntiDebugResult CheckMethod(AntiDebugMethod method);

    /**
     * 应用隐式响应（投毒）
     * @param result 检测结果
     * @param vmContext VM 上下文指针
     */
    void ApplyImplicitResponse(const AntiDebugResult& result, void* vmContext);

    /**
     * 生成反调试检测 shellcode
     * @param is64Bit 是否 64 位
     * @param codeSize 输出代码大小
     * @return 检测代码
     */
    BYTE* GenerateCheckCode(bool is64Bit, DWORD* codeSize);

private:
    // 时序检测
    bool CheckTimingRDTSC();
    bool CheckTimingQPC();
    bool CheckTimingGetTickCount();

    // 状态检测
    bool CheckPEBBeingDebugged();
    bool CheckPEBNtGlobalFlag();
    bool CheckHeapFlags();
    bool CheckHardwareBreakpoints();
    bool CheckKdDebugger();

    // 完整性检测
    bool CheckCodeIntegrity();
    bool CheckAPIIntegrity();

    // 环境检测
    bool CheckParentProcess();
    bool CheckDebuggerWindows();
    bool CheckInjectedModules();

    // 主动对抗
    void HideCurrentThread();
    bool ValidateExceptionChain();

    // 辅助函数
    void* GetPEB();
    uint64_t GetTimestamp();
    uint32_t HashFunction(const char* name);

    // 成员变量
    AntiDebugConfig m_config;
    bool m_initialized;
    uint64_t m_lastCheckTime;
    uint32_t m_detectionCount;
};

} // namespace CipherShell

#endif // CS_ANTI_DEBUG_H
