/**
 * CipherShell 隐式响应机制
 * 检测到调试时不直接退出，而是悄悄破坏程序状态
 */

#ifndef CS_IMPLICIT_RESPONSE_H
#define CS_IMPLICIT_RESPONSE_H

#include <cstdint>
#include <windows.h>

namespace CipherShell {

// ============================================================================
// 响应类型
// ============================================================================

enum class ResponseType : uint32_t {
    None                = 0,        // 无响应
    KeyPoison           = 1,        // 密钥投毒
    DataCorruption      = 2,        // 数据损坏
    LogicDivergence     = 3,        // 逻辑分叉
    DelayedCrash        = 4,        // 延迟崩溃
    SilentFail          = 5,        // 静默失败
    WrongResult         = 6,        // 返回错误结果
};

// ============================================================================
// 响应配置
// ============================================================================

struct ResponseConfig {
    ResponseType    primaryResponse;        // 主要响应类型
    ResponseType    fallbackResponse;       // 备用响应类型
    uint32_t        minDelay;               // 最小延迟（指令数）
    uint32_t        maxDelay;               // 最大延迟（指令数）
    bool            cascadeOnReDetect;      // 重复检测时级联响应
    uint32_t        cascadeMultiplier;      // 级联倍数

    ResponseConfig() :
        primaryResponse(ResponseType::KeyPoison),
        fallbackResponse(ResponseType::DelayedCrash),
        minDelay(100),
        maxDelay(1000),
        cascadeOnReDetect(true),
        cascadeMultiplier(2) {}
};

// ============================================================================
// 响应上下文
// ============================================================================

struct ResponseContext {
    bool            triggered;              // 是否已触发
    uint32_t        triggerCount;           // 触发次数
    uint32_t        currentDelay;           // 当前延迟
    uint32_t        poisonKey[8];           // 投毒密钥
    uint64_t        triggerTimestamp;       // 触发时间戳
    ResponseType    activeResponse;         // 当前激活的响应类型
};

// ============================================================================
// 隐式响应类
// ============================================================================

class ImplicitResponse {
public:
    ImplicitResponse();
    ~ImplicitResponse();

    /**
     * 初始化响应系统
     * @param config 响应配置
     * @return 是否成功
     */
    bool Initialize(const ResponseConfig& config);

    /**
     * 触发响应
     * @param context 响应上下文
     * @param detectionMethod 检测方法
     */
    void TriggerResponse(ResponseContext& context, uint32_t detectionMethod);

    /**
     * 应用密钥投毒
     * @param context 响应上下文
     * @param key 要投毒的密钥
     * @param keySize 密钥大小
     */
    void ApplyKeyPoison(ResponseContext& context, void* key, uint32_t keySize);

    /**
     * 应用数据损坏
     * @param context 响应上下文
     * @param data 要损坏的数据
     * @param dataSize 数据大小
     */
    void ApplyDataCorruption(ResponseContext& context, void* data, uint32_t dataSize);

    /**
     * 应用逻辑分叉
     * @param context 响应上下文
     * @param condition 原始条件
     * @return 修改后的条件
     */
    bool ApplyLogicDivergence(ResponseContext& context, bool condition);

    /**
     * 应用错误结果
     * @param context 响应上下文
     * @param originalResult 原始结果
     * @return 修改后的结果
     */
    uint64_t ApplyWrongResult(ResponseContext& context, uint64_t originalResult);

    /**
     * 检查延迟是否到期
     * @param context 响应上下文
     * @return 是否到期
     */
    bool IsDelayExpired(ResponseContext& context);

    /**
     * 获取当前投毒值
     * @param context 响应上下文
     * @return 投毒值
     */
    uint32_t GetPoisonValue(ResponseContext& context);

private:
    // 响应实现
    void GeneratePoisonKey(ResponseContext& context, uint32_t seed);
    uint32_t CalculatePoisonDelta(uint32_t triggerCount);
    uint32_t GenerateRandomDelay();

    // 辅助函数
    uint32_t HashMix(uint32_t a, uint32_t b);
    void SecureZeroMemory(void* ptr, size_t size);

    // 成员变量
    ResponseConfig m_config;
    bool m_initialized;
    uint32_t m_globalSeed;
};

} // namespace CipherShell

#endif // CS_IMPLICIT_RESPONSE_H
