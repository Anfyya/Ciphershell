/**
 * CipherShell 隐式响应机制 - 实现
 */

#include "implicit_response.h"
#include <intrin.h>
#include <cstring>
#include <cstdlib>

namespace CipherShell {

// ============================================================================
// 构造/析构
// ============================================================================

ImplicitResponse::ImplicitResponse() 
    : m_initialized(false)
    , m_globalSeed(0x12345678)
{
    memset(&m_config, 0, sizeof(m_config));
}

ImplicitResponse::~ImplicitResponse() {}

// ============================================================================
// 公共接口
// ============================================================================

bool ImplicitResponse::Initialize(const ResponseConfig& config) {
    m_config = config;
    m_globalSeed = (uint32_t)__rdtsc();
    m_initialized = true;
    return true;
}

void ImplicitResponse::TriggerResponse(ResponseContext& context, uint32_t detectionMethod) {
    if (!m_initialized) return;

    context.triggered = true;
    context.triggerCount++;
    context.triggerTimestamp = __rdtsc();
    context.activeResponse = m_config.primaryResponse;

    // 计算延迟
    if (m_config.cascadeOnReDetect && context.triggerCount > 1) {
        // 级联：每次检测延迟减少
        context.currentDelay = GenerateRandomDelay() / 
            (context.triggerCount * m_config.cascadeMultiplier);
    } else {
        context.currentDelay = GenerateRandomDelay();
    }

    // 生成投毒密钥
    GeneratePoisonKey(context, detectionMethod);
}

void ImplicitResponse::ApplyKeyPoison(ResponseContext& context, void* key, uint32_t keySize) {
    if (!context.triggered || !key) return;

    uint8_t* keyBytes = (uint8_t*)key;
    uint32_t poisonDelta = CalculatePoisonDelta(context.triggerCount);

    // 用投毒密钥修改原始密钥
    for (uint32_t i = 0; i < keySize; i++) {
        uint8_t poisonByte = ((uint8_t*)context.poisonKey)[i % 32];
        keyBytes[i] ^= poisonByte;
    }

    // 额外的混淆
    keyBytes[0] ^= (uint8_t)(poisonDelta);
    keyBytes[keySize - 1] ^= (uint8_t)(poisonDelta >> 8);
}

void ImplicitResponse::ApplyDataCorruption(ResponseContext& context, void* data, uint32_t dataSize) {
    if (!context.triggered || !data) return;

    uint8_t* dataBytes = (uint8_t*)data;
    uint32_t poisonDelta = CalculatePoisonDelta(context.triggerCount);

    // 随机损坏几个字节
    uint32_t corruptCount = 1 + (context.triggerCount % 4);
    for (uint32_t i = 0; i < corruptCount; i++) {
        uint32_t index = (poisonDelta + i * 7) % dataSize;
        dataBytes[index] ^= 0xFF;
    }
}

bool ImplicitResponse::ApplyLogicDivergence(ResponseContext& context, bool condition) {
    if (!context.triggered) return condition;

    // 根据触发次数决定是否翻转条件
    if (context.triggerCount % 2 == 1) {
        return !condition;
    }
    return condition;
}

uint64_t ImplicitResponse::ApplyWrongResult(ResponseContext& context, uint64_t originalResult) {
    if (!context.triggered) return originalResult;

    // 返回一个接近但错误的结果
    uint32_t poisonDelta = CalculatePoisonDelta(context.triggerCount);
    return originalResult + poisonDelta;
}

bool ImplicitResponse::IsDelayExpired(ResponseContext& context) {
    if (!context.triggered) return true;

    uint64_t currentTimestamp = __rdtsc();
    uint64_t elapsed = currentTimestamp - context.triggerTimestamp;

    // 简化：假设每条指令约 1-5 个周期
    return (elapsed / 3) >= context.currentDelay;
}

uint32_t ImplicitResponse::GetPoisonValue(ResponseContext& context) {
    if (!context.triggered) return 0;

    return context.poisonKey[0];
}

// ============================================================================
// 内部实现
// ============================================================================

void ImplicitResponse::GeneratePoisonKey(ResponseContext& context, uint32_t seed) {
    // 使用检测方法和全局种子生成投毒密钥
    uint32_t mix = HashMix(seed, m_globalSeed);

    for (int i = 0; i < 8; i++) {
        mix = HashMix(mix, seed + i);
        context.poisonKey[i] = mix;
    }
}

uint32_t ImplicitResponse::CalculatePoisonDelta(uint32_t triggerCount) {
    // 根据触发次数计算投毒增量
    // 触发次数越多，投毒越严重
    uint32_t base = 0x12345678;
    for (uint32_t i = 0; i < triggerCount; i++) {
        base = HashMix(base, 0xDEADBEEF);
    }
    return base;
}

uint32_t ImplicitResponse::GenerateRandomDelay() {
    if (m_config.minDelay >= m_config.maxDelay) {
        return m_config.minDelay;
    }

    uint32_t range = m_config.maxDelay - m_config.minDelay;
    return m_config.minDelay + ((__rdtsc() ^ m_globalSeed) % range);
}

uint32_t ImplicitResponse::HashMix(uint32_t a, uint32_t b) {
    // MurmurHash3 混合函数
    uint32_t h = a;
    h ^= b;
    h ^= h >> 16;
    h *= 0x85EBCA6B;
    h ^= h >> 13;
    h *= 0xC2B2AE35;
    h ^= h >> 16;
    return h;
}

void ImplicitResponse::SecureZeroMemory(void* ptr, size_t size) {
    volatile uint8_t* p = (volatile uint8_t*)ptr;
    for (size_t i = 0; i < size; i++) {
        p[i] = 0;
    }
}

} // namespace CipherShell
