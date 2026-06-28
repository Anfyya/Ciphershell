/**
 * CipherShell ChaCha20 加密实现
 * 精简的流密码实现，不依赖外部库
 */

#ifndef CS_CHACHA20_H
#define CS_CHACHA20_H

#include <cstdint>
#include <cstring>

namespace CipherShell {

// ============================================================================
// ChaCha20 常量
// ============================================================================

#define CHACHA20_KEY_SIZE   32
#define CHACHA20_NONCE_SIZE 12
#define CHACHA20_BLOCK_SIZE 64

// ============================================================================
// ChaCha20 上下文
// ============================================================================

struct ChaCha20Context {
    uint32_t state[16];     // 内部状态
    uint8_t  keyStream[64]; // 密钥流缓冲区
    uint32_t position;      // 当前块位置
};

// ============================================================================
// ChaCha20 类
// ============================================================================

class ChaCha20 {
public:
    ChaCha20();
    ~ChaCha20();

    /**
     * 初始化 ChaCha20 上下文
     * @param key 32字节密钥
     * @param nonce 12字节随机数
     * @param counter 初始计数器
     */
    void Init(const uint8_t* key, const uint8_t* nonce, uint32_t counter = 0);

    /**
     * 加密/解密数据（ChaCha20 是对称的）
     * @param data 输入数据
     * @param output 输出缓冲区
     * @param length 数据长度
     */
    void Process(const uint8_t* data, uint8_t* output, uint32_t length);

    /**
     * 就地加密/解密
     * @param data 数据缓冲区
     * @param length 数据长度
     */
    void ProcessInPlace(uint8_t* data, uint32_t length);

private:
    // ChaCha20 核心运算
    void QuarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d);
    void GenerateBlock();
    void XORBlock(const uint8_t* input, uint8_t* output, uint32_t length);

    // 辅助函数
    static uint32_t RotateLeft(uint32_t value, int count);
    static uint32_t Load32(const uint8_t* ptr);
    static void Store32(uint8_t* ptr, uint32_t value);

    ChaCha20Context m_ctx;
    bool m_initialized;
};

// ============================================================================
// 实现
// ============================================================================

inline ChaCha20::ChaCha20() : m_initialized(false) {
    memset(&m_ctx, 0, sizeof(m_ctx));
}

inline ChaCha20::~ChaCha20() {
    // 安全清除敏感数据
    memset(&m_ctx, 0, sizeof(m_ctx));
}

inline void ChaCha20::Init(const uint8_t* key, const uint8_t* nonce, uint32_t counter) {
    // "expand 32-byte k" 魔术常量
    m_ctx.state[0] = 0x61707865;
    m_ctx.state[1] = 0x3320646e;
    m_ctx.state[2] = 0x79622d32;
    m_ctx.state[3] = 0x6b206574;

    // 密钥 (8 个 uint32_t)
    for (int i = 0; i < 8; i++) {
        m_ctx.state[4 + i] = Load32(key + i * 4);
    }

    // 计数器
    m_ctx.state[12] = counter;

    // 随机数 (3 个 uint32_t)
    for (int i = 0; i < 3; i++) {
        m_ctx.state[13 + i] = Load32(nonce + i * 4);
    }

    m_ctx.position = 0;
    m_initialized = true;
}

inline void ChaCha20::Process(const uint8_t* data, uint8_t* output, uint32_t length) {
    if (!m_initialized || length == 0) return;

    uint32_t processed = 0;
    while (processed < length) {
        // 生成新的密钥流块
        if (m_ctx.position == 0) {
            GenerateBlock();
        }

        // 计算本块可处理的字节数
        uint32_t remaining = CHACHA20_BLOCK_SIZE - m_ctx.position;
        uint32_t toProcess = (length - processed < remaining) ? (length - processed) : remaining;

        // XOR 操作
        for (uint32_t i = 0; i < toProcess; i++) {
            output[processed + i] = data[processed + i] ^ m_ctx.keyStream[m_ctx.position + i];
        }

        processed += toProcess;
        m_ctx.position = (m_ctx.position + toProcess) % CHACHA20_BLOCK_SIZE;
    }
}

inline void ChaCha20::ProcessInPlace(uint8_t* data, uint32_t length) {
    Process(data, data, length);
}

inline void ChaCha20::QuarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b; d ^= a; d = RotateLeft(d, 16);
    c += d; b ^= c; b = RotateLeft(b, 12);
    a += b; d ^= a; d = RotateLeft(d, 8);
    c += d; b ^= c; b = RotateLeft(b, 7);
}

inline void ChaCha20::GenerateBlock() {
    // 复制初始状态
    uint32_t workingState[16];
    memcpy(workingState, m_ctx.state, sizeof(workingState));

    // 20 轮（10 次列轮 + 10 次对角轮）
    for (int i = 0; i < 10; i++) {
        // 列轮
        QuarterRound(workingState[0], workingState[4], workingState[8],  workingState[12]);
        QuarterRound(workingState[1], workingState[5], workingState[9],  workingState[13]);
        QuarterRound(workingState[2], workingState[6], workingState[10], workingState[14]);
        QuarterRound(workingState[3], workingState[7], workingState[11], workingState[15]);

        // 对角轮
        QuarterRound(workingState[0], workingState[5], workingState[10], workingState[15]);
        QuarterRound(workingState[1], workingState[6], workingState[11], workingState[12]);
        QuarterRound(workingState[2], workingState[7], workingState[8],  workingState[13]);
        QuarterRound(workingState[3], workingState[4], workingState[9],  workingState[14]);
    }

    // 加上初始状态
    for (int i = 0; i < 16; i++) {
        workingState[i] += m_ctx.state[i];
    }

    // 转换为字节流
    for (int i = 0; i < 16; i++) {
        Store32(m_ctx.keyStream + i * 4, workingState[i]);
    }

    // 递增计数器
    m_ctx.state[12]++;
}

inline void ChaCha20::XORBlock(const uint8_t* input, uint8_t* output, uint32_t length) {
    for (uint32_t i = 0; i < length; i++) {
        output[i] = input[i] ^ m_ctx.keyStream[m_ctx.position + i];
    }
}

inline uint32_t ChaCha20::RotateLeft(uint32_t value, int count) {
    return (value << count) | (value >> (32 - count));
}

inline uint32_t ChaCha20::Load32(const uint8_t* ptr) {
    return (uint32_t)ptr[0] |
           ((uint32_t)ptr[1] << 8) |
           ((uint32_t)ptr[2] << 16) |
           ((uint32_t)ptr[3] << 24);
}

inline void ChaCha20::Store32(uint8_t* ptr, uint32_t value) {
    ptr[0] = (uint8_t)(value);
    ptr[1] = (uint8_t)(value >> 8);
    ptr[2] = (uint8_t)(value >> 16);
    ptr[3] = (uint8_t)(value >> 24);
}

} // namespace CipherShell

#endif // CS_CHACHA20_H
