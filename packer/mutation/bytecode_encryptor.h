/**
 * CipherShell Bytecode 加密器
 * 滚动密钥流 + 密文反馈
 */

#ifndef CS_BYTECODE_ENCRYPTOR_H
#define CS_BYTECODE_ENCRYPTOR_H

#include <cstdint>
#include <cstdlib>
#include <cstddef>
#include <cstring>
#include <vector>

namespace CipherShell {

// ============================================================================
// 加密模式
// ============================================================================

enum class BytecodeEncryptionMode {
    None,           // 不加密
    XOR,            // 简单 XOR
    Rolling,        // 滚动密钥
    ChaCha20,       // ChaCha20 流密码
    AES_CTR         // AES-CTR 模式
};

// ============================================================================
// 加密配置
// ============================================================================

struct BytecodeEncryptConfig {
    BytecodeEncryptionMode  mode;
    uint8_t                 key[32];
    uint8_t                 nonce[12];
    uint32_t                initialCounter;
    bool                    enableIntegrityCheck;   // 启用完整性校验
    bool                    enableAntiPatch;         // 启用防 patch 机制

    BytecodeEncryptConfig() :
        mode(BytecodeEncryptionMode::Rolling),
        initialCounter(0),
        enableIntegrityCheck(true),
        enableAntiPatch(true)
    {
        // 随机初始化密钥
        for (int i = 0; i < 32; i++) key[i] = (uint8_t)(rand() % 256);
        for (int i = 0; i < 12; i++) nonce[i] = (uint8_t)(rand() % 256);
    }
};

// ============================================================================
// Bytecode 加密器类
// ============================================================================

class BytecodeEncryptor {
public:
    BytecodeEncryptor();
    ~BytecodeEncryptor();

    /**
     * 加密字节码
     * @param bytecode 原始字节码
     * @param config 加密配置
     * @return 加密后的字节码
     */
    std::vector<uint8_t> Encrypt(
        const std::vector<uint8_t>& bytecode,
        const BytecodeEncryptConfig& config
    );

    /**
     * 解密字节码（用于验证）
     * @param encrypted 加密后的字节码
     * @param config 加密配置
     * @return 解密后的字节码
     */
    std::vector<uint8_t> Decrypt(
        const std::vector<uint8_t>& encrypted,
        const BytecodeEncryptConfig& config
    );

    /**
     * 计算字节码完整性校验和
     * @param bytecode 字节码
     * @return 校验和
     */
    uint32_t CalculateChecksum(const std::vector<uint8_t>& bytecode);

    /**
     * 生成解密 stub 代码（嵌入到输出 PE 中）
     * @param config 加密配置
     * @param is64Bit 是否 64 位
     * @param stubSize 输出大小
     * @return 解密 stub 代码
     */
    uint8_t* GenerateDecryptStub(
        const BytecodeEncryptConfig& config,
        bool is64Bit,
        uint32_t* stubSize
    );

private:
    // 加密模式实现
    void EncryptXOR(std::vector<uint8_t>& data, const uint8_t* key);
    void EncryptRolling(std::vector<uint8_t>& data, const uint8_t* key);
    void DecryptRolling(std::vector<uint8_t>& data, const uint8_t* key);

    // 辅助函数
    uint32_t CRC32(const uint8_t* data, size_t length);
    void GenerateIntegrityTag(std::vector<uint8_t>& bytecode, const uint8_t* key);
    bool VerifyIntegrityTag(const std::vector<uint8_t>& bytecode, const uint8_t* key);
};

} // namespace CipherShell

#endif // CS_BYTECODE_ENCRYPTOR_H
