/**
 * CipherShell 高级字符串加密
 * 支持延迟解密、内存保护、一次性解密等高级特性
 */

#ifndef CS_STRING_ENCRYPTOR_ADVANCED_H
#define CS_STRING_ENCRYPTOR_ADVANCED_H

#include "string_encryptor.h"
#include <unordered_map>

namespace CipherShell {

// ============================================================================
// 字符串加密模式
// ============================================================================

enum class StringEncryptionMode : uint32_t {
    Simple          = 0,    // 简单 XOR 加密
    ChaCha20        = 1,    // ChaCha20 流密码
    Rolling         = 2,    // 滚动密钥
    OneTimeDecrypt  = 3,    // 一次性解密（解密后立即擦除）
    LazyDecrypt     = 4,    // 延迟解密（首次访问时解密）
};

// ============================================================================
// 字符串存储结构
// ============================================================================

struct EncryptedStringStorage {
    DWORD       id;                 // 字符串 ID
    DWORD       rva;                // 原始 RVA
    BYTE*       encryptedData;      // 加密后的数据
    DWORD       encryptedSize;      // 加密后大小
    DWORD       originalSize;       // 原始大小
    uint8_t     key[32];            // 解密密钥
    uint8_t     nonce[12];          // 随机数
    bool        decrypted;          // 是否已解密
    bool        erased;             // 是否已擦除
    void*       decryptedBuffer;    // 解密后的缓冲区
};

// ============================================================================
// 高级字符串加密配置
// ============================================================================

struct AdvancedStringConfig : CS_STRING_CONFIG {
    StringEncryptionMode    mode;               // 加密模式
    bool                    antiDump;           // 反 dump 保护
    bool                    eraseAfterUse;      // 使用后擦除
    bool                    randomizeLayout;    // 随机化布局
    DWORD                   maxStringLength;    // 最大字符串长度
    bool                    encryptWideStrings; // 加密宽字符
    bool                    detectStringRefs;   // 自动检测引用

    AdvancedStringConfig() :
        CS_STRING_CONFIG(),
        mode(StringEncryptionMode::ChaCha20),
        antiDump(true),
        eraseAfterUse(false),
        randomizeLayout(true),
        maxStringLength(4096),
        encryptWideStrings(true),
        detectStringRefs(true) {}
};

// ============================================================================
// 高级字符串加密器类
// ============================================================================

class StringEncryptorAdvanced : public StringEncryptor {
public:
    StringEncryptorAdvanced();
    ~StringEncryptorAdvanced();

    /**
     * 使用高级模式加密字符串
     * @param image PE 镜像
     * @param config 高级配置
     * @return 加密的字符串存储列表
     */
    std::vector<EncryptedStringStorage> EncryptAdvanced(
        CS_PE_IMAGE* image,
        const AdvancedStringConfig& config
    );

    /**
     * 生成运行时解密 stub
     * @param storage 字符串存储
     * @param is64Bit 是否 64 位
     * @param stubSize 输出大小
     * @return stub 代码
     */
    BYTE* GenerateDecryptStub(
        const EncryptedStringStorage& storage,
        bool is64Bit,
        DWORD* stubSize
    );

    /**
     * 生成全局字符串管理器
     * @param strings 所有加密的字符串
     * @param is64Bit 是否 64 位
     * @param managerSize 输出大小
     * @return 管理器代码
     */
    BYTE* GenerateStringManager(
        const std::vector<EncryptedStringStorage>& strings,
        bool is64Bit,
        DWORD* managerSize
    );

    /**
     * 解密单个字符串（运行时调用）
     * @param storage 字符串存储
     * @return 解密后的字符串指针
     */
    void* DecryptString(EncryptedStringStorage& storage);

    /**
     * 擦除已解密的字符串
     * @param storage 字符串存储
     */
    void EraseString(EncryptedStringStorage& storage);

private:
    // 加密模式实现
    bool EncryptSimple(BYTE* data, DWORD size, const uint8_t* key);
    bool EncryptChaCha20(BYTE* data, DWORD size, const uint8_t* key, const uint8_t* nonce);
    bool EncryptRolling(BYTE* data, DWORD size, const uint8_t* key);

    // 解密模式实现
    bool DecryptSimple(BYTE* data, DWORD size, const uint8_t* key);
    bool DecryptChaCha20(BYTE* data, DWORD size, const uint8_t* key, const uint8_t* nonce);
    bool DecryptRolling(BYTE* data, DWORD size, const uint8_t* key);

    // 引用修补
    bool PatchStringReferences(
        CS_PE_IMAGE* image,
        const std::vector<EncryptedStringStorage>& strings
    );

    // 辅助函数
    DWORD GenerateStringId();
    void GenerateKey(uint8_t* key, DWORD size);

    // 成员变量
    std::unordered_map<DWORD, EncryptedStringStorage> m_storageMap;
    DWORD m_nextStringId;
};

} // namespace CipherShell

#endif // CS_STRING_ENCRYPTOR_ADVANCED_H
