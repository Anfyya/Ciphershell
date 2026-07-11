/**
 * CipherShell Section 加密器
 * 加密 PE 文件中的代码段和数据段
 */

#ifndef CS_SECTION_ENCRYPTOR_H
#define CS_SECTION_ENCRYPTOR_H

#include "../pe_parser/pe_parser.h"
#include "../third_party/chacha20.h"
#include <cstdint>
#include <vector>
#include <string>

namespace CipherShell {

// ============================================================================
// 加密密钥结构
// ============================================================================

struct CS_ENCRYPTION_KEY {
    uint8_t     key[32];        // ChaCha20 密钥
    uint8_t     nonce[12];      // ChaCha20 随机数
    uint32_t    counter;        // 初始计数器
};

// ============================================================================
// Section 加密信息
// ============================================================================

struct CS_ENCRYPTED_SECTION {
    WORD        sectionIndex;       // Section 索引
    DWORD       originalRVA;        // 原始 RVA
    DWORD       originalSize;       // 原始大小
    DWORD       encryptedSize;      // 加密后大小（可能因对齐而不同）
    DWORD       originalCharacteristics; // 运行时恢复 W^X 时使用的原始节权限
    CS_ENCRYPTION_KEY sectionKey;   // 每个 section 的独立密钥
};

// ============================================================================
// 加密配置
// ============================================================================

struct CS_ENCRYPT_CONFIG {
    BOOL        encryptCodeSections;    // 加密代码段
    BOOL        encryptDataSections;    // 加密数据段
    BOOL        encryptResources;       // 加密资源段
    BOOL        removeExecutePermission;// 加密后移除执行权限
    DWORD       keyDerivationRounds;    // 密钥派生轮数
    BOOL        usePerSectionKeys;      // 每个 section 使用独立密钥
    WORD        excludeSectionsAtOrAfter;
    BOOL        excludeRelocationTargets;

    // 构造函数 - 默认值
    CS_ENCRYPT_CONFIG() :
        encryptCodeSections(TRUE),
        encryptDataSections(TRUE),
        encryptResources(FALSE),
        removeExecutePermission(TRUE),
        keyDerivationRounds(1000),
        usePerSectionKeys(TRUE),
        excludeSectionsAtOrAfter(0xFFFFu),
        excludeRelocationTargets(TRUE) {}
};

// ============================================================================
// Section 加密器类
// ============================================================================

class SectionEncryptor {
public:
    SectionEncryptor();
    ~SectionEncryptor();

    /**
     * 加密 PE 镜像中的 sections
     * @param image PE 镜像
     * @param config 加密配置
     * @param masterKey 主密钥（用于派生各 section 密钥）
     * @return 加密的 section 信息列表
     */
    std::vector<CS_ENCRYPTED_SECTION> EncryptSections(
        CS_PE_IMAGE* image,
        const CS_ENCRYPT_CONFIG& config,
        const CS_ENCRYPTION_KEY& masterKey
    );

    /**
     * 解密 PE 镜像中的 sections
     * @param image PE 镜像
     * @param encryptedSections 加密的 section 信息
     * @return 是否成功
     */
    bool DecryptSections(
        CS_PE_IMAGE* image,
        const std::vector<CS_ENCRYPTED_SECTION>& encryptedSections
    );

    /**
     * 生成随机加密密钥
     * @return 随机密钥
     */
    bool GenerateRandomKey(CS_ENCRYPTION_KEY& key);

    /**
     * 从主密钥派生 section 密钥
     * @param masterKey 主密钥
     * @param sectionIndex section 索引
     * @param sectionRVA section RVA
     * @return 派生的密钥
     */
    CS_ENCRYPTION_KEY DeriveSectionKey(
        const CS_ENCRYPTION_KEY& masterKey,
        WORD sectionIndex,
        DWORD sectionRVA
    );

    /**
     * 获取加密后的密钥数据（用于嵌入 stub）
     * @param encryptedSections 加密的 section 信息
     * @param outputSize 输出数据大小
     * @return 序列化的密钥数据
     */
    BYTE* SerializeKeys(
        const std::vector<CS_ENCRYPTED_SECTION>& encryptedSections,
        DWORD* outputSize
    );

private:
    // 加密单个 section
    bool EncryptSection(
        CS_PE_IMAGE* image,
        WORD sectionIndex,
        const CS_ENCRYPTION_KEY& key
    );

    // 解密单个 section
    bool DecryptSection(
        CS_PE_IMAGE* image,
        WORD sectionIndex,
        const CS_ENCRYPTION_KEY& key
    );

    // 密钥派生函数
    void DeriveKey(
        const CS_ENCRYPTION_KEY& masterKey,
        const uint8_t* salt,
        uint32_t saltLength,
        CS_ENCRYPTION_KEY& derivedKey,
        uint32_t rounds
    );

    // 辅助函数
    bool IsCodeSection(DWORD characteristics);
    bool IsDataSection(DWORD characteristics);
    bool ShouldEncryptSection(PIMAGE_SECTION_HEADER section, const CS_ENCRYPT_CONFIG& config);

    // 安全内存操作
    void SecureZeroMemory(void* ptr, size_t size);
};

} // namespace CipherShell

#endif // CS_SECTION_ENCRYPTOR_H
