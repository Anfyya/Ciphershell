/**
 * CipherShell 字符串加密器
 * 扫描并加密 PE 中的字符串引用
 */

#ifndef CS_STRING_ENCRYPTOR_H
#define CS_STRING_ENCRYPTOR_H

#include "../pe_parser/pe_parser.h"
#include "../third_party/chacha20.h"
#include <cstdint>
#include <vector>
#include <string>

namespace CipherShell {

// ============================================================================
// 字符串信息
// ============================================================================

struct CS_STRING_ENTRY {
    DWORD       rva;            // 字符串 RVA
    DWORD       offset;         // 文件偏移
    DWORD       length;         // 字符串长度（含 null）
    DWORD       encryptedSize;  // 加密后大小
    uint8_t     key[32];        // 每个字符串的独立密钥
    uint8_t     nonce[12];      // 随机数
    std::string original;       // 原始字符串（用于调试）
    bool        isWideChar;     // 是否宽字符
};

// ============================================================================
// 字符串引用（引用字符串的代码位置）
// ============================================================================

struct CS_STRING_REF {
    DWORD       codeRVA;        // 引用代码的 RVA
    DWORD       codeOffset;     // 引用代码的文件偏移
    DWORD       stringRVA;      // 被引用的字符串 RVA
    DWORD       instrLength;    // 指令长度
    bool        isDirectPush;   // 是否 push offset 模式
};

// ============================================================================
// 加密配置
// ============================================================================

struct CS_STRING_CONFIG {
    DWORD       minLength;          // 最小字符串长度
    DWORD       maxLength;          // 最大字符串长度
    bool        encryptWideStrings; // 加宽字符字符串
    bool        encryptAnsiStrings; // 加密 ANSI 字符串
    bool        insertDecryptionStub; // 是否插入解密桩

    CS_STRING_CONFIG() :
        minLength(4),
        maxLength(4096),
        encryptWideStrings(true),
        encryptAnsiStrings(true),
        insertDecryptionStub(true) {}
};

// ============================================================================
// 字符串加密器类
// ============================================================================

class StringEncryptor {
public:
    StringEncryptor();
    ~StringEncryptor();

    /**
     * 扫描 PE 中的字符串
     * @param image PE 镜像
     * @param config 扫描配置
     * @return 发现的字符串列表
     */
    std::vector<CS_STRING_ENTRY> ScanStrings(
        CS_PE_IMAGE* image,
        const CS_STRING_CONFIG& config
    );

    /**
     * 查找字符串引用
     * @param image PE 镜像
     * @param strings 字符串列表
     * @return 引用列表
     */
    std::vector<CS_STRING_REF> FindStringReferences(
        CS_PE_IMAGE* image,
        const std::vector<CS_STRING_ENTRY>& strings
    );

    /**
     * 加密字符串
     * @param image PE 镜像
     * @param strings 字符串列表
     * @return 是否成功
     */
    bool EncryptStrings(
        CS_PE_IMAGE* image,
        std::vector<CS_STRING_ENTRY>& strings
    );

    /**
     * 生成运行时解密函数
     * @param is64Bit 是否 64 位
     * @param funcSize 输出函数大小
     * @return 解密函数代码
     */
    BYTE* GenerateDecryptFunction(bool is64Bit, DWORD* funcSize);

private:
    // 字符串检测
    bool IsPrintableString(const BYTE* data, DWORD length, bool& isWide);
    bool IsLikelyString(const BYTE* data, DWORD length);

    // 引用查找
    bool IsStringReference(CS_PE_IMAGE* image, DWORD codeOffset, DWORD& stringRVA);

    // 加密实现
    void EncryptSingleString(CS_STRING_ENTRY& entry, const uint8_t* data, DWORD length);
    DWORD AlignValue(DWORD value, DWORD alignment);

    // 随机数
    void GenerateRandomBytes(uint8_t* buffer, DWORD length);
};

} // namespace CipherShell

#endif // CS_STRING_ENCRYPTOR_H
