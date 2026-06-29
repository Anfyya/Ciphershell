/**
 * CipherShell Section 加密器 - 实现
 */

#include "section_encryptor.h"
#include <cstring>
#include <cstdlib>
#include <ctime>

// BUG6修复：使用密码学安全的随机数生成器替代 rand()
// rand() 的输出可预测（种子空间小、线性同余算法），攻击者可暴力破解密钥
#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <random>
#endif

namespace CipherShell {

// ============================================================================
// 构造/析构
// ============================================================================

SectionEncryptor::SectionEncryptor() {
    // BUG6修复：不再使用 srand/rand，密钥生成已改用 CSPRNG
}

SectionEncryptor::~SectionEncryptor() {}

// ============================================================================
// 公共接口
// ============================================================================

std::vector<CS_ENCRYPTED_SECTION> SectionEncryptor::EncryptSections(
    CS_PE_IMAGE* image,
    const CS_ENCRYPT_CONFIG& config,
    const CS_ENCRYPTION_KEY& masterKey)
{
    std::vector<CS_ENCRYPTED_SECTION> result;

    if (!image || !image->isValid) {
        return result;
    }

    // 遍历所有 sections
    for (WORD i = 0; i < image->numSections; i++) {
        PIMAGE_SECTION_HEADER section = &image->sections[i];

        // 检查是否需要加密此 section
        if (!ShouldEncryptSection(section, config)) {
            continue;
        }

        // 生成或派生密钥
        CS_ENCRYPTION_KEY sectionKey;
        if (config.usePerSectionKeys) {
            sectionKey = DeriveSectionKey(masterKey, i, section->VirtualAddress);
        } else {
            sectionKey = masterKey;
        }

        // 加密 section
        if (EncryptSection(image, i, sectionKey)) {
            CS_ENCRYPTED_SECTION encSection;
            encSection.sectionIndex = i;
            encSection.originalRVA = section->VirtualAddress;
            encSection.originalSize = section->Misc.VirtualSize;
            encSection.encryptedSize = section->SizeOfRawData;
            memcpy(&encSection.sectionKey, &sectionKey, sizeof(CS_ENCRYPTION_KEY));

            result.push_back(encSection);
        }
    }

    return result;
}

bool SectionEncryptor::DecryptSections(
    CS_PE_IMAGE* image,
    const std::vector<CS_ENCRYPTED_SECTION>& encryptedSections)
{
    if (!image || !image->isValid) {
        return false;
    }

    // 解密每个 section
    for (const auto& encSection : encryptedSections) {
        if (!DecryptSection(image, encSection.sectionIndex, encSection.sectionKey)) {
            return false;
        }
    }

    return true;
}

CS_ENCRYPTION_KEY SectionEncryptor::GenerateRandomKey() {
    CS_ENCRYPTION_KEY key;

    // BUG6修复：使用密码学安全的随机数生成器
    // rand() 种子空间仅 32 位，且输出序列可预测，不适用于密钥生成
#ifdef _WIN32
    // Windows 平台：使用 BCryptGenRandom（CNG API），提供 CSPRNG
    BCryptGenRandom(NULL, key.key, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    BCryptGenRandom(NULL, key.nonce, 12, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    BCryptGenRandom(NULL, (PUCHAR)&key.counter, sizeof(key.counter), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
#else
    // 跨平台：使用 std::random_device 获取硬件熵源
    std::random_device rd;
    // 生成随机密钥
    for (int i = 0; i < 32; i += 4) {
        uint32_t val = rd();
        int remaining = 32 - i;
        int copyLen = remaining < 4 ? remaining : 4;
        memcpy(key.key + i, &val, copyLen);
    }
    // 生成随机 nonce
    for (int i = 0; i < 12; i += 4) {
        uint32_t val = rd();
        int remaining = 12 - i;
        int copyLen = remaining < 4 ? remaining : 4;
        memcpy(key.nonce + i, &val, copyLen);
    }
    uint32_t counterVal = rd();
    key.counter = counterVal;
#endif

    return key;
}

CS_ENCRYPTION_KEY SectionEncryptor::DeriveSectionKey(
    const CS_ENCRYPTION_KEY& masterKey,
    WORD sectionIndex,
    DWORD sectionRVA)
{
    // 构造 salt：section 索引 + RVA
    uint8_t salt[8];
    salt[0] = (uint8_t)(sectionIndex);
    salt[1] = (uint8_t)(sectionIndex >> 8);
    salt[2] = (uint8_t)(sectionRVA);
    salt[3] = (uint8_t)(sectionRVA >> 8);
    salt[4] = (uint8_t)(sectionRVA >> 16);
    salt[5] = (uint8_t)(sectionRVA >> 24);
    salt[6] = 0xC5;  // CipherShell 标记
    salt[7] = 0x5E;

    CS_ENCRYPTION_KEY derivedKey;
    DeriveKey(masterKey, salt, sizeof(salt), derivedKey, 100);

    return derivedKey;
}

BYTE* SectionEncryptor::SerializeKeys(
    const std::vector<CS_ENCRYPTED_SECTION>& encryptedSections,
    DWORD* outputSize)
{
    if (!outputSize || encryptedSections.empty()) {
        return nullptr;
    }

    // 计算输出大小
    // 格式：[section_count:4][section_info:N*56]
    DWORD totalSize = 4 + (DWORD)encryptedSections.size() * (4 + 4 + 4 + 32 + 12 + 4);

    BYTE* output = new(std::nothrow) BYTE[totalSize];
    if (!output) {
        return nullptr;
    }

    DWORD offset = 0;

    // 写入 section 数量
    *(DWORD*)(output + offset) = (DWORD)encryptedSections.size();
    offset += 4;

    // 写入每个 section 的信息
    for (const auto& encSection : encryptedSections) {
        *(DWORD*)(output + offset) = encSection.sectionIndex;
        offset += 4;

        *(DWORD*)(output + offset) = encSection.originalRVA;
        offset += 4;

        *(DWORD*)(output + offset) = encSection.originalSize;
        offset += 4;

        memcpy(output + offset, encSection.sectionKey.key, 32);
        offset += 32;

        memcpy(output + offset, encSection.sectionKey.nonce, 12);
        offset += 12;

        *(DWORD*)(output + offset) = encSection.sectionKey.counter;
        offset += 4;
    }

    *outputSize = totalSize;
    return output;
}

// ============================================================================
// 内部实现
// ============================================================================

bool SectionEncryptor::EncryptSection(
    CS_PE_IMAGE* image,
    WORD sectionIndex,
    const CS_ENCRYPTION_KEY& key)
{
    if (sectionIndex >= image->numSections) {
        return false;
    }

    PIMAGE_SECTION_HEADER section = &image->sections[sectionIndex];

    // 检查 section 是否有数据
    if (section->SizeOfRawData == 0 || section->PointerToRawData == 0) {
        return false;
    }

    // 检查边界
    if (section->PointerToRawData + section->SizeOfRawData > image->rawSize) {
        return false;
    }

    // XOR with key[0] (single byte, matching stub implementation)
    BYTE* sectionData = image->rawData + section->PointerToRawData;
    for (DWORD i = 0; i < section->SizeOfRawData; i++) {
        sectionData[i] ^= key.key[0];
    }

    // 给 section 加写权限，stub 需要写回解密后的数据
    section->Characteristics |= IMAGE_SCN_MEM_WRITE;
    // section->Characteristics &= ~IMAGE_SCN_MEM_EXECUTE;

    return true;
}

bool SectionEncryptor::DecryptSection(
    CS_PE_IMAGE* image,
    WORD sectionIndex,
    const CS_ENCRYPTION_KEY& key)
{
    if (sectionIndex >= image->numSections) {
        return false;
    }

    PIMAGE_SECTION_HEADER section = &image->sections[sectionIndex];

    // 检查 section 是否有数据
    if (section->SizeOfRawData == 0 || section->PointerToRawData == 0) {
        return false;
    }

    // 检查边界
    if (section->PointerToRawData + section->SizeOfRawData > image->rawSize) {
        return false;
    }

    // BUG5修复：解密必须与加密使用相同算法
    // EncryptSection 使用 XOR key[0] 加密，XOR 是对称操作（加密 = 解密）
    // 之前错误地使用 ChaCha20 解密，导致解密后数据损坏
    // stub 中同样使用 XOR 解密，这里保持一致
    BYTE* sectionData = image->rawData + section->PointerToRawData;
    for (DWORD i = 0; i < section->SizeOfRawData; i++) {
        sectionData[i] ^= key.key[0];
    }

    // 恢复执行权限
    section->Characteristics |= IMAGE_SCN_MEM_EXECUTE;

    return true;
}

void SectionEncryptor::DeriveKey(
    const CS_ENCRYPTION_KEY& masterKey,
    const uint8_t* salt,
    uint32_t saltLength,
    CS_ENCRYPTION_KEY& derivedKey,
    uint32_t rounds)
{
    // 简化的密钥派生：使用 ChaCha20 迭代
    // 实际应用中应使用更安全的 KDF 如 HKDF 或 PBKDF2

    uint8_t currentKey[32];
    memcpy(currentKey, masterKey.key, 32);

    for (uint32_t round = 0; round < rounds; round++) {
        ChaCha20 cipher;
        cipher.Init(currentKey, salt, round);

        // 生成新的密钥材料
        uint8_t newKeyMaterial[32];
        memset(newKeyMaterial, 0, 32);
        cipher.Process(newKeyMaterial, newKeyMaterial, 32);

        // 与当前密钥混合
        for (int i = 0; i < 32; i++) {
            currentKey[i] ^= newKeyMaterial[i];
        }
    }

    // 设置派生密钥
    memcpy(derivedKey.key, currentKey, 32);

    // 从密钥派生 nonce
    ChaCha20 nonceCipher;
    uint8_t nonceSalt[12] = {0x4E, 0x4F, 0x4E, 0x43, 0x45, 0x5F,  // "NONCE_"
                             0x53, 0x41, 0x4C, 0x54, 0x5F, 0x58}; // "SALT_X"
    nonceCipher.Init(currentKey, nonceSalt, 0);
    uint8_t nonceOutput[12] = {0};
    nonceCipher.Process(nonceOutput, nonceOutput, 12);
    memcpy(derivedKey.nonce, nonceOutput, 12);

    derivedKey.counter = 0;

    // 清除临时数据
    SecureZeroMemory(currentKey, sizeof(currentKey));
}

bool SectionEncryptor::IsCodeSection(DWORD characteristics) {
    return (characteristics & IMAGE_SCN_CNT_CODE) != 0 ||
           (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
}

bool SectionEncryptor::IsDataSection(DWORD characteristics) {
    return (characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) != 0 ||
           (characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0;
}

bool SectionEncryptor::ShouldEncryptSection(PIMAGE_SECTION_HEADER section, const CS_ENCRYPT_CONFIG& config) {
    // 跳过空 section
    if (section->SizeOfRawData == 0) {
        return false;
    }

    // 跳过头部 section（通常是 .rsrc, .reloc 等）
    char name[9] = {0};
    memcpy(name, section->Name, 8);

    // 保留资源段（如果配置要求）
    if (strncmp(name, ".rsrc", 5) == 0 && !config.encryptResources) {
        return false;
    }

    // 保留重定位段
    if (strncmp(name, ".reloc", 6) == 0) {
        return false;
    }

    // 根据配置决定是否加密
    if (config.encryptCodeSections && IsCodeSection(section->Characteristics)) {
        return true;
    }

    if (config.encryptDataSections && IsDataSection(section->Characteristics)) {
        return true;
    }

    return false;
}

void SectionEncryptor::SecureZeroMemory(void* ptr, size_t size) {
    volatile uint8_t* p = (volatile uint8_t*)ptr;
    for (size_t i = 0; i < size; i++) {
        p[i] = 0;
    }
}

} // namespace CipherShell
