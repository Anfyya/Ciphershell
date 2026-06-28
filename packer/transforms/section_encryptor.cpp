/**
 * CipherShell Section 加密器 - 实现
 */

#include "section_encryptor.h"
#include <cstring>
#include <cstdlib>
#include <ctime>

namespace CipherShell {

// ============================================================================
// 构造/析构
// ============================================================================

SectionEncryptor::SectionEncryptor() {
    srand((unsigned int)time(nullptr));
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

    // 生成随机密钥
    for (int i = 0; i < 32; i++) {
        key.key[i] = (uint8_t)(rand() % 256);
    }

    // 生成随机 nonce
    for (int i = 0; i < 12; i++) {
        key.nonce[i] = (uint8_t)(rand() % 256);
    }

    key.counter = (uint32_t)rand();

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

    // 初始化 ChaCha20
    ChaCha20 cipher;
    cipher.Init(key.key, key.nonce, key.counter);

    // 加密 section 数据
    BYTE* sectionData = image->rawData + section->PointerToRawData;
    cipher.ProcessInPlace(sectionData, section->SizeOfRawData);

    // 如果配置要求，移除执行权限
    section->Characteristics &= ~IMAGE_SCN_MEM_EXECUTE;

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

    // 初始化 ChaCha20
    ChaCha20 cipher;
    cipher.Init(key.key, key.nonce, key.counter);

    // 解密 section 数据
    BYTE* sectionData = image->rawData + section->PointerToRawData;
    cipher.ProcessInPlace(sectionData, section->SizeOfRawData);

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
