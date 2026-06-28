/**
 * CipherShell Bytecode 加密器 - 实现
 */

#include "bytecode_encryptor.h"
#include <cstring>
#include <cstdlib>
#include <ctime>

namespace CipherShell {

// ============================================================================
// CRC32 表
// ============================================================================

static uint32_t crc32_table[256];
static bool crc32_table_initialized = false;

static void init_crc32_table() {
    if (crc32_table_initialized) return;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
        crc32_table[i] = crc;
    }
    crc32_table_initialized = true;
}

// ============================================================================
// 构造/析构
// ============================================================================

BytecodeEncryptor::BytecodeEncryptor() {
    srand((unsigned int)time(nullptr));
    init_crc32_table();
}

BytecodeEncryptor::~BytecodeEncryptor() {}

// ============================================================================
// 公共接口
// ============================================================================

std::vector<uint8_t> BytecodeEncryptor::Encrypt(
    const std::vector<uint8_t>& bytecode,
    const BytecodeEncryptConfig& config)
{
    std::vector<uint8_t> result = bytecode;

    if (result.empty()) return result;

    switch (config.mode) {
        case BytecodeEncryptionMode::None:
            break;
        case BytecodeEncryptionMode::XOR:
            EncryptXOR(result, config.key);
            break;
        case BytecodeEncryptionMode::Rolling:
            EncryptRolling(result, config.key);
            break;
        case BytecodeEncryptionMode::ChaCha20:
        case BytecodeEncryptionMode::AES_CTR:
            // 简化：使用滚动密钥替代
            EncryptRolling(result, config.key);
            break;
    }

    // 添加完整性标签
    if (config.enableIntegrityCheck) {
        GenerateIntegrityTag(result, config.key);
    }

    return result;
}

std::vector<uint8_t> BytecodeEncryptor::Decrypt(
    const std::vector<uint8_t>& encrypted,
    const BytecodeEncryptConfig& config)
{
    std::vector<uint8_t> result = encrypted;

    if (result.empty()) return result;

    // 验证完整性标签
    if (config.enableIntegrityCheck) {
        if (!VerifyIntegrityTag(result, config.key)) {
            // 完整性校验失败，字节码被篡改
            return std::vector<uint8_t>();
        }
        // 移除标签
        result.resize(result.size() - 4);
    }

    switch (config.mode) {
        case BytecodeEncryptionMode::None:
            break;
        case BytecodeEncryptionMode::XOR:
            EncryptXOR(result, config.key);  // XOR 是对称的
            break;
        case BytecodeEncryptionMode::Rolling:
            DecryptRolling(result, config.key);
            break;
        case BytecodeEncryptionMode::ChaCha20:
        case BytecodeEncryptionMode::AES_CTR:
            DecryptRolling(result, config.key);
            break;
    }

    return result;
}

uint32_t BytecodeEncryptor::CalculateChecksum(const std::vector<uint8_t>& bytecode) {
    return CRC32(bytecode.data(), bytecode.size());
}

uint8_t* BytecodeEncryptor::GenerateDecryptStub(
    const BytecodeEncryptConfig& config,
    bool is64Bit,
    uint32_t* stubSize)
{
    if (!stubSize) return nullptr;

    // 生成解密 stub 的 shellcode
    // 这段代码会在运行时解密字节码

    // 简化的 stub（使用 XOR 解密）
    if (is64Bit) {
        static const uint8_t x64_stub[] = {
            // rcx = data pointer, rdx = data size, r8 = key pointer
            0x48, 0x85, 0xD2,                   // test rdx, rdx
            0x74, 0x15,                         // jz .done
            0x48, 0x31, 0xDB,                   // xor rbx, rbx
            // .loop:
            0x41, 0x8A, 0x04, 0x18,             // mov al, [r8+rbx]
            0x30, 0x01,                         // xor [rcx], al
            0x48, 0xFF, 0xC1,                   // inc rcx
            0x48, 0xFF, 0xC3,                   // inc rbx
            0x48, 0x83, 0xE3, 0x1F,             // and rbx, 31
            0x48, 0xFF, 0xCA,                   // dec rdx
            0x75, 0xE8,                         // jnz .loop
            // .done:
            0xC3                                // ret
        };

        *stubSize = sizeof(x64_stub);
        uint8_t* output = new uint8_t[sizeof(x64_stub)];
        memcpy(output, x64_stub, sizeof(x64_stub));
        return output;
    } else {
        static const uint8_t x86_stub[] = {
            // [esp+4] = data, [esp+8] = size, [esp+12] = key
            0x55,                               // push ebp
            0x89, 0xE5,                         // mov ebp, esp
            0x53,                               // push ebx
            0x56,                               // push esi
            0x8B, 0x75, 0x08,                   // mov esi, [ebp+8]
            0x8B, 0x4D, 0x0C,                   // mov ecx, [ebp+12]
            0x8B, 0x5D, 0x10,                   // mov ebx, [ebp+16]
            0x85, 0xC9,                         // test ecx, ecx
            0x74, 0x0C,                         // jz .done
            0x31, 0xD2,                         // xor edx, edx
            // .loop:
            0x8A, 0x04, 0x13,                   // mov al, [ebx+edx]
            0x30, 0x06,                         // xor [esi], al
            0x46,                               // inc esi
            0x42,                               // inc edx
            0x83, 0xE2, 0x1F,                   // and edx, 31
            0x49,                               // dec ecx
            0x75, 0xF4,                         // jnz .loop
            // .done:
            0x5E,                               // pop esi
            0x5B,                               // pop ebx
            0x5D,                               // pop ebp
            0xC3                                // ret
        };

        *stubSize = sizeof(x86_stub);
        uint8_t* output = new uint8_t[sizeof(x86_stub)];
        memcpy(output, x86_stub, sizeof(x86_stub));
        return output;
    }
}

// ============================================================================
// 内部实现
// ============================================================================

void BytecodeEncryptor::EncryptXOR(std::vector<uint8_t>& data, const uint8_t* key) {
    for (size_t i = 0; i < data.size(); i++) {
        data[i] ^= key[i % 32];
    }
}

void BytecodeEncryptor::EncryptRolling(std::vector<uint8_t>& data, const uint8_t* key) {
    // 初始化滚动密钥
    uint32_t rollingKey = 0;
    for (int i = 0; i < 4; i++) {
        rollingKey |= ((uint32_t)key[i]) << (i * 8);
    }

    for (size_t i = 0; i < data.size(); i++) {
        uint8_t keyByte = (uint8_t)(rollingKey & 0xFF);
        uint8_t encrypted = data[i] ^ keyByte;
        data[i] = encrypted;

        // 更新滚动密钥：循环右移 8 位 + 与密文混合
        rollingKey = (rollingKey >> 8) | (rollingKey << 24);
        rollingKey ^= (uint32_t)encrypted;
    }
}

void BytecodeEncryptor::DecryptRolling(std::vector<uint8_t>& data, const uint8_t* key) {
    // 初始化滚动密钥
    uint32_t rollingKey = 0;
    for (int i = 0; i < 4; i++) {
        rollingKey |= ((uint32_t)key[i]) << (i * 8);
    }

    for (size_t i = 0; i < data.size(); i++) {
        uint8_t keyByte = (uint8_t)(rollingKey & 0xFF);
        uint8_t encrypted = data[i];
        data[i] = encrypted ^ keyByte;

        // 更新滚动密钥：与密文混合（加密时用的是密文）
        rollingKey = (rollingKey >> 8) | (rollingKey << 24);
        rollingKey ^= (uint32_t)encrypted;
    }
}

uint32_t BytecodeEncryptor::CRC32(const uint8_t* data, size_t length) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < length; i++) {
        crc = crc32_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFF;
}

void BytecodeEncryptor::GenerateIntegrityTag(std::vector<uint8_t>& bytecode, const uint8_t* key) {
    // 计算 CRC32
    uint32_t crc = CRC32(bytecode.data(), bytecode.size());

    // 用密钥混淆 CRC
    for (int i = 0; i < 4; i++) {
        crc ^= ((uint32_t)key[i * 8]) << (i * 8);
    }

    // 追加到字节码末尾
    bytecode.push_back((uint8_t)(crc));
    bytecode.push_back((uint8_t)(crc >> 8));
    bytecode.push_back((uint8_t)(crc >> 16));
    bytecode.push_back((uint8_t)(crc >> 24));
}

bool BytecodeEncryptor::VerifyIntegrityTag(const std::vector<uint8_t>& bytecode, const uint8_t* key) {
    if (bytecode.size() < 4) return false;

    // 提取标签
    size_t dataSize = bytecode.size() - 4;
    uint32_t storedTag = (uint32_t)bytecode[dataSize] |
                         ((uint32_t)bytecode[dataSize + 1] << 8) |
                         ((uint32_t)bytecode[dataSize + 2] << 16) |
                         ((uint32_t)bytecode[dataSize + 3] << 24);

    // 计算期望的标签
    uint32_t expectedCrc = CRC32(bytecode.data(), dataSize);
    for (int i = 0; i < 4; i++) {
        expectedCrc ^= ((uint32_t)key[i * 8]) << (i * 8);
    }

    return storedTag == expectedCrc;
}

} // namespace CipherShell
