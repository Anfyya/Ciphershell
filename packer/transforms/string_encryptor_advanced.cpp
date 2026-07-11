/**
 * CipherShell 高级字符串加密 - 实现
 */

#include "string_encryptor_advanced.h"
#include <cstring>
#include <cstdlib>
#include <ctime>

namespace CipherShell {

// ============================================================================
// 构造/析构
// ============================================================================

StringEncryptorAdvanced::StringEncryptorAdvanced() 
    : StringEncryptor()
    , m_nextStringId(1)
{
    srand((unsigned int)time(nullptr));
}

StringEncryptorAdvanced::~StringEncryptorAdvanced() {}

// ============================================================================
// 公共接口
// ============================================================================

std::vector<EncryptedStringStorage> StringEncryptorAdvanced::EncryptAdvanced(
    CS_PE_IMAGE* image,
    const AdvancedStringConfig& config)
{
    std::vector<EncryptedStringStorage> result;

    if (!image || !image->isValid) {
        return result;
    }

    // 扫描字符串
    auto strings = ScanStrings(image, config);

    // 加密每个字符串
    for (auto& str : strings) {
        EncryptedStringStorage storage;
        storage.id = GenerateStringId();
        storage.rva = str.rva;
        storage.originalSize = str.length;
        storage.decrypted = false;
        storage.erased = false;
        storage.decryptedBuffer = nullptr;

        // 生成密钥
        GenerateKey(storage.key, 32);
        memcpy(storage.nonce, str.nonce, 12);

        // 分配加密缓冲区
        storage.encryptedSize = str.length;
        storage.encryptedData = new BYTE[storage.encryptedSize];
        memcpy(storage.encryptedData, image->rawData + str.offset, storage.encryptedSize);

        // 根据模式加密
        switch (config.mode) {
            case StringEncryptionMode::Simple:
                EncryptSimple(storage.encryptedData, storage.encryptedSize, storage.key);
                break;
            case StringEncryptionMode::ChaCha20:
                EncryptChaCha20(storage.encryptedData, storage.encryptedSize, storage.key, storage.nonce);
                break;
            case StringEncryptionMode::Rolling:
                EncryptRolling(storage.encryptedData, storage.encryptedSize, storage.key);
                break;
            default:
                EncryptChaCha20(storage.encryptedData, storage.encryptedSize, storage.key, storage.nonce);
                break;
        }

        // 写回加密后的数据
        memcpy(image->rawData + str.offset, storage.encryptedData, storage.encryptedSize);

        // 保存到存储
        m_storageMap[storage.id] = storage;
        result.push_back(storage);
    }

    // 修补引用
    if (config.detectStringRefs) {
        PatchStringReferences(image, result);
    }

    return result;
}

BYTE* StringEncryptorAdvanced::GenerateDecryptStub(
    const EncryptedStringStorage& storage,
    bool is64Bit,
    DWORD* stubSize)
{
    if (!stubSize) return nullptr;

    // 生成解密存根代码
    // 这段代码会被插入到原来引用字符串的位置

    if (is64Bit) {
        // x64: 调用全局解密函数
        // lea rcx, [string_data]
        // mov edx, string_size
        // lea r8, [key]
        // call decrypt_func
        static const BYTE x64_stub_template[] = {
            0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,  // lea rcx, [rip+offset] ; string data
            0xBA, 0x00, 0x00, 0x00, 0x00,                // mov edx, size
            0x4C, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00,    // lea r8, [rip+offset] ; key
            0xE8, 0x00, 0x00, 0x00, 0x00,                // call decrypt_func
        };

        *stubSize = sizeof(x64_stub_template);
        BYTE* output = new BYTE[sizeof(x64_stub_template)];
        memcpy(output, x64_stub_template, sizeof(x64_stub_template));

        // 填充实际偏移（需要在链接时计算）
        // 这里先填 0
        return output;
    } else {
        // x86: 调用全局解密函数
        // push key
        // push size
        // push string_data
        // call decrypt_func
        static const BYTE x86_stub_template[] = {
            0x68, 0x00, 0x00, 0x00, 0x00,    // push key_addr
            0x68, 0x00, 0x00, 0x00, 0x00,    // push size
            0x68, 0x00, 0x00, 0x00, 0x00,    // push string_addr
            0xE8, 0x00, 0x00, 0x00, 0x00,    // call decrypt_func
        };

        *stubSize = sizeof(x86_stub_template);
        BYTE* output = new BYTE[sizeof(x86_stub_template)];
        memcpy(output, x86_stub_template, sizeof(x86_stub_template));
        return output;
    }
}

BYTE* StringEncryptorAdvanced::GenerateStringManager(
    const std::vector<EncryptedStringStorage>& strings,
    bool is64Bit,
    DWORD* managerSize)
{
    if (!managerSize) return nullptr;

    // 计算管理器大小
    // 格式：[string_count:4][string_entries:N*40]
    DWORD entrySize = 4 + 4 + 4 + 32 + 12;  // id + rva + size + key + nonce
    DWORD totalSize = 4 + (DWORD)strings.size() * entrySize;

    BYTE* manager = new(std::nothrow) BYTE[totalSize];
    if (!manager) return nullptr;

    DWORD offset = 0;

    // 写入字符串数量
    *(DWORD*)(manager + offset) = (DWORD)strings.size();
    offset += 4;

    // 写入每个字符串的信息
    for (const auto& str : strings) {
        *(DWORD*)(manager + offset) = str.id;
        offset += 4;

        *(DWORD*)(manager + offset) = str.rva;
        offset += 4;

        *(DWORD*)(manager + offset) = str.originalSize;
        offset += 4;

        memcpy(manager + offset, str.key, 32);
        offset += 32;

        memcpy(manager + offset, str.nonce, 12);
        offset += 12;
    }

    *managerSize = totalSize;
    return manager;
}

void* StringEncryptorAdvanced::DecryptString(EncryptedStringStorage& storage) {
    if (storage.decrypted && storage.decryptedBuffer) {
        return storage.decryptedBuffer;
    }

    // 分配解密缓冲区
    storage.decryptedBuffer = new BYTE[storage.originalSize + 2];  // +2 for null terminator
    memset(storage.decryptedBuffer, 0, storage.originalSize + 2);

    // 复制加密数据
    memcpy(storage.decryptedBuffer, storage.encryptedData, storage.encryptedSize);

    // 解密
    DecryptChaCha20((BYTE*)storage.decryptedBuffer, storage.encryptedSize, storage.key, storage.nonce);

    storage.decrypted = true;
    return storage.decryptedBuffer;
}

void StringEncryptorAdvanced::EraseString(EncryptedStringStorage& storage) {
    if (storage.decryptedBuffer) {
        // 安全擦除
        volatile BYTE* p = (volatile BYTE*)storage.decryptedBuffer;
        for (DWORD i = 0; i < storage.originalSize; i++) {
            p[i] = 0;
        }
        delete[] static_cast<BYTE*>(storage.decryptedBuffer);
        storage.decryptedBuffer = nullptr;
    }
    storage.erased = true;
}

// ============================================================================
// 内部实现
// ============================================================================

bool StringEncryptorAdvanced::EncryptSimple(BYTE* data, DWORD size, const uint8_t* key) {
    for (DWORD i = 0; i < size; i++) {
        data[i] ^= key[i % 32];
    }
    return true;
}

bool StringEncryptorAdvanced::EncryptChaCha20(BYTE* data, DWORD size, const uint8_t* key, const uint8_t* nonce) {
    ChaCha20 cipher;
    cipher.Init(key, nonce, 0);
    cipher.ProcessInPlace(data, size);
    return true;
}

bool StringEncryptorAdvanced::EncryptRolling(BYTE* data, DWORD size, const uint8_t* key) {
    uint8_t rollingKey = key[0];
    for (DWORD i = 0; i < size; i++) {
        data[i] ^= rollingKey;
        rollingKey = (rollingKey << 1) | (rollingKey >> 7);  // 循环左移
        rollingKey ^= key[i % 32];
    }
    return true;
}

bool StringEncryptorAdvanced::DecryptSimple(BYTE* data, DWORD size, const uint8_t* key) {
    return EncryptSimple(data, size, key);  // XOR 是对称的
}

bool StringEncryptorAdvanced::DecryptChaCha20(BYTE* data, DWORD size, const uint8_t* key, const uint8_t* nonce) {
    ChaCha20 cipher;
    cipher.Init(key, nonce, 0);
    cipher.ProcessInPlace(data, size);
    return true;
}

bool StringEncryptorAdvanced::DecryptRolling(BYTE* data, DWORD size, const uint8_t* key) {
    // Rolling 解密需要反向操作
    // 这里简化为重新加密（因为是异或操作）
    return EncryptRolling(data, size, key);
}

bool StringEncryptorAdvanced::PatchStringReferences(
    CS_PE_IMAGE* image,
    const std::vector<EncryptedStringStorage>& strings)
{
    if (!image || strings.empty()) return false;

    // 构建 RVA 到字符串的映射
    std::unordered_map<DWORD, const EncryptedStringStorage*> rvaMap;
    for (const auto& str : strings) {
        rvaMap[str.rva] = &str;
    }

    // 扫描代码段，修补引用
    for (WORD i = 0; i < image->numSections; i++) {
        if (!(image->sections[i].Characteristics & IMAGE_SCN_CNT_CODE)) {
            continue;
        }

        BYTE* codeData = image->rawData + image->sections[i].PointerToRawData;
        DWORD codeSize = image->sections[i].SizeOfRawData;

        for (DWORD offset = 0; offset < codeSize - 5; offset++) {
            // 查找 push imm32 (0x68) 或 mov reg, imm32 (0xB8-0xBF)
            if (codeData[offset] == 0x68 || 
                (codeData[offset] >= 0xB8 && codeData[offset] <= 0xBF)) {
                DWORD imm32 = *(DWORD*)(codeData + offset + 1);

                // 检查是否是字符串 RVA
                auto it = rvaMap.find(imm32);
                if (it != rvaMap.end()) {
                    // 这里需要替换为解密 stub 的地址
                    // 实际实现需要更复杂的链接过程
                }
            }
        }
    }

    return true;
}

DWORD StringEncryptorAdvanced::GenerateStringId() {
    return m_nextStringId++;
}

void StringEncryptorAdvanced::GenerateKey(uint8_t* key, DWORD size) {
    for (DWORD i = 0; i < size; i++) {
        key[i] = (uint8_t)(rand() % 256);
    }
}

} // namespace CipherShell
