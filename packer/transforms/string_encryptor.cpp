/**
 * CipherShell 字符串加密器 - 实现
 */

#include "string_encryptor.h"
#include "runtime_stream_cipher.h"
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <unordered_map>
#ifdef _WIN32
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <random>
#endif

namespace CipherShell {

// ============================================================================
// 构造/析构
// ============================================================================

StringEncryptor::StringEncryptor() {
}

StringEncryptor::~StringEncryptor() {}

// ============================================================================
// 公共接口
// ============================================================================

std::vector<CS_STRING_ENTRY> StringEncryptor::ScanStrings(
    CS_PE_IMAGE* image,
    const CS_STRING_CONFIG& config)
{
    std::vector<CS_STRING_ENTRY> result;
    m_lastError.clear();

    if (!image || !image->isValid) {
        return result;
    }

    // 扫描所有 section
    for (WORD i = 0; i < image->numSections; i++) {
        PIMAGE_SECTION_HEADER section = &image->sections[i];

        // 跳过不可读的 section
        if (section->SizeOfRawData == 0 || section->PointerToRawData == 0) {
            continue;
        }

        if (section->PointerToRawData > image->rawSize ||
            section->SizeOfRawData > image->rawSize - section->PointerToRawData) {
            continue;
        }

        bool readable = (section->Characteristics & IMAGE_SCN_MEM_READ) != 0;
        bool executable = (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        bool code = (section->Characteristics & IMAGE_SCN_CNT_CODE) != 0;
        bool initializedData = (section->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) != 0;
        if (code || executable || !config.scanReadableSections || !readable || !initializedData) {
            continue;
        }

        char sectionName[9] = {};
        std::memcpy(sectionName, section->Name, 8);
        if (std::strncmp(sectionName, ".rsrc", 5) == 0 && !config.scanResources) continue;

        const BYTE* sectionData = image->rawData + section->PointerToRawData;
        DWORD sectionSize = section->SizeOfRawData;

        // 扫描字符串
        DWORD pos = 0;
        while (pos < sectionSize) {
            // 检查是否可能是字符串
            DWORD strLen = 0;

            // 检查 ANSI 字符串
            if (config.encryptAnsiStrings && pos + config.minLength <= sectionSize) {
                strLen = 0;
                while (pos + strLen < sectionSize && strLen < config.maxLength) {
                    BYTE ch = sectionData[pos + strLen];
                    if (ch == 0) {
                        strLen++;  // 包含 null 终止符
                        break;
                    }
                    if (ch < 0x20 || ch > 0x7E) {
                        if (ch != '\t' && ch != '\n' && ch != '\r') {
                            break;  // 非可打印字符
                        }
                    }
                    strLen++;
                }

                if (strLen >= config.minLength && sectionData[pos + strLen - 1] == 0) {
                    CS_STRING_ENTRY entry;
                    entry.rva = section->VirtualAddress + pos;
                    entry.offset = section->PointerToRawData + pos;
                    entry.length = strLen;
                    entry.isWideChar = false;
                    entry.original = (const char*)(sectionData + pos);

                    // 生成独立密钥
                    if (!GenerateRandomBytes(entry.key, 32) || !GenerateRandomBytes(entry.nonce, 12)) {
                        m_lastError = "secure random generation failed for ANSI string";
                        return {};
                    }

                    result.push_back(entry);
                    pos += strLen;
                    continue;
                }
            }

            // 检查宽字符字符串
            if (config.encryptWideStrings && pos + config.minLength * 2 <= sectionSize) {
                strLen = 0;
                while (pos + strLen * 2 + 1 < sectionSize && strLen < config.maxLength) {
                    wchar_t ch = *(wchar_t*)(sectionData + pos + strLen * 2);
                    if (ch == 0) {
                        strLen++;  // 包含 null 终止符
                        break;
                    }
                    if (ch < 0x20 || ch > 0x7E) {
                        break;
                    }
                    strLen++;
                }

                if (strLen >= config.minLength && 
                    *(wchar_t*)(sectionData + pos + (strLen - 1) * 2) == 0) {
                    CS_STRING_ENTRY entry;
                    entry.rva = section->VirtualAddress + pos;
                    entry.offset = section->PointerToRawData + pos;
                    entry.length = strLen * 2;  // 字节数
                    entry.isWideChar = true;

                    // 转换为窄字符串用于记录
                    char narrowBuf[256] = {0};
                    for (DWORD j = 0; j < strLen && j < 255; j++) {
                        wchar_t ch = *(wchar_t*)(sectionData + pos + j * 2);
                        narrowBuf[j] = (ch < 0x80) ? (char)ch : '?';
                    }
                    entry.original = narrowBuf;

                    if (!GenerateRandomBytes(entry.key, 32) || !GenerateRandomBytes(entry.nonce, 12)) {
                        m_lastError = "secure random generation failed for UTF-16 string";
                        return {};
                    }

                    result.push_back(entry);
                    pos += strLen * 2;
                    continue;
                }
            }

            pos++;
        }
    }

    return result;
}

std::vector<CS_STRING_REF> StringEncryptor::FindStringReferences(
    CS_PE_IMAGE* image,
    const std::vector<CS_STRING_ENTRY>& strings)
{
    std::vector<CS_STRING_REF> result;

    if (!image || !image->isValid || strings.empty()) {
        return result;
    }

    // 构建 RVA 到字符串索引的映射
    std::unordered_map<DWORD, DWORD> rvaToIndex;
    for (DWORD i = 0; i < strings.size(); i++) {
        rvaToIndex[strings[i].rva] = i;
    }

    // 扫描代码段中的引用
    for (WORD i = 0; i < image->numSections; i++) {
        PIMAGE_SECTION_HEADER section = &image->sections[i];

        // 只扫描可执行代码段
        if (!(section->Characteristics & IMAGE_SCN_CNT_CODE)) {
            continue;
        }

        const BYTE* codeData = image->rawData + section->PointerToRawData;
        DWORD codeSize = section->SizeOfRawData;

        // BUG 11 修复：push imm32 / mov reg,imm32 中的立即数是 VA（含 ImageBase），
        // 需要减去 ImageBase 转换为 RVA 后再与 rvaToIndex 匹配。
        ULONGLONG imageBase = 0;
        if (image->is64Bit && image->ntHeaders64) {
            imageBase = image->ntHeaders64->OptionalHeader.ImageBase;
        } else if (image->ntHeaders32) {
            imageBase = image->ntHeaders32->OptionalHeader.ImageBase;
        }

        // 简化扫描：查找直接引用（push offset / mov reg, offset 模式）
        for (DWORD offset = 0; offset < codeSize - 5; offset++) {
            // 检查 push imm32 (0x68) 或 mov reg, imm32 (0xB8-0xBF)
            if (codeData[offset] == 0x68 ||
                (codeData[offset] >= 0xB8 && codeData[offset] <= 0xBF)) {
                // 获取立即数（VA）
                DWORD imm32 = *(DWORD*)(codeData + offset + 1);

                // BUG 11 修复：将 VA 转换为 RVA 后再查找
                DWORD stringRVA = imm32 - (DWORD)imageBase;

                // 检查是否是字符串 RVA
                if (rvaToIndex.find(stringRVA) != rvaToIndex.end()) {
                    CS_STRING_REF ref;
                    ref.codeRVA = section->VirtualAddress + offset;
                    ref.codeOffset = section->PointerToRawData + offset;
                    ref.stringRVA = stringRVA;
                    ref.instrLength = 5;
                    ref.isDirectPush = (codeData[offset] == 0x68);

                    result.push_back(ref);
                }
            }

            // lea reg, [rip+offset] (x64)
            if (image->is64Bit && offset < codeSize - 7) {
                // BUG 12 修复：检查 LEA 指令时需要正确解析 ModR/M 字节
                // LEA 格式：REX.W (0x48) + 0x8D + ModR/M
                // RIP-relative 寻址：ModR/M 的 mod=00, rm=101 (0bXX_rrr_101)
                if (codeData[offset] == 0x48 && codeData[offset + 1] == 0x8D) {
                    uint8_t modrm = codeData[offset + 2];
                    uint8_t mod = (modrm >> 6) & 3;
                    uint8_t rm = modrm & 7;

                    // 只处理 RIP-relative 寻址 (mod=00, rm=101)
                    if (mod == 0x00 && rm == 0x05) {
                        // 计算 RIP 相对地址
                        int32_t rel32 = *(int32_t*)(codeData + offset + 3);
                        DWORD targetRVA = section->VirtualAddress + offset + 7 + rel32;

                        if (rvaToIndex.find(targetRVA) != rvaToIndex.end()) {
                            CS_STRING_REF ref;
                            ref.codeRVA = section->VirtualAddress + offset;
                            ref.codeOffset = section->PointerToRawData + offset;
                            ref.stringRVA = targetRVA;
                            ref.instrLength = 7;
                            ref.isDirectPush = false;

                            result.push_back(ref);
                        }
                    }
                }
            }
        }
    }

    return result;
}

bool StringEncryptor::EncryptStrings(
    CS_PE_IMAGE* image,
    std::vector<CS_STRING_ENTRY>& strings)
{
    if (!image || !image->isValid) {
        return false;
    }

    for (auto& entry : strings) {
        // 检查偏移是否有效
        if (entry.offset + entry.length > image->rawSize) {
            m_lastError = "string range is outside file data";
            return false;
        }

        // 获取字符串数据
        BYTE* data = image->rawData + entry.offset;

        RuntimeStreamCipher::ApplyRolling(data, entry.length, entry.key, true);

        // 更新加密后大小
        entry.encryptedSize = entry.length;
    }

    return true;
}

BYTE* StringEncryptor::GenerateDecryptFunction(bool is64Bit, DWORD* funcSize) {
    if (!funcSize) return nullptr;

    // x86 rolling stream cipher decrypt (matches RuntimeStreamCipher::ApplyRolling).
    // cdecl: decrypt_string(void* data, DWORD length, const BYTE key[32])
    // Regs: ESI=data, ECX=count, EDI=key, EAX=state, EBX=key_index, EDX=scratch
    static const BYTE x86_decrypt[] = {
        0x55,                               // push ebp
        0x89, 0xE5,                         // mov ebp, esp
        0x53,                               // push ebx
        0x56,                               // push esi
        0x57,                               // push edi
        0x8B, 0x75, 0x08,                   // mov esi, [ebp+8]  ; data
        0x8B, 0x4D, 0x0C,                   // mov ecx, [ebp+12] ; length
        0x8B, 0x7D, 0x10,                   // mov edi, [ebp+16] ; key
        0x8B, 0x07,                         // mov eax, [edi]    ; state = *(u32*)key
        0x85, 0xC0,                         // test eax, eax
        0x75, 0x05,                         // jnz .stateOk
        0xB8, 0x11, 0x5E, 0xC5, 0x0C,      // mov eax, 0x0C5C5E11
        // .stateOk:
        0x31, 0xDB,                         // xor ebx, ebx      ; key index = 0
        // .loop:
        0x85, 0xC9,                         // test ecx, ecx
        0x74, 0x1D,                         // jz .done (skip 29 bytes)
        0x0F, 0xB6, 0x16,                   // movzx edx, byte [esi] ; ciphertext
        0x52,                               // push edx           ; save feedback
        0x8A, 0x14, 0x1F,                   // mov dl, [edi+ebx]  ; key[index]
        0x30, 0xC2,                         // xor dl, al         ; mask
        0x30, 0x16,                         // xor [esi], dl      ; decrypt
        0x5A,                               // pop edx            ; feedback
        0xC1, 0xC8, 0x08,                   // ror eax, 8
        0x31, 0xD0,                         // xor eax, edx       ; state ^= feedback
        0x46,                               // inc esi
        0x43,                               // inc ebx
        0x83, 0xFB, 0x20,                   // cmp ebx, 32
        0x72, 0x02,                         // jb .noWrap
        0x31, 0xDB,                         // xor ebx, ebx
        // .noWrap:
        0x49,                               // dec ecx
        0xEB, 0xDF,                         // jmp .loop
        // .done:
        0x5F,                               // pop edi
        0x5E,                               // pop esi
        0x5B,                               // pop ebx
        0x5D,                               // pop ebp
        0xC3                                // ret
    };

    // x64 rolling stream cipher decrypt (matches RuntimeStreamCipher::ApplyRolling).
    // Win64: RCX=data, RDX=length, R8=key
    // Regs: RSI=data, RCX=count, RDI=key, EAX=state, EBX=feedback, EDX=key_index
    static const BYTE x64_decrypt[] = {
        0x48, 0x89, 0x5C, 0x24, 0x08,       // mov [rsp+8], rbx
        0x48, 0x89, 0x74, 0x24, 0x10,       // mov [rsp+16], rsi
        0x48, 0x89, 0x7C, 0x24, 0x18,       // mov [rsp+24], rdi
        0x48, 0x89, 0xCE,                   // mov rsi, rcx      ; data
        0x48, 0x89, 0xD1,                   // mov rcx, rdx      ; length
        0x4C, 0x89, 0xC7,                   // mov rdi, r8       ; key
        0x8B, 0x07,                         // mov eax, [rdi]    ; state
        0x85, 0xC0,                         // test eax, eax
        0x75, 0x05,                         // jnz .stateOk
        0xB8, 0x11, 0x5E, 0xC5, 0x0C,      // mov eax, 0x0C5C5E11
        // .stateOk:
        0x31, 0xD2,                         // xor edx, edx      ; key index
        // .loop:
        0x48, 0x85, 0xC9,                   // test rcx, rcx
        0x74, 0x23,                         // jz .done (skip 35 bytes)
        0x0F, 0xB6, 0x1E,                   // movzx ebx, byte [rsi] ; ciphertext
        0x44, 0x8A, 0x04, 0x17,             // mov r8b, [rdi+rdx]; key[index]
        0x41, 0x30, 0xC0,                   // xor r8b, al       ; mask
        0x44, 0x30, 0x06,                   // xor [rsi], r8b    ; decrypt
        0xC1, 0xC8, 0x08,                   // ror eax, 8
        0x31, 0xD8,                         // xor eax, ebx      ; state ^= feedback
        0x48, 0xFF, 0xC6,                   // inc rsi
        0xFF, 0xC2,                         // inc edx
        0x83, 0xFA, 0x20,                   // cmp edx, 32
        0x72, 0x02,                         // jb .noWrap
        0x31, 0xD2,                         // xor edx, edx
        // .noWrap:
        0x48, 0xFF, 0xC9,                   // dec rcx
        0xEB, 0xD8,                         // jmp .loop
        // .done:
        0x48, 0x8B, 0x5C, 0x24, 0x08,       // mov rbx, [rsp+8]
        0x48, 0x8B, 0x74, 0x24, 0x10,       // mov rsi, [rsp+16]
        0x48, 0x8B, 0x7C, 0x24, 0x18,       // mov rdi, [rsp+24]
        0xC3                                // ret
    };

    if (is64Bit) {
        *funcSize = sizeof(x64_decrypt);
        BYTE* output = new BYTE[sizeof(x64_decrypt)];
        memcpy(output, x64_decrypt, sizeof(x64_decrypt));
        return output;
    } else {
        *funcSize = sizeof(x86_decrypt);
        BYTE* output = new BYTE[sizeof(x86_decrypt)];
        memcpy(output, x86_decrypt, sizeof(x86_decrypt));
        return output;
    }
}

// ============================================================================
// 内部实现
// ============================================================================

bool StringEncryptor::IsPrintableString(const BYTE* data, DWORD length, bool& isWide) {
    if (length < 2) return false;

    // 检查是否以 null 结尾
    if (data[length - 1] != 0) return false;

    // 检查字符是否可打印
    for (DWORD i = 0; i < length - 1; i++) {
        BYTE ch = data[i];
        if (ch < 0x20 || ch > 0x7E) {
            if (ch != '\t' && ch != '\n' && ch != '\r') {
                return false;
            }
        }
    }

    isWide = false;
    return true;
}

bool StringEncryptor::IsLikelyString(const BYTE* data, DWORD length) {
    if (length < 3) return false;

    int printableCount = 0;
    for (DWORD i = 0; i < length; i++) {
        if (data[i] >= 0x20 && data[i] <= 0x7E) {
            printableCount++;
        }
    }

    // 至少 80% 的字符是可打印的
    return (printableCount * 100 / length) >= 80;
}

bool StringEncryptor::IsStringReference(CS_PE_IMAGE* image, DWORD codeOffset, DWORD& stringRVA) {
    if (codeOffset + 5 > image->rawSize) return false;

    const BYTE* code = image->rawData + codeOffset;

    // 检查 push imm32 (0x68 XX XX XX XX)
    if (code[0] == 0x68) {
        stringRVA = *(DWORD*)(code + 1);
        return true;
    }

    // 检查 mov eax, imm32 (0xB8 XX XX XX XX)
    if (code[0] >= 0xB8 && code[0] <= 0xBF) {
        stringRVA = *(DWORD*)(code + 1);
        return true;
    }

    return false;
}

void StringEncryptor::EncryptSingleString(CS_STRING_ENTRY& entry, const uint8_t* data, DWORD length) {
    ChaCha20 cipher;
    cipher.Init(entry.key, entry.nonce, 0);

    // 加密数据
    BYTE* encrypted = new BYTE[length];
    cipher.Process(data, encrypted, length);

    delete[] encrypted;
}

DWORD StringEncryptor::AlignValue(DWORD value, DWORD alignment) {
    if (alignment == 0) return value;
    return (value + alignment - 1) & ~(alignment - 1);
}

bool StringEncryptor::GenerateRandomBytes(uint8_t* buffer, DWORD length) {
    if (!buffer || length == 0) return false;
#ifdef _WIN32
    return BCryptGenRandom(
        nullptr,
        reinterpret_cast<PUCHAR>(buffer),
        length,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0;
#else
    try {
        std::random_device random;
        for (DWORD i = 0; i < length; i++) buffer[i] = static_cast<uint8_t>(random());
        return true;
    } catch (...) {
        return false;
    }
#endif
}

} // namespace CipherShell
