/**
 * CipherShell 签名消除器 - 实现
 */

#include "signature_eliminator.h"
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <sstream>

namespace CipherShell {

// ============================================================================
// 已知壳的特征模式
// ============================================================================

// VMProtect 特征：.vmp0, .vmp1 section
const BYTE SignatureEliminator::s_vmpPattern[] = {0x2E, 0x76, 0x6D, 0x70, 0x30};  // ".vmp0"

// Themida 特征
const BYTE SignatureEliminator::s_themidaPattern[] = {0x2E, 0x74, 0x68, 0x65, 0x6D, 0x69, 0x64, 0x61};  // ".themida"

// UPX 特征
const BYTE SignatureEliminator::s_upxPattern[] = {0x55, 0x50, 0x58, 0x30};  // "UPX0"

// ASPack 特征
const BYTE SignatureEliminator::s_aspackPattern[] = {0x2E, 0x41, 0x53, 0x50, 0x61, 0x63, 0x6B};  // ".ASPack"

// ============================================================================
// 构造/析构
// ============================================================================

SignatureEliminator::SignatureEliminator() {
    srand((unsigned int)time(nullptr));
}

SignatureEliminator::~SignatureEliminator() {}

// ============================================================================
// 公共接口
// ============================================================================

std::vector<SignatureMatch> SignatureEliminator::DetectSignatures(CS_PE_IMAGE* image) {
    std::vector<SignatureMatch> matches;

    if (!image || !image->isValid) {
        return matches;
    }

    // 检测各种壳的签名
    CheckVMProtectSignature(image, matches);
    CheckThemidaSignature(image, matches);
    CheckUPXSignature(image, matches);
    CheckASPackSignature(image, matches);
    CheckPEiDSignatures(image, matches);

    return matches;
}

bool SignatureEliminator::EliminateSignatures(CS_PE_IMAGE* image, const EliminationConfig& config) {
    if (!image || !image->isValid) {
        return false;
    }

    // 随机化 section 名称
    if (config.randomizeSectionNames) {
        RandomizeSectionNames(image);
    }

    // 清除 Rich Header
    if (config.clearRichHeader) {
        ClearRichHeader(image);
    }

    // 清除调试目录
    if (config.clearDebugDirectory) {
        ClearDebugDirectory(image);
    }

    // 清除时间戳
    if (config.randomizeTimestamps) {
        ClearTimestamps(image);
    }

    // 清除校验和
    if (config.clearChecksum) {
        ClearChecksum(image);
    }

    return true;
}

bool SignatureEliminator::VerifyElimination(CS_PE_IMAGE* image) {
    if (!image || !image->isValid) {
        return false;
    }

    // 重新检测
    auto matches = DetectSignatures(image);
    return matches.empty();
}

// ============================================================================
// 签名检测实现
// ============================================================================

bool SignatureEliminator::CheckVMProtectSignature(CS_PE_IMAGE* image, std::vector<SignatureMatch>& matches) {
    // 检查 section 名称
    for (WORD i = 0; i < image->numSections; i++) {
        char name[9] = {0};
        memcpy(name, image->sections[i].Name, 8);

        if (strncmp(name, ".vmp", 4) == 0) {
            SignatureMatch match;
            match.signatureName = "VMProtect";
            match.detector = "PEiD/DIE";
            match.matchOffset = (DWORD)((BYTE*)&image->sections[i] - image->rawData);
            match.matchLength = 8;
            match.description = "VMProtect section detected: " + std::string(name);
            matches.push_back(match);
            return true;
        }
    }

    return false;
}

bool SignatureEliminator::CheckThemidaSignature(CS_PE_IMAGE* image, std::vector<SignatureMatch>& matches) {
    // 检查 section 名称
    for (WORD i = 0; i < image->numSections; i++) {
        char name[9] = {0};
        memcpy(name, image->sections[i].Name, 8);

        if (strncmp(name, ".themida", 8) == 0 || strncmp(name, ".winlice", 8) == 0) {
            SignatureMatch match;
            match.signatureName = "Themida/WinLicense";
            match.detector = "PEiD/DIE";
            match.matchOffset = (DWORD)((BYTE*)&image->sections[i] - image->rawData);
            match.matchLength = 8;
            match.description = "Themida section detected: " + std::string(name);
            matches.push_back(match);
            return true;
        }
    }

    return false;
}

bool SignatureEliminator::CheckUPXSignature(CS_PE_IMAGE* image, std::vector<SignatureMatch>& matches) {
    // 检查 section 名称
    for (WORD i = 0; i < image->numSections; i++) {
        char name[9] = {0};
        memcpy(name, image->sections[i].Name, 8);

        if (strncmp(name, "UPX", 3) == 0) {
            SignatureMatch match;
            match.signatureName = "UPX";
            match.detector = "PEiD/DIE";
            match.matchOffset = (DWORD)((BYTE*)&image->sections[i] - image->rawData);
            match.matchLength = 8;
            match.description = "UPX section detected: " + std::string(name);
            matches.push_back(match);
            return true;
        }
    }

    return false;
}

bool SignatureEliminator::CheckASPackSignature(CS_PE_IMAGE* image, std::vector<SignatureMatch>& matches) {
    // 检查 section 名称
    for (WORD i = 0; i < image->numSections; i++) {
        char name[9] = {0};
        memcpy(name, image->sections[i].Name, 8);

        if (strncmp(name, ".ASPack", 7) == 0 || strncmp(name, ".adata", 6) == 0) {
            SignatureMatch match;
            match.signatureName = "ASPack";
            match.detector = "PEiD/DIE";
            match.matchOffset = (DWORD)((BYTE*)&image->sections[i] - image->rawData);
            match.matchLength = 8;
            match.description = "ASPack section detected: " + std::string(name);
            matches.push_back(match);
            return true;
        }
    }

    return false;
}

bool SignatureEliminator::CheckPEiDSignatures(CS_PE_IMAGE* image, std::vector<SignatureMatch>& matches) {
    // 检查入口点模式
    DWORD entryRVA = 0;
    if (image->is64Bit) {
        entryRVA = image->ntHeaders64->OptionalHeader.AddressOfEntryPoint;
    } else {
        entryRVA = image->ntHeaders32->OptionalHeader.AddressOfEntryPoint;
    }

    // 查找入口点在文件中的偏移
    for (WORD i = 0; i < image->numSections; i++) {
        if (entryRVA >= image->sections[i].VirtualAddress &&
            entryRVA < image->sections[i].VirtualAddress + image->sections[i].Misc.VirtualSize) {
            DWORD offset = entryRVA - image->sections[i].VirtualAddress + image->sections[i].PointerToRawData;
            
            if (offset + 16 <= image->rawSize) {
                const BYTE* entryCode = image->rawData + offset;
                
                // 检查常见的壳入口模式
                // pushad / mov ebp, esp / ...
                if (entryCode[0] == 0x60 && entryCode[1] == 0x89 && entryCode[2] == 0xE5) {
                    SignatureMatch match;
                    match.signatureName = "Generic Packer Entry";
                    match.detector = "Heuristic";
                    match.matchOffset = offset;
                    match.matchLength = 3;
                    match.description = "Common packer entry pattern detected";
                    matches.push_back(match);
                }
            }
            break;
        }
    }

    return !matches.empty();
}

// ============================================================================
// 消除操作实现
// ============================================================================

bool SignatureEliminator::RandomizeSectionNames(CS_PE_IMAGE* image) {
    for (WORD i = 0; i < image->numSections; i++) {
        char name[9] = {0};
        memcpy(name, image->sections[i].Name, 8);

        // 保留 .rsrc 和 .reloc（Windows loader 需要）
        if (strncmp(name, ".rsrc", 5) == 0 || strncmp(name, ".reloc", 6) == 0) {
            continue;
        }

        // 生成随机名称
        char newName[8];
        GenerateRandomName(newName, 8);
        memcpy(image->sections[i].Name, newName, 8);
    }

    return true;
}

bool SignatureEliminator::ClearRichHeader(CS_PE_IMAGE* image) {
    if (!image->hasRichHeader) {
        return true;
    }

    // Rich Header 在 DOS Header 和 PE 签名之间
    // 清除从 0x80 到 e_lfanew 之间的数据
    DWORD start = 0x80;
    DWORD end = image->dosHeader->e_lfanew;

    if (start < end && end <= image->rawSize) {
        memset(image->rawData + start, 0, end - start);
        image->hasRichHeader = FALSE;
    }

    return true;
}

bool SignatureEliminator::ClearDebugDirectory(CS_PE_IMAGE* image) {
    // 清除调试目录
    if (image->is64Bit) {
        image->ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
        image->ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
    } else {
        image->ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
        image->ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
    }

    return true;
}

bool SignatureEliminator::ClearTimestamps(CS_PE_IMAGE* image) {
    // 清除时间戳
    if (image->is64Bit) {
        image->ntHeaders64->FileHeader.TimeDateStamp = 0;
    } else {
        image->ntHeaders32->FileHeader.TimeDateStamp = 0;
    }

    return true;
}

bool SignatureEliminator::ClearChecksum(CS_PE_IMAGE* image) {
    // 清除校验和
    if (image->is64Bit) {
        image->ntHeaders64->OptionalHeader.CheckSum = 0;
    } else {
        image->ntHeaders32->OptionalHeader.CheckSum = 0;
    }

    return true;
}

// ============================================================================
// 辅助函数
// ============================================================================

bool SignatureEliminator::PatternMatch(const BYTE* data, DWORD size, const BYTE* pattern, DWORD patternSize) {
    if (size < patternSize) return false;

    for (DWORD i = 0; i <= size - patternSize; i++) {
        if (memcmp(data + i, pattern, patternSize) == 0) {
            return true;
        }
    }

    return false;
}

DWORD SignatureEliminator::GenerateRandomDWORD() {
    return ((DWORD)rand() << 16) | (DWORD)rand();
}

void SignatureEliminator::GenerateRandomName(char* name, DWORD length) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyz";

    // BUG 18 修复：生成随机名称后自检，确保不匹配已知签名
    const int maxRetries = 10;
    for (int retry = 0; retry < maxRetries; retry++) {
        for (DWORD i = 0; i < length; i++) {
            name[i] = charset[rand() % (sizeof(charset) - 1)];
        }

        // 自检：确保生成的名称不匹配已知壳的 section 名
        if (VerifyNoSignatureMatch((const BYTE*)name, length)) {
            return;  // 通过自检，可以使用
        }
        // 未通过自检，重新生成
    }
    // 超过重试次数，使用最后生成的名称（极低概率到这里）
}

// BUG 17 修复：从外部文件加载签名数据库
uint32_t SignatureEliminator::LoadSignatureDatabase(const std::string& filePath) {
    std::ifstream file(filePath);
    if (!file.is_open()) {
        return 0;
    }

    uint32_t loadedCount = 0;
    std::string line;

    while (std::getline(file, line)) {
        // 跳过空行和注释
        if (line.empty() || line[0] == '#') continue;

        // 格式: "名称:十六进制字节串"
        size_t colonPos = line.find(':');
        if (colonPos == std::string::npos) continue;

        ExternalSignature sig;
        sig.name = line.substr(0, colonPos);
        std::string hexStr = line.substr(colonPos + 1);

        // 解析十六进制字节
        for (size_t i = 0; i + 1 < hexStr.size(); i += 2) {
            std::string byteStr = hexStr.substr(i, 2);
            try {
                uint8_t byte = (uint8_t)std::stoul(byteStr, nullptr, 16);
                sig.pattern.push_back(byte);
            } catch (...) {
                break;
            }
        }

        if (!sig.pattern.empty()) {
            m_externalSignatures.push_back(sig);
            loadedCount++;
        }
    }

    return loadedCount;
}

// BUG 18 修复：验证数据不匹配已知签名
bool SignatureEliminator::VerifyNoSignatureMatch(const BYTE* data, DWORD size) {
    // 检查内置签名
    if (PatternMatch(data, size, s_vmpPattern, sizeof(s_vmpPattern))) return false;
    if (PatternMatch(data, size, s_themidaPattern, sizeof(s_themidaPattern))) return false;
    if (PatternMatch(data, size, s_upxPattern, sizeof(s_upxPattern))) return false;
    if (PatternMatch(data, size, s_aspackPattern, sizeof(s_aspackPattern))) return false;

    // 检查外部加载的签名
    for (const auto& sig : m_externalSignatures) {
        if (!sig.pattern.empty() &&
            PatternMatch(data, size, sig.pattern.data(), (DWORD)sig.pattern.size())) {
            return false;
        }
    }

    return true;
}

} // namespace CipherShell
