/**
 * CipherShell 签名消除器
 * 确保输出文件不会触发已知的壳检测签名
 */

#ifndef CS_SIGNATURE_ELIMINATOR_H
#define CS_SIGNATURE_ELIMINATOR_H

#include "../pe_parser/pe_parser.h"
#include <string>
#include <vector>

namespace CipherShell {

// ============================================================================
// 签名检测结果
// ============================================================================

struct SignatureMatch {
    std::string     signatureName;      // 签名名称
    std::string     detector;           // 检测工具 (PEiD, DIE, YARA)
    DWORD           matchOffset;        // 匹配偏移
    DWORD           matchLength;        // 匹配长度
    std::string     description;        // 描述
};

// ============================================================================
// 消除配置
// ============================================================================

struct EliminationConfig {
    bool    randomizeSectionNames;
    bool    randomizeTimestamps;
    bool    clearRichHeader;
    bool    clearDebugDirectory;
    bool    clearChecksum;
    bool    randomizeFileAlignment;
    bool    randomizeSectionAlignment;
    bool    addFakeImports;
    bool    addFakeResources;

    EliminationConfig() :
        randomizeSectionNames(true),
        randomizeTimestamps(true),
        clearRichHeader(true),
        clearDebugDirectory(true),
        clearChecksum(true),
        randomizeFileAlignment(false),
        randomizeSectionAlignment(false),
        addFakeImports(true),
        addFakeResources(false) {}
};

// ============================================================================
// 签名消除器类
// ============================================================================

class SignatureEliminator {
public:
    SignatureEliminator();
    ~SignatureEliminator();

    /**
     * 检测 PE 文件中的壳签名
     * @param image PE 镜像
     * @return 匹配的签名列表
     */
    std::vector<SignatureMatch> DetectSignatures(CS_PE_IMAGE* image);

    /**
     * 消除已知签名
     * @param image PE 镜像
     * @param config 消除配置
     * @return 是否成功
     */
    bool EliminateSignatures(CS_PE_IMAGE* image, const EliminationConfig& config);

    /**
     * 验证消除结果
     * @param image PE 镜像
     * @return 是否仍有签名匹配
     */
    bool VerifyElimination(CS_PE_IMAGE* image);

private:
    // 签名检测
    bool CheckVMProtectSignature(CS_PE_IMAGE* image, std::vector<SignatureMatch>& matches);
    bool CheckThemidaSignature(CS_PE_IMAGE* image, std::vector<SignatureMatch>& matches);
    bool CheckUPXSignature(CS_PE_IMAGE* image, std::vector<SignatureMatch>& matches);
    bool CheckASPackSignature(CS_PE_IMAGE* image, std::vector<SignatureMatch>& matches);
    bool CheckPEiDSignatures(CS_PE_IMAGE* image, std::vector<SignatureMatch>& matches);

    // 消除操作
    bool RandomizeSectionNames(CS_PE_IMAGE* image);
    bool ClearRichHeader(CS_PE_IMAGE* image);
    bool ClearDebugDirectory(CS_PE_IMAGE* image);
    bool ClearTimestamps(CS_PE_IMAGE* image);
    bool ClearChecksum(CS_PE_IMAGE* image);

    // 辅助函数
    bool PatternMatch(const BYTE* data, DWORD size, const BYTE* pattern, DWORD patternSize);
    DWORD GenerateRandomDWORD();
    void GenerateRandomName(char* name, DWORD length);

    // BUG 17 修复：支持从外部配置文件加载签名数据库
public:
    /**
     * 从外部文件加载签名数据库
     * 文件格式：每行一个签名，格式为 "名称:十六进制字节"
     * 例如：VMProtect:2E766D7030
     * @param filePath 签名数据库文件路径
     * @return 加载的签名数量
     */
    uint32_t LoadSignatureDatabase(const std::string& filePath);

private:
    // BUG 18 修复：生成随机内容后自检，确保不匹配已知签名
    bool VerifyNoSignatureMatch(const BYTE* data, DWORD size);

    // 外部加载的签名数据库
    struct ExternalSignature {
        std::string name;
        std::vector<BYTE> pattern;
    };
    std::vector<ExternalSignature> m_externalSignatures;

    // 已知壳的特征模式（内置默认，可被外部数据库补充）
    static const BYTE s_vmpPattern[];
    static const BYTE s_themidaPattern[];
    static const BYTE s_upxPattern[];
    static const BYTE s_aspackPattern[];
};

} // namespace CipherShell

#endif // CS_SIGNATURE_ELIMINATOR_H
