/**
 * CipherShell 签名消除器
 * 按配置处理并验证受控 PE 元数据；不承诺消除所有启发式签名匹配
 */

#ifndef CS_SIGNATURE_ELIMINATOR_H
#define CS_SIGNATURE_ELIMINATOR_H

#include "../pe_parser/pe_parser.h"
#include <array>
#include <string>
#include <vector>

namespace CipherShell {

struct GlobalConfig;

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
        addFakeImports(false),
        addFakeResources(false) {}
};

/**
 * 将用户可见的 [global] 配置逐项映射为签名处理策略。
 *
 * 该函数是 main.cpp 与测试共用的唯一映射入口，避免 UI/TOML 字段在生产链
 * 中发生互换或重新落回 EliminationConfig 的隐式默认值。
 */
EliminationConfig BuildEliminationConfig(const GlobalConfig& global);

// 一次签名元数据阶段结束后的精确状态快照。最终重建/写盘验证按字节比较
// 该状态，不能只凭“看起来像随机名”推断变换仍然存在。
struct EliminationState {
    bool is64Bit = false;
    WORD machine = 0;
    WORD optionalHeaderMagic = 0;
    WORD sizeOfOptionalHeader = 0;
    WORD numberOfSections = 0;
    DWORD numberOfRvaAndSizes = 0;
    DWORD peHeaderOffset = 0;
    bool hasRichHeader = false;
    DWORD debugDirectoryRVA = 0;
    DWORD debugDirectorySize = 0;
    DWORD coffTimestamp = 0;
    DWORD checksum = 0;
    std::vector<std::array<BYTE, IMAGE_SIZEOF_SHORT_NAME>> sectionNames;
    std::vector<BYTE> dosStubBytes;
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
     * @param reason 失败时写入具体原因，供调用方 fail-closed 上报
     * @return 是否成功；任意声明为启用的子步骤失败即整体失败，不吞掉错误
     */
    bool EliminateSignatures(CS_PE_IMAGE* image, const EliminationConfig& config,
        std::string& reason);

    /**
     * 验证消除结果
     * @param image PE 镜像
     * @return 是否仍有签名匹配
     */
    bool VerifyElimination(CS_PE_IMAGE* image);

    /**
     * 按本次配置验证已请求操作的后置条件。
     *
     * 与无参版本不同，本方法不会因为镜像中仍存在一个未请求消除的入口点或
     * section 特征就误判失败。clearChecksum 是现有的强制输出卫生策略，也会
     * 在启用时独立验证，但不代表四个 global 签名控制项已启用。
     *
     * @param image PE 镜像
     * @param config 本次实际使用的消除配置
     * @param reason 失败时写入可用于 fail-closed 上报的具体原因
     * @return 所有已启用操作的后置条件是否都成立
     */
    bool VerifyElimination(CS_PE_IMAGE* image, const EliminationConfig& config,
        std::string& reason);

    /**
     * 捕获 section 名及四项元数据的精确状态，用于证明重建/写盘未改写
     * 已验证的中间产物。
     */
    bool CaptureState(CS_PE_IMAGE* image, EliminationState& state,
        std::string& reason);

    /**
     * 验证本次配置相对于输入状态确实执行或保持了逐项语义，并返回最终快照。
     */
    bool VerifyTransition(const EliminationState& before, CS_PE_IMAGE* image,
        const EliminationConfig& config, EliminationState& after,
        std::string& reason);

    /**
     * 对重建后/写盘后的 PE 与已验证快照做精确比较。
     */
    bool VerifyExactState(CS_PE_IMAGE* image,
        const EliminationState& expected, std::string& reason);

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
    bool GenerateRandomName(char* name, DWORD length);

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
