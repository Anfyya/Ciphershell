/**
 * CipherShell 导入表混淆器
 * 实现导入表混淆策略（策略A：API Hash化，策略B：导入表重建伪装，策略C：混合模式）
 */

#ifndef CS_IMPORT_OBFUSCATOR_H
#define CS_IMPORT_OBFUSCATOR_H

#include "../pe_parser/pe_parser.h"
#include "stub/stage1/api_resolver.h"
#include <vector>
#include <string>

namespace CipherShell {

// ============================================================================
// 导入表混淆策略
// ============================================================================

enum class ImportObfuscationStrategy {
    StrategyA,      // API Hash 化：清空 IAT，运行时通过 hash resolve
    StrategyB,      // 导入表重建伪装：生成假导入表，真实调用通过 hash resolve
    StrategyC       // 混合模式：真实 API 用 hash resolve，同时保留假导入表
};

// ============================================================================
// 混淆后的导入信息
// ============================================================================

struct CS_OBFUSCATED_IMPORT {
    uint32_t    dllHash;        // DLL 名称哈希
    uint32_t    funcHash;       // 函数名称哈希
    DWORD       originalRVA;    // 原始 IAT 位置 RVA
    // BUG 13 修复：使用 std::string 代替 const char*，
    // 避免临时 string 对象销毁后 c_str() 悬空指针
    std::string dllName;        // 原始 DLL 名称
    std::string funcName;       // 原始函数名称
    bool        isFake;         // 是否为假导入
};

// ============================================================================
// 混淆配置
// ============================================================================

struct CS_IMPORT_OBFUSCATION_CONFIG {
    ImportObfuscationStrategy   strategy;           // 混淆策略
    uint32_t                    fakeImportCount;    // 假导入数量
    bool                        preserveCriticalImports;  // 保留关键导入（如 LoadLibrary, GetProcAddress）
    bool                        addDelayImports;    // 添加延迟导入作为干扰

    // 构造函数 - 默认值
    CS_IMPORT_OBFUSCATION_CONFIG() :
        strategy(ImportObfuscationStrategy::StrategyC),
        fakeImportCount(10),
        preserveCriticalImports(true),
        addDelayImports(true) {}
};

// ============================================================================
// 导入表混淆器类
// ============================================================================

class ImportObfuscator {
public:
    ImportObfuscator();
    ~ImportObfuscator();

    /**
     * 混淆导入表
     * @param image PE 镜像
     * @param config 混淆配置
     * @param resolver API 解析器（用于计算哈希）
     * @return 混淆后的导入信息列表
     */
    std::vector<CS_OBFUSCATED_IMPORT> ObfuscateImports(
        CS_PE_IMAGE* image,
        const CS_IMPORT_OBFUSCATION_CONFIG& config,
        APIResolver* resolver
    );

    /**
     * 生成导入表解析 stub 代码
     * @param imports 导入信息列表
     * @param is64Bit 是否为 64 位
     * @param stubSize 输出 stub 大小
     * @return stub 代码数据
     */
    BYTE* GenerateImportStub(
        const std::vector<CS_OBFUSCATED_IMPORT>& imports,
        bool is64Bit,
        DWORD* stubSize
    );

    /**
     * 清除原始导入表
     * @param image PE 镜像
     * @return 是否成功
     */
    bool ClearOriginalImports(CS_PE_IMAGE* image);

    /**
     * 生成假导入表
     * @param image PE 镜像
     * @param count 假导入数量
     * @return 是否成功
     */
    bool GenerateFakeImports(CS_PE_IMAGE* image, uint32_t count);

private:
    // 策略实现
    bool ApplyStrategyA(CS_PE_IMAGE* image, const CS_IMPORT_OBFUSCATION_CONFIG& config, APIResolver* resolver);
    bool ApplyStrategyB(CS_PE_IMAGE* image, const CS_IMPORT_OBFUSCATION_CONFIG& config, APIResolver* resolver);
    bool ApplyStrategyC(CS_PE_IMAGE* image, const CS_IMPORT_OBFUSCATION_CONFIG& config, APIResolver* resolver);

    // 辅助函数
    bool IsCriticalImport(const char* dllName, const char* funcName);
    std::string GenerateRandomDLLName();
    std::string GenerateRandomFuncName();

    // 常用的假 DLL 和函数名称
    static const char* s_fakeDLLNames[];
    static const char* s_fakeFuncNames[];
};

} // namespace CipherShell

#endif // CS_IMPORT_OBFUSCATOR_H
