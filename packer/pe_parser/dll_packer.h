/**
 * CipherShell DLL 加壳器
 * 处理 DLL 特有的保护需求
 */

#ifndef CS_DLL_PACKER_H
#define CS_DLL_PACKER_H

#include "pe_parser.h"
#include <cstdint>
#include <vector>
#include <string>

namespace CipherShell {

// ============================================================================
// DLL 导出信息
// ============================================================================

struct DLLExportEntry {
    std::string     name;           // 函数名
    uint16_t        ordinal;        // 序号
    uint32_t        rva;            // 原始 RVA
    uint32_t        newRva;         // 新 RVA（指向 trampoline）
    bool            isForwarded;    // 是否转发
    std::string     forwarderName;  // 转发器名称
};

// ============================================================================
// DLL 保护配置
// ============================================================================

struct DLLPackConfig {
    bool        preserveExports;        // 保留导出表
    bool        preserveRelocations;    // 保留重定位
    bool        preserveTLS;            // 保留 TLS
    bool        preserveExceptions;     // 保留异常处理（x64）
    bool        hookDllMain;            // Hook DllMain
    bool        protectDllMain;         // 保护 DllMain 代码
    int         protectionLevel;        // 保护等级

    DLLPackConfig() :
        preserveExports(true),
        preserveRelocations(true),
        preserveTLS(true),
        preserveExceptions(true),
        hookDllMain(true),
        protectDllMain(true),
        protectionLevel(3) {}
};

// ============================================================================
// DLL 加壳结果
// ============================================================================

struct DLLPackResult {
    std::vector<DLLExportEntry> exports;        // 导出表
    BYTE*       trampolineCode;                  // 跳板代码
    DWORD       trampolineSize;                  // 跳板大小
    BYTE*       relocationData;                  // 重定位数据
    DWORD       relocationSize;                  // 重定位大小
    bool        success;
    std::string errorMessage;
};

// ============================================================================
// DLL 加壳器类
// ============================================================================

class DLLPacker {
public:
    DLLPacker();
    ~DLLPacker();

    /**
     * 加壳 DLL
     * @param image PE 镜像
     * @param config 配置
     * @return 加壳结果
     */
    DLLPackResult PackDLL(CS_PE_IMAGE* image, const DLLPackConfig& config);

    /**
     * 生成导出函数跳板
     * @param exports 导出列表
     * @param imageBase 映像基址
     * @param is64Bit 是否 64 位
     * @param trampolineSize 输出大小
     * @return 跳板代码
     */
    BYTE* GenerateExportTrampolines(
        const std::vector<DLLExportEntry>& exports,
        uint64_t imageBase,
        bool is64Bit,
        DWORD* trampolineSize
    );

    /**
     * 生成 DllMain 跳板
     * @param originalDllMain 原始 DllMain RVA
     * @param is64Bit 是否 64 位
     * @param stubSize 输出大小
     * @return 跳板代码
     */
    BYTE* GenerateDllMainStub(
        uint32_t originalDllMain,
        bool is64Bit,
        DWORD* stubSize
    );

    /**
     * 处理 x64 异常处理表
     * @param image PE 镜像
     * @param newExceptionHandler 新的异常处理器 RVA
     * @return 是否成功
     */
    bool PatchExceptionTable(CS_PE_IMAGE* image, uint32_t newExceptionHandler);

    /**
     * 注册动态异常处理表
     * @param image PE 镜像
     * @param runtimeFunctions RUNTIME_FUNCTION 数组
     * @param count 数量
     * @return 是否成功
     */
    bool RegisterDynamicExceptionTable(
        CS_PE_IMAGE* image,
        void* runtimeFunctions,
        uint32_t count
    );

private:
    // 导出表处理
    std::vector<DLLExportEntry> ParseExports(CS_PE_IMAGE* image);
    bool RebuildExportTable(CS_PE_IMAGE* image, const std::vector<DLLExportEntry>& exports);

    // 重定位处理
    bool ProcessRelocations(CS_PE_IMAGE* image, uint64_t newBase);

    // TLS 处理
    bool PreserveTLSCallbacks(CS_PE_IMAGE* image);

    // 辅助函数
    DWORD RVAToOffset(CS_PE_IMAGE* image, DWORD rva);
    bool IsValidExport(const DLLExportEntry& entry);
};

} // namespace CipherShell

#endif // CS_DLL_PACKER_H
