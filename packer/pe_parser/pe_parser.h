/**
 * CipherShell PE Parser
 * 自研 PE 解析器，不依赖第三方库
 * 支持 PE32 (x86) 和 PE32+ (x64)
 */

#ifndef CS_PE_PARSER_H
#define CS_PE_PARSER_H

#ifdef _WIN32
#include <windows.h>
#else
#include "windows_compat.h"
#endif
#include <cstdint>
#include <string>
#include <vector>

namespace CipherShell {

// ============================================================================
// 前向声明
// ============================================================================

struct CS_PE_IMAGE;

// ============================================================================
// 导入表结构
// ============================================================================

struct CS_IMPORT_FUNCTION {
    std::string     name;           // 函数名（按名称导入）
    WORD            ordinal;        // 序号（按序号导入）
    DWORD           thunkRVA;       // Thunk 在 IAT 中的 RVA
    bool            isOrdinal;      // 是否按序号导入
};

struct CS_IMPORT_DLL {
    std::string                     dllName;
    DWORD                           originalFirstThunkRVA;  // ILT RVA
    DWORD                           firstThunkRVA;          // IAT RVA
    std::vector<CS_IMPORT_FUNCTION> functions;
};

struct CS_IMPORT_TABLE {
    std::vector<CS_IMPORT_DLL>      dlls;
};

// ============================================================================
// 导出表结构
// ============================================================================

struct CS_EXPORT_FUNCTION {
    std::string     name;           // 函数名
    WORD            ordinal;        // 序号
    DWORD           functionRVA;    // 函数 RVA
    std::string     forwarderName;  // 转发器名称（如果有）
    bool            isForwarded;
};

struct CS_EXPORT_TABLE {
    std::string                         dllName;
    DWORD                               ordinalBase;
    std::vector<CS_EXPORT_FUNCTION>     functions;
};

// ============================================================================
// 重定位表结构
// ============================================================================

struct CS_RELOC_ENTRY {
    DWORD   pageRVA;        // 页 RVA
    WORD    type;           // 重定位类型
    WORD    offset;         // 页内偏移
    DWORD64 fullRVA;        // 完整 RVA（pageRVA + offset）
};

struct CS_RELOC_TABLE {
    std::vector<CS_RELOC_ENTRY> entries;
};

// ============================================================================
// 资源表结构
// ============================================================================

struct CS_RESOURCE_ENTRY {
    DWORD       type;           // 资源类型
    DWORD       id;             // 资源 ID
    WORD        languageId;     // 语言 ID
    std::string name;           // 资源名称（如果有）
    DWORD       dataRVA;        // 数据 RVA
    DWORD       dataSize;       // 数据大小
    bool        isNamed;        // 是否按名称
};

struct CS_RESOURCE_TREE {
    std::vector<CS_RESOURCE_ENTRY> entries;
};

// ============================================================================
// TLS 结构
// ============================================================================

struct CS_TLS_INFO {
    DWORD64     startAddress;       // TLS 数据起始地址
    DWORD64     endAddress;         // TLS 数据结束地址
    DWORD64     indexAddress;       // TLS 索引地址
    DWORD64     callbacksAddress;   // TLS 回调数组地址
    DWORD       callbackCount;      // 回调数量
    bool        valid;
};

// ============================================================================
// 异常处理表结构 (x64)
// ============================================================================

struct CS_RUNTIME_FUNCTION {
    DWORD   beginAddress;
    DWORD   endAddress;
    DWORD   unwindData;
};

struct CS_EXCEPTION_TABLE {
    std::vector<CS_RUNTIME_FUNCTION> entries;
};

// ============================================================================
// Load Config 结构
// ============================================================================

struct CS_LOAD_CONFIG {
    DWORD       directoryRVA;
    DWORD       directorySize;
    DWORD64     securityCookie;
    DWORD64     guardCFCheckFunctionPointer;
    DWORD64     guardCFDispatchFunctionPointer;
    DWORD64     guardCFFunctionTable;
    DWORD64     guardCFFunctionCount;
    DWORD       guardFlags;
    DWORD       guardTableEntrySize;
    std::vector<DWORD> guardFunctionRVAs;
    bool        hasCFG;             // Control Flow Guard
    bool        hasRFGuard;         // Return Flow Guard
    bool        valid;
};

// ============================================================================
// Debug 目录结构
// ============================================================================

struct CS_DEBUG_ENTRY {
    DWORD   type;
    DWORD   sizeOfData;
    DWORD   addressOfRawData;
    DWORD   pointerToRawData;
};

struct CS_DEBUG_DIRECTORY {
    std::vector<CS_DEBUG_ENTRY> entries;
};

// ============================================================================
// 延迟导入结构
// ============================================================================

struct CS_DELAY_IMPORT_DLL {
    std::string                     dllName;
    DWORD                           moduleHandleRVA;
    DWORD                           iatRVA;
    DWORD                           intRVA;
    std::vector<CS_IMPORT_FUNCTION> functions;
};

struct CS_DELAY_IMPORT_TABLE {
    std::vector<CS_DELAY_IMPORT_DLL> dlls;
};

// ============================================================================
// PE 主结构
// ============================================================================

struct CS_PE_IMAGE {
    // 原始文件数据
    BYTE*                   rawData;
    DWORD                   rawSize;
    std::string             filePath;

    // 解析后的头
    PIMAGE_DOS_HEADER       dosHeader;
    PIMAGE_NT_HEADERS64     ntHeaders64;    // 统一用64位结构
    PIMAGE_NT_HEADERS32     ntHeaders32;    // x86 时使用
    PIMAGE_SECTION_HEADER   sections;
    WORD                    numSections;
    BOOL                    is64Bit;

    // 解析后的目录
    CS_IMPORT_TABLE         imports;
    CS_EXPORT_TABLE         exports;
    CS_RELOC_TABLE          relocs;
    CS_RESOURCE_TREE        resources;
    CS_TLS_INFO             tls;
    CS_EXCEPTION_TABLE      exceptions;
    CS_LOAD_CONFIG          loadConfig;
    CS_DEBUG_DIRECTORY      debugDir;
    CS_DELAY_IMPORT_TABLE   delayImports;

    // 元数据
    BOOL                    hasOverlay;
    DWORD                   overlayOffset;
    BOOL                    hasSignature;
    BOOL                    hasRichHeader;
    DWORD                   richHeaderOffset;
    BOOL                    isDotNet;

    // 解析状态
    BOOL                    isValid;
    std::string             errorMessage;
};

// ============================================================================
// PE Parser 类
// ============================================================================

class PEParser {
public:
    PEParser();
    ~PEParser();

    /**
     * 从文件加载并解析 PE
     * @param filePath 文件路径
     * @return 解析后的 PE 镜像，失败时 isValid 为 FALSE
     */
    CS_PE_IMAGE* LoadFromFile(const std::string& filePath);

    /**
     * 从内存缓冲区解析 PE
     * @param buffer 数据缓冲区
     * @param size 缓冲区大小
     * @return 解析后的 PE 镜像
     */
    CS_PE_IMAGE* LoadFromBuffer(BYTE* buffer, DWORD size);

    /**
     * 释放 PE 镜像资源
     */
    void FreeImage(CS_PE_IMAGE* image);

private:
    // 解析各个组件
    bool ParseHeaders(CS_PE_IMAGE* image);
    bool ParseDataDirectories(CS_PE_IMAGE* image);
    bool ParseImportTable(CS_PE_IMAGE* image);
    bool ParseExportTable(CS_PE_IMAGE* image);
    bool ParseRelocationTable(CS_PE_IMAGE* image);
    bool ParseResourceTable(CS_PE_IMAGE* image);
    bool ParseTLS(CS_PE_IMAGE* image);
    bool ParseExceptionTable(CS_PE_IMAGE* image);
    bool ParseLoadConfig(CS_PE_IMAGE* image);
    bool ParseDebugDirectory(CS_PE_IMAGE* image);
    bool ParseDelayImports(CS_PE_IMAGE* image);
    bool ParseRichHeader(CS_PE_IMAGE* image);
    bool DetectOverlay(CS_PE_IMAGE* image);
    bool DetectDotNet(CS_PE_IMAGE* image);

    // 辅助函数
    DWORD RVAToOffset(CS_PE_IMAGE* image, DWORD rva);
    bool IsValidPE(CS_PE_IMAGE* image);
    bool CheckBounds(CS_PE_IMAGE* image, DWORD offset, DWORD size);

    // 错误处理
    void SetError(CS_PE_IMAGE* image, const std::string& message);
};

} // namespace CipherShell

#endif // CS_PE_PARSER_H
