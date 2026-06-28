/**
 * CipherShell API Hash Resolve
 * 运行时通过哈希值解析 API 函数地址
 */

#ifndef CS_API_RESOLVER_H
#define CS_API_RESOLVER_H

#ifdef _WIN32
#include <windows.h>
#else
#include "windows_compat.h"
#endif
#include <cstdint>
#include <string>
#include <unordered_map>

namespace CipherShell {

// ============================================================================
// API 哈希结构
// ============================================================================

struct CS_API_HASH {
    uint32_t    dllHash;        // DLL 名称哈希
    uint32_t    funcHash;       // 函数名称哈希
    const char* dllName;        // DLL 名称（可选，用于调试）
    const char* funcName;       // 函数名称（可选，用于调试）
};

// ============================================================================
// 解析结果
// ============================================================================

struct CS_RESOLVED_API {
    FARPROC     address;        // 函数地址
    bool        resolved;       // 是否成功解析
    uint32_t    dllHash;
    uint32_t    funcHash;
};

// ============================================================================
// API Resolver 类
// ============================================================================

class APIResolver {
public:
    APIResolver();
    ~APIResolver();

    /**
     * 初始化解析器
     * @return 是否成功
     */
    bool Initialize();

    /**
     * 通过哈希值解析函数地址
     * @param dllHash DLL 名称哈希
     * @param funcHash 函数名称哈希
     * @return 函数地址，失败返回 NULL
     */
    FARPROC Resolve(uint32_t dllHash, uint32_t funcHash);

    /**
     * 通过名称解析函数地址
     * @param dllName DLL 名称
     * @param funcName 函数名称
     * @return 函数地址，失败返回 NULL
     */
    FARPROC Resolve(const char* dllName, const char* funcName);

    /**
     * 批量解析 API
     * @param hashes 哈希数组
     * @param count 数组大小
     * @param results 解析结果数组
     * @return 成功解析的数量
     */
    uint32_t ResolveBatch(const CS_API_HASH* hashes, uint32_t count, CS_RESOLVED_API* results);

    /**
     * 计算字符串哈希（自定义算法，避免被识别）
     * @param str 输入字符串
     * @return 哈希值
     */
    static uint32_t HashString(const char* str);

    /**
     * 计算字符串哈希（宽字符版本）
     * @param str 输入字符串
     * @return 哈希值
     */
    static uint32_t HashStringW(const wchar_t* str);

    /**
     * 预加载常用 DLL
     */
    void PreloadCommonDLLs();

private:
    // DLL 模块缓存
    struct DLLCache {
        HMODULE     handle;
        uint32_t    hash;
        char        name[MAX_PATH];
    };

    // 函数缓存
    struct FunctionCache {
        FARPROC     address;
        uint32_t    dllHash;
        uint32_t    funcHash;
    };

    // 内部方法
    HMODULE LoadDLLByHash(uint32_t dllHash);
    FARPROC GetFunctionByHash(HMODULE hModule, uint32_t funcHash);
    HMODULE FindInPEB(uint32_t dllHash);

    // 辅助函数
    static uint32_t RotateLeft(uint32_t value, int count);
    static char ToLower(char c);
    static wchar_t ToLowerW(wchar_t c);

    // 成员变量
    std::unordered_map<uint32_t, DLLCache>      m_dllCache;
    std::unordered_map<uint64_t, FunctionCache>  m_funcCache;
    bool m_initialized;
};

// ============================================================================
// 预定义的常用 API 哈希
// ============================================================================

// kernel32.dll 常用函数哈希（通过 ROL5+XOR+FNV 算法计算，保证无冲突）
namespace Kernel32 {
    constexpr uint32_t DLL_HASH = 0xD65BA5BB;  // "kernel32.dll"

    constexpr uint32_t LoadLibraryA = 0x8FD7CC53;
    constexpr uint32_t LoadLibraryW = 0xA5D7EEF5;
    constexpr uint32_t GetProcAddress = 0x336F6B52;
    constexpr uint32_t VirtualAlloc = 0x1E8D570D;
    constexpr uint32_t VirtualFree = 0x1BCCEA4B;
    constexpr uint32_t VirtualProtect = 0x768C12BE;
    constexpr uint32_t GetModuleHandleA = 0xE87B8427;
    constexpr uint32_t GetModuleHandleW = 0xD67B67D1;
    constexpr uint32_t ExitProcess = 0x3CC61DEA;
    constexpr uint32_t GetLastError = 0xCB628E10;
    constexpr uint32_t Sleep = 0x23DAD859;
    constexpr uint32_t CreateFileA = 0xC7236433;
    constexpr uint32_t CreateFileW = 0xDD2386D5;
    constexpr uint32_t ReadFile = 0x2A3A1E3F;
    constexpr uint32_t WriteFile = 0x9E2262A1;
    constexpr uint32_t CloseHandle = 0x4C637F40;
    constexpr uint32_t GetFileSize = 0x6CA85AB1;
    constexpr uint32_t CreateThread = 0xAD0FD260;
    constexpr uint32_t WaitForSingleObject = 0x381AD853;
    constexpr uint32_t GetCurrentProcess = 0x06E4D002;
    constexpr uint32_t GetCurrentThread = 0x058CB591;
    constexpr uint32_t GetCurrentProcessId = 0x5AF2D12B;
    constexpr uint32_t GetCurrentThreadId = 0x09FCD7CD;
}

// ntdll.dll 常用函数哈希
namespace Ntdll {
    constexpr uint32_t DLL_HASH = 0x56D284FF;  // "ntdll.dll"

    constexpr uint32_t NtQueryInformationProcess = 0x3CD299AD;
    constexpr uint32_t NtQueryInformationThread = 0x459D75CA;
    constexpr uint32_t NtSetInformationThread = 0xF7AC4F4B;
    constexpr uint32_t NtQuerySystemInformation = 0xD897928C;
    constexpr uint32_t NtClose = 0xA5E75C0F;
    constexpr uint32_t NtOpenProcess = 0x71430E3F;
    constexpr uint32_t NtAllocateVirtualMemory = 0xEF25A62F;
    constexpr uint32_t NtFreeVirtualMemory = 0x05394DC8;
    constexpr uint32_t NtProtectVirtualMemory = 0xF095CECD;
    constexpr uint32_t RtlInitUnicodeString = 0xC659856D;
    constexpr uint32_t RtlCreateHeap = 0x3F02133E;
    constexpr uint32_t LdrLoadDll = 0x56BF024E;
    constexpr uint32_t LdrGetProcedureAddress = 0xFB12F75F;
}

// user32.dll 常用函数哈希
namespace User32 {
    constexpr uint32_t DLL_HASH = 0x25252E45;  // "user32.dll"

    constexpr uint32_t MessageBoxA = 0x45DE5E8D;
    constexpr uint32_t MessageBoxW = 0x2FDE3BEB;
    constexpr uint32_t GetDesktopWindow = 0xAC786149;
    constexpr uint32_t FindWindowA = 0xFD7BD43C;
    constexpr uint32_t FindWindowW = 0xEB7BB7E6;
}

// advapi32.dll 常用函数哈希
namespace Advapi32 {
    constexpr uint32_t DLL_HASH = 0x6A5A7823;  // "advapi32.dll"

    constexpr uint32_t RegOpenKeyExA = 0x270E457E;
    constexpr uint32_t RegQueryValueExA = 0x7F284751;
    constexpr uint32_t RegCloseKey = 0xA335E583;
    constexpr uint32_t GetTokenInformation = 0xA6E4D9F2;
}

} // namespace CipherShell

#endif // CS_API_RESOLVER_H
