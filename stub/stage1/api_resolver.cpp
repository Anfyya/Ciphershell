/**
 * CipherShell API Hash Resolve - 实现
 */

#include "api_resolver.h"
#ifdef _WIN32
#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#else
#include "windows_compat.h"
#endif
#include <cstring>

namespace CipherShell {

// ============================================================================
// 构造/析构
// ============================================================================

APIResolver::APIResolver() : m_initialized(false) {}

APIResolver::~APIResolver() {
    // 清除缓存
    m_dllCache.clear();
    m_funcCache.clear();
}

// ============================================================================
// 公共接口
// ============================================================================

bool APIResolver::Initialize() {
    if (m_initialized) {
        return true;
    }

    // 预加载常用 DLL
    PreloadCommonDLLs();

    m_initialized = true;
    return true;
}

FARPROC APIResolver::Resolve(uint32_t dllHash, uint32_t funcHash) {
    if (!m_initialized) {
        return nullptr;
    }

    // 生成缓存键
    uint64_t cacheKey = ((uint64_t)dllHash << 32) | funcHash;

    // 检查缓存
    auto it = m_funcCache.find(cacheKey);
    if (it != m_funcCache.end()) {
        return it->second.address;
    }

    // 获取或加载 DLL
    HMODULE hModule = LoadDLLByHash(dllHash);
    if (!hModule) {
        return nullptr;
    }

    // 获取函数地址
    FARPROC funcAddr = GetFunctionByHash(hModule, funcHash);
    if (!funcAddr) {
        return nullptr;
    }

    // 缓存结果
    FunctionCache cache;
    cache.address = funcAddr;
    cache.dllHash = dllHash;
    cache.funcHash = funcHash;
    m_funcCache[cacheKey] = cache;

    return funcAddr;
}

FARPROC APIResolver::Resolve(const char* dllName, const char* funcName) {
    if (!m_initialized || !dllName || !funcName) {
        return nullptr;
    }

    uint32_t dllHash = HashString(dllName);
    uint32_t funcHash = HashString(funcName);

    return Resolve(dllHash, funcHash);
}

uint32_t APIResolver::ResolveBatch(const CS_API_HASH* hashes, uint32_t count, CS_RESOLVED_API* results) {
    if (!m_initialized || !hashes || !results) {
        return 0;
    }

    uint32_t resolvedCount = 0;

    for (uint32_t i = 0; i < count; i++) {
        results[i].dllHash = hashes[i].dllHash;
        results[i].funcHash = hashes[i].funcHash;
        results[i].address = Resolve(hashes[i].dllHash, hashes[i].funcHash);
        results[i].resolved = (results[i].address != nullptr);

        if (results[i].resolved) {
            resolvedCount++;
        }
    }

    return resolvedCount;
}

uint32_t APIResolver::HashString(const char* str) {
    if (!str) return 0;

    uint32_t hash = 0x35;  // 初始种子

    while (*str) {
        char c = ToLower(*str);
        hash = RotateLeft(hash, 7) ^ (uint8_t)c;
        str++;
    }

    // 最终混淆
    hash ^= hash >> 16;
    hash *= 0x85EBCA6B;
    hash ^= hash >> 13;
    hash *= 0xC2B2AE35;
    hash ^= hash >> 16;

    return hash;
}

uint32_t APIResolver::HashStringW(const wchar_t* str) {
    if (!str) return 0;

    uint32_t hash = 0x35;  // 初始种子

    while (*str) {
        wchar_t c = ToLowerW(*str);
        hash = RotateLeft(hash, 7) ^ (uint16_t)c;
        str++;
    }

    // 最终混淆
    hash ^= hash >> 16;
    hash *= 0x85EBCA6B;
    hash ^= hash >> 13;
    hash *= 0xC2B2AE35;
    hash ^= hash >> 16;

    return hash;
}

void APIResolver::PreloadCommonDLLs() {
    // 预加载 kernel32.dll（通常已加载）
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        DLLCache cache;
        cache.handle = hKernel32;
        cache.hash = Kernel32::DLL_HASH;
        strcpy_s(cache.name, "kernel32.dll");
        m_dllCache[Kernel32::DLL_HASH] = cache;
    }

    // 预加载 ntdll.dll（通常已加载）
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll) {
        DLLCache cache;
        cache.handle = hNtdll;
        cache.hash = Ntdll::DLL_HASH;
        strcpy_s(cache.name, "ntdll.dll");
        m_dllCache[Ntdll::DLL_HASH] = cache;
    }
}

// ============================================================================
// 内部实现
// ============================================================================

HMODULE APIResolver::LoadDLLByHash(uint32_t dllHash) {
    // 检查缓存
    auto it = m_dllCache.find(dllHash);
    if (it != m_dllCache.end()) {
        return it->second.handle;
    }

    // 尝试从 PEB 查找
    HMODULE hModule = FindInPEB(dllHash);
    if (hModule) {
        DLLCache cache;
        cache.handle = hModule;
        cache.hash = dllHash;
        cache.name[0] = '\0';
        m_dllCache[dllHash] = cache;
        return hModule;
    }

    // 如果找不到，需要加载
    // 这里需要通过 LoadLibraryA 加载
    // 但 LoadLibraryA 本身也需要解析...
    // 实际上，kernel32!LoadLibraryA 应该在 Stage0 中已解析

    return nullptr;
}

FARPROC APIResolver::GetFunctionByHash(HMODULE hModule, uint32_t funcHash) {
    if (!hModule) return nullptr;

    // 获取导出表
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return nullptr;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return nullptr;
    }

    DWORD exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportDirRVA == 0) {
        return nullptr;
    }

    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + exportDirRVA);

    DWORD* functions = (DWORD*)((BYTE*)hModule + exportDir->AddressOfFunctions);
    DWORD* names = (DWORD*)((BYTE*)hModule + exportDir->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)hModule + exportDir->AddressOfNameOrdinals);

    // 遍历导出名称
    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        const char* name = (const char*)((BYTE*)hModule + names[i]);
        uint32_t hash = HashString(name);

        if (hash == funcHash) {
            // 找到匹配的函数
            WORD ordinal = ordinals[i];
            DWORD funcRVA = functions[ordinal];

            // 检查是否是转发器
            if (funcRVA >= exportDirRVA &&
                funcRVA < exportDirRVA + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size) {
                // 转发器，暂不处理
                continue;
            }

            return (FARPROC)((BYTE*)hModule + funcRVA);
        }
    }

    return nullptr;
}

HMODULE APIResolver::FindInPEB(uint32_t dllHash) {
    // BUG 19 修复：在 Windows 平台实现真正的 PEB 遍历，
    // 通过 TEB -> PEB -> Ldr -> InMemoryOrderModuleList 遍历已加载模块，
    // 不依赖 GetModuleHandleA（GetModuleHandleA 本身需要导入表解析）。
    // 非 Windows 平台保持 stub 实现。

#ifdef _WIN32
    // 通过 NtCurrentTeb() 获取 PEB 地址
    // PEB 结构中 Ldr 字段偏移：x64 为 +0x18，x86 为 +0x0C
    // PEB_LDR_DATA 中 InMemoryOrderModuleList 偏移：x64 为 +0x20，x86 为 +0x14

#ifdef _WIN64
    // x64: 通过 GS 段寄存器获取 TEB，TEB+0x60 = PEB
    BYTE* pPEB = nullptr;
    __try {
        pPEB = (BYTE*)NtCurrentTeb()->ProcessEnvironmentBlock;
    } __except(1) {
        return nullptr;
    }
    if (!pPEB) return nullptr;

    // PEB+0x18 = Ldr (PEB_LDR_DATA*)
    BYTE* pLdr = *(BYTE**)(pPEB + 0x18);
    if (!pLdr) return nullptr;

    // PEB_LDR_DATA+0x20 = InMemoryOrderModuleList (LIST_ENTRY)
    LIST_ENTRY* pListHead = (LIST_ENTRY*)(pLdr + 0x20);
    LIST_ENTRY* pEntry = pListHead->Flink;

    while (pEntry != pListHead) {
        // LDR_DATA_TABLE_ENTRY 中 InMemoryOrderLinks 后的结构：
        // +0x00 = InMemoryOrderLinks (LIST_ENTRY)
        // +0x10 (x64) / +0x08 (x86) = 从 InMemoryOrderLinks 开始的偏移
        // 对于 InMemoryOrderModuleList，DllBase 在 entry 基址 +0x20 (x64)
        // BaseDllName (UNICODE_STRING) 在 entry 基址 +0x48 (x64)

        // 获取 LDR_DATA_TABLE_ENTRY 基址
        // InMemoryOrderLinks 是 LDR_DATA_TABLE_ENTRY 的第二个 LIST_ENTRY
        // 所以 entry_base = pEntry - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks)
        // 在 x64 上，InMemoryOrderLinks offset = 0x10
        BYTE* entryBase = (BYTE*)pEntry - 0x10;

        // DllBase 在 LDR_DATA_TABLE_ENTRY+0x30 (x64)
        HMODULE dllBase = *(HMODULE*)(entryBase + 0x30);

        // BaseDllName (UNICODE_STRING) 在 LDR_DATA_TABLE_ENTRY+0x58 (x64)
        // UNICODE_STRING: Length(USHORT) + MaxLength(USHORT) + padding + Buffer(PWSTR)
        USHORT nameLen = *(USHORT*)(entryBase + 0x58);
        wchar_t* nameBuffer = *(wchar_t**)(entryBase + 0x60);

        if (nameBuffer && nameLen > 0 && dllBase) {
            // 计算 DLL 名称的哈希值
            uint32_t hash = HashStringW(nameBuffer);
            if (hash == dllHash) {
                return dllBase;
            }
        }

        pEntry = pEntry->Flink;
    }

    return nullptr;

#else  // x86
    // x86: 通过 FS 段寄存器获取 TEB，TEB+0x30 = PEB
    BYTE* pPEB = nullptr;
    __try {
        pPEB = (BYTE*)NtCurrentTeb()->ProcessEnvironmentBlock;
    } __except(1) {
        return nullptr;
    }
    if (!pPEB) return nullptr;

    // PEB+0x0C = Ldr (PEB_LDR_DATA*)
    BYTE* pLdr = *(BYTE**)(pPEB + 0x0C);
    if (!pLdr) return nullptr;

    // PEB_LDR_DATA+0x14 = InMemoryOrderModuleList (LIST_ENTRY)
    LIST_ENTRY* pListHead = (LIST_ENTRY*)(pLdr + 0x14);
    LIST_ENTRY* pEntry = pListHead->Flink;

    while (pEntry != pListHead) {
        // x86 下 InMemoryOrderLinks offset = 0x08
        BYTE* entryBase = (BYTE*)pEntry - 0x08;

        // DllBase 在 LDR_DATA_TABLE_ENTRY+0x18 (x86)
        HMODULE dllBase = *(HMODULE*)(entryBase + 0x18);

        // BaseDllName (UNICODE_STRING) 在 LDR_DATA_TABLE_ENTRY+0x2C (x86)
        USHORT nameLen = *(USHORT*)(entryBase + 0x2C);
        wchar_t* nameBuffer = *(wchar_t**)(entryBase + 0x30);

        if (nameBuffer && nameLen > 0 && dllBase) {
            uint32_t hash = HashStringW(nameBuffer);
            if (hash == dllHash) {
                return dllBase;
            }
        }

        pEntry = pEntry->Flink;
    }

    return nullptr;
#endif // _WIN64

#else  // 非 Windows 平台：保持 stub 实现
    // 非 Windows 平台没有 PEB，使用回退列表
    const char* commonDLLs[] = {
        "kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll",
        "gdi32.dll", "shell32.dll", "ole32.dll", "msvcrt.dll",
        nullptr
    };

    for (int i = 0; commonDLLs[i]; i++) {
        uint32_t hash = HashString(commonDLLs[i]);
        if (hash == dllHash) {
            HMODULE hMod = GetModuleHandleA(commonDLLs[i]);
            if (hMod) return hMod;
        }
    }

    return nullptr;
#endif // _WIN32
}

// ============================================================================
// 辅助函数
// ============================================================================

uint32_t APIResolver::RotateLeft(uint32_t value, int count) {
    return (value << count) | (value >> (32 - count));
}

char APIResolver::ToLower(char c) {
    if (c >= 'A' && c <= 'Z') {
        return c + 32;
    }
    return c;
}

wchar_t APIResolver::ToLowerW(wchar_t c) {
    if (c >= L'A' && c <= L'Z') {
        return c + 32;
    }
    return c;
}

} // namespace CipherShell
