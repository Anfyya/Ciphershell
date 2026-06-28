/**
 * CipherShell 导入表混淆器 - 实现
 */

#include "import_obfuscator.h"
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <algorithm>

namespace CipherShell {

// ============================================================================
// 假 DLL 和函数名称
// ============================================================================

const char* ImportObfuscator::s_fakeDLLNames[] = {
    "kernel32.dll",     // 真实但常用的 DLL
    "user32.dll",
    "advapi32.dll",
    "gdi32.dll",
    "shell32.dll",
    "ole32.dll",
    "oleaut32.dll",
    "msvcrt.dll",
    "ws2_32.dll",
    "wininet.dll",
    "urlmon.dll",
    "shlwapi.dll",
    "version.dll",
    "crypt32.dll",
    "bcrypt.dll",
    "ncrypt.dll",
    "rpcrt4.dll",
    "comctl32.dll",
    "comdlg32.dll",
    "ntdll.dll"
};

const char* ImportObfuscator::s_fakeFuncNames[] = {
    "GetVersionExA",
    "GetSystemInfo",
    "GetNativeSystemInfo",
    "GetTickCount",
    "QueryPerformanceCounter",
    "QueryPerformanceFrequency",
    "GetCurrentProcessId",
    "GetCurrentThreadId",
    "GetLastError",
    "SetLastError",
    "GetCommandLineA",
    "GetCommandLineW",
    "GetEnvironmentStrings",
    "FreeEnvironmentStringsA",
    "GetStdHandle",
    "SetStdHandle",
    "GetConsoleMode",
    "SetConsoleMode",
    "WriteConsoleA",
    "ReadConsoleA",
    "CharUpperA",
    "CharLowerA",
    "lstrlenA",
    "lstrcpyA",
    "lstrcatA",
    "lstrcmpA",
    "MulDiv",
    "GetSystemTime",
    "GetLocalTime",
    "SystemTimeToFileTime",
    "FileTimeToSystemTime",
    "GetTimeZoneInformation",
    "SetTimeZoneInformation",
    "CreateDirectoryA",
    "RemoveDirectoryA",
    "GetCurrentDirectoryA",
    "SetCurrentDirectoryA",
    "GetFullPathNameA",
    "GetLongPathNameA",
    "GetShortPathNameA",
    "SearchPathA",
    "GetTempPathA",
    "GetTempFileNameA",
    "GetDriveTypeA",
    "GetDiskFreeSpaceA",
    "GetVolumeInformationA",
    "GetComputerNameA",
    "SetComputerNameA",
    "GetUserNameA",
    "GetWindowsDirectoryA",
    "GetSystemDirectoryA",
    "GetSystemWindowsDirectoryA"
};

// ============================================================================
// 构造/析构
// ============================================================================

ImportObfuscator::ImportObfuscator() {
    srand((unsigned int)time(nullptr));
}

ImportObfuscator::~ImportObfuscator() {}

// ============================================================================
// 公共接口
// ============================================================================

std::vector<CS_OBFUSCATED_IMPORT> ImportObfuscator::ObfuscateImports(
    CS_PE_IMAGE* image,
    const CS_IMPORT_OBFUSCATION_CONFIG& config,
    APIResolver* resolver)
{
    std::vector<CS_OBFUSCATED_IMPORT> result;

    if (!image || !image->isValid || !resolver) {
        return result;
    }

    // 根据策略应用混淆
    bool success = false;
    switch (config.strategy) {
        case ImportObfuscationStrategy::StrategyA:
            success = ApplyStrategyA(image, config, resolver);
            break;
        case ImportObfuscationStrategy::StrategyB:
            success = ApplyStrategyB(image, config, resolver);
            break;
        case ImportObfuscationStrategy::StrategyC:
            success = ApplyStrategyC(image, config, resolver);
            break;
    }

    if (!success) {
        return result;
    }

    // 收集混淆后的导入信息
    // 遍历原始导入表，为每个函数生成哈希
    for (const auto& dll : image->imports.dlls) {
        for (const auto& func : dll.functions) {
            CS_OBFUSCATED_IMPORT obfImport;
            obfImport.dllHash = APIResolver::HashString(dll.dllName.c_str());
            obfImport.dllName = dll.dllName.c_str();

            if (func.isOrdinal) {
                // 按序号导入：使用序号作为哈希
                obfImport.funcHash = func.ordinal;
                obfImport.funcName = nullptr;
            } else {
                obfImport.funcHash = APIResolver::HashString(func.name.c_str());
                obfImport.funcName = func.name.c_str();
            }

            obfImport.originalRVA = func.thunkRVA;
            obfImport.isFake = false;

            result.push_back(obfImport);
        }
    }

    return result;
}

BYTE* ImportObfuscator::GenerateImportStub(
    const std::vector<CS_OBFUSCATED_IMPORT>& imports,
    bool is64Bit,
    DWORD* stubSize)
{
    if (!stubSize || imports.empty()) {
        return nullptr;
    }

    // 计算 stub 大小
    // 格式：[import_count:4][import_data:N*12]
    DWORD totalSize = 4 + (DWORD)imports.size() * 12;

    BYTE* stub = new(std::nothrow) BYTE[totalSize];
    if (!stub) {
        return nullptr;
    }

    DWORD offset = 0;

    // 写入导入数量
    *(DWORD*)(stub + offset) = (DWORD)imports.size();
    offset += 4;

    // 写入每个导入的信息
    for (const auto& imp : imports) {
        *(DWORD*)(stub + offset) = imp.dllHash;
        offset += 4;

        *(DWORD*)(stub + offset) = imp.funcHash;
        offset += 4;

        *(DWORD*)(stub + offset) = imp.originalRVA;
        offset += 4;
    }

    *stubSize = totalSize;
    return stub;
}

bool ImportObfuscator::ClearOriginalImports(CS_PE_IMAGE* image) {
    if (!image || !image->isValid) {
        return false;
    }

    // 获取导入表目录
    IMAGE_DATA_DIRECTORY importDir;
    if (image->is64Bit) {
        importDir = image->ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    } else {
        importDir = image->ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    }

    if (importDir.VirtualAddress == 0) {
        return true;  // 没有导入表
    }

    // 清空导入表内容（但保留目录项）
    DWORD importOffset = 0;
    for (WORD i = 0; i < image->numSections; i++) {
        if (image->sections[i].VirtualAddress <= importDir.VirtualAddress &&
            image->sections[i].VirtualAddress + image->sections[i].SizeOfRawData > importDir.VirtualAddress) {
            importOffset = importDir.VirtualAddress - image->sections[i].VirtualAddress +
                           image->sections[i].PointerToRawData;
            break;
        }
    }

    if (importOffset > 0 && importOffset + importDir.Size <= image->rawSize) {
        memset(image->rawData + importOffset, 0, importDir.Size);
    }

    // 清空 IAT 内容
    for (auto& dll : image->imports.dlls) {
        DWORD iatOffset = 0;
        for (WORD i = 0; i < image->numSections; i++) {
            if (image->sections[i].VirtualAddress <= dll.firstThunkRVA &&
                image->sections[i].VirtualAddress + image->sections[i].SizeOfRawData > dll.firstThunkRVA) {
                iatOffset = dll.firstThunkRVA - image->sections[i].VirtualAddress +
                            image->sections[i].PointerToRawData;
                break;
            }
        }

        if (iatOffset > 0) {
            DWORD iatSize = (DWORD)dll.functions.size() * (image->is64Bit ? 8 : 4);
            if (iatOffset + iatSize <= image->rawSize) {
                memset(image->rawData + iatOffset, 0, iatSize);
            }
        }
    }

    return true;
}

bool ImportObfuscator::GenerateFakeImports(CS_PE_IMAGE* image, uint32_t count) {
    if (!image || !image->isValid || count == 0) {
        return false;
    }

    // 生成假的导入 DLL 和函数
    for (uint32_t i = 0; i < count; i++) {
        CS_IMPORT_DLL fakeDll;
        fakeDll.dllName = GenerateRandomDLLName();
        fakeDll.originalFirstThunkRVA = 0;
        fakeDll.firstThunkRVA = 0;

        // 为每个 DLL 生成 1-3 个假函数
        int funcCount = rand() % 3 + 1;
        for (int j = 0; j < funcCount; j++) {
            CS_IMPORT_FUNCTION fakeFunc;
            fakeFunc.name = GenerateRandomFuncName();
            fakeFunc.ordinal = 0;
            fakeFunc.thunkRVA = 0;
            fakeFunc.isOrdinal = false;

            fakeDll.functions.push_back(fakeFunc);
        }

        image->imports.dlls.push_back(fakeDll);
    }

    return true;
}

// ============================================================================
// 策略实现
// ============================================================================

bool ImportObfuscator::ApplyStrategyA(
    CS_PE_IMAGE* image,
    const CS_IMPORT_OBFUSCATION_CONFIG& config,
    APIResolver* resolver)
{
    // 策略A：清空 IAT，只保留 LoadLibraryA 和 GetProcAddress
    // 其余所有 API 调用改为运行时 hash resolve

    // 保留关键导入
    if (config.preserveCriticalImports) {
        // 只保留 kernel32!LoadLibraryA 和 kernel32!GetProcAddress
        // 其他全部清除
    }

    // 清空原始导入表
    return ClearOriginalImports(image);
}

bool ImportObfuscator::ApplyStrategyB(
    CS_PE_IMAGE* image,
    const CS_IMPORT_OBFUSCATION_CONFIG& config,
    APIResolver* resolver)
{
    // 策略B：生成假导入表，真实调用通过 hash resolve

    // 先应用策略A
    if (!ApplyStrategyA(image, config, resolver)) {
        return false;
    }

    // 生成假导入
    return GenerateFakeImports(image, config.fakeImportCount);
}

bool ImportObfuscator::ApplyStrategyC(
    CS_PE_IMAGE* image,
    const CS_IMPORT_OBFUSCATION_CONFIG& config,
    APIResolver* resolver)
{
    // 策略C：混合模式
    // 真实 API 用 hash resolve，同时保留一组无关的假导入表

    // 保留关键导入（LoadLibraryA, GetProcAddress）
    // 其他真实 API 改为 hash resolve
    // 生成假导入表作为干扰

    // 先应用策略B
    return ApplyStrategyB(image, config, resolver);
}

// ============================================================================
// 辅助函数
// ============================================================================

bool ImportObfuscator::IsCriticalImport(const char* dllName, const char* funcName) {
    if (!dllName || !funcName) return false;

    // 检查是否是关键导入
    if (_stricmp(dllName, "kernel32.dll") == 0) {
        if (_stricmp(funcName, "LoadLibraryA") == 0 ||
            _stricmp(funcName, "LoadLibraryW") == 0 ||
            _stricmp(funcName, "GetProcAddress") == 0 ||
            _stricmp(funcName, "GetModuleHandleA") == 0 ||
            _stricmp(funcName, "GetModuleHandleW") == 0) {
            return true;
        }
    }

    return false;
}

std::string ImportObfuscator::GenerateRandomDLLName() {
    int index = rand() % (sizeof(s_fakeDLLNames) / sizeof(s_fakeDLLNames[0]));
    return s_fakeDLLNames[index];
}

std::string ImportObfuscator::GenerateRandomFuncName() {
    int index = rand() % (sizeof(s_fakeFuncNames) / sizeof(s_fakeFuncNames[0]));
    return s_fakeFuncNames[index];
}

} // namespace CipherShell
