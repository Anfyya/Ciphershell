/**
 * CipherShell 导入表混淆器 - 实现
 */

#include "import_obfuscator.h"
#include "../pe_parser/pe_emitter.h"
#include "../pe_parser/pe_utils.h"
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <algorithm>
#include <new>

namespace CipherShell {

namespace {
uint32_t AlignUp32(uint32_t value, uint32_t alignment) {
    if (alignment == 0) return value;
    return (value + alignment - 1u) & ~(alignment - 1u);
}

void AppendCString(std::vector<uint8_t>& data, const char* value) {
    if (!value) return;
    while (*value) data.push_back(static_cast<uint8_t>(*value++));
    data.push_back(0);
}

void ResizeAligned(std::vector<uint8_t>& data, uint32_t alignment) {
    data.resize(AlignUp32(static_cast<uint32_t>(data.size()), alignment), 0);
}

bool IsNullImportDescriptor(const IMAGE_IMPORT_DESCRIPTOR& descriptor) {
    return descriptor.OriginalFirstThunk == 0 && descriptor.TimeDateStamp == 0 &&
        descriptor.ForwarderChain == 0 && descriptor.Name == 0 && descriptor.FirstThunk == 0;
}

IMAGE_DATA_DIRECTORY GetImportDirectory(const CS_PE_IMAGE* image) {
    return image->is64Bit
        ? image->ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
        : image->ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
}

void SetImportDirectory(CS_PE_IMAGE* image, uint32_t rva, uint32_t size) {
    if (image->is64Bit) {
        image->ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = rva;
        image->ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = size;
        image->ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT] = {};
    } else {
        image->ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = rva;
        image->ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = size;
        image->ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT] = {};
    }
}

const char* kSafeKernel32FakeImports[] = {
    "GetTickCount",
    "GetCurrentProcessId",
    "GetCurrentThreadId",
    "GetLastError",
    "SetLastError",
    "GetCommandLineA",
    "GetCommandLineW",
    "GetModuleHandleA",
    "GetModuleHandleW",
    "QueryPerformanceCounter",
    "GetSystemTime",
    "GetLocalTime",
    "GetStdHandle",
    "GetEnvironmentStringsW",
    "FreeEnvironmentStringsW"
};
}

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

    m_applied = false;
    m_writtenFakeImportCount = 0;
    m_lastError.clear();
    m_generatedFakeImports.clear();

    if (!image || !image->isValid || !resolver) {
        m_lastError = "invalid image or API resolver";
        return result;
    }

    const std::vector<CS_IMPORT_DLL> originalImports = image->imports.dlls;

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
        if (m_lastError.empty()) m_lastError = "import protection strategy failed";
        return result;
    }

    // 收集混淆后的导入信息
    // 遍历原始导入表，为每个函数生成哈希
    // BUG 13 修复：使用 std::string 拷贝代替 c_str() 裸指针，
    // 避免源 string 销毁或 vector 重分配后指针悬空。
    for (const auto& dll : originalImports) {
        for (const auto& func : dll.functions) {
            CS_OBFUSCATED_IMPORT obfImport;
            obfImport.dllHash = APIResolver::HashString(dll.dllName.c_str());
            obfImport.dllName = dll.dllName;  // std::string 拷贝

            if (func.isOrdinal) {
                // 按序号导入：使用序号作为哈希
                obfImport.funcHash = func.ordinal;
                obfImport.funcName = "";
            } else {
                obfImport.funcHash = APIResolver::HashString(func.name.c_str());
                obfImport.funcName = func.name;  // std::string 拷贝
            }

            obfImport.originalRVA = func.thunkRVA;
            obfImport.isFake = false;

            result.push_back(obfImport);
        }
    }

    result.insert(result.end(), m_generatedFakeImports.begin(), m_generatedFakeImports.end());
    m_applied = true;

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

    // 清空导入表内容（但保留目录项）；改走 PEEmitter::FillBytes 而不是手算
    // section 命中区间再对 image->rawData 落笔——RVA→文件偏移与越界校验统一
    // 由 emitter 负责，不再由每个调用方各自重算一遍。
    PEEmitter emitter(image);
    emitter.FillBytes(importDir.VirtualAddress, importDir.Size, 0, nullptr);

    // 清空 IAT 内容
    for (auto& dll : image->imports.dlls) {
        const DWORD iatSize = (DWORD)dll.functions.size() * (image->is64Bit ? 8 : 4);
        if (iatSize != 0) {
            emitter.FillBytes(dll.firstThunkRVA, iatSize, 0, nullptr);
        }
    }

    return true;
}

bool ImportObfuscator::GenerateFakeImports(CS_PE_IMAGE* image, uint32_t count) {
    if (!image || !image->isValid || count == 0) {
        m_lastError = "invalid image or zero fake import count";
        return false;
    }

    const uint32_t catalogCount = static_cast<uint32_t>(
        sizeof(kSafeKernel32FakeImports) / sizeof(kSafeKernel32FakeImports[0]));
    count = (std::min)(count, catalogCount);

    std::vector<IMAGE_IMPORT_DESCRIPTOR> originalDescriptors;
    const IMAGE_DATA_DIRECTORY importDir = GetImportDirectory(image);
    if (importDir.VirtualAddress != 0 && importDir.Size != 0) {
        const uint32_t importOffset = PEUtils::RvaToOffset(image, importDir.VirtualAddress);
        const uint32_t maxDescriptors = importDir.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
        if (importOffset == 0 || maxDescriptors == 0 ||
            !PEUtils::CheckRawBounds(image, importOffset, importDir.Size)) {
            m_lastError = "original import directory is outside file bounds";
            return false;
        }

        bool foundTerminator = false;
        for (uint32_t i = 0; i < maxDescriptors; i++) {
            IMAGE_IMPORT_DESCRIPTOR descriptor{};
            std::memcpy(&descriptor,
                image->rawData + importOffset + i * sizeof(IMAGE_IMPORT_DESCRIPTOR),
                sizeof(descriptor));
            if (IsNullImportDescriptor(descriptor)) {
                foundTerminator = true;
                break;
            }
            originalDescriptors.push_back(descriptor);
        }
        if (!foundTerminator) {
            m_lastError = "original import descriptor table has no terminator";
            return false;
        }
    }

    const uint32_t descriptorCount = static_cast<uint32_t>(originalDescriptors.size()) + 2u;
    const uint32_t descriptorBytes = descriptorCount * sizeof(IMAGE_IMPORT_DESCRIPTOR);
    std::vector<uint8_t> section(descriptorBytes, 0);
    if (!originalDescriptors.empty()) {
        std::memcpy(section.data(), originalDescriptors.data(),
            originalDescriptors.size() * sizeof(IMAGE_IMPORT_DESCRIPTOR));
    }

    const uint32_t dllNameOffset = static_cast<uint32_t>(section.size());
    AppendCString(section, "kernel32.dll");
    ResizeAligned(section, 2);

    std::vector<uint32_t> hintNameOffsets;
    hintNameOffsets.reserve(count);
    for (uint32_t i = 0; i < count; i++) {
        hintNameOffsets.push_back(static_cast<uint32_t>(section.size()));
        section.push_back(0);
        section.push_back(0);
        AppendCString(section, kSafeKernel32FakeImports[i]);
        ResizeAligned(section, 2);
    }

    const uint32_t thunkSize = image->is64Bit ? 8u : 4u;
    ResizeAligned(section, thunkSize);
    const uint32_t iltOffset = static_cast<uint32_t>(section.size());
    section.resize(section.size() + (count + 1u) * thunkSize, 0);
    const uint32_t iatOffset = static_cast<uint32_t>(section.size());
    section.resize(section.size() + (count + 1u) * thunkSize, 0);

    char sectionName[8] = {'.','c','s','i','m','p',0,0};
    PEEmitter emitter(image);
    auto append = emitter.AppendSection(
        sectionName,
        section,
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);
    if (!append.success) {
        m_lastError = "failed to append rebuilt import section: " + append.error;
        return false;
    }

    // 新 section 的内容一律通过 PEEmitter::PatchBytes 写入，而不是直接对
    // image->rawData + 偏移落笔，使越界写入在 PatchBytes 内部的
    // CheckedAdd/rawSize 校验中 fail-closed，不依赖调用方手算偏移永远正确。
    IMAGE_IMPORT_DESCRIPTOR fakeDescriptor{};
    fakeDescriptor.OriginalFirstThunk = append.rva + iltOffset;
    fakeDescriptor.Name = append.rva + dllNameOffset;
    fakeDescriptor.FirstThunk = append.rva + iatOffset;
    std::vector<uint8_t> fakeDescriptorBytes(sizeof(fakeDescriptor));
    std::memcpy(fakeDescriptorBytes.data(), &fakeDescriptor, sizeof(fakeDescriptor));
    const uint32_t fakeDescriptorRVA = append.rva +
        static_cast<uint32_t>(originalDescriptors.size() * sizeof(IMAGE_IMPORT_DESCRIPTOR));
    std::string patchError;
    if (!emitter.PatchBytes(fakeDescriptorRVA, fakeDescriptorBytes, &patchError)) {
        m_lastError = "failed to patch fake import descriptor: " + patchError;
        return false;
    }

    CS_IMPORT_DLL fakeDll{};
    fakeDll.dllName = "kernel32.dll";
    fakeDll.originalFirstThunkRVA = fakeDescriptor.OriginalFirstThunk;
    fakeDll.firstThunkRVA = fakeDescriptor.FirstThunk;

    for (uint32_t i = 0; i < count; i++) {
        const uint64_t hintNameRVA = static_cast<uint64_t>(append.rva) + hintNameOffsets[i];
        std::vector<uint8_t> thunkBytes(thunkSize);
        std::memcpy(thunkBytes.data(), &hintNameRVA, thunkSize);
        if (!emitter.PatchBytes(append.rva + iltOffset + i * thunkSize, thunkBytes, &patchError) ||
            !emitter.PatchBytes(append.rva + iatOffset + i * thunkSize, thunkBytes, &patchError)) {
            m_lastError = "failed to patch fake import thunk: " + patchError;
            return false;
        }

        CS_IMPORT_FUNCTION fakeFunction{};
        fakeFunction.name = kSafeKernel32FakeImports[i];
        fakeFunction.thunkRVA = append.rva + iatOffset + i * thunkSize;
        fakeDll.functions.push_back(fakeFunction);

        CS_OBFUSCATED_IMPORT fakeRecord{};
        fakeRecord.dllHash = APIResolver::HashString("kernel32.dll");
        fakeRecord.funcHash = APIResolver::HashString(kSafeKernel32FakeImports[i]);
        fakeRecord.originalRVA = fakeFunction.thunkRVA;
        fakeRecord.dllName = "kernel32.dll";
        fakeRecord.funcName = fakeFunction.name;
        fakeRecord.isFake = true;
        m_generatedFakeImports.push_back(fakeRecord);
    }

    image->imports.dlls.push_back(fakeDll);
    SetImportDirectory(image, append.rva, descriptorBytes);
    m_writtenFakeImportCount = count;

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
    // Strategy A is fail-closed until callsites and the runtime resolver are linked.
    (void)image; (void)config; (void)resolver;
    m_lastError = "runtime resolver callsite rewrite is not implemented";
    return false;
}

bool ImportObfuscator::ApplyStrategyB(
    CS_PE_IMAGE* image,
    const CS_IMPORT_OBFUSCATION_CONFIG& config,
    APIResolver* resolver)
{
    (void)resolver;
    return GenerateFakeImports(image, config.fakeImportCount);
}

bool ImportObfuscator::ApplyStrategyC(
    CS_PE_IMAGE* image,
    const CS_IMPORT_OBFUSCATION_CONFIG& config,
    APIResolver* resolver)
{
    (void)image; (void)config; (void)resolver;
    m_lastError = "hybrid import protection requires runtime resolver callsite rewrite";
    return false;
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
