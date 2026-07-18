/**
 * CipherShell PE Parser - 实现
 */

#include "pe_parser.h"
#include <cstddef>
#include "pe_utils.h"
#include <cstring>
#include <algorithm>
#include <sstream>

namespace CipherShell {

namespace {
bool IsPowerOfTwo(uint32_t value) {
    return value != 0 && (value & (value - 1u)) == 0;
}

// 纯诊断用途：把数值格式化进错误信息，不参与任何校验判定。
std::string IntToHex(uint64_t value) {
    std::ostringstream stream;
    stream << std::hex << value;
    return stream.str();
}

bool CheckedAdd(DWORD left, DWORD right, DWORD& result) {
    const uint64_t sum = static_cast<uint64_t>(left) + right;
    if (sum > 0xFFFFFFFFull) return false;
    result = static_cast<DWORD>(sum);
    return true;
}

bool ReadCString(const CS_PE_IMAGE* image, DWORD offset, std::string& value) {
    if (!image || !image->rawData || offset >= image->rawSize) return false;
    const char* begin = reinterpret_cast<const char*>(image->rawData + offset);
    const void* end = std::memchr(begin, '\0', image->rawSize - offset);
    if (!end) return false;
    value.assign(begin, static_cast<const char*>(end));
    return true;
}

}

// ============================================================================
// 构造/析构
// ============================================================================

PEParser::PEParser() {}

PEParser::~PEParser() {}

// ============================================================================
// 公共接口
// ============================================================================

CS_PE_IMAGE* PEParser::LoadFromFile(const std::string& filePath) {
    // 打开文件
    HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        return nullptr;
    }

    // 获取文件大小
    DWORD fileSize = GetFileSize(hFile, nullptr);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        CloseHandle(hFile);
        return nullptr;
    }

    BYTE* buffer = new(std::nothrow) BYTE[fileSize];
    if (!buffer) {
        CloseHandle(hFile);
        return nullptr;
    }

    // 读取文件
    DWORD bytesRead;
    if (!ReadFile(hFile, buffer, fileSize, &bytesRead, nullptr) || bytesRead != fileSize) {
        delete[] buffer;
        CloseHandle(hFile);
        return nullptr;
    }
    CloseHandle(hFile);

    // 解析
    CS_PE_IMAGE* image = LoadFromBuffer(buffer, fileSize);
    if (image) {
        image->filePath = filePath;
        // 注意：rawData 的所有权转移到 image，不再 delete
    } else {
        delete[] buffer;
    }

    return image;
}

CS_PE_IMAGE* PEParser::LoadFromBuffer(BYTE* buffer, DWORD size) {
    if (!buffer || size < sizeof(IMAGE_DOS_HEADER)) {
        return nullptr;
    }

    // 创建 PE 镜像
    CS_PE_IMAGE* image = new(std::nothrow) CS_PE_IMAGE();
    if (!image) {
        return nullptr;
    }

    image->rawData = buffer;
    image->rawSize = size;
    image->isValid = FALSE;

    // 验证基本 PE 结构
    if (!IsValidPE(image)) {
        SetError(image, "Invalid PE file");
        return image;
    }

    if (!ParseHeaders(image)) {
        return image;
    }

    // 解析数据目录
    if (!ParseDataDirectories(image)) {
        return image;
    }

    // 解析 Rich Header
    ParseRichHeader(image);

    // 检测 .NET
    DetectDotNet(image);

    // 检测 Overlay
    DetectOverlay(image);

    image->isValid = TRUE;
    return image;
}

void PEParser::FreeImage(CS_PE_IMAGE* image) {
    if (image) {
        if (image->rawData) {
            delete[] image->rawData;
        }
        delete image;
    }
}

// ============================================================================
// 头部解析
// ============================================================================

bool PEParser::ParseHeaders(CS_PE_IMAGE* image) {
    image->dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(image->rawData);
    if (image->dosHeader->e_lfanew < 0) {
        SetError(image, "Negative NT headers offset");
        return false;
    }

    const DWORD ntOffset = static_cast<DWORD>(image->dosHeader->e_lfanew);
    const DWORD ntPrefixSize = sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    if (!CheckBounds(image, ntOffset, ntPrefixSize)) {
        SetError(image, "Invalid NT headers offset");
        return false;
    }

    const DWORD signature = *reinterpret_cast<const DWORD*>(image->rawData + ntOffset);
    if (signature != IMAGE_NT_SIGNATURE) {
        SetError(image, "Invalid PE signature");
        return false;
    }

    PIMAGE_FILE_HEADER fileHeader = reinterpret_cast<PIMAGE_FILE_HEADER>(
        image->rawData + ntOffset + sizeof(DWORD));
    const DWORD optionalOffset = ntOffset + ntPrefixSize;
    if (!CheckBounds(image, optionalOffset, fileHeader->SizeOfOptionalHeader)) {
        SetError(image, "Optional header exceeds file bounds");
        return false;
    }
    if (fileHeader->NumberOfSections == 0 || fileHeader->NumberOfSections > 96) {
        SetError(image, "Invalid section count");
        return false;
    }

    if (fileHeader->Machine == IMAGE_FILE_MACHINE_AMD64) {
        if (fileHeader->SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64)) {
            SetError(image, "Truncated PE32+ optional header");
            return false;
        }
        image->is64Bit = TRUE;
        image->ntHeaders64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(image->rawData + ntOffset);
        image->ntHeaders32 = nullptr;
        if (image->ntHeaders64->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            SetError(image, "Invalid PE32+ optional header magic");
            return false;
        }
    } else if (fileHeader->Machine == IMAGE_FILE_MACHINE_I386) {
        if (fileHeader->SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER32)) {
            SetError(image, "Truncated PE32 optional header");
            return false;
        }
        image->is64Bit = FALSE;
        image->ntHeaders32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(image->rawData + ntOffset);
        image->ntHeaders64 = nullptr;
        if (image->ntHeaders32->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            SetError(image, "Invalid PE32 optional header magic");
            return false;
        }
    } else {
        SetError(image, "Unsupported machine type");
        return false;
    }

    const DWORD sectionOffset = optionalOffset + fileHeader->SizeOfOptionalHeader;
    const uint64_t sectionBytes = static_cast<uint64_t>(fileHeader->NumberOfSections) *
        sizeof(IMAGE_SECTION_HEADER);
    if (sectionBytes > 0xFFFFFFFFull ||
        !CheckBounds(image, sectionOffset, static_cast<DWORD>(sectionBytes))) {
        SetError(image, "Section headers exceed file bounds");
        return false;
    }

    image->numSections = fileHeader->NumberOfSections;
    image->sections = reinterpret_cast<PIMAGE_SECTION_HEADER>(image->rawData + sectionOffset);

    const DWORD fileAlignment = image->is64Bit
        ? image->ntHeaders64->OptionalHeader.FileAlignment
        : image->ntHeaders32->OptionalHeader.FileAlignment;
    const DWORD sectionAlignment = image->is64Bit
        ? image->ntHeaders64->OptionalHeader.SectionAlignment
        : image->ntHeaders32->OptionalHeader.SectionAlignment;
    if (!IsPowerOfTwo(fileAlignment) || !IsPowerOfTwo(sectionAlignment) ||
        sectionAlignment < fileAlignment) {
        SetError(image, "Invalid PE alignment values");
        return false;
    }

    for (WORD i = 0; i < image->numSections; i++) {
        const IMAGE_SECTION_HEADER& section = image->sections[i];
        if (section.SizeOfRawData != 0 &&
            !CheckBounds(image, section.PointerToRawData, section.SizeOfRawData)) {
            SetError(image, "Section raw data exceeds file bounds");
            return false;
        }
        const uint64_t virtualEnd = static_cast<uint64_t>(section.VirtualAddress) +
            (std::max)(static_cast<uint32_t>(section.Misc.VirtualSize),
                       static_cast<uint32_t>(section.SizeOfRawData));
        if (virtualEnd > 0x100000000ull) {
            SetError(image, "Section virtual range overflows RVA space");
            return false;
        }
    }

    return true;
}

// ============================================================================
// 数据目录解析
// ============================================================================

bool PEParser::ParseDataDirectories(CS_PE_IMAGE* image) {
    auto directory = [image](size_t index) -> IMAGE_DATA_DIRECTORY {
        const DWORD count = image->is64Bit
            ? image->ntHeaders64->OptionalHeader.NumberOfRvaAndSizes
            : image->ntHeaders32->OptionalHeader.NumberOfRvaAndSizes;
        if (index >= count || index >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return {};
        return image->is64Bit
            ? image->ntHeaders64->OptionalHeader.DataDirectory[index]
            : image->ntHeaders32->OptionalHeader.DataDirectory[index];
    };
    auto parseIfPresent = [&](size_t index, bool (PEParser::*parser)(CS_PE_IMAGE*),
                              const char* name) {
        const IMAGE_DATA_DIRECTORY dir = directory(index);
        if (dir.VirtualAddress == 0 && dir.Size == 0) return true;
        if (dir.VirtualAddress == 0 || dir.Size == 0) {
            SetError(image, std::string("Malformed ") + name + " directory");
            return false;
        }
        if (!(this->*parser)(image)) {
            // 部分 parser（目前是 ParseLoadConfig）在失败前已经用 SetError
            // 写入了具体是哪个校验、哪些数值触发的失败；不要用这条通用消息
            // 把那份诊断信息覆盖掉。其余还没做到这一步的 parser 继续用这条
            // 通用消息兜底，行为不变。
            if (image->errorMessage.empty()) {
                SetError(image, std::string("Malformed ") + name + " directory");
            }
            return false;
        }
        return true;
    };

    return parseIfPresent(IMAGE_DIRECTORY_ENTRY_IMPORT, &PEParser::ParseImportTable, "import") &&
        parseIfPresent(IMAGE_DIRECTORY_ENTRY_EXPORT, &PEParser::ParseExportTable, "export") &&
        parseIfPresent(IMAGE_DIRECTORY_ENTRY_BASERELOC, &PEParser::ParseRelocationTable, "relocation") &&
        parseIfPresent(IMAGE_DIRECTORY_ENTRY_RESOURCE, &PEParser::ParseResourceTable, "resource") &&
        parseIfPresent(IMAGE_DIRECTORY_ENTRY_TLS, &PEParser::ParseTLS, "TLS") &&
        (!image->is64Bit || parseIfPresent(IMAGE_DIRECTORY_ENTRY_EXCEPTION,
            &PEParser::ParseExceptionTable, "exception")) &&
        parseIfPresent(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, &PEParser::ParseLoadConfig, "load config") &&
        parseIfPresent(IMAGE_DIRECTORY_ENTRY_DEBUG, &PEParser::ParseDebugDirectory, "debug") &&
        parseIfPresent(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, &PEParser::ParseDelayImports, "delay import") &&
        parseIfPresent(IMAGE_DIRECTORY_ENTRY_SECURITY, &PEParser::ParseSecurity, "security");
}

// ============================================================================
// 导入表解析
// ============================================================================

bool PEParser::ParseImportTable(CS_PE_IMAGE* image) {
    IMAGE_DATA_DIRECTORY importDir;
    if (image->is64Bit) {
        importDir = image->ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    } else {
        importDir = image->ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    }

    if (importDir.VirtualAddress == 0 || importDir.Size == 0) {
        return false;
    }

    DWORD importOffset = RVAToOffset(image, importDir.VirtualAddress);
    if (importOffset == 0 || !CheckBounds(image, importOffset, importDir.Size)) {
        return false;
    }
    const DWORD descriptorCount = importDir.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
    if (descriptorCount == 0) return false;
    bool terminated = false;

    for (DWORD descriptorIndex = 0; descriptorIndex < descriptorCount; ++descriptorIndex) {
        IMAGE_IMPORT_DESCRIPTOR descriptor{};
        std::memcpy(&descriptor,
            image->rawData + importOffset + descriptorIndex * sizeof(descriptor),
            sizeof(descriptor));
        if (descriptor.Name == 0 && descriptor.FirstThunk == 0 &&
            descriptor.OriginalFirstThunk == 0) {
            terminated = true;
            break;
        }
        CS_IMPORT_DLL importDll;

        // DLL 名称
        const DWORD nameOffset = RVAToOffset(image, descriptor.Name);
        if (nameOffset == 0 || !ReadCString(image, nameOffset, importDll.dllName)) return false;
        importDll.originalFirstThunkRVA = descriptor.OriginalFirstThunk;
        importDll.firstThunkRVA = descriptor.FirstThunk;

        DWORD iltOffset = RVAToOffset(image, descriptor.OriginalFirstThunk);
        const DWORD iatOffset = RVAToOffset(image, descriptor.FirstThunk);

        if (iltOffset == 0) {
            // 某些情况下 ILT 可能为0，使用 IAT
            iltOffset = iatOffset;
        }

        if (iltOffset == 0 || iatOffset == 0) return false;
        {
            const DWORD thunkSize = image->is64Bit
                ? sizeof(IMAGE_THUNK_DATA64) : sizeof(IMAGE_THUNK_DATA32);
            const DWORD maxThunks = (std::min)(
                (image->rawSize - iltOffset) / thunkSize,
                (image->rawSize - iatOffset) / thunkSize);
            bool thunkTerminated = false;
            if (image->is64Bit) {
                for (DWORD thunkIndex = 0; thunkIndex < maxThunks; ++thunkIndex) {
                    IMAGE_THUNK_DATA64 ilt{};
                    std::memcpy(&ilt, image->rawData + iltOffset + thunkIndex * thunkSize,
                        sizeof(ilt));
                    if (ilt.u1.AddressOfData == 0) {
                        thunkTerminated = true;
                        break;
                    }
                    CS_IMPORT_FUNCTION func;
                    func.thunkRVA = descriptor.FirstThunk + thunkIndex * thunkSize;

                    if (IMAGE_SNAP_BY_ORDINAL64(ilt.u1.Ordinal)) {
                        // 按序号导入
                        func.isOrdinal = true;
                        func.ordinal = IMAGE_ORDINAL64(ilt.u1.Ordinal);
                    } else {
                        // 按名称导入
                        func.isOrdinal = false;
                        if (ilt.u1.AddressOfData > 0xFFFFFFFFull) return false;
                        const DWORD hintNameOffset = RVAToOffset(
                            image, static_cast<DWORD>(ilt.u1.AddressOfData));
                        if (hintNameOffset == 0 || !CheckBounds(image, hintNameOffset, sizeof(WORD)) ||
                            !ReadCString(image, hintNameOffset + sizeof(WORD), func.name)) return false;
                        std::memcpy(&func.ordinal, image->rawData + hintNameOffset, sizeof(WORD));
                    }

                    importDll.functions.push_back(func);
                }
            } else {
                for (DWORD thunkIndex = 0; thunkIndex < maxThunks; ++thunkIndex) {
                    IMAGE_THUNK_DATA32 ilt{};
                    std::memcpy(&ilt, image->rawData + iltOffset + thunkIndex * thunkSize,
                        sizeof(ilt));
                    if (ilt.u1.AddressOfData == 0) {
                        thunkTerminated = true;
                        break;
                    }
                    CS_IMPORT_FUNCTION func;
                    func.thunkRVA = descriptor.FirstThunk + thunkIndex * thunkSize;

                    if (IMAGE_SNAP_BY_ORDINAL32(ilt.u1.Ordinal)) {
                        func.isOrdinal = true;
                        func.ordinal = IMAGE_ORDINAL32(ilt.u1.Ordinal);
                    } else {
                        func.isOrdinal = false;
                        const DWORD hintNameOffset = RVAToOffset(image, ilt.u1.AddressOfData);
                        if (hintNameOffset == 0 || !CheckBounds(image, hintNameOffset, sizeof(WORD)) ||
                            !ReadCString(image, hintNameOffset + sizeof(WORD), func.name)) return false;
                        std::memcpy(&func.ordinal, image->rawData + hintNameOffset, sizeof(WORD));
                    }

                    importDll.functions.push_back(func);
                }
            }
            if (!thunkTerminated) return false;
        }

        image->imports.dlls.push_back(importDll);
    }
    return terminated;
}

// ============================================================================
// 导出表解析
// ============================================================================

bool PEParser::ParseExportTable(CS_PE_IMAGE* image) {
    IMAGE_DATA_DIRECTORY exportDir;
    if (image->is64Bit) {
        exportDir = image->ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    } else {
        exportDir = image->ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    }

    if (exportDir.VirtualAddress == 0 || exportDir.Size == 0) {
        return false;
    }

    DWORD exportOffset = RVAToOffset(image, exportDir.VirtualAddress);
    if (exportOffset == 0 || !CheckBounds(image, exportOffset, sizeof(IMAGE_EXPORT_DIRECTORY))) {
        return false;
    }

    IMAGE_EXPORT_DIRECTORY exportDirectory{};
    std::memcpy(&exportDirectory, image->rawData + exportOffset, sizeof(exportDirectory));
    const IMAGE_EXPORT_DIRECTORY* exportDirPtr = &exportDirectory;
    if (exportDirPtr->NumberOfFunctions > image->rawSize / sizeof(DWORD) ||
        exportDirPtr->NumberOfNames > exportDirPtr->NumberOfFunctions) return false;

    // DLL 名称
    DWORD dllNameOffset = RVAToOffset(image, exportDirPtr->Name);
    if (dllNameOffset == 0 || !ReadCString(image, dllNameOffset, image->exports.dllName)) return false;
    image->exports.ordinalBase = exportDirPtr->Base;

    // 获取函数、名称、序号表
    DWORD functionsOffset = RVAToOffset(image, exportDirPtr->AddressOfFunctions);
    DWORD namesOffset = RVAToOffset(image, exportDirPtr->AddressOfNames);
    DWORD ordinalsOffset = RVAToOffset(image, exportDirPtr->AddressOfNameOrdinals);

    const uint64_t functionBytes = static_cast<uint64_t>(exportDirPtr->NumberOfFunctions) * sizeof(DWORD);
    const uint64_t nameBytes = static_cast<uint64_t>(exportDirPtr->NumberOfNames) * sizeof(DWORD);
    const uint64_t ordinalBytes = static_cast<uint64_t>(exportDirPtr->NumberOfNames) * sizeof(WORD);
    if (functionsOffset == 0 || functionBytes > 0xFFFFFFFFull ||
        !CheckBounds(image, functionsOffset, static_cast<DWORD>(functionBytes)) ||
        (exportDirPtr->NumberOfNames != 0 &&
            (namesOffset == 0 || ordinalsOffset == 0 || nameBytes > 0xFFFFFFFFull ||
             ordinalBytes > 0xFFFFFFFFull ||
             !CheckBounds(image, namesOffset, static_cast<DWORD>(nameBytes)) ||
             !CheckBounds(image, ordinalsOffset, static_cast<DWORD>(ordinalBytes))))) return false;

    DWORD* functions = (DWORD*)(image->rawData + functionsOffset);
    DWORD* names = namesOffset ? (DWORD*)(image->rawData + namesOffset) : nullptr;
    WORD* ordinals = ordinalsOffset ? (WORD*)(image->rawData + ordinalsOffset) : nullptr;

    // 构建序号到名称的映射
    std::vector<std::string> ordinalToName(exportDirPtr->NumberOfFunctions);
    if (names && ordinals) {
        for (DWORD i = 0; i < exportDirPtr->NumberOfNames; i++) {
            WORD ordinal = ordinals[i];
            if (ordinal < exportDirPtr->NumberOfFunctions) {
                DWORD nameOffset = RVAToOffset(image, names[i]);
                if (nameOffset == 0 || !ReadCString(image, nameOffset, ordinalToName[ordinal]))
                    return false;
            }
        }
    }

    // 构建导出函数列表
    for (DWORD i = 0; i < exportDirPtr->NumberOfFunctions; i++) {
        if (functions[i] == 0) continue;  // 空槽位
        CS_EXPORT_FUNCTION func;
        func.ordinal = (WORD)(i + exportDirPtr->Base);
        func.functionRVA = functions[i];
        func.name = ordinalToName[i];

        const uint64_t exportEnd = static_cast<uint64_t>(exportDir.VirtualAddress) + exportDir.Size;
        if (functions[i] >= exportDir.VirtualAddress && functions[i] < exportEnd) {
            func.isForwarded = true;
            DWORD forwarderOffset = RVAToOffset(image, functions[i]);
            if (forwarderOffset == 0 || !ReadCString(image, forwarderOffset, func.forwarderName))
                return false;
        } else {
            func.isForwarded = false;
        }

        image->exports.functions.push_back(func);
    }

    return true;
}

// ============================================================================
// 重定位表解析
// ============================================================================

bool PEParser::ParseRelocationTable(CS_PE_IMAGE* image) {
    IMAGE_DATA_DIRECTORY relocDir;
    if (image->is64Bit) {
        relocDir = image->ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    } else {
        relocDir = image->ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    }

    if (relocDir.VirtualAddress == 0 || relocDir.Size == 0) {
        return false;
    }

    DWORD relocOffset = RVAToOffset(image, relocDir.VirtualAddress);
    if (relocOffset == 0 || !CheckBounds(image, relocOffset, relocDir.Size)) {
        return false;
    }

    DWORD currentOffset = relocOffset;
    DWORD endOffset = 0;
    if (!CheckedAdd(relocOffset, relocDir.Size, endOffset)) return false;

    while (currentOffset < endOffset) {
        if (!CheckBounds(image, currentOffset, sizeof(IMAGE_BASE_RELOCATION))) return false;

        PIMAGE_BASE_RELOCATION relocBlock = (PIMAGE_BASE_RELOCATION)(image->rawData + currentOffset);

        if (relocBlock->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
            (relocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) % sizeof(WORD) != 0 ||
            relocBlock->SizeOfBlock > endOffset - currentOffset) return false;
        if (relocBlock->VirtualAddress == 0) return false;

        DWORD entryCount = (relocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* entries = (WORD*)(image->rawData + currentOffset + sizeof(IMAGE_BASE_RELOCATION));

        for (DWORD i = 0; i < entryCount; i++) {
            WORD entry = entries[i];
            WORD type = entry >> 12;
            WORD offset = entry & 0xFFF;

            if (type == IMAGE_REL_BASED_ABSOLUTE) {
                continue;
            }

            CS_RELOC_ENTRY relocEntry;
            relocEntry.pageRVA = relocBlock->VirtualAddress;
            relocEntry.type = type;
            relocEntry.offset = offset;
            relocEntry.fullRVA = relocBlock->VirtualAddress + offset;

            image->relocs.entries.push_back(relocEntry);
        }

        currentOffset += relocBlock->SizeOfBlock;
    }

    return currentOffset == endOffset;
}

// ============================================================================
// 资源表解析

namespace {
constexpr uint32_t kResourceDepthLimit = 32;
constexpr uint32_t kResourceNodeLimit = 1000000;

struct ResourceParseState {
    const CS_PE_IMAGE* image;
    DWORD base;     // resource directory 起始文件偏移
    DWORD span;     // DataDirectory.Size，树内偏移相对 base
    uint32_t nodesVisited = 0;
    std::vector<uint32_t> path;  // 当前递归路径上的子目录相对偏移，用于环检测
    std::vector<CS_RESOURCE_ENTRY> entries;
    bool failed = false;
    std::string error;

    bool InRange(uint32_t rel, uint32_t size) const {
        return rel <= span && size <= span - rel;
    }
};

// RAII 守卫：确保递归路径在任何退出路径（含提前 return / 异常）下都正确恢复，
// 不留下错误的递归状态用于后续环检测。
struct ResourcePathGuard {
    std::vector<uint32_t>& path;
    ResourcePathGuard(std::vector<uint32_t>& p, uint32_t v) : path(p) { path.push_back(v); }
    ~ResourcePathGuard() { if (!path.empty()) path.pop_back(); }
};

bool ParseResourceSubdir(ResourceParseState& s, uint32_t relOffset, uint32_t depth,
                         CS_RESOURCE_ENTRY cur) {
    if (s.failed) return false;
    if (depth > kResourceDepthLimit) {
        s.failed = true; s.error = "resource tree depth limit exceeded"; return false;
    }
    if (s.nodesVisited++ > kResourceNodeLimit) {
        s.failed = true; s.error = "resource node count limit exceeded"; return false;
    }
    // 用当前递归路径集合检测环，不使用全局 visited，避免误杀合法共享节点。
    for (uint32_t p : s.path) {
        if (p == relOffset) {
            s.failed = true; s.error = "resource tree contains a cycle"; return false;
        }
    }
    // push 后由 guard 在所有退出路径统一 pop，提前 return 也不会留下残余状态。
    ResourcePathGuard guard(s.path, relOffset);

    if (!s.InRange(relOffset, sizeof(IMAGE_RESOURCE_DIRECTORY))) {
        s.failed = true; s.error = "resource directory header out of range"; return false;
    }
    IMAGE_RESOURCE_DIRECTORY dir{};
    std::memcpy(&dir, s.image->rawData + s.base + relOffset, sizeof(dir));

    // NumberOfNamedEntries + NumberOfIdEntries 加法与乘法不溢出。
    const uint64_t namedCount = dir.NumberOfNamedEntries;
    const uint64_t idCount = dir.NumberOfIdEntries;
    const uint64_t total64 = namedCount + idCount;
    const uint64_t entryBytes = total64 * static_cast<uint64_t>(sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));
    if (total64 > 0xFFFF || entryBytes > 0xFFFFFFFFull ||
        !s.InRange(static_cast<uint32_t>(relOffset + sizeof(IMAGE_RESOURCE_DIRECTORY)),
                   static_cast<uint32_t>(entryBytes))) {
        s.failed = true; s.error = "resource directory entry array out of range"; return false;
    }
    const uint32_t total = static_cast<uint32_t>(total64);
    const IMAGE_RESOURCE_DIRECTORY_ENTRY* entries = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY_ENTRY*>(
        s.image->rawData + s.base + relOffset + sizeof(IMAGE_RESOURCE_DIRECTORY));

    for (uint32_t i = 0; i < total; ++i) {
        CS_RESOURCE_ENTRY child = cur;
        const IMAGE_RESOURCE_DIRECTORY_ENTRY& e = entries[i];

        if (e.Name & 0x80000000u) {
            // 名称字符串（相对 base 的偏移）。
            const uint32_t nameRel = e.Name & 0x7FFFFFFFu;
            if (!s.InRange(nameRel, sizeof(WORD))) {
                s.failed = true; s.error = "resource name length field out of range"; return false;
            }
            WORD strLen = 0;
            std::memcpy(&strLen, s.image->rawData + s.base + nameRel, sizeof(WORD));
            const uint64_t strBytes = sizeof(WORD) + static_cast<uint64_t>(strLen) * 2ull;
            if (strBytes > 0xFFFFFFFFull || !s.InRange(nameRel, static_cast<uint32_t>(strBytes))) {
                s.failed = true; s.error = "resource name UTF-16 data truncated/out of range"; return false;
            }
            const WCHAR* wstr = reinterpret_cast<const WCHAR*>(
                s.image->rawData + s.base + nameRel + sizeof(WORD));
            std::string name8;
            name8.reserve(strLen);
            for (WORD c = 0; c < strLen; ++c) {
                const WCHAR ch = wstr[c];
                name8.push_back(ch < 0x80 ? static_cast<char>(ch) : '?');
            }
            child.isNamed = true;
            child.name = std::move(name8);
            if (depth == 1) child.id = 0;
            else if (depth >= 2) child.languageId = 0;
        } else {
            // ID。
            child.isNamed = false;
            const uint32_t idVal = e.Name;
            if (depth == 0) child.type = idVal;
            else if (depth == 1) child.id = idVal;
            else child.languageId = static_cast<WORD>(idVal);
        }

        if (e.OffsetToData & 0x80000000u) {
            // 子目录（相对 base）。
            const uint32_t subRel = e.OffsetToData & 0x7FFFFFFFu;
            if (!ParseResourceSubdir(s, subRel, depth + 1, child)) {
                return false;
            }
        } else {
            // IMAGE_RESOURCE_DATA_ENTRY（相对 base）。
            const uint32_t dataRel = e.OffsetToData;
            if (!s.InRange(dataRel, sizeof(IMAGE_RESOURCE_DATA_ENTRY))) {
                s.failed = true; s.error = "resource data entry out of range"; return false;
            }
            IMAGE_RESOURCE_DATA_ENTRY de{};
            std::memcpy(&de, s.image->rawData + s.base + dataRel, sizeof(de));
            // de.OffsetToData 是 RVA，映射到文件范围。
            const DWORD dataFileOff = PEUtils::RvaToOffset(s.image, de.OffsetToData);
            if (dataFileOff == 0 || de.Size > s.image->rawSize - dataFileOff) {
                s.failed = true; s.error = "resource data RVA+size does not map into the file"; return false;
            }
            child.dataRVA = de.OffsetToData;
            child.dataSize = de.Size;
            s.entries.push_back(child);
        }
    }

    return true;
}
} // namespace

bool PEParser::ParseResourceTable(CS_PE_IMAGE* image) {
    IMAGE_DATA_DIRECTORY resourceDir;
    if (image->is64Bit) {
        resourceDir = image->ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
    } else {
        resourceDir = image->ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
    }

    if (resourceDir.VirtualAddress == 0 || resourceDir.Size == 0) {
        return false;
    }

    const DWORD resourceOffset = RVAToOffset(image, resourceDir.VirtualAddress);
    if (resourceOffset == 0 || !CheckBounds(image, resourceOffset, resourceDir.Size)) {
        return false;
    }

    // 先解析到局部容器，全部成功后一次性提交，避免留下半解析数据。
    ResourceParseState state;
    state.image = image;
    state.base = resourceOffset;
    state.span = resourceDir.Size;

    CS_RESOURCE_ENTRY root{};
    if (!ParseResourceSubdir(state, 0, 0, root) || state.failed) {
        return false;
    }

    image->resources.entries = std::move(state.entries);
    return true;
}

// ============================================================================
// TLS 解析
// ============================================================================

bool PEParser::ParseTLS(CS_PE_IMAGE* image) {
    IMAGE_DATA_DIRECTORY tlsDir;
    if (image->is64Bit) {
        tlsDir = image->ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    } else {
        tlsDir = image->ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    }

    if (tlsDir.VirtualAddress == 0 || tlsDir.Size == 0) {
        return false;
    }

    DWORD tlsOffset = RVAToOffset(image, tlsDir.VirtualAddress);
    const DWORD tlsStructSize = image->is64Bit
        ? sizeof(IMAGE_TLS_DIRECTORY64) : sizeof(IMAGE_TLS_DIRECTORY32);
    if (tlsOffset == 0 || tlsDir.Size < tlsStructSize ||
        !CheckBounds(image, tlsOffset, tlsStructSize)) {
        return false;
    }

    // 先解析到局部结构，全部验证通过后才一次性提交，失败不得留下部分状态。
    CS_TLS_INFO local{};
    local.directoryRVA = tlsDir.VirtualAddress;

    if (image->is64Bit) {
        PIMAGE_TLS_DIRECTORY64 tlsDir64 = (PIMAGE_TLS_DIRECTORY64)(image->rawData + tlsOffset);
        local.startAddress = tlsDir64->StartAddressOfRawData;
        local.endAddress = tlsDir64->EndAddressOfRawData;
        local.indexAddress = tlsDir64->AddressOfIndex;
        local.callbacksAddress = tlsDir64->AddressOfCallBacks;
    } else {
        PIMAGE_TLS_DIRECTORY32 tlsDir32 = (PIMAGE_TLS_DIRECTORY32)(image->rawData + tlsOffset);
        local.startAddress = tlsDir32->StartAddressOfRawData;
        local.endAddress = tlsDir32->EndAddressOfRawData;
        local.indexAddress = tlsDir32->AddressOfIndex;
        local.callbacksAddress = tlsDir32->AddressOfCallBacks;
    }

    const uint64_t imageBase = image->is64Bit
        ? image->ntHeaders64->OptionalHeader.ImageBase
        : image->ntHeaders32->OptionalHeader.ImageBase;

    // VA → RVA：VA 必须不小于 ImageBase，且差值落在 32 位 RVA 空间内。
    auto vaToRva = [&](DWORD64 va, DWORD& rvaOut) -> bool {
        if (va < imageBase || va - imageBase > 0xFFFFFFFFull) return false;
        rvaOut = static_cast<DWORD>(va - imageBase);
        return true;
    };

    // 1. Start/End：TLS 模板数据范围，Start <= End；非空范围必须整体落在同一个
    //    file-backed section 内——分别校验两个端点不够，因为它们可能落在不同 section，
    //    中间跨越空洞或另一段数据，因此用区间校验整体确认。
    if (local.startAddress != 0 || local.endAddress != 0) {
        DWORD startRVA = 0, endRVA = 0;
        if (!vaToRva(local.startAddress, startRVA) || !vaToRva(local.endAddress, endRVA) ||
            startRVA > endRVA) {
            return false;
        }
        if (startRVA != endRVA && !PEUtils::IsFileBackedRange(image, startRVA, endRVA)) {
            return false;
        }
    }

    // 2. AddressOfIndex：TLS 索引变量地址，必须非零、VA→RVA 合法，且至少能容纳一个
    //    完整 DWORD（4 字节）落在同一个 file-backed section 内，而非仅首字节可映射。
    DWORD indexRVA = 0;
    if (local.indexAddress == 0 || !vaToRva(local.indexAddress, indexRVA) ||
        !PEUtils::IsFileBackedSpan(image, indexRVA, sizeof(DWORD))) {
        return false;
    }

    // 3. 回调数组：VA→RVA、逐项读取直到 NULL 终止符，且每个回调必须位于可执行 file-backed section。
    std::vector<DWORD64> callbacks;
    if (local.callbacksAddress != 0) {
        DWORD callbacksRVA = 0;
        if (!vaToRva(local.callbacksAddress, callbacksRVA)) {
            return false;
        }
        DWORD callbackOffset = RVAToOffset(image, callbacksRVA);
        if (callbackOffset == 0 || callbackOffset >= image->rawSize) {
            return false;
        }
        // 扫描范围必须限制在 callbacksRVA 所在 section 自身的 file-backed 区域内，
        // 不能越界读到下一个 section 或 overlay 的数据（那会把不相关的字节误判为
        // 回调 VA 或意外的 0 终止符）。PointerToRawData+SizeOfRawData 已在 ParseHeaders
        // 阶段对每个 section 校验过不越界，此处直接使用是安全的。
        uint32_t sectionRawEnd = 0;
        bool foundSection = false;
        for (WORD i = 0; i < image->numSections; ++i) {
            const IMAGE_SECTION_HEADER& s = image->sections[i];
            if (callbackOffset >= s.PointerToRawData &&
                callbackOffset < s.PointerToRawData + s.SizeOfRawData) {
                sectionRawEnd = s.PointerToRawData + s.SizeOfRawData;
                foundSection = true;
                break;
            }
        }
        if (!foundSection) {
            return false;
        }
        const DWORD pointerSize = image->is64Bit ? 8u : 4u;
        const DWORD scanLimit = (std::min)(static_cast<uint32_t>(image->rawSize), sectionRawEnd);
        if (callbackOffset >= scanLimit) {
            return false;
        }
        const DWORD maxCallbacks = (scanLimit - callbackOffset) / pointerSize;
        bool terminated = false;
        for (DWORD count = 0; count < maxCallbacks; ++count) {
            DWORD64 callback = 0;
            std::memcpy(&callback, image->rawData + callbackOffset + count * pointerSize,
                pointerSize);
            if (callback == 0) {
                terminated = true;
                break;
            }
            DWORD callbackRVA = 0;
            if (!vaToRva(callback, callbackRVA) ||
                !PEUtils::IsExecutableFileBackedAddress(image, callbackRVA)) {
                return false;
            }
            callbacks.push_back(callback);
        }
        if (!terminated) {
            return false;
        }
    }

    // 全部验证通过后一次性提交。
    local.callbackAddresses = std::move(callbacks);
    local.callbackCount = static_cast<DWORD>(local.callbackAddresses.size());
    local.valid = TRUE;
    image->tls = std::move(local);
    return true;
}

// ============================================================================
// 异常处理表解析 (x64)
// ============================================================================

bool PEParser::ParseExceptionTable(CS_PE_IMAGE* image) {
    if (!image->is64Bit) {
        return false;
    }

    IMAGE_DATA_DIRECTORY exceptionDir =
        image->ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

    if (exceptionDir.VirtualAddress == 0 || exceptionDir.Size == 0) {
        return false;
    }

    DWORD exceptionOffset = RVAToOffset(image, exceptionDir.VirtualAddress);
    if (exceptionOffset == 0 ||
        exceptionDir.Size % sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY) != 0 ||
        !CheckBounds(image, exceptionOffset, exceptionDir.Size)) return false;

    const DWORD entryCount = exceptionDir.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
    const PIMAGE_RUNTIME_FUNCTION_ENTRY runtimeFuncs =
        (PIMAGE_RUNTIME_FUNCTION_ENTRY)(image->rawData + exceptionOffset);

    // 先解析到局部容器，全部通过验证后才提交，失败不得留下部分 entries。
    std::vector<CS_RUNTIME_FUNCTION> local;
    local.reserve(entryCount);

    DWORD previousEnd = 0;
    bool firstEntry = true;
    for (DWORD i = 0; i < entryCount; i++) {
        CS_RUNTIME_FUNCTION entry;
        entry.beginAddress = runtimeFuncs[i].BeginAddress;
        entry.endAddress = runtimeFuncs[i].EndAddress;
        entry.unwindData = runtimeFuncs[i].UnwindData;

        // BeginAddress < EndAddress；UnwindData 非零，且必须是一个完整合法的 UNWIND_INFO
        // （版本受支持、UnwindCode 数组落在文件范围内、按 Flags 校验 handler/链式尾部）。
        if (!PEUtils::IsValidRuntimeFunction(image, entry)) {
            return false;
        }
        // 表必须按 BeginAddress 有序且不重叠（允许相邻 entry 的 end == 下一个 begin）。
        if (!firstEntry && entry.beginAddress < previousEnd) {
            return false;
        }
        previousEnd = entry.endAddress;
        firstEntry = false;

        local.push_back(entry);
    }

    image->exceptions.entries = std::move(local);
    return true;
}

// ============================================================================
// Load Config 解析
// ============================================================================

bool PEParser::ParseLoadConfig(CS_PE_IMAGE* image) {
    IMAGE_DATA_DIRECTORY loadConfigDir;
    if (image->is64Bit) {
        loadConfigDir = image->ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
    } else {
        loadConfigDir = image->ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
    }

    if (loadConfigDir.VirtualAddress == 0 || loadConfigDir.Size == 0) {
        return false;
    }

    // 1. 先验证目录 RVA 与原始文件范围。
    const DWORD loadConfigOffset = RVAToOffset(image, loadConfigDir.VirtualAddress);
    if (loadConfigOffset == 0 || loadConfigOffset >= image->rawSize) {
        SetError(image, "load config: directory RVA 0x" +
            IntToHex(loadConfigDir.VirtualAddress) +
            " does not map into the file (rawSize=0x" + IntToHex(image->rawSize) + ")");
        return false;
    }

    // rawAvailable = rawSize - directoryOffset：真正能防止越界读取的边界是
    // "结构体必须完整落在文件里"，不是 directory.Size 本身。LINK.EXE 有据
    // 可查的已知行为：新增字段（GuardXFG/CastGuard/…）让 Load Config
    // 结构体实际变大后，DataDirectory 数组里登记的 Size 有时仍是旧版本/
    // 偏小的值，与结构体自己开头的 Size 字段不一致——这是当前主流 MSVC
    // 工具链下的良性现象，不是畸形/恶意 PE 的特征；Windows 加载器本身读取
    // Load Config 时，也是直接信任结构体内部的 Size 字段，不会拿
    // DataDirectory.Size 做二次限制。因此不再用 directory.Size 限制
    // declaredSize，只保留"必须落在文件真实边界内"（下面）和"不能超过
    // 已知结构体的绝对合理上限"（下面 structuralUpperBound）这两道真正
    // 防越界/防离谱声明的关卡。
    const uint64_t rawAvailable64 =
        static_cast<uint64_t>(image->rawSize) - loadConfigOffset;
    if (rawAvailable64 > 0xFFFFFFFFull) {
        SetError(image, "load config: rawAvailable64 0x" + IntToHex(rawAvailable64) +
            " exceeds 32-bit range");
        return false;
    }
    const DWORD rawAvailable = static_cast<DWORD>(rawAvailable64);

    // 2. 至少有 sizeof(DWORD) 后，读取 Load Config 开头的 Size 字段。
    if (rawAvailable < sizeof(DWORD)) {
        SetError(image, "load config: rawAvailable 0x" + IntToHex(rawAvailable) +
            " is smaller than the leading Size DWORD");
        return false;
    }

    DWORD declaredSize = 0;
    std::memcpy(&declaredSize, image->rawData + loadConfigOffset, sizeof(DWORD));
    // 4. declaredSize 自身不合法、超过文件可用范围、或大到不像任何已知版本
    // 的 IMAGE_LOAD_CONFIG_DIRECTORY64/32 时解析失败。
    if (declaredSize < sizeof(DWORD)) {
        SetError(image, "load config: declaredSize 0x" + IntToHex(declaredSize) +
            " is smaller than sizeof(DWORD)");
        return false;
    }
    if (declaredSize > rawAvailable) {
        SetError(image, "load config: declaredSize 0x" + IntToHex(declaredSize) +
            " (the structure's own leading Size field) does not fit in the file "
            "(rawAvailable=0x" + IntToHex(rawAvailable) + ", rawSize-offset=0x" +
            IntToHex(static_cast<uint64_t>(image->rawSize) - loadConfigOffset) + ")");
        return false;
    }
    // 文件总长边界还不够：结构必须完整落在同一个 file-backed
    // section 内，不得借助紧随 section 的 overlay 补齐声明大小。
    if (!PEUtils::IsFileBackedSpan(image, loadConfigDir.VirtualAddress, declaredSize)) {
        SetError(image, "load config: declaredSize 0x" + IntToHex(declaredSize) +
            " crosses the containing file-backed section boundary");
        return false;
    }
    // 绝对结构上限：即便落在文件边界内，也不能大到不像任何已知版本的
    // IMAGE_LOAD_CONFIG_DIRECTORY64/32。用编译当前所链接头文件里的
    // sizeof(乘以宽裕倍数) 而不是写死某个历史数值，未来 Windows SDK 继续
    // 新增字段时这个上限自动跟着当前工具链的结构体定义一起变大，不需要
    // 再回来改这个常量；同时仍然拒绝真正被构造成离谱大小的伪造声明。
    constexpr DWORD kLoadConfigSizeSlack = 4;
    const size_t knownStructSize = image->is64Bit
        ? sizeof(IMAGE_LOAD_CONFIG_DIRECTORY64)
        : sizeof(IMAGE_LOAD_CONFIG_DIRECTORY32);
    const DWORD structuralUpperBound =
        static_cast<DWORD>(knownStructSize) * kLoadConfigSizeSlack;
    if (declaredSize > structuralUpperBound) {
        SetError(image, "load config: declaredSize 0x" + IntToHex(declaredSize) +
            " exceeds the absolute structural upper bound 0x" +
            IntToHex(structuralUpperBound) + " (" +
            std::to_string(kLoadConfigSizeSlack) + "x sizeof(IMAGE_LOAD_CONFIG_DIRECTORY" +
            (image->is64Bit ? "64" : "32") + ")=0x" + IntToHex(knownStructSize) + ")");
        return false;
    }

    // 5. effectiveSize 必须使用 declaredSize，而非整个目录大小。
    const DWORD effectiveSize = declaredSize;
    auto hasField = [effectiveSize](size_t offset, size_t size) {
        return offset <= effectiveSize && size <= effectiveSize - offset;
    };

    // 全部在 local 上构建，成功后才一次性提交，避免半解析状态。
    // 旧版较短的结构合法：只要 declaredSize 自身合法且在文件范围内即允许解析，
    // 只解析该版本实际存在的字段；后期新增字段（含 GuardFlags）缺失时按零处理，
    // 不因缺少后期字段而拒绝整个 PE。
    CS_LOAD_CONFIG local{};

    if (image->is64Bit) {
        PIMAGE_LOAD_CONFIG_DIRECTORY64 lc = (PIMAGE_LOAD_CONFIG_DIRECTORY64)(image->rawData + loadConfigOffset);
        if (hasField(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, SecurityCookie), sizeof(lc->SecurityCookie)))
            local.securityCookie = lc->SecurityCookie;
        // x64 不使用 SafeSEH（使用 .pdata 异常表），不解析 SEHandlerTable/Count。
        if (hasField(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, GuardCFCheckFunctionPointer), sizeof(lc->GuardCFCheckFunctionPointer)))
            local.guardCFCheckFunctionPointer = lc->GuardCFCheckFunctionPointer;
        if (hasField(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, GuardCFDispatchFunctionPointer), sizeof(lc->GuardCFDispatchFunctionPointer)))
            local.guardCFDispatchFunctionPointer = lc->GuardCFDispatchFunctionPointer;
        if (hasField(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, GuardCFFunctionTable), sizeof(lc->GuardCFFunctionTable)))
            local.guardCFFunctionTable = lc->GuardCFFunctionTable;
        if (hasField(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, GuardCFFunctionCount), sizeof(lc->GuardCFFunctionCount)))
            local.guardCFFunctionCount = lc->GuardCFFunctionCount;
        if (hasField(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, GuardFlags), sizeof(DWORD))) {
            local.guardFlags = lc->GuardFlags;
            local.hasCFG = (lc->GuardFlags & IMAGE_GUARD_CF_INSTRUMENTED) != 0;
            local.hasRFGuard = (lc->GuardFlags &
                (IMAGE_GUARD_RF_INSTRUMENTED | IMAGE_GUARD_RF_ENABLE |
                 IMAGE_GUARD_RF_STRICT)) != 0;
        }
    } else {
        PIMAGE_LOAD_CONFIG_DIRECTORY32 lc = (PIMAGE_LOAD_CONFIG_DIRECTORY32)(image->rawData + loadConfigOffset);
        if (hasField(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, SecurityCookie), sizeof(lc->SecurityCookie)))
            local.securityCookie = lc->SecurityCookie;
        if (hasField(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, SEHandlerTable), sizeof(lc->SEHandlerTable)))
            local.seHandlerTable = lc->SEHandlerTable;
        if (hasField(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, SEHandlerCount), sizeof(lc->SEHandlerCount)))
            local.seHandlerCount = lc->SEHandlerCount;
        if (hasField(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, GuardCFCheckFunctionPointer), sizeof(lc->GuardCFCheckFunctionPointer)))
            local.guardCFCheckFunctionPointer = lc->GuardCFCheckFunctionPointer;
        if (hasField(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, GuardCFDispatchFunctionPointer), sizeof(lc->GuardCFDispatchFunctionPointer)))
            local.guardCFDispatchFunctionPointer = lc->GuardCFDispatchFunctionPointer;
        if (hasField(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, GuardCFFunctionTable), sizeof(lc->GuardCFFunctionTable)))
            local.guardCFFunctionTable = lc->GuardCFFunctionTable;
        if (hasField(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, GuardCFFunctionCount), sizeof(lc->GuardCFFunctionCount)))
            local.guardCFFunctionCount = lc->GuardCFFunctionCount;
        if (hasField(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, GuardFlags), sizeof(DWORD))) {
            local.guardFlags = lc->GuardFlags;
            local.hasCFG = (lc->GuardFlags & IMAGE_GUARD_CF_INSTRUMENTED) != 0;
            local.hasRFGuard = (lc->GuardFlags &
                (IMAGE_GUARD_RF_INSTRUMENTED | IMAGE_GUARD_RF_ENABLE |
                 IMAGE_GUARD_RF_STRICT)) != 0;
        }
    }

    // 只有所有已声明字段都通过验证后才能设置 valid = true。
    local.directoryRVA = loadConfigDir.VirtualAddress;
    local.directorySize = loadConfigDir.Size;
    local.valid = TRUE;

    const uint64_t imageBase = image->is64Bit
        ? image->ntHeaders64->OptionalHeader.ImageBase
        : image->ntHeaders32->OptionalHeader.ImageBase;

    // 解析 Guard CF function table（带 64 位溢出检查）。
    if (local.guardCFFunctionTable != 0 && local.guardCFFunctionCount != 0) {
        constexpr DWORD kGuardTableSizeMask = 0xF0000000u;
        constexpr DWORD kGuardTableSizeShift = 28u;
        const DWORD extraBytes = (local.guardFlags & kGuardTableSizeMask) >>
            kGuardTableSizeShift;
        const DWORD entrySize = sizeof(DWORD) + extraBytes;
        local.guardTableEntrySize = entrySize;
        if (local.guardCFFunctionTable < imageBase ||
            local.guardCFFunctionTable - imageBase > 0xFFFFFFFFULL ||
            local.guardCFFunctionCount > 0x1000000ULL) {
            SetError(image, "load config: Guard CF function table VA 0x" +
                IntToHex(local.guardCFFunctionTable) + " (imageBase=0x" +
                IntToHex(imageBase) + ") or count 0x" +
                IntToHex(local.guardCFFunctionCount) + " is out of range");
            return false;
        }
        const DWORD tableRVA = static_cast<DWORD>(
            local.guardCFFunctionTable - imageBase);
        const DWORD tableOffset = RVAToOffset(image, tableRVA);
        const uint64_t tableBytes = local.guardCFFunctionCount *
            static_cast<uint64_t>(entrySize);  // 64 位乘法，无溢出截断
        if (tableOffset == 0 ||
            tableBytes > static_cast<uint64_t>(image->rawSize) - tableOffset) {
            SetError(image, "load config: Guard CF function table rva=0x" +
                IntToHex(tableRVA) + " fileOffset=0x" + IntToHex(tableOffset) +
                " entrySize=0x" + IntToHex(entrySize) + " count=0x" +
                IntToHex(local.guardCFFunctionCount) +
                " does not fit in the file (rawSize=0x" +
                IntToHex(image->rawSize) + ")");
            return false;
        }
        std::vector<DWORD> guardRVAs;
        guardRVAs.reserve(static_cast<size_t>(local.guardCFFunctionCount));
        for (uint64_t i = 0; i < local.guardCFFunctionCount; ++i) {
            DWORD functionRVA = 0;
            std::memcpy(&functionRVA,
                image->rawData + tableOffset + static_cast<size_t>(i * entrySize),
                sizeof(functionRVA));
            guardRVAs.push_back(functionRVA);
        }
        local.guardFunctionRVAs = std::move(guardRVAs);
    }

    // 解析 x86 SafeSEH handler 表（SEHandlerTable/Count）。
    // 只对 PE32 解析；x64 使用 .pdata 异常表，不解析 SafeSEH。
    // SEHandlerTable 是 VA：不小于 ImageBase，差值不超过 32 位，count×sizeof(DWORD) 不溢出。
    if (!image->is64Bit && local.seHandlerTable != 0 && local.seHandlerCount != 0) {
        if (local.seHandlerTable < imageBase ||
            local.seHandlerTable - imageBase > 0xFFFFFFFFULL ||
            local.seHandlerCount > 0x1000000ULL) {
            SetError(image, "load config: SafeSEH handler table VA 0x" +
                IntToHex(local.seHandlerTable) + " or count 0x" +
                IntToHex(local.seHandlerCount) + " is out of range");
            return false;
        }
        const DWORD sehRVA = static_cast<DWORD>(local.seHandlerTable - imageBase);
        const uint64_t tableBytes = local.seHandlerCount *
            static_cast<uint64_t>(sizeof(DWORD));  // 64 位乘法
        const DWORD tableOffset = RVAToOffset(image, sehRVA);
        if (tableOffset == 0 ||
            tableBytes > static_cast<uint64_t>(image->rawSize) - tableOffset) {
            SetError(image, "load config: SafeSEH handler table rva=0x" +
                IntToHex(sehRVA) + " fileOffset=0x" + IntToHex(tableOffset) +
                " does not fit in the file (rawSize=0x" +
                IntToHex(image->rawSize) + ")");
            return false;
        }
        // 每个 handler RVA 必须位于映像范围、能映射到文件数据、且位于可执行 section。
        auto handlerRvaIsValid = [&](DWORD rva) -> bool {
            return rva != 0 && PEUtils::IsExecutableFileBackedAddress(image, rva);
        };
        std::vector<DWORD> sehRVAs;
        sehRVAs.reserve(static_cast<size_t>(local.seHandlerCount));
        for (uint64_t i = 0; i < local.seHandlerCount; ++i) {
            DWORD handlerRVA = 0;
            std::memcpy(&handlerRVA,
                image->rawData + tableOffset + static_cast<size_t>(i * sizeof(DWORD)),
                sizeof(handlerRVA));
            if (!handlerRvaIsValid(handlerRVA)) {
                SetError(image, "load config: SafeSEH handler[" + std::to_string(i) +
                    "] rva=0x" + IntToHex(handlerRVA) + " is not executable/file-backed");
                return false;
            }
            sehRVAs.push_back(handlerRVA);
        }
        local.safeSEHHandlerRVAs = std::move(sehRVAs);
    }

    // 全部成功后一次性提交。
    image->loadConfig = std::move(local);
    return image->loadConfig.valid;
}

// ============================================================================
// Debug 目录解析
// ============================================================================

bool PEParser::ParseDebugDirectory(CS_PE_IMAGE* image) {
    IMAGE_DATA_DIRECTORY debugDir;
    if (image->is64Bit) {
        debugDir = image->ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    } else {
        debugDir = image->ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    }

    if (debugDir.VirtualAddress == 0 || debugDir.Size == 0) {
        return false;
    }

    // 1. Size 必须是 IMAGE_DEBUG_DIRECTORY 大小的整数倍。
    // 2. 目录数组整体在文件范围内。
    const DWORD debugOffset = RVAToOffset(image, debugDir.VirtualAddress);
    if (debugOffset == 0 || debugDir.Size % sizeof(IMAGE_DEBUG_DIRECTORY) != 0 ||
        !CheckBounds(image, debugOffset, debugDir.Size)) {
        return false;
    }

    const DWORD entryCount = debugDir.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
    const PIMAGE_DEBUG_DIRECTORY debugEntries = (PIMAGE_DEBUG_DIRECTORY)(image->rawData + debugOffset);

    // 5. 先解析到局部 vector，全部成功后再写入。
    std::vector<CS_DEBUG_ENTRY> local;
    local.reserve(entryCount);
    constexpr DWORD kDebugTypeExtendedDllCharacteristics = 20u;
    constexpr WORD kExtendedDllCharacteristicsCetCompat = 0x0001u;
    WORD extendedDllCharacteristics = 0u;
    bool sawExtendedDllCharacteristics = false;

    for (DWORD i = 0; i < entryCount; i++) {
        const IMAGE_DEBUG_DIRECTORY& src = debugEntries[i];
        CS_DEBUG_ENTRY entry;
        entry.type = src.Type;
        entry.sizeOfData = src.SizeOfData;
        entry.addressOfRawData = src.AddressOfRawData;
        entry.pointerToRawData = src.PointerToRawData;

        // 3. SizeOfData > 0 时，PointerToRawData 必须存在并完整位于文件范围（溢出安全）。
        if (entry.sizeOfData > 0) {
            const uint64_t payloadEnd = static_cast<uint64_t>(entry.pointerToRawData) +
                entry.sizeOfData;
            if (entry.pointerToRawData == 0 ||
                payloadEnd > static_cast<uint64_t>(image->rawSize)) {
                return false;
            }
        }

        // 4. AddressOfRawData 非零时，必须能从 RVA 映射到文件，且映射范围覆盖 SizeOfData。
        if (entry.addressOfRawData != 0) {
            const DWORD addrOff = RVAToOffset(image, entry.addressOfRawData);
            if (addrOff == 0) {
                return false;
            }
            if (entry.sizeOfData > 0) {
                const uint64_t coverEnd = static_cast<uint64_t>(addrOff) + entry.sizeOfData;
                if (coverEnd > static_cast<uint64_t>(image->rawSize)) {
                    return false;
                }
            }
        }

        if (entry.type == kDebugTypeExtendedDllCharacteristics) {
            // PE/COFF defines this payload as the extended DLL-characteristic
            // bit word.  Duplicate entries are ambiguous security metadata;
            // accepting the first or last one would let a malformed image
            // hide CET compatibility from transforms that rewrite returns.
            if (sawExtendedDllCharacteristics ||
                entry.sizeOfData < sizeof(WORD)) {
                return false;
            }
            std::memcpy(&extendedDllCharacteristics,
                image->rawData + entry.pointerToRawData, sizeof(WORD));
            sawExtendedDllCharacteristics = true;
        }

        local.push_back(entry);
    }

    // 6. 任一条目失败，整个目录解析失败（已在循环中 return false）。
    image->debugDir.entries = std::move(local);
    image->debugDir.extendedDllCharacteristics =
        extendedDllCharacteristics;
    image->debugDir.hasCetCompat =
        (extendedDllCharacteristics &
            kExtendedDllCharacteristicsCetCompat) != 0u;
    return true;
}

// ============================================================================
// 延迟导入解析
// ============================================================================

bool PEParser::ParseDelayImports(CS_PE_IMAGE* image) {
    IMAGE_DATA_DIRECTORY delayImportDir;
    if (image->is64Bit) {
        delayImportDir = image->ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    } else {
        delayImportDir = image->ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    }

    if (delayImportDir.VirtualAddress == 0 || delayImportDir.Size == 0) {
        return false;
    }

    // 1/2. 描述符固定 32 字节；DataDirectory.Size 必须是其整数倍。
    if (delayImportDir.Size % sizeof(IMAGE_DELAYLOAD_DESCRIPTOR) != 0) {
        return false;
    }
    const DWORD delayOffset = RVAToOffset(image, delayImportDir.VirtualAddress);
    if (delayOffset == 0 || !CheckBounds(image, delayOffset, delayImportDir.Size)) {
        return false;
    }
    const DWORD descriptorCount = delayImportDir.Size / sizeof(IMAGE_DELAYLOAD_DESCRIPTOR);
    const DWORD thunkSize = image->is64Bit ? 8u : 4u;

    // 全部解析到局部容器，成功并发现终止项后一次性提交。
    std::vector<CS_DELAY_IMPORT_DLL> local;
    bool terminated = false;

    for (DWORD di = 0; di < descriptorCount; ++di) {
        IMAGE_DELAYLOAD_DESCRIPTOR desc{};
        std::memcpy(&desc,
            image->rawData + delayOffset + di * sizeof(IMAGE_DELAYLOAD_DESCRIPTOR),
            sizeof(desc));

        // 3. 必须在目录范围内遇到全零终止描述符。
        if (desc.Attributes.AllAttributes == 0 && desc.DllNameRVA == 0 &&
            desc.ModuleHandleRVA == 0 && desc.ImportAddressTableRVA == 0 &&
            desc.ImportNameTableRVA == 0 && desc.BoundImportAddressTableRVA == 0 &&
            desc.UnloadInformationTableRVA == 0 && desc.TimeDateStamp == 0) {
            terminated = true;
            break;
        }

        // 4. 当前只支持 RVA-based descriptor；attributes bit 0 未设置时明确拒绝。
        if ((desc.Attributes.AllAttributes & 0x1u) == 0) {
            return false;
        }

        CS_DELAY_IMPORT_DLL dll{};
        dll.moduleHandleRVA = desc.ModuleHandleRVA;
        dll.iatRVA = desc.ImportAddressTableRVA;
        dll.intRVA = desc.ImportNameTableRVA;

        // 5. 验证 DLL 名称 RVA 和 NUL 终止字符串。
        const DWORD dllNameOff = RVAToOffset(image, desc.DllNameRVA);
        if (desc.DllNameRVA == 0 || dllNameOff == 0 ||
            !ReadCString(image, dllNameOff, dll.dllName)) {
            return false;
        }

        // 6. INT 与 IAT：起始 RVA 可映射，每次读取前检查完整 thunk 宽度。
        if (desc.ImportNameTableRVA == 0 || desc.ImportAddressTableRVA == 0) {
            return false;
        }
        const DWORD intOff = RVAToOffset(image, desc.ImportNameTableRVA);
        const DWORD iatOff = RVAToOffset(image, desc.ImportAddressTableRVA);
        if (intOff == 0 || iatOff == 0) {
            return false;
        }

        // 解析 INT 直到零终止项。func.thunkRVA = IAT 槽 RVA，用 64 位累加并校验回绕。
        std::vector<CS_IMPORT_FUNCTION> funcs;
        bool intTerminated = false;
        for (DWORD idx = 0; ; ++idx) {
            if (idx > 0x1000000) return false;  // 防恶意
            const uint64_t pos = static_cast<uint64_t>(intOff) +
                static_cast<uint64_t>(idx) * thunkSize;
            if (pos + thunkSize > static_cast<uint64_t>(image->rawSize)) {
                return false;  // INT 未在文件范围内终止
            }
            uint64_t thunkVal = 0;
            std::memcpy(&thunkVal, image->rawData + pos, thunkSize);
            if (thunkVal == 0) {
                intTerminated = true;
                break;
            }
            CS_IMPORT_FUNCTION func;
            // ImportAddressTableRVA + idx * thunkSize，显式防止 32 位回绕。
            const uint64_t slotRVA = static_cast<uint64_t>(desc.ImportAddressTableRVA) +
                static_cast<uint64_t>(idx) * thunkSize;
            if (slotRVA > 0xFFFFFFFFull) return false;
            func.thunkRVA = static_cast<DWORD>(slotRVA);
            const bool isOrdinal = image->is64Bit
                ? IMAGE_SNAP_BY_ORDINAL64(thunkVal)
                : IMAGE_SNAP_BY_ORDINAL32(static_cast<DWORD>(thunkVal));
            if (isOrdinal) {
                func.isOrdinal = true;
                func.ordinal = image->is64Bit
                    ? IMAGE_ORDINAL64(thunkVal)
                    : IMAGE_ORDINAL32(static_cast<DWORD>(thunkVal));
            } else {
                // 7. 非 ordinal：验证 Hint 字段与名称字符串。
                func.isOrdinal = false;
                if (thunkVal > 0xFFFFFFFFull) return false;
                const DWORD hintNameRVA = static_cast<DWORD>(thunkVal);
                const DWORD hintNameOff = RVAToOffset(image, hintNameRVA);
                if (hintNameOff == 0 ||
                    !CheckBounds(image, hintNameOff, sizeof(WORD)) ||
                    !ReadCString(image, hintNameOff + sizeof(WORD), func.name)) {
                    return false;
                }
                std::memcpy(&func.ordinal, image->rawData + hintNameOff, sizeof(WORD));
            }
            funcs.push_back(func);
        }
        if (!intTerminated) return false;

        // IAT 必须至少覆盖与 INT 相同数量的项及终止槽，并读取确认最后的终止槽为零。
        const size_t thunkCount = funcs.size();
        const uint64_t iatNeed = static_cast<uint64_t>(iatOff) +
            (static_cast<uint64_t>(thunkCount) + 1ull) * thunkSize;
        if (iatNeed > static_cast<uint64_t>(image->rawSize)) {
            return false;
        }
        uint64_t iatTerm = 0;
        std::memcpy(&iatTerm, image->rawData + iatOff + thunkCount * thunkSize, thunkSize);
        if (iatTerm != 0) return false;  // IAT 末尾终止槽非零

        // 8. moduleHandleRVA 非零时，至少容纳一个指针宽度。
        if (desc.ModuleHandleRVA != 0) {
            const DWORD mhOff = RVAToOffset(image, desc.ModuleHandleRVA);
            if (mhOff == 0 ||
                static_cast<uint64_t>(mhOff) + thunkSize > static_cast<uint64_t>(image->rawSize)) {
                return false;
            }
        }
        // 9/10. boundIatRVA / unloadIatRVA 非零时，不仅覆盖容量，还要读取并确认
        // 末尾终止槽为零（验证表结构而非仅容量）。
        auto tableTerminatorIsZero = [&](DWORD rva) -> bool {
            const DWORD off = RVAToOffset(image, rva);
            if (off == 0) return false;
            const uint64_t need = static_cast<uint64_t>(off) +
                (static_cast<uint64_t>(thunkCount) + 1ull) * thunkSize;
            if (need > static_cast<uint64_t>(image->rawSize)) return false;
            uint64_t term = 0;
            std::memcpy(&term, image->rawData + off + thunkCount * thunkSize, thunkSize);
            return term == 0;
        };
        if (desc.BoundImportAddressTableRVA != 0 &&
            !tableTerminatorIsZero(desc.BoundImportAddressTableRVA)) {
            return false;
        }
        if (desc.UnloadInformationTableRVA != 0 &&
            !tableTerminatorIsZero(desc.UnloadInformationTableRVA)) {
            return false;
        }

        // 12. 单个 descriptor 全部验证成功后才加入局部结果。
        dll.functions = std::move(funcs);
        local.push_back(std::move(dll));
    }

    // 13. 所有 descriptors 成功并发现终止项后才提交；否则失败。
    if (!terminated) return false;

    image->delayImports.dlls = std::move(local);
    return true;
}

// ============================================================================
// Security Directory / WIN_CERTIFICATE 解析
// ============================================================================

bool PEParser::ParseSecurity(CS_PE_IMAGE* image) {
    IMAGE_DATA_DIRECTORY secDir;
    if (image->is64Bit) {
        secDir = image->ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    } else {
        secDir = image->ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    }
    if (secDir.VirtualAddress == 0 || secDir.Size == 0) {
        return false;  // 由 parseIfPresent 保证仅在两者均非零时进入
    }

    // 1. VirtualAddress 是文件偏移，绝不做 RVA 转换。
    const DWORD dirOffset = secDir.VirtualAddress;
    // 2. 验证目录整体文件范围（加法溢出安全）。
    const uint64_t dirEnd = static_cast<uint64_t>(dirOffset) + secDir.Size;
    if (dirOffset == 0 || dirOffset >= image->rawSize ||
        dirEnd > static_cast<uint64_t>(image->rawSize)) {
        return false;
    }

    // 3. 遍历 WIN_CERTIFICATE 记录链。
    DWORD cursor = dirOffset;
    const DWORD end = static_cast<DWORD>(dirEnd);
    bool sawAny = false;
    while (cursor < end) {
        // 最小长度至少 8 字节。
        if (static_cast<uint64_t>(cursor) + 8ull > static_cast<uint64_t>(image->rawSize)) {
            return false;
        }
        DWORD dwLength = 0;
        std::memcpy(&dwLength, image->rawData + cursor, sizeof(dwLength));
        if (dwLength < 8) {
            return false;  // dwLength 小于 WIN_CERTIFICATE 头
        }
        const uint64_t recEnd = static_cast<uint64_t>(cursor) + dwLength;
        if (recEnd > static_cast<uint64_t>(end)) {
            return false;  // dwLength 越界
        }
        sawAny = true;
        // 每条记录按 8 字节对齐前进，对齐计算不得溢出。
        const uint64_t aligned = (recEnd + 7ull) & ~7ull;
        if (aligned > static_cast<uint64_t>(end)) {
            return false;  // 对齐后越过目录末尾
        }
        cursor = static_cast<DWORD>(aligned);
    }

    // 最终 cursor 必须精确到达目录末尾。
    if (cursor != end || !sawAny) {
        return false;
    }

    // 4. 只在整条证书链有效时设置 hasSignature。
    image->hasSignature = TRUE;
    return true;
}

// ============================================================================
// Rich Header 解析
// ============================================================================

bool PEParser::ParseRichHeader(CS_PE_IMAGE* image) {
    // Rich Header 在 DOS Header 和 PE 签名之间
    // 搜索 "Rich" 标记
    DWORD richSignature = 0x68636952;  // "Rich"
    if (!image || !image->rawData || !image->dosHeader ||
        image->dosHeader->e_lfanew <= static_cast<LONG>(sizeof(IMAGE_DOS_HEADER)) ||
        static_cast<uint64_t>(image->dosHeader->e_lfanew) > image->rawSize) {
        return false;
    }
    const DWORD end = static_cast<DWORD>(image->dosHeader->e_lfanew);
    for (DWORD i = sizeof(IMAGE_DOS_HEADER); i <= end - sizeof(DWORD); i += 4) {
        DWORD value = 0;
        std::memcpy(&value, image->rawData + i, sizeof(value));
        if (value == richSignature) {
            image->hasRichHeader = TRUE;
            image->richHeaderOffset = i;
            return true;
        }
    }

    return false;
}

// ============================================================================
// .NET 检测
// ============================================================================

bool PEParser::DetectDotNet(CS_PE_IMAGE* image) {
    IMAGE_DATA_DIRECTORY comDir;
    if (image->is64Bit) {
        comDir = image->ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
    } else {
        comDir = image->ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
    }

    image->isDotNet = (comDir.VirtualAddress != 0 && comDir.Size != 0);
    return image->isDotNet;
}

// ============================================================================
// Overlay 检测

bool PEParser::DetectOverlay(CS_PE_IMAGE* image) {
    DWORD lastSectionEnd = 0;
    for (WORD i = 0; i < image->numSections; i++) {
        DWORD sectionEnd = image->sections[i].PointerToRawData + image->sections[i].SizeOfRawData;
        if (sectionEnd > lastSectionEnd) {
            lastSectionEnd = sectionEnd;
        }
    }

    // 检查是否有额外数据
    if (lastSectionEnd < image->rawSize) {
        image->hasOverlay = TRUE;
        image->overlayOffset = lastSectionEnd;
    }

    return image->hasOverlay;
}

// ============================================================================
// 辅助函数
// ============================================================================

DWORD PEParser::RVAToOffset(CS_PE_IMAGE* image, DWORD rva) {
    return PEUtils::RvaToOffset(image, rva);
}

bool PEParser::IsValidPE(CS_PE_IMAGE* image) {
    if (image->rawSize < sizeof(IMAGE_DOS_HEADER)) {
        return false;
    }

    // 检查 DOS 签名
    if (image->rawData[0] != 'M' || image->rawData[1] != 'Z') {
        return false;
    }

    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(image->rawData);
    if (dosHeader->e_lfanew < 0) {
        return false;
    }
    const DWORD ntOffset = static_cast<DWORD>(dosHeader->e_lfanew);
    if (!CheckBounds(image, ntOffset, sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER))) {
        return false;
    }
    DWORD signature = 0;
    std::memcpy(&signature, image->rawData + ntOffset, sizeof(signature));
    if (signature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    return true;
}

bool PEParser::CheckBounds(CS_PE_IMAGE* image, DWORD offset, DWORD size) {
    // 安全写法：先检查 offset 是否越界，再用减法检查 size
    return (offset <= image->rawSize && size <= image->rawSize - offset);
}

void PEParser::SetError(CS_PE_IMAGE* image, const std::string& message) {
    if (image) {
        image->errorMessage = message;
        image->isValid = FALSE;
    }
}

} // namespace CipherShell
