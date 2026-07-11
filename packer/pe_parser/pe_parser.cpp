/**
 * CipherShell PE Parser - 实现
 */

#include "pe_parser.h"
#include <cstddef>
#include "pe_utils.h"
#include <cstring>
#include <algorithm>

namespace CipherShell {

namespace {
bool IsPowerOfTwo(uint32_t value) {
    return value != 0 && (value & (value - 1u)) == 0;
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
    (void)ParseImportTable(image);
    (void)ParseExportTable(image);
    (void)ParseRelocationTable(image);
    (void)ParseResourceTable(image);
    (void)ParseTLS(image);

    if (image->is64Bit) {
        (void)ParseExceptionTable(image);
    }

    (void)ParseLoadConfig(image);
    (void)ParseDebugDirectory(image);
    (void)ParseDelayImports(image);

    return true;
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
    if (importOffset == 0) {
        return false;
    }

    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(image->rawData + importOffset);

    while (importDesc->Name != 0) {
        CS_IMPORT_DLL importDll;

        // DLL 鍚嶇О
        DWORD nameOffset = RVAToOffset(image, importDesc->Name);
        if (nameOffset == 0) {
            importDesc++;
            continue;
        }
        importDll.dllName = (char*)(image->rawData + nameOffset);
        importDll.originalFirstThunkRVA = importDesc->OriginalFirstThunk;
        importDll.firstThunkRVA = importDesc->FirstThunk;

        DWORD iltOffset = RVAToOffset(image, importDesc->OriginalFirstThunk);
        DWORD iatOffset = RVAToOffset(image, importDesc->FirstThunk);

        if (iltOffset == 0) {
            // 某些情况下 ILT 可能为0，使用 IAT
            iltOffset = iatOffset;
        }

        if (iltOffset != 0 && iatOffset != 0) {
            if (image->is64Bit) {
                // 64位 Thunk
                PIMAGE_THUNK_DATA64 ilt = (PIMAGE_THUNK_DATA64)(image->rawData + iltOffset);
                PIMAGE_THUNK_DATA64 iat = (PIMAGE_THUNK_DATA64)(image->rawData + iatOffset);
                DWORD thunkIndex = 0;

                while (ilt->u1.AddressOfData != 0) {
                    CS_IMPORT_FUNCTION func;
                    func.thunkRVA = importDesc->FirstThunk + thunkIndex * sizeof(IMAGE_THUNK_DATA64);

                    if (IMAGE_SNAP_BY_ORDINAL64(ilt->u1.Ordinal)) {
                        // 按序号导入
                        func.ordinal = IMAGE_ORDINAL64(ilt->u1.Ordinal);
                    } else {
                        // 按名称导入
                        func.isOrdinal = false;
                        DWORD hintNameOffset = RVAToOffset(image, (DWORD)ilt->u1.AddressOfData);
                        if (hintNameOffset != 0) {
                            PIMAGE_IMPORT_BY_NAME importByName =
                                (PIMAGE_IMPORT_BY_NAME)(image->rawData + hintNameOffset);
                            func.name = importByName->Name;
                            func.ordinal = importByName->Hint;
                        }
                    }

                    importDll.functions.push_back(func);
                    ilt++;
                    iat++;
                    thunkIndex++;
                }
            } else {
                // 32位 Thunk
                PIMAGE_THUNK_DATA32 ilt = (PIMAGE_THUNK_DATA32)(image->rawData + iltOffset);
                PIMAGE_THUNK_DATA32 iat = (PIMAGE_THUNK_DATA32)(image->rawData + iatOffset);
                DWORD thunkIndex = 0;

                while (ilt->u1.AddressOfData != 0) {
                    CS_IMPORT_FUNCTION func;
                    func.thunkRVA = importDesc->FirstThunk + thunkIndex * sizeof(IMAGE_THUNK_DATA32);

                    if (IMAGE_SNAP_BY_ORDINAL32(ilt->u1.Ordinal)) {
                        func.isOrdinal = true;
                        func.ordinal = IMAGE_ORDINAL32(ilt->u1.Ordinal);
                    } else {
                        func.isOrdinal = false;
                        DWORD hintNameOffset = RVAToOffset(image, ilt->u1.AddressOfData);
                        if (hintNameOffset != 0) {
                            PIMAGE_IMPORT_BY_NAME importByName =
                                (PIMAGE_IMPORT_BY_NAME)(image->rawData + hintNameOffset);
                            func.name = importByName->Name;
                            func.ordinal = importByName->Hint;
                        }
                    }

                    importDll.functions.push_back(func);
                    ilt++;
                    iat++;
                    thunkIndex++;
                }
            }
        }

        image->imports.dlls.push_back(importDll);
        importDesc++;
    }

    return true;
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
    if (exportOffset == 0) {
        return false;
    }

    PIMAGE_EXPORT_DIRECTORY exportDirPtr = (PIMAGE_EXPORT_DIRECTORY)(image->rawData + exportOffset);

    // DLL 鍚嶇О
    DWORD dllNameOffset = RVAToOffset(image, exportDirPtr->Name);
    if (dllNameOffset != 0) {
        image->exports.dllName = (char*)(image->rawData + dllNameOffset);
    }
    image->exports.ordinalBase = exportDirPtr->Base;

    // 获取函数、名称、序号表
    DWORD functionsOffset = RVAToOffset(image, exportDirPtr->AddressOfFunctions);
    DWORD namesOffset = RVAToOffset(image, exportDirPtr->AddressOfNames);
    DWORD ordinalsOffset = RVAToOffset(image, exportDirPtr->AddressOfNameOrdinals);

    if (functionsOffset == 0) {
        return false;
    }

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
                if (nameOffset != 0) {
                    ordinalToName[ordinal] = (char*)(image->rawData + nameOffset);
                }
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

        if (functions[i] >= exportDir.VirtualAddress &&
            functions[i] < exportDir.VirtualAddress + exportDir.Size) {
            func.isForwarded = true;
            DWORD forwarderOffset = RVAToOffset(image, functions[i]);
            if (forwarderOffset != 0) {
                func.forwarderName = (char*)(image->rawData + forwarderOffset);
            }
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
    if (relocOffset == 0) {
        return false;
    }

    DWORD currentOffset = relocOffset;
    DWORD endOffset = relocOffset + relocDir.Size;

    while (currentOffset < endOffset) {
        if (!CheckBounds(image, currentOffset, sizeof(IMAGE_BASE_RELOCATION))) {
            break;
        }

        PIMAGE_BASE_RELOCATION relocBlock = (PIMAGE_BASE_RELOCATION)(image->rawData + currentOffset);

        if (relocBlock->VirtualAddress == 0 || relocBlock->SizeOfBlock == 0) {
            break;
        }

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

    return true;
}

// ============================================================================
// 资源表解析

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

    DWORD resourceOffset = RVAToOffset(image, resourceDir.VirtualAddress);
    if (resourceOffset == 0) {
        return false;
    }

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
    if (tlsOffset == 0) {
        return false;
    }

    image->tls.directoryRVA = tlsDir.VirtualAddress;
    image->tls.callbackAddresses.clear();
    if (image->is64Bit) {
        PIMAGE_TLS_DIRECTORY64 tlsDir64 = (PIMAGE_TLS_DIRECTORY64)(image->rawData + tlsOffset);
        image->tls.startAddress = tlsDir64->StartAddressOfRawData;
        image->tls.endAddress = tlsDir64->EndAddressOfRawData;
        image->tls.indexAddress = tlsDir64->AddressOfIndex;
        image->tls.callbacksAddress = tlsDir64->AddressOfCallBacks;
    } else {
        PIMAGE_TLS_DIRECTORY32 tlsDir32 = (PIMAGE_TLS_DIRECTORY32)(image->rawData + tlsOffset);
        image->tls.startAddress = tlsDir32->StartAddressOfRawData;
        image->tls.endAddress = tlsDir32->EndAddressOfRawData;
        image->tls.indexAddress = tlsDir32->AddressOfIndex;
        image->tls.callbacksAddress = tlsDir32->AddressOfCallBacks;
    }

    image->tls.valid = TRUE;

    // 计算回调数量
    if (image->tls.callbacksAddress != 0) {
        DWORD callbackOffset = RVAToOffset(image, (DWORD)(image->tls.callbacksAddress -
            (image->is64Bit ? image->ntHeaders64->OptionalHeader.ImageBase :
                              image->ntHeaders32->OptionalHeader.ImageBase)));

        if (callbackOffset != 0 && callbackOffset < image->rawSize) {
            const DWORD pointerSize = image->is64Bit ? 8u : 4u;
            const DWORD maxCallbacks = (image->rawSize - callbackOffset) / pointerSize;
            bool terminated = false;
            for (DWORD count = 0; count < maxCallbacks; ++count) {
                DWORD64 callback = 0;
                std::memcpy(&callback, image->rawData + callbackOffset + count * pointerSize,
                    pointerSize);
                if (callback == 0) {
                    terminated = true;
                    break;
                }
                image->tls.callbackAddresses.push_back(callback);
            }
            if (!terminated) {
                image->tls.callbackAddresses.clear();
                image->tls.valid = FALSE;
                return false;
            }
            image->tls.callbackCount = static_cast<DWORD>(image->tls.callbackAddresses.size());
        }
    }

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
    if (exceptionOffset == 0) {
        return false;
    }

    DWORD entryCount = exceptionDir.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
    PIMAGE_RUNTIME_FUNCTION_ENTRY runtimeFuncs =
        (PIMAGE_RUNTIME_FUNCTION_ENTRY)(image->rawData + exceptionOffset);

    for (DWORD i = 0; i < entryCount; i++) {
        CS_RUNTIME_FUNCTION entry;
        entry.beginAddress = runtimeFuncs[i].BeginAddress;
        entry.endAddress = runtimeFuncs[i].EndAddress;
        entry.unwindData = runtimeFuncs[i].UnwindData;
        image->exceptions.entries.push_back(entry);
    }

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

    DWORD loadConfigOffset = RVAToOffset(image, loadConfigDir.VirtualAddress);
    if (loadConfigOffset == 0 || loadConfigOffset >= image->rawSize) {
        return false;
    }

    image->loadConfig.directoryRVA = loadConfigDir.VirtualAddress;
    image->loadConfig.directorySize = loadConfigDir.Size;
    const size_t available = (std::min)(
        static_cast<size_t>(loadConfigDir.Size),
        static_cast<size_t>(image->rawSize - loadConfigOffset));
    auto hasField = [available](size_t offset, size_t size) {
        return offset <= available && size <= available - offset;
    };

    if (image->is64Bit) {
        if (hasField(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, GuardFlags), sizeof(DWORD))) {
            PIMAGE_LOAD_CONFIG_DIRECTORY64 lc = (PIMAGE_LOAD_CONFIG_DIRECTORY64)(image->rawData + loadConfigOffset);
            if (hasField(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, SecurityCookie), sizeof(lc->SecurityCookie)))
                image->loadConfig.securityCookie = lc->SecurityCookie;
            if (hasField(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, GuardCFCheckFunctionPointer), sizeof(lc->GuardCFCheckFunctionPointer)))
                image->loadConfig.guardCFCheckFunctionPointer = lc->GuardCFCheckFunctionPointer;
            if (hasField(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, GuardCFDispatchFunctionPointer), sizeof(lc->GuardCFDispatchFunctionPointer)))
                image->loadConfig.guardCFDispatchFunctionPointer = lc->GuardCFDispatchFunctionPointer;
            if (hasField(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, GuardCFFunctionTable), sizeof(lc->GuardCFFunctionTable)))
                image->loadConfig.guardCFFunctionTable = lc->GuardCFFunctionTable;
            if (hasField(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, GuardCFFunctionCount), sizeof(lc->GuardCFFunctionCount)))
                image->loadConfig.guardCFFunctionCount = lc->GuardCFFunctionCount;
            image->loadConfig.guardFlags = lc->GuardFlags;
            image->loadConfig.hasCFG = (lc->GuardFlags & IMAGE_GUARD_CF_INSTRUMENTED) != 0;
            image->loadConfig.hasRFGuard = (lc->GuardFlags &
                (IMAGE_GUARD_RF_INSTRUMENTED | IMAGE_GUARD_RF_ENABLE |
                 IMAGE_GUARD_RF_STRICT)) != 0;
            image->loadConfig.valid = TRUE;
        }
    } else {
        if (hasField(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, GuardFlags), sizeof(DWORD))) {
            PIMAGE_LOAD_CONFIG_DIRECTORY32 lc = (PIMAGE_LOAD_CONFIG_DIRECTORY32)(image->rawData + loadConfigOffset);
            if (hasField(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, SecurityCookie), sizeof(lc->SecurityCookie)))
                image->loadConfig.securityCookie = lc->SecurityCookie;
            if (hasField(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, GuardCFCheckFunctionPointer), sizeof(lc->GuardCFCheckFunctionPointer)))
                image->loadConfig.guardCFCheckFunctionPointer = lc->GuardCFCheckFunctionPointer;
            if (hasField(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, GuardCFDispatchFunctionPointer), sizeof(lc->GuardCFDispatchFunctionPointer)))
                image->loadConfig.guardCFDispatchFunctionPointer = lc->GuardCFDispatchFunctionPointer;
            if (hasField(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, GuardCFFunctionTable), sizeof(lc->GuardCFFunctionTable)))
                image->loadConfig.guardCFFunctionTable = lc->GuardCFFunctionTable;
            if (hasField(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, GuardCFFunctionCount), sizeof(lc->GuardCFFunctionCount)))
                image->loadConfig.guardCFFunctionCount = lc->GuardCFFunctionCount;
            image->loadConfig.guardFlags = lc->GuardFlags;
            image->loadConfig.hasCFG = (lc->GuardFlags & IMAGE_GUARD_CF_INSTRUMENTED) != 0;
            image->loadConfig.hasRFGuard = (lc->GuardFlags &
                (IMAGE_GUARD_RF_INSTRUMENTED | IMAGE_GUARD_RF_ENABLE |
                 IMAGE_GUARD_RF_STRICT)) != 0;
            image->loadConfig.valid = TRUE;
        }
    }

    if (image->loadConfig.valid && image->loadConfig.guardCFFunctionTable != 0 &&
        image->loadConfig.guardCFFunctionCount != 0) {
        constexpr DWORD kGuardTableSizeMask = 0xF0000000u;
        constexpr DWORD kGuardTableSizeShift = 28u;
        const DWORD extraBytes = (image->loadConfig.guardFlags & kGuardTableSizeMask) >>
            kGuardTableSizeShift;
        const DWORD entrySize = sizeof(DWORD) + extraBytes;
        image->loadConfig.guardTableEntrySize = entrySize;
        const uint64_t imageBase = image->is64Bit
            ? image->ntHeaders64->OptionalHeader.ImageBase
            : image->ntHeaders32->OptionalHeader.ImageBase;
        if (image->loadConfig.guardCFFunctionTable < imageBase ||
            image->loadConfig.guardCFFunctionTable - imageBase > 0xFFFFFFFFULL ||
            image->loadConfig.guardCFFunctionCount > 0x1000000ULL) {
            image->loadConfig.valid = FALSE;
            return false;
        }
        const DWORD tableRVA = static_cast<DWORD>(
            image->loadConfig.guardCFFunctionTable - imageBase);
        const DWORD tableOffset = RVAToOffset(image, tableRVA);
        const uint64_t tableBytes = image->loadConfig.guardCFFunctionCount * entrySize;
        if (tableOffset == 0 || tableBytes > image->rawSize - tableOffset) {
            image->loadConfig.valid = FALSE;
            return false;
        }
        image->loadConfig.guardFunctionRVAs.reserve(
            static_cast<size_t>(image->loadConfig.guardCFFunctionCount));
        for (uint64_t i = 0; i < image->loadConfig.guardCFFunctionCount; ++i) {
            DWORD functionRVA = 0;
            std::memcpy(&functionRVA,
                image->rawData + tableOffset + static_cast<size_t>(i * entrySize), sizeof(functionRVA));
            image->loadConfig.guardFunctionRVAs.push_back(functionRVA);
        }
    }

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

    DWORD debugOffset = RVAToOffset(image, debugDir.VirtualAddress);
    if (debugOffset == 0) {
        return false;
    }

    DWORD entryCount = debugDir.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
    PIMAGE_DEBUG_DIRECTORY debugEntries = (PIMAGE_DEBUG_DIRECTORY)(image->rawData + debugOffset);

    for (DWORD i = 0; i < entryCount; i++) {
        CS_DEBUG_ENTRY entry;
        entry.type = debugEntries[i].Type;
        entry.sizeOfData = debugEntries[i].SizeOfData;
        entry.addressOfRawData = debugEntries[i].AddressOfRawData;
        entry.pointerToRawData = debugEntries[i].PointerToRawData;
        image->debugDir.entries.push_back(entry);
    }

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

    DWORD delayOffset = RVAToOffset(image, delayImportDir.VirtualAddress);
    if (delayOffset == 0) {
        return false;
    }

    // 延迟导入使用 IMAGE_DELAYLOAD_DESCRIPTOR 结构
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


