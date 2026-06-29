/**
 * CipherShell PE Parser - 实现
 */

#include "pe_parser.h"
#include <cstring>
#include <algorithm>

namespace CipherShell {

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

    // 分配缓冲区
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

    // 初始化 — new CS_PE_IMAGE() 已经零初始化 POD 并构造 string/vector，
    // 绝不能用 memset，会破坏 std::string/std::vector 内部状态
    image->rawData = buffer;
    image->rawSize = size;
    image->isValid = FALSE;

    // 验证基本 PE 结构
    if (!IsValidPE(image)) {
        SetError(image, "Invalid PE file");
        return image;
    }

    // 解析头
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
    // DOS Header
    image->dosHeader = (PIMAGE_DOS_HEADER)image->rawData;

    // NT Headers
    DWORD ntOffset = image->dosHeader->e_lfanew;
    if (!CheckBounds(image, ntOffset, sizeof(IMAGE_NT_HEADERS64))) {
        SetError(image, "Invalid NT Headers offset");
        return false;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(image->rawData + ntOffset);

    // 检查签名
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        SetError(image, "Invalid PE signature");
        return false;
    }

    // 判断 x86/x64
    if (ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
        image->is64Bit = TRUE;
        image->ntHeaders64 = (PIMAGE_NT_HEADERS64)ntHeaders;
    } else if (ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
        image->is64Bit = FALSE;
        image->ntHeaders32 = (PIMAGE_NT_HEADERS32)ntHeaders;
        // BUG1修复：32位PE不能设置ntHeaders64指针，两者结构体布局不同
        // IMAGE_NT_HEADERS32.OptionalHeader 与 IMAGE_NT_HEADERS64.OptionalHeader 字段偏移不同
        // 用ntHeaders64读取32位PE会导致ImageBase、SizeOfImage、EntryPoint等字段错位
        image->ntHeaders64 = nullptr;
    } else {
        SetError(image, "Unsupported machine type");
        return false;
    }

    // Section Headers
    image->numSections = ntHeaders->FileHeader.NumberOfSections;
    if (image->is64Bit) {
        image->sections = IMAGE_FIRST_SECTION(image->ntHeaders64);
    } else {
        image->sections = IMAGE_FIRST_SECTION(image->ntHeaders32);
    }

    // 验证 section 头不越界
    DWORD sectionEnd = (DWORD)((BYTE*)image->sections - image->rawData) +
                       image->numSections * sizeof(IMAGE_SECTION_HEADER);
    if (!CheckBounds(image, 0, sectionEnd)) {
        SetError(image, "Section headers exceed file bounds");
        return false;
    }

    return true;
}

// ============================================================================
// 数据目录解析
// ============================================================================

bool PEParser::ParseDataDirectories(CS_PE_IMAGE* image) {
    // 导入表
    if (!ParseImportTable(image)) {
        // 导入表解析失败不是致命错误，可能没有导入表
    }

    // 导出表
    if (!ParseExportTable(image)) {
        // 导出表可能不存在
    }

    // 重定位表
    if (!ParseRelocationTable(image)) {
        // 重定位表可能不存在（EXE 通常有，DLL 必须有）
    }

    // 资源表
    if (!ParseResourceTable(image)) {
        // 资源可能不存在
    }

    // TLS
    if (!ParseTLS(image)) {
        // TLS 可能不存在
    }

    // 异常处理表 (x64)
    if (image->is64Bit) {
        if (!ParseExceptionTable(image)) {
            // 异常表可能不存在
        }
    }

    // Load Config
    if (!ParseLoadConfig(image)) {
        // Load Config 可能不存在
    }

    // Debug 目录
    if (!ParseDebugDirectory(image)) {
        // Debug 信息可能不存在
    }

    // 延迟导入
    if (!ParseDelayImports(image)) {
        // 延迟导入可能不存在
    }

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

    // 遍历导入描述符
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(image->rawData + importOffset);

    while (importDesc->Name != 0) {
        CS_IMPORT_DLL importDll;

        // DLL 名称
        DWORD nameOffset = RVAToOffset(image, importDesc->Name);
        if (nameOffset == 0) {
            importDesc++;
            continue;
        }
        importDll.dllName = (char*)(image->rawData + nameOffset);
        importDll.originalFirstThunkRVA = importDesc->OriginalFirstThunk;
        importDll.firstThunkRVA = importDesc->FirstThunk;

        // 解析 ILT（Import Lookup Table）
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
                        func.isOrdinal = true;
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

    // DLL 名称
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

        // 检查是否是转发器
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

            // 跳过填充项
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
// ============================================================================

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

    // 资源表解析较复杂，这里只做基本验证
    // 完整实现将在后续版本中添加
    DWORD resourceOffset = RVAToOffset(image, resourceDir.VirtualAddress);
    if (resourceOffset == 0) {
        return false;
    }

    // 标记资源表存在
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

        if (callbackOffset != 0) {
            DWORD count = 0;
            if (image->is64Bit) {
                DWORD64* callbacks = (DWORD64*)(image->rawData + callbackOffset);
                while (callbacks[count] != 0) count++;
            } else {
                DWORD* callbacks = (DWORD*)(image->rawData + callbackOffset);
                while (callbacks[count] != 0) count++;
            }
            image->tls.callbackCount = count;
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
    if (loadConfigOffset == 0) {
        return false;
    }

    // Load Config 结构大小随版本变化，这里只读取公共部分
    if (image->is64Bit) {
        if (loadConfigDir.Size >= sizeof(IMAGE_LOAD_CONFIG_DIRECTORY64)) {
            PIMAGE_LOAD_CONFIG_DIRECTORY64 lc = (PIMAGE_LOAD_CONFIG_DIRECTORY64)(image->rawData + loadConfigOffset);
            image->loadConfig.securityCookie = lc->SecurityCookie;
            image->loadConfig.guardCFCheckFunctionPointer = lc->GuardCFCheckFunctionPointer;
            image->loadConfig.guardCFDispatchFunctionPointer = lc->GuardCFDispatchFunctionPointer;
            image->loadConfig.guardFlags = lc->GuardFlags;
            image->loadConfig.hasCFG = (lc->GuardFlags & IMAGE_GUARD_CF_INSTRUMENTED) != 0;
            image->loadConfig.valid = TRUE;
        }
    } else {
        if (loadConfigDir.Size >= sizeof(IMAGE_LOAD_CONFIG_DIRECTORY32)) {
            PIMAGE_LOAD_CONFIG_DIRECTORY32 lc = (PIMAGE_LOAD_CONFIG_DIRECTORY32)(image->rawData + loadConfigOffset);
            image->loadConfig.securityCookie = lc->SecurityCookie;
            image->loadConfig.guardCFCheckFunctionPointer = lc->GuardCFCheckFunctionPointer;
            image->loadConfig.guardCFDispatchFunctionPointer = lc->GuardCFDispatchFunctionPointer;
            image->loadConfig.guardFlags = lc->GuardFlags;
            image->loadConfig.hasCFG = (lc->GuardFlags & IMAGE_GUARD_CF_INSTRUMENTED) != 0;
            image->loadConfig.valid = TRUE;
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
    // 这里只做基本标记，完整实现后续添加
    return true;
}

// ============================================================================
// Rich Header 解析
// ============================================================================

bool PEParser::ParseRichHeader(CS_PE_IMAGE* image) {
    // Rich Header 在 DOS Header 和 PE 签名之间
    // 搜索 "Rich" 标记
    DWORD richSignature = 0x68636952;  // "Rich"

    for (DWORD i = sizeof(IMAGE_DOS_HEADER); i < image->dosHeader->e_lfanew; i += 4) {
        DWORD* ptr = (DWORD*)(image->rawData + i);
        if (*ptr == richSignature) {
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
// ============================================================================

bool PEParser::DetectOverlay(CS_PE_IMAGE* image) {
    // 找到最后一个 section 的结束位置
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
    if (rva == 0) return 0;

    // 遍历所有 section，找到 RVA 所在的 section
    for (WORD i = 0; i < image->numSections; i++) {
        DWORD sectionStart = image->sections[i].VirtualAddress;
        DWORD sectionEnd = sectionStart + image->sections[i].SizeOfRawData;

        if (rva >= sectionStart && rva < sectionEnd) {
            // 计算文件偏移
            DWORD offset = rva - sectionStart + image->sections[i].PointerToRawData;
            if (CheckBounds(image, offset, 1)) {
                return offset;
            }
        }
    }

    // 如果 RVA 在 headers 范围内
    if (rva < image->sections[0].PointerToRawData) {
        return rva;
    }

    return 0;
}

bool PEParser::IsValidPE(CS_PE_IMAGE* image) {
    if (image->rawSize < sizeof(IMAGE_DOS_HEADER)) {
        return false;
    }

    // 检查 DOS 签名
    if (image->rawData[0] != 'M' || image->rawData[1] != 'Z') {
        return false;
    }

    // 获取 NT Headers 偏移
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)image->rawData;
    if (dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS32) > image->rawSize) {
        return false;
    }

    // 检查 PE 签名
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(image->rawData + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    return true;
}

bool PEParser::CheckBounds(CS_PE_IMAGE* image, DWORD offset, DWORD size) {
    // BUG2修复：防止 offset+size 整数溢出绕过边界检查
    // 例如 offset=0xFFFFFFF0, size=0x20 时, offset+size=0x10 会错误地通过检查
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
