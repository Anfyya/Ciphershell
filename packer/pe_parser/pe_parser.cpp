/**
 * CipherShell PE Parser - 瀹炵幇
 */

#include "pe_parser.h"
#include "pe_utils.h"
#include <cstring>
#include <algorithm>

namespace CipherShell {

// ============================================================================
// 鏋勯€?鏋愭瀯
// ============================================================================

PEParser::PEParser() {}

PEParser::~PEParser() {}

// ============================================================================
// 鍏叡鎺ュ彛
// ============================================================================

CS_PE_IMAGE* PEParser::LoadFromFile(const std::string& filePath) {
    // 鎵撳紑鏂囦欢
    HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        return nullptr;
    }

    // 鑾峰彇鏂囦欢澶у皬
    DWORD fileSize = GetFileSize(hFile, nullptr);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        CloseHandle(hFile);
        return nullptr;
    }

    // 鍒嗛厤缂撳啿鍖?    BYTE* buffer = new(std::nothrow) BYTE[fileSize];
    if (!buffer) {
        CloseHandle(hFile);
        return nullptr;
    }

    // 璇诲彇鏂囦欢
    DWORD bytesRead;
    if (!ReadFile(hFile, buffer, fileSize, &bytesRead, nullptr) || bytesRead != fileSize) {
        delete[] buffer;
        CloseHandle(hFile);
        return nullptr;
    }
    CloseHandle(hFile);

    // 瑙ｆ瀽
    CS_PE_IMAGE* image = LoadFromBuffer(buffer, fileSize);
    if (image) {
        image->filePath = filePath;
        // 娉ㄦ剰锛歳awData 鐨勬墍鏈夋潈杞Щ鍒?image锛屼笉鍐?delete
    } else {
        delete[] buffer;
    }

    return image;
}

CS_PE_IMAGE* PEParser::LoadFromBuffer(BYTE* buffer, DWORD size) {
    if (!buffer || size < sizeof(IMAGE_DOS_HEADER)) {
        return nullptr;
    }

    // 鍒涘缓 PE 闀滃儚
    CS_PE_IMAGE* image = new(std::nothrow) CS_PE_IMAGE();
    if (!image) {
        return nullptr;
    }

    // 鍒濆鍖?鈥?new CS_PE_IMAGE() 宸茬粡闆跺垵濮嬪寲 POD 骞舵瀯閫?string/vector锛?    // 缁濅笉鑳界敤 memset锛屼細鐮村潖 std::string/std::vector 鍐呴儴鐘舵€?    image->rawData = buffer;
    image->rawSize = size;
    image->isValid = FALSE;

    // 楠岃瘉鍩烘湰 PE 缁撴瀯
    if (!IsValidPE(image)) {
        SetError(image, "Invalid PE file");
        return image;
    }

    // 瑙ｆ瀽澶?    if (!ParseHeaders(image)) {
        return image;
    }

    // 瑙ｆ瀽鏁版嵁鐩綍
    if (!ParseDataDirectories(image)) {
        return image;
    }

    // 瑙ｆ瀽 Rich Header
    ParseRichHeader(image);

    // 妫€娴?.NET
    DetectDotNet(image);

    // 妫€娴?Overlay
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
// 澶撮儴瑙ｆ瀽
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

    // 妫€鏌ョ鍚?    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        SetError(image, "Invalid PE signature");
        return false;
    }

    // 鍒ゆ柇 x86/x64
    if (ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
        image->is64Bit = TRUE;
        image->ntHeaders64 = (PIMAGE_NT_HEADERS64)ntHeaders;
    } else if (ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
        image->is64Bit = FALSE;
        image->ntHeaders32 = (PIMAGE_NT_HEADERS32)ntHeaders;
        // BUG1淇锛?2浣峆E涓嶈兘璁剧疆ntHeaders64鎸囬拡锛屼袱鑰呯粨鏋勪綋甯冨眬涓嶅悓
        // IMAGE_NT_HEADERS32.OptionalHeader 涓?IMAGE_NT_HEADERS64.OptionalHeader 瀛楁鍋忕Щ涓嶅悓
        // 鐢╪tHeaders64璇诲彇32浣峆E浼氬鑷碔mageBase銆丼izeOfImage銆丒ntryPoint绛夊瓧娈甸敊浣?        image->ntHeaders64 = nullptr;
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

    // 楠岃瘉 section 澶翠笉瓒婄晫
    DWORD sectionEnd = (DWORD)((BYTE*)image->sections - image->rawData) +
                       image->numSections * sizeof(IMAGE_SECTION_HEADER);
    if (!CheckBounds(image, 0, sectionEnd)) {
        SetError(image, "Section headers exceed file bounds");
        return false;
    }

    return true;
}

// ============================================================================
// 鏁版嵁鐩綍瑙ｆ瀽
// ============================================================================

bool PEParser::ParseDataDirectories(CS_PE_IMAGE* image) {
    // 瀵煎叆琛?    if (!ParseImportTable(image)) {
        // 瀵煎叆琛ㄨВ鏋愬け璐ヤ笉鏄嚧鍛介敊璇紝鍙兘娌℃湁瀵煎叆琛?    }

    // 瀵煎嚭琛?    if (!ParseExportTable(image)) {
        // 瀵煎嚭琛ㄥ彲鑳戒笉瀛樺湪
    }

    // 閲嶅畾浣嶈〃
    if (!ParseRelocationTable(image)) {
        // 閲嶅畾浣嶈〃鍙兘涓嶅瓨鍦紙EXE 閫氬父鏈夛紝DLL 蹇呴』鏈夛級
    }

    // 璧勬簮琛?    if (!ParseResourceTable(image)) {
        // 璧勬簮鍙兘涓嶅瓨鍦?    }

    // TLS
    if (!ParseTLS(image)) {
        // TLS 鍙兘涓嶅瓨鍦?    }

    // 寮傚父澶勭悊琛?(x64)
    if (image->is64Bit) {
        if (!ParseExceptionTable(image)) {
            // 寮傚父琛ㄥ彲鑳戒笉瀛樺湪
        }
    }

    // Load Config
    if (!ParseLoadConfig(image)) {
        // Load Config 鍙兘涓嶅瓨鍦?    }

    // Debug 鐩綍
    if (!ParseDebugDirectory(image)) {
        // Debug 淇℃伅鍙兘涓嶅瓨鍦?    }

    // 寤惰繜瀵煎叆
    if (!ParseDelayImports(image)) {
        // 寤惰繜瀵煎叆鍙兘涓嶅瓨鍦?    }

    return true;
}

// ============================================================================
// 瀵煎叆琛ㄨВ鏋?// ============================================================================

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

    // 閬嶅巻瀵煎叆鎻忚堪绗?    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(image->rawData + importOffset);

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

        // 瑙ｆ瀽 ILT锛圛mport Lookup Table锛?        DWORD iltOffset = RVAToOffset(image, importDesc->OriginalFirstThunk);
        DWORD iatOffset = RVAToOffset(image, importDesc->FirstThunk);

        if (iltOffset == 0) {
            // 鏌愪簺鎯呭喌涓?ILT 鍙兘涓?锛屼娇鐢?IAT
            iltOffset = iatOffset;
        }

        if (iltOffset != 0 && iatOffset != 0) {
            if (image->is64Bit) {
                // 64浣?Thunk
                PIMAGE_THUNK_DATA64 ilt = (PIMAGE_THUNK_DATA64)(image->rawData + iltOffset);
                PIMAGE_THUNK_DATA64 iat = (PIMAGE_THUNK_DATA64)(image->rawData + iatOffset);
                DWORD thunkIndex = 0;

                while (ilt->u1.AddressOfData != 0) {
                    CS_IMPORT_FUNCTION func;
                    func.thunkRVA = importDesc->FirstThunk + thunkIndex * sizeof(IMAGE_THUNK_DATA64);

                    if (IMAGE_SNAP_BY_ORDINAL64(ilt->u1.Ordinal)) {
                        // 鎸夊簭鍙峰鍏?                        func.isOrdinal = true;
                        func.ordinal = IMAGE_ORDINAL64(ilt->u1.Ordinal);
                    } else {
                        // 鎸夊悕绉板鍏?                        func.isOrdinal = false;
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
                // 32浣?Thunk
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
// 瀵煎嚭琛ㄨВ鏋?// ============================================================================

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

    // 鑾峰彇鍑芥暟銆佸悕绉般€佸簭鍙疯〃
    DWORD functionsOffset = RVAToOffset(image, exportDirPtr->AddressOfFunctions);
    DWORD namesOffset = RVAToOffset(image, exportDirPtr->AddressOfNames);
    DWORD ordinalsOffset = RVAToOffset(image, exportDirPtr->AddressOfNameOrdinals);

    if (functionsOffset == 0) {
        return false;
    }

    DWORD* functions = (DWORD*)(image->rawData + functionsOffset);
    DWORD* names = namesOffset ? (DWORD*)(image->rawData + namesOffset) : nullptr;
    WORD* ordinals = ordinalsOffset ? (WORD*)(image->rawData + ordinalsOffset) : nullptr;

    // 鏋勫缓搴忓彿鍒板悕绉扮殑鏄犲皠
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

    // 鏋勫缓瀵煎嚭鍑芥暟鍒楄〃
    for (DWORD i = 0; i < exportDirPtr->NumberOfFunctions; i++) {
        if (functions[i] == 0) continue;  // 绌烘Ы浣?
        CS_EXPORT_FUNCTION func;
        func.ordinal = (WORD)(i + exportDirPtr->Base);
        func.functionRVA = functions[i];
        func.name = ordinalToName[i];

        // 妫€鏌ユ槸鍚︽槸杞彂鍣?        if (functions[i] >= exportDir.VirtualAddress &&
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
// 閲嶅畾浣嶈〃瑙ｆ瀽
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

            // 璺宠繃濉厖椤?            if (type == IMAGE_REL_BASED_ABSOLUTE) {
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
// 璧勬簮琛ㄨВ鏋?// ============================================================================

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

    // 璧勬簮琛ㄨВ鏋愯緝澶嶆潅锛岃繖閲屽彧鍋氬熀鏈獙璇?    // 瀹屾暣瀹炵幇灏嗗湪鍚庣画鐗堟湰涓坊鍔?    DWORD resourceOffset = RVAToOffset(image, resourceDir.VirtualAddress);
    if (resourceOffset == 0) {
        return false;
    }

    // 鏍囪璧勬簮琛ㄥ瓨鍦?    return true;
}

// ============================================================================
// TLS 瑙ｆ瀽
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

    // 璁＄畻鍥炶皟鏁伴噺
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
// 寮傚父澶勭悊琛ㄨВ鏋?(x64)
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
// Load Config 瑙ｆ瀽
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

    // Load Config 缁撴瀯澶у皬闅忕増鏈彉鍖栵紝杩欓噷鍙鍙栧叕鍏遍儴鍒?    if (image->is64Bit) {
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
// Debug 鐩綍瑙ｆ瀽
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
// 寤惰繜瀵煎叆瑙ｆ瀽
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

    // 寤惰繜瀵煎叆浣跨敤 IMAGE_DELAYLOAD_DESCRIPTOR 缁撴瀯
    // 杩欓噷鍙仛鍩烘湰鏍囪锛屽畬鏁村疄鐜板悗缁坊鍔?    return true;
}

// ============================================================================
// Rich Header 瑙ｆ瀽
// ============================================================================

bool PEParser::ParseRichHeader(CS_PE_IMAGE* image) {
    // Rich Header 鍦?DOS Header 鍜?PE 绛惧悕涔嬮棿
    // 鎼滅储 "Rich" 鏍囪
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
// .NET 妫€娴?// ============================================================================

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
// Overlay 妫€娴?// ============================================================================

bool PEParser::DetectOverlay(CS_PE_IMAGE* image) {
    // 鎵惧埌鏈€鍚庝竴涓?section 鐨勭粨鏉熶綅缃?    DWORD lastSectionEnd = 0;
    for (WORD i = 0; i < image->numSections; i++) {
        DWORD sectionEnd = image->sections[i].PointerToRawData + image->sections[i].SizeOfRawData;
        if (sectionEnd > lastSectionEnd) {
            lastSectionEnd = sectionEnd;
        }
    }

    // 妫€鏌ユ槸鍚︽湁棰濆鏁版嵁
    if (lastSectionEnd < image->rawSize) {
        image->hasOverlay = TRUE;
        image->overlayOffset = lastSectionEnd;
    }

    return image->hasOverlay;
}

// ============================================================================
// 杈呭姪鍑芥暟
// ============================================================================

DWORD PEParser::RVAToOffset(CS_PE_IMAGE* image, DWORD rva) {
    return PEUtils::RvaToOffset(image, rva);
}

bool PEParser::IsValidPE(CS_PE_IMAGE* image) {
    if (image->rawSize < sizeof(IMAGE_DOS_HEADER)) {
        return false;
    }

    // 妫€鏌?DOS 绛惧悕
    if (image->rawData[0] != 'M' || image->rawData[1] != 'Z') {
        return false;
    }

    // 鑾峰彇 NT Headers 鍋忕Щ
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)image->rawData;
    if (dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS32) > image->rawSize) {
        return false;
    }

    // 妫€鏌?PE 绛惧悕
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(image->rawData + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    return true;
}

bool PEParser::CheckBounds(CS_PE_IMAGE* image, DWORD offset, DWORD size) {
    // BUG2淇锛氶槻姝?offset+size 鏁存暟婧㈠嚭缁曡繃杈圭晫妫€鏌?    // 渚嬪 offset=0xFFFFFFF0, size=0x20 鏃? offset+size=0x10 浼氶敊璇湴閫氳繃妫€鏌?    // 瀹夊叏鍐欐硶锛氬厛妫€鏌?offset 鏄惁瓒婄晫锛屽啀鐢ㄥ噺娉曟鏌?size
    return (offset <= image->rawSize && size <= image->rawSize - offset);
}

void PEParser::SetError(CS_PE_IMAGE* image, const std::string& message) {
    if (image) {
        image->errorMessage = message;
        image->isValid = FALSE;
    }
}

} // namespace CipherShell


