/**
 * CipherShell PE Rebuilder - 瀹炵幇
 */

#include "pe_rebuilder.h"
#include "pe_utils.h"
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <algorithm>

namespace CipherShell {

// ============================================================================
// 鏋勯€?鏋愭瀯
// ============================================================================

PERebuilder::PERebuilder() {
    // 鍒濆鍖栭殢鏈烘暟鐢熸垚鍣?    srand((unsigned int)time(nullptr));
}

PERebuilder::~PERebuilder() {}

// ============================================================================
// 鍏叡鎺ュ彛
// ============================================================================

BYTE* PERebuilder::RebuildImage(CS_PE_IMAGE* image, const CS_REBUILD_CONFIG& config, DWORD* outputSize) {
    if (!image || !image->isValid || !outputSize) {
        return nullptr;
    }

    // 绠€鍗曟柟娉曪細澶嶅埗鏁翠釜鍘熷鏂囦欢锛岀劧鍚庝慨鏀?    DWORD totalSize = image->rawSize + 0x10000;  // 棰濆绌洪棿

    // 鍒嗛厤杈撳嚭缂撳啿鍖?    BYTE* output = new(std::nothrow) BYTE[totalSize];
    if (!output) {
        return nullptr;
    }
    memset(output, 0, totalSize);

    // 澶嶅埗鍘熷鏁版嵁
    memcpy(output, image->rawData, image->rawSize);

    // 鑾峰彇 NT Headers
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)output;
    if (dosHeader->e_lfanew <= 0 || static_cast<DWORD>(dosHeader->e_lfanew) >= image->rawSize) {
        *outputSize = image->rawSize;
        return output;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(output + static_cast<DWORD>(dosHeader->e_lfanew));

    // 娓呴櫎鏃堕棿鎴?    if (config.zeroTimestamps) {
        ntHeaders->FileHeader.TimeDateStamp = 0;
    }

    // 娓呴櫎璋冭瘯淇℃伅
    if (!config.preserveDebugInfo) {
        if (ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
            PIMAGE_NT_HEADERS64 nt64 = (PIMAGE_NT_HEADERS64)ntHeaders;
            nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
            nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
        } else {
            PIMAGE_NT_HEADERS32 nt32 = (PIMAGE_NT_HEADERS32)ntHeaders;
            nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
            nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
        }
    }

    // 娓呴櫎鏍￠獙鍜?    if (!config.preserveChecksum) {
        if (ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
            ((PIMAGE_NT_HEADERS64)ntHeaders)->OptionalHeader.CheckSum = 0;
        } else {
            ((PIMAGE_NT_HEADERS32)ntHeaders)->OptionalHeader.CheckSum = 0;
        }
    }

    // 闅忔満鍖?section 鍚嶇О
    if (config.randomizeSectionNames) {
        PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(ntHeaders);
        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            char name[9] = {0};
            memcpy(name, sections[i].Name, 8);
            if (strncmp(name, ".rsrc", 5) != 0 && strncmp(name, ".reloc", 6) != 0) {
                GenerateRandomName((char*)sections[i].Name, 8);
            }
        }
    }

    *outputSize = image->rawSize;
    return output;
}

void PERebuilder::AddSection(std::vector<CS_SECTION_CONFIG>& sections, const CS_SECTION_CONFIG& section) {
    CS_SECTION_CONFIG fixedSection = section;

    // BUG4淇锛歏irtualSize=0 浼氬鑷磋妭鍖哄湪鍐呭瓨涓鏄犲皠涓洪浂澶у皬锛岃妭鍖烘暟鎹涪澶?    // Windows PE 鍔犺浇鍣ㄥ湪 VirtualSize=0 鏃跺彲鑳戒笉鍒嗛厤鍐呭瓨椤碉紝瀵艰嚧杩愯鏃惰闂繚渚?    // 鑷冲皯搴旂瓑浜?SizeOfRawData锛堝嵆 dataSize锛夛紝纭繚鏁版嵁鑳藉畬鏁存槧灏勫埌鍐呭瓨
    if (fixedSection.virtualSize == 0 && fixedSection.dataSize > 0) {
        DWORD align = fixedSection.alignment > 0 ? fixedSection.alignment : 0x1000;
        // 鎸?SectionAlignment 瀵归綈
        fixedSection.virtualSize = (fixedSection.dataSize + align - 1) & ~(align - 1);
    }

    sections.push_back(fixedSection);
}

char* PERebuilder::GenerateRandomSectionName() {
    static char name[8];
    GenerateRandomName(name, 8);
    return name;
}

bool PERebuilder::ModifySectionCharacteristics(CS_PE_IMAGE* image, WORD sectionIndex, DWORD newCharacteristics) {
    if (!image || sectionIndex >= image->numSections) {
        return false;
    }

    image->sections[sectionIndex].Characteristics = newCharacteristics;
    return true;
}

bool PERebuilder::SetEntryPoint(CS_PE_IMAGE* image, DWORD newEntryPoint) {
    if (!image) {
        return false;
    }

    if (image->is64Bit) {
        image->ntHeaders64->OptionalHeader.AddressOfEntryPoint = newEntryPoint;
    } else {
        image->ntHeaders32->OptionalHeader.AddressOfEntryPoint = newEntryPoint;
    }

    return true;
}

// ============================================================================
// 閲嶅缓瀹炵幇
// ============================================================================

bool PERebuilder::RebuildHeaders(BYTE* output, CS_PE_IMAGE* image, const CS_REBUILD_CONFIG& config) {
    // 澶嶅埗鍘熷澶撮儴
    DWORD headerSize = image->sections[0].PointerToRawData;
    if (headerSize == 0 || headerSize > image->rawSize) headerSize = 0x400;
    if (headerSize > image->rawSize) headerSize = image->rawSize;
    
    memcpy(output, image->rawData, headerSize);

    // 鑾峰彇杈撳嚭缂撳啿鍖轰腑鐨?NT Headers 鎸囬拡
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)output;
    if (dosHeader->e_lfanew <= 0 || static_cast<DWORD>(dosHeader->e_lfanew) > headerSize) return true;
    
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(output + static_cast<DWORD>(dosHeader->e_lfanew));

    // 澶勭悊 Rich Header
    if (!config.preserveRichHeader && image->hasRichHeader && image->richHeaderOffset > static_cast<DWORD>(sizeof(IMAGE_DOS_HEADER))) {
        DWORD richClearSize = image->richHeaderOffset - static_cast<DWORD>(sizeof(IMAGE_DOS_HEADER));
        if (richClearSize < headerSize) {
            memset(output + sizeof(IMAGE_DOS_HEADER), 0, richClearSize);
        }
    }

    // 澶勭悊鏃堕棿鎴筹紙淇敼杈撳嚭缂撳啿鍖猴紝涓嶆槸鍘熷闀滃儚锛?    if (config.zeroTimestamps) {
        ntHeaders->FileHeader.TimeDateStamp = 0;
    } else if (config.randomizeTimestamps) {
        ntHeaders->FileHeader.TimeDateStamp = GenerateRandomDWORD();
    }

    // 澶勭悊璋冭瘯淇℃伅锛堜慨鏀硅緭鍑虹紦鍐插尯锛?    if (!config.preserveDebugInfo) {
        if (image->is64Bit && ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
            PIMAGE_NT_HEADERS64 ntHeaders64 = (PIMAGE_NT_HEADERS64)ntHeaders;
            ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
            ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
        } else {
            PIMAGE_NT_HEADERS32 ntHeaders32 = (PIMAGE_NT_HEADERS32)ntHeaders;
            ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
            ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
        }
    }

    // 澶勭悊鏍￠獙鍜?    if (!config.preserveChecksum) {
        if (image->is64Bit && ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
            PIMAGE_NT_HEADERS64 ntHeaders64 = (PIMAGE_NT_HEADERS64)ntHeaders;
            ntHeaders64->OptionalHeader.CheckSum = 0;
        } else {
            PIMAGE_NT_HEADERS32 ntHeaders32 = (PIMAGE_NT_HEADERS32)ntHeaders;
            ntHeaders32->OptionalHeader.CheckSum = 0;
        }
    }

    return true;
}

bool PERebuilder::RebuildSections(BYTE* output, CS_PE_IMAGE* image, const CS_REBUILD_CONFIG& config) {
    // 鑾峰彇 NT Headers 淇℃伅
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)output;
    if (dosHeader->e_lfanew <= 0 || static_cast<DWORD>(dosHeader->e_lfanew) > 0x1000) return false;
    
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(output + static_cast<DWORD>(dosHeader->e_lfanew));

    DWORD headerSize = image->sections[0].PointerToRawData;
    if (headerSize == 0 || headerSize > image->rawSize) headerSize = 0x200;
    
    DWORD currentOffset = AlignValue(headerSize, config.fileAlignment);

    for (WORD i = 0; i < image->numSections; i++) {
        PIMAGE_SECTION_HEADER section = &image->sections[i];

        // 瀹夊叏妫€鏌?        if (section->SizeOfRawData == 0) continue;
        if (section->PointerToRawData == 0) continue;
        if (section->PointerToRawData + section->SizeOfRawData > image->rawSize) continue;

        // 澶嶅埗 section 鏁版嵁
        DWORD copySize = section->SizeOfRawData;
        if (copySize > 0) {
            memcpy(output + currentOffset,
                   image->rawData + section->PointerToRawData,
                   copySize);
        }

        // 鏇存柊 section 澶翠腑鐨勫亸绉?        DWORD sectionHeaderOffset = dosHeader->e_lfanew +
            sizeof(DWORD) +  // PE signature
            sizeof(IMAGE_FILE_HEADER) +
            ntHeaders->FileHeader.SizeOfOptionalHeader +
            i * sizeof(IMAGE_SECTION_HEADER);
        
        if (sectionHeaderOffset + sizeof(IMAGE_SECTION_HEADER) <= headerSize) {
            PIMAGE_SECTION_HEADER outputSection = (PIMAGE_SECTION_HEADER)(output + sectionHeaderOffset);
            outputSection->PointerToRawData = currentOffset;
            outputSection->SizeOfRawData = AlignValue(section->SizeOfRawData, config.fileAlignment);

            // 闅忔満鍖?section 鍚嶇О
            if (config.randomizeSectionNames) {
                char name[9] = {0};
                memcpy(name, outputSection->Name, 8);
                if (strncmp(name, ".rsrc", 5) != 0 && strncmp(name, ".reloc", 6) != 0) {
                    GenerateRandomName((char*)outputSection->Name, 8);
                }
            }
        }

        currentOffset += AlignValue(section->SizeOfRawData, config.fileAlignment);
    }

    return true;
}

bool PERebuilder::RebuildOverlay(BYTE* output, CS_PE_IMAGE* image, const CS_REBUILD_CONFIG& config) {
    if (!config.preserveOverlay || !image->hasOverlay) {
        return true;
    }

    // 鎵惧埌鏈€鍚庝竴涓?section 鐨勭粨鏉熶綅缃?    DWORD lastSectionEnd = 0;
    for (WORD i = 0; i < image->numSections; i++) {
        DWORD sectionEnd = image->sections[i].PointerToRawData + image->sections[i].SizeOfRawData;
        if (sectionEnd > lastSectionEnd) {
            lastSectionEnd = sectionEnd;
        }
    }

    // 澶嶅埗 overlay 鏁版嵁
    DWORD overlaySize = image->rawSize - image->overlayOffset;
    memcpy(output + lastSectionEnd,
           image->rawData + image->overlayOffset,
           overlaySize);

    return true;
}

// ============================================================================
// 杈呭姪鍑芥暟
// ============================================================================

DWORD PERebuilder::AlignValue(DWORD value, DWORD alignment) {
    if (alignment == 0) return value;
    return (value + alignment - 1) & ~(alignment - 1);
}

void PERebuilder::GenerateRandomName(char* name, DWORD length) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyz";
    for (DWORD i = 0; i < length - 1; i++) {
        name[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    name[length - 1] = '\0';
}

DWORD PERebuilder::CalculateChecksum(BYTE* data, DWORD size) {
    DWORD checksum = 0;
    DWORD remainder = size % 4;
    DWORD longs = size / 4;

    // 瀵规瘡涓?DWORD 姹傚拰
    for (DWORD i = 0; i < longs; i++) {
        DWORD value = *(DWORD*)(data + i * 4);
        checksum += value;
        if (checksum < value) {
            checksum++;
        }
    }

    // 澶勭悊鍓╀綑瀛楄妭
    if (remainder > 0) {
        DWORD value = 0;
        memcpy(&value, data + longs * 4, remainder);
        checksum += value;
        if (checksum < value) {
            checksum++;
        }
    }

    // 楂樹綆16浣嶇浉鍔?    checksum = (checksum & 0xFFFF) + (checksum >> 16);
    checksum += (checksum >> 16);
    checksum &= 0xFFFF;

    return checksum + size;
}

bool PERebuilder::UpdateChecksum(BYTE* peData, DWORD actualFileSize) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)peData;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(peData + static_cast<DWORD>(dosHeader->e_lfanew));

    // BUG3淇锛氫娇鐢ㄥ疄闄呮枃浠剁紦鍐插尯澶у皬鑰岄潪 SizeOfImage锛堝唴瀛樻槧鍍忓ぇ灏忥級
    // SizeOfImage 鏄?PE 鏄犲皠鍒板唴瀛樺悗鐨勫ぇ灏忥紙鎸?SectionAlignment 瀵归綈锛夛紝閫氬父杩滃ぇ浜庢枃浠跺ぇ灏?    // 鐢?SizeOfImage 璁＄畻鏍￠獙鍜屼細璇诲彇瓒呭嚭鏂囦欢鏁版嵁鑼冨洿鐨勫唴瀛橈紝瀵艰嚧鏍￠獙鍜岄敊璇?    DWORD checksum = CalculateChecksum(peData, actualFileSize);

    // 鏇存柊鏍￠獙鍜?    if (ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
        ((PIMAGE_NT_HEADERS64)ntHeaders)->OptionalHeader.CheckSum = checksum;
    } else {
        ((PIMAGE_NT_HEADERS32)ntHeaders)->OptionalHeader.CheckSum = checksum;
    }

    return true;
}

DWORD PERebuilder::GenerateRandomDWORD() {
    return ((DWORD)rand() << 16) | (DWORD)rand();
}

BYTE PERebuilder::GenerateRandomBYTE() {
    return (BYTE)(rand() % 256);
}

} // namespace CipherShell

