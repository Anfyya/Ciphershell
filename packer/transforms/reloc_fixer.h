/**
 * CipherShell 重定位修复器
 * 处理 PE 文件的重定位表
 */

#ifndef CS_RELOC_FIXER_H
#define CS_RELOC_FIXER_H

#include "../pe_parser/pe_parser.h"
#include <cstdint>
#include <vector>

namespace CipherShell {

// ============================================================================
// 重定位配置
// ============================================================================

struct CS_RELOC_CONFIG {
    BOOL        preserveRelocs;         // 保留重定位表
    BOOL        encryptRelocs;          // 加密重定位表
    BOOL        randomizeRelocs;        // 随机化重定位顺序
    DWORD       relocAlignment;         // 重定位对齐

    // 构造函数 - 默认值
    CS_RELOC_CONFIG() :
        preserveRelocs(TRUE),
        encryptRelocs(FALSE),
        randomizeRelocs(FALSE),
        relocAlignment(0x1000) {}
};

// ============================================================================
// 重定位修复器类
// ============================================================================

class RelocFixer {
public:
    RelocFixer();
    ~RelocFixer();

    /**
     * 修复重定位表
     * @param image PE 镜像
     * @param newImageBase 新的映像基址
     * @param config 重定位配置
     * @return 是否成功
     */
    bool FixRelocations(
        CS_PE_IMAGE* image,
        DWORD64 newImageBase,
        const CS_RELOC_CONFIG& config
    );

    /**
     * 重建重定位表
     * @param image PE 镜像
     * @param newRelocs 新的重定位条目
     * @return 是否成功
     */
    bool RebuildRelocations(
        CS_PE_IMAGE* image,
        const std::vector<CS_RELOC_ENTRY>& newRelocs
    );

    /**
     * 应用重定位到内存映像
     * @param imageBase 映像基址
     * @param relocs 重定位条目
     * @param delta 基址差值
     * @return 是否成功
     */
    static bool ApplyRelocations(
        BYTE* imageBase,
        const std::vector<CS_RELOC_ENTRY>& relocs,
        int64_t delta
    );

    /**
     * 从内存映像中提取重定位信息
     * @param imageBase 映像基址
     * @param imageSize 映像大小
     * @param originalBase 原始基址
     * @return 重定位条目列表
     */
    static std::vector<CS_RELOC_ENTRY> ExtractRelocations(
        BYTE* imageBase,
        DWORD imageSize,
        DWORD64 originalBase
    );

private:
    // 重定位类型处理
    bool ProcessRelocType(BYTE* address, WORD type, int64_t delta);

    // 辅助函数
    DWORD AlignValue(DWORD value, DWORD alignment);
    bool IsValidRelocType(WORD type, bool is64Bit);
};

} // namespace CipherShell

#endif // CS_RELOC_FIXER_H
