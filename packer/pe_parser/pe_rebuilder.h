/**
 * CipherShell PE Rebuilder
 * 重建 PE 文件结构
 */

#ifndef CS_PE_REBUILDER_H
#define CS_PE_REBUILDER_H

#include "pe_parser.h"
#include <vector>
#include <string>

namespace CipherShell {

// ============================================================================
// Section 配置
// ============================================================================

struct CS_SECTION_CONFIG {
    char            name[8];            // Section 名称
    DWORD           virtualSize;        // 虚拟大小
    DWORD           characteristics;    // 属性标志
    BYTE*           data;               // Section 数据
    DWORD           dataSize;           // 数据大小
    DWORD           alignment;          // 对齐要求
};

// ============================================================================
// PE 重建配置
// ============================================================================

struct CS_REBUILD_CONFIG {
    // 基本选项
    BOOL            preserveTimestamps;     // 保留时间戳
    BOOL            preserveChecksum;       // 保留校验和
    BOOL            preserveRichHeader;     // 保留 Rich Header
    BOOL            preserveDebugInfo;      // 保留调试信息
    BOOL            preserveSignature;      // 保留签名
    BOOL            preserveOverlay;        // 保留 Overlay 数据

    // 随机化选项
    BOOL            randomizeSectionNames;  // 随机化 section 名称
    BOOL            randomizeTimestamps;    // 随机化时间戳
    BOOL            zeroTimestamps;         // 时间戳归零

    // 对齐选项
    DWORD           fileAlignment;          // 文件对齐
    DWORD           sectionAlignment;       // 内存对齐

    // 构造函数 - 默认值
    CS_REBUILD_CONFIG() :
        preserveTimestamps(FALSE),
        preserveChecksum(FALSE),
        preserveRichHeader(FALSE),
        preserveDebugInfo(FALSE),
        preserveSignature(FALSE),
        preserveOverlay(TRUE),
        randomizeSectionNames(TRUE),
        randomizeTimestamps(FALSE),
        zeroTimestamps(TRUE),
        fileAlignment(0x200),
        sectionAlignment(0x1000) {}
};

// ============================================================================
// PE Rebuilder 类
// ============================================================================

class PERebuilder {
public:
    PERebuilder();
    ~PERebuilder();

    /**
     * 从解析后的 PE 镜像重建文件
     * @param image 解析后的 PE 镜像
     * @param config 重建配置
     * @param outputSize 输出数据大小
     * @return 重建后的 PE 数据，调用者负责释放
     */
    BYTE* RebuildImage(CS_PE_IMAGE* image, const CS_REBUILD_CONFIG& config, DWORD* outputSize);

    /**
     * 添加新的 section
     * @param sections section 列表
     * @param section 要添加的 section
     */
    void AddSection(std::vector<CS_SECTION_CONFIG>& sections, const CS_SECTION_CONFIG& section);

    /**
     * 生成随机 section 名称
     * @return 8字节的随机名称
     */
    char* GenerateRandomSectionName();

    /**
     * 修改现有 section 的属性
     * @param image PE 镜像
     * @param sectionIndex section 索引
     * @param newCharacteristics 新属性
     * @return 是否成功
     */
    bool ModifySectionCharacteristics(CS_PE_IMAGE* image, WORD sectionIndex, DWORD newCharacteristics);

    /**
     * 设置入口点
     * @param image PE 镜像
     * @param newEntryPoint 新入口点 RVA
     * @return 是否成功
     */
    bool SetEntryPoint(CS_PE_IMAGE* image, DWORD newEntryPoint);

private:
    // 辅助函数
    void GenerateRandomName(char* name, DWORD length);
};

} // namespace CipherShell

#endif // CS_PE_REBUILDER_H
