#ifndef CS_PE_EMITTER_H
#define CS_PE_EMITTER_H

#include "pe_parser.h"
#include <cstdint>
#include <string>
#include <vector>

namespace CipherShell {

struct PEAppendSectionResult {
    bool success = false;
    uint32_t sectionIndex = 0;
    uint32_t rva = 0;
    uint32_t rawOffset = 0;
    uint32_t rawSize = 0;
    uint32_t virtualSize = 0;
    std::string error;
};

class PEEmitter {
public:
    explicit PEEmitter(CS_PE_IMAGE* image);

    bool IsValid() const;
    uint32_t GetFileAlignment() const;
    uint32_t GetSectionAlignment() const;
    uint32_t GetSizeOfHeaders() const;
    uint32_t GetEntryPoint() const;
    void SetEntryPoint(uint32_t rva);
    uint32_t RvaToOffset(uint32_t rva) const;
    bool PredictNextSectionRVA(uint32_t& rva, std::string* error = nullptr) const;

    PEAppendSectionResult AppendSection(
        const char name[8],
        const std::vector<uint8_t>& data,
        uint32_t characteristics);

    bool PatchBytes(uint32_t rva, const std::vector<uint8_t>& bytes, std::string* error = nullptr);
    bool FillBytes(uint32_t rva, uint32_t size, uint8_t value, std::string* error = nullptr);
    bool SetSectionCharacteristics(uint32_t sectionIndex, uint32_t characteristics, std::string* error = nullptr);
    bool RebuildExceptionDirectory(
        const std::vector<CS_RUNTIME_FUNCTION>& additionalEntries,
        const char sectionName[8],
        PEAppendSectionResult* sectionResult = nullptr,
        std::string* error = nullptr);
    bool RebuildGuardCFFunctionTable(
        const std::vector<uint32_t>& additionalFunctionRVAs,
        const char sectionName[8],
        PEAppendSectionResult* sectionResult = nullptr,
        std::string* error = nullptr);
    // x86 only.  additionalHandlerRVAs are newly generated SEH handler entry
    // points (already final image RVAs) that must be callable during unwind.
    //
    //   - No existing SafeSEH contract (LoadConfig has no valid
    //     SEHandlerTable/SEHandlerCount): a no-op success.  Fabricating a new
    //     SafeSEH table here would apply strict handler enumeration to
    //     pre-existing code that was never linked with /SAFESEH, silently
    //     invalidating its legitimate handlers.
    //   - IMAGE_DLLCHARACTERISTICS_NO_SEH set: fail-closed.  That flag makes
    //     RtlIsValidHandler reject every handler in this module unconditionally,
    //     so a newly installed handler could never run.
    //   - A valid existing table: merge, sort, and dedupe by RVA, then commit
    //     via AppendSection + PatchBytes, exactly like RebuildGuardCFFunctionTable.
    //   - Any other structural problem (unpatchable fields, table outside the
    //     file, overflow): fail-closed rather than emit a runtime that Windows
    //     would refuse to call the handler for.
    // Calling this for a 64-bit image always fails: x64 has no SafeSEH.
    bool RebuildSafeSEHHandlerTable(
        const std::vector<uint32_t>& additionalHandlerRVAs,
        const char sectionName[8],
        PEAppendSectionResult* sectionResult = nullptr,
        std::string* error = nullptr);
    bool RebuildBaseRelocationDirectory(
        const std::vector<CS_RELOC_ENTRY>& additionalEntries,
        const char sectionName[8],
        PEAppendSectionResult* sectionResult = nullptr,
        std::string* error = nullptr);

private:
    // 统一偏移映射的计算结果：在 buffer 重建之前，用旧 buffer/旧 section 状态
    // 算出全部“文件偏移型”引用重映射后的新值。任何一项映射溢出都会导致
    // BuildRemapPlan 整体失败,从而 AppendSection 在分配/提交新 buffer 之前就返回错误，
    // image 保持完全不变。
    struct RemapPlan {
        std::vector<uint32_t> sectionRaw;      // 每个现有 section 的新 PointerToRawData（按索引对齐）
        bool hasOverlay = false;
        uint32_t overlayOffset = 0;
        bool hasSecurity = false;
        uint32_t securityOffset = 0;
        bool hasDebug = false;
        uint32_t debugDirNewOffset = 0;         // Debug Directory 数组自身重映射后的新文件偏移
        std::vector<uint32_t> debugPointers;    // 每个 IMAGE_DEBUG_DIRECTORY.PointerToRawData 的新值
    };

    uint32_t AlignUp(uint32_t value, uint32_t alignment) const;
    void RefreshPointers(uint32_t ntOffset);
    void SetSizeOfHeaders(uint32_t value);
    void SetSizeOfImage(uint32_t value);
    // 统一偏移映射：
    //   off < firstRaw            → off            (头部不动)
    //   firstRaw <= off < lastFileEnd → off + headerDelta   (section 数据随头部间隙平移)
    //   off >= lastFileEnd        → overlayDestBase + (off - lastFileEnd)  (overlay 移到新 section 之后)
    // 覆盖 section.PointerToRawData、overlayOffset、Security Directory 文件偏移、
    // Debug Directory 每个 IMAGE_DEBUG_DIRECTORY.PointerToRawData（含同步副本）。
    // 必须在 rawData 替换为新 buffer 之前调用（读取旧 buffer/旧 section 状态）；
    // 任何映射溢出都返回 false，调用方据此在提交前中止，image 完全不变。
    bool BuildRemapPlan(uint32_t firstRaw, uint32_t lastFileEnd, uint32_t headerDelta,
                        uint32_t overlayDestBase, RemapPlan& plan) const;
    // 纯写入、不失败：把 BuildRemapPlan 算好的值写入新 buffer。必须在 rawData/rawSize
    // 已替换到新 buffer之后、写入新 section 之前调用。
    void ApplyRemapPlan(const RemapPlan& plan);

    CS_PE_IMAGE* m_image;
};

} // namespace CipherShell

#endif // CS_PE_EMITTER_H
