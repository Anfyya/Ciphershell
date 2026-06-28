/**
 * CipherShell Stub Builder
 * 生成内嵌解密 stub，使加壳后的程序能正常运行
 */

#ifndef CS_STUB_BUILDER_H
#define CS_STUB_BUILDER_H

#include "../pe_parser/pe_parser.h"
#include "section_encryptor.h"
#include <cstdint>
#include <vector>

namespace CipherShell {

// ============================================================================
// Stub 参数（嵌入到 PE 中供 stub 读取）
// ============================================================================

#pragma pack(push, 1)
struct CS_STUB_PARAMS {
    uint32_t    magic;              // 0x43535350 "CSSP"
    uint32_t    oepRVA;             // 原始入口点 RVA
    uint32_t    sectionRVA;         // 加密 section 的 RVA
    uint32_t    sectionSize;        // 加密 section 的大小
    uint8_t     key[32];            // ChaCha20/XOR 密钥
    uint32_t    keySize;            // 密钥长度
    uint32_t    imageBaseLow;       // 映像基址低 32 位
    uint32_t    imageBaseHigh;      // 映像基址高 32 位
};
#pragma pack(pop)

// ============================================================================
// Stub Builder 类
// ============================================================================

class StubBuilder {
public:
    StubBuilder();
    ~StubBuilder();

    /**
     * 生成 x86 解密 stub shellcode
     * @param params stub 参数
     * @param stubData 输出 stub 数据
     * @param stubSize 输出 stub 大小
     * @return 是否成功
     */
    bool GenerateX86Stub(const CS_STUB_PARAMS& params, BYTE** stubData, DWORD* stubSize);

    /**
     * 生成 x64 解密 stub shellcode
     * @param params stub 参数
     * @param stubData 输出 stub 数据
     * @param stubSize 输出 stub 大小
     * @return 是否成功
     */
    bool GenerateX64Stub(const CS_STUB_PARAMS& params, BYTE** stubData, DWORD* stubSize);

    /**
     * 将 stub 和参数嵌入到 PE 中
     * @param image PE 镜像
     * @param encryptedSections 加密的 section 列表
     * @param oepRVA 原始入口点 RVA
     * @return 是否成功
     */
    bool EmbedStub(
        CS_PE_IMAGE* image,
        const std::vector<CS_ENCRYPTED_SECTION>& encryptedSections,
        DWORD oepRVA
    );

private:
    // 生成 XOR 解密循环的 x86 shellcode
    std::vector<BYTE> BuildX86DecryptLoop(const CS_STUB_PARAMS& params);

    // 生成 XOR 解密循环的 x64 shellcode
    std::vector<BYTE> BuildX64DecryptLoop(const CS_STUB_PARAMS& params);

    // 辅助
    void EmitByte(std::vector<BYTE>& code, uint8_t b);
    void EmitDword(std::vector<BYTE>& code, uint32_t val);
    void EmitQword(std::vector<BYTE>& code, uint64_t val);
};

} // namespace CipherShell

#endif // CS_STUB_BUILDER_H
