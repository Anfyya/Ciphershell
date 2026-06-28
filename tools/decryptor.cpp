/**
 * CipherShell 解密工具
 * 手动解密已加壳的 PE 文件
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <cstring>

// ============================================================================
// ChaCha20 简化实现
// ============================================================================

static uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

static void quarterround(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b; d ^= a; d = rotl32(d, 16);
    c += d; b ^= c; b = rotl32(b, 12);
    a += b; d ^= a; d = rotl32(d, 8);
    c += d; b ^= c; b = rotl32(b, 7);
}

// ============================================================================
// 滚动密钥解密
// ============================================================================

void DecryptWithRollingKey(uint8_t* data, size_t size, const uint8_t* key) {
    uint32_t rollingKey = 0;
    for (int i = 0; i < 4; i++) {
        rollingKey |= ((uint32_t)key[i]) << (i * 8);
    }

    for (size_t i = 0; i < size; i++) {
        uint8_t keyByte = (uint8_t)(rollingKey & 0xFF);
        data[i] ^= keyByte;
        rollingKey = (rollingKey >> 8) | (rollingKey << 24);
        rollingKey ^= (uint32_t)data[i];
    }
}

// ============================================================================
// PE 结构
// ============================================================================

#pragma pack(push, 1)
struct PEHeader {
    uint32_t signature;
    uint16_t machine;
    uint16_t numSections;
    uint32_t timestamp;
    uint32_t symbolTable;
    uint32_t numSymbols;
    uint16_t optionalHeaderSize;
    uint16_t characteristics;
};
#pragma pack(pop)

// ============================================================================
// 主函数
// ============================================================================

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cout << "CipherShell Decryptor v0.1" << std::endl;
        std::cout << "用法: decryptor <输入文件> <输出文件>" << std::endl;
        return 1;
    }

    std::string inputFile = argv[1];
    std::string outputFile = argv[2];

    // 读取输入文件
    std::ifstream inFile(inputFile, std::ios::binary | std::ios::ate);
    if (!inFile) {
        std::cerr << "错误: 无法打开输入文件" << std::endl;
        return 1;
    }

    size_t fileSize = inFile.tellg();
    inFile.seekg(0);

    std::vector<uint8_t> data(fileSize);
    inFile.read(reinterpret_cast<char*>(data.data()), fileSize);
    inFile.close();

    // 验证 PE 签名
    if (data[0] != 'M' || data[1] != 'Z') {
        std::cerr << "错误: 不是有效的 PE 文件" << std::endl;
        return 1;
    }

    // 获取 PE 头偏移
    uint32_t peOffset = *reinterpret_cast<uint32_t*>(&data[0x3C]);
    if (peOffset + sizeof(PEHeader) > fileSize) {
        std::cerr << "错误: PE 头偏移无效" << std::endl;
        return 1;
    }

    PEHeader* pe = reinterpret_cast<PEHeader*>(&data[peOffset]);
    if (pe->signature != 0x00004550) {  // "PE\0\0"
        std::cerr << "错误: PE 签名无效" << std::endl;
        return 1;
    }

    std::cout << "PE 文件信息:" << std::endl;
    std::cout << "  机器类型: 0x" << std::hex << pe->machine << std::dec << std::endl;
    std::cout << "  Section 数量: " << pe->numSections << std::endl;

    // 注意：这里只是演示解密流程
    // 实际的 CipherShell 加壳会在特定位置存储加密密钥
    // 这里我们使用默认密钥进行测试

    uint8_t defaultKey[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };

    // 解密 section 数据
    // 注意：这里只是演示，实际需要从 PE 中读取加密信息
    std::cout << "  解密完成（演示模式）" << std::endl;

    // 写入输出文件
    std::ofstream outFile(outputFile, std::ios::binary);
    if (!outFile) {
        std::cerr << "错误: 无法创建输出文件" << std::endl;
        return 1;
    }

    outFile.write(reinterpret_cast<char*>(data.data()), fileSize);
    outFile.close();

    std::cout << "输出文件: " << outputFile << std::endl;
    std::cout << "注意: 这是演示版本，实际解密需要完整的 stub 支持" << std::endl;

    return 0;
}
