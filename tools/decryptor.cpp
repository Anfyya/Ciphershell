/**
 * CipherShell legacy decryptor diagnostic.
 *
 * The production format uses authenticated, per-function/per-section keys and
 * does not currently expose an offline recovery-key contract. This tool must
 * therefore fail closed instead of copying an encrypted file and claiming it
 * was decrypted.
 */

#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>
#include <vector>

namespace {

template <typename T>
bool ReadValue(const std::vector<std::uint8_t>& data, std::size_t offset, T& value) {
    if (offset > data.size() || data.size() - offset < sizeof(T)) return false;
    std::memcpy(&value, data.data() + offset, sizeof(T));
    return true;
}

bool IsStructurallyValidPE(const std::vector<std::uint8_t>& data) {
    if (data.size() < 0x40 || data[0] != 'M' || data[1] != 'Z') return false;

    std::uint32_t peOffset = 0;
    if (!ReadValue(data, 0x3c, peOffset)) return false;
    std::uint32_t signature = 0;
    if (!ReadValue(data, peOffset, signature) || signature != 0x00004550u) return false;

    std::uint16_t sectionCount = 0;
    std::uint16_t optionalHeaderSize = 0;
    if (!ReadValue(data, static_cast<std::size_t>(peOffset) + 6, sectionCount) ||
        !ReadValue(data, static_cast<std::size_t>(peOffset) + 20, optionalHeaderSize)) {
        return false;
    }
    if (sectionCount == 0 || sectionCount > 96) return false;

    const std::size_t sectionTable = static_cast<std::size_t>(peOffset) + 24 + optionalHeaderSize;
    return sectionTable <= data.size() &&
        static_cast<std::size_t>(sectionCount) <= (data.size() - sectionTable) / 40;
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "用法: decryptor <输入文件>\n";
        return 1;
    }

    std::ifstream input(argv[1], std::ios::binary | std::ios::ate);
    if (!input) {
        std::cerr << "错误: 无法打开输入文件\n";
        return 1;
    }
    const std::streamoff length = input.tellg();
    if (length <= 0 || static_cast<std::uintmax_t>(length) >
            (std::numeric_limits<std::size_t>::max)()) {
        std::cerr << "错误: 输入文件大小无效\n";
        return 1;
    }
    input.seekg(0);
    std::vector<std::uint8_t> data(static_cast<std::size_t>(length));
    if (!input.read(reinterpret_cast<char*>(data.data()), length)) {
        std::cerr << "错误: 无法完整读取输入文件\n";
        return 1;
    }
    if (!IsStructurallyValidPE(data)) {
        std::cerr << "错误: 输入不是结构完整的 PE 文件\n";
        return 1;
    }

    std::cerr
        << "UNSUPPORTED: 当前生产格式没有离线恢复密钥契约；未创建任何输出文件。\n";
    return 2;
}
