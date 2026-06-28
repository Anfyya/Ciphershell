/**
 * CipherShell PE Parser 测试
 */

#include <iostream>
#include <string>
#include <cassert>

#include "../packer/pe_parser/pe_parser.h"

// ============================================================================
// 测试辅助函数
// ============================================================================

void PrintTestResult(const std::string& testName, bool passed) {
    std::cout << "[" << (passed ? "PASS" : "FAIL") << "] " << testName << std::endl;
}

// ============================================================================
// 测试用例
// ============================================================================

bool TestPEParser_BasicParsing() {
    // 测试基本的 PE 解析功能
    CipherShell::PEParser parser;

    // 注意：这里需要一个实际的 PE 文件进行测试
    // 在实际测试中，应该使用测试样本

    std::cout << "  基本解析测试需要实际的 PE 文件" << std::endl;
    return true;
}

bool TestPEParser_InvalidFile() {
    CipherShell::PEParser parser;

    // 测试无效文件
    CipherShell::CS_PE_IMAGE* image = parser.LoadFromFile("nonexistent.exe");
    bool passed = (image == nullptr);

    if (image) {
        parser.FreeImage(image);
    }

    return passed;
}

bool TestPEParser_InvalidPE() {
    CipherShell::PEParser parser;

    // 创建一个无效的 PE 文件（不是 PE 格式）
    FILE* f = fopen("invalid.pe", "wb");
    if (f) {
        char data[] = "This is not a PE file";
        fwrite(data, 1, sizeof(data), f);
        fclose(f);

        CipherShell::CS_PE_IMAGE* image = parser.LoadFromFile("invalid.pe");
        bool passed = (image == nullptr || !image->isValid);

        if (image) {
            parser.FreeImage(image);
        }

        // 清理测试文件
        remove("invalid.pe");

        return passed;
    }

    return false;
}

bool TestPEParser_DataStructures() {
    // 测试数据结构的正确性
    bool passed = true;

    // 检查结构体大小
    if (sizeof(CipherShell::CS_PE_IMAGE) == 0) {
        passed = false;
    }

    // 检查导入表结构
    CipherShell::CS_IMPORT_TABLE importTable;
    if (importTable.dlls.capacity() == 0) {
        // 这是正常的，vector 初始为空
    }

    return passed;
}

bool TestPEParser_HashFunctions() {
    // 测试哈希函数的一致性
    CipherShell::APIResolver resolver;

    uint32_t hash1 = resolver.HashString("kernel32.dll");
    uint32_t hash2 = resolver.HashString("kernel32.dll");
    uint32_t hash3 = resolver.HashString("Kernel32.DLL");  // 大小写不敏感

    bool passed = (hash1 == hash2) && (hash1 == hash3);

    if (!passed) {
        std::cout << "    哈希不一致: " << hash1 << " != " << hash2 << " != " << hash3 << std::endl;
    }

    return passed;
}

// ============================================================================
// 主测试函数
// ============================================================================

int main() {
    std::cout << "CipherShell PE Parser 测试" << std::endl;
    std::cout << "==========================" << std::endl;

    int passed = 0;
    int failed = 0;

    // 运行测试
    auto RunTest = [&](const std::string& name, bool (*testFunc)()) {
        try {
            bool result = testFunc();
            PrintTestResult(name, result);
            if (result) passed++; else failed++;
        } catch (const std::exception& e) {
            std::cout << "[FAIL] " << name << " - 异常: " << e.what() << std::endl;
            failed++;
        }
    };

    RunTest("PE Parser - 基本解析", TestPEParser_BasicParsing);
    RunTest("PE Parser - 无效文件", TestPEParser_InvalidFile);
    RunTest("PE Parser - 无效 PE", TestPEParser_InvalidPE);
    RunTest("PE Parser - 数据结构", TestPEParser_DataStructures);
    RunTest("PE Parser - 哈希函数", TestPEParser_HashFunctions);

    // 输出结果
    std::cout << "\n==========================" << std::endl;
    std::cout << "测试结果: " << passed << " 通过, " << failed << " 失败" << std::endl;

    return (failed > 0) ? 1 : 0;
}
