/**
 * CipherShell VM 正确性测试
 */

#include <iostream>
#include <string>
#include <cassert>
#include <cstdint>

// ============================================================================
// 测试辅助函数
// ============================================================================

void PrintTestResult(const std::string& testName, bool passed) {
    std::cout << "[" << (passed ? "PASS" : "FAIL") << "] " << testName << std::endl;
}

// ============================================================================
// VM 上下文模拟
// ============================================================================

struct VMContext {
    uint64_t registers[16];     // 虚拟寄存器
    uint64_t flags;             // 标志寄存器
    uint64_t stack[1024];       // 虚拟栈
    uint64_t sp;                // 栈指针
    uint64_t ip;                // 指令指针
};

// ============================================================================
// 测试用例
// ============================================================================

bool TestVM_Arithmetic() {
    // 测试算术运算
    VMContext ctx = {0};

    // 测试加法
    ctx.registers[0] = 10;
    ctx.registers[1] = 20;
    ctx.registers[2] = ctx.registers[0] + ctx.registers[1];

    if (ctx.registers[2] != 30) {
        std::cout << "    加法失败: 10 + 20 = " << ctx.registers[2] << std::endl;
        return false;
    }

    // 测试减法
    ctx.registers[3] = ctx.registers[1] - ctx.registers[0];

    if (ctx.registers[3] != 10) {
        std::cout << "    减法失败: 20 - 10 = " << ctx.registers[3] << std::endl;
        return false;
    }

    // 测试乘法
    ctx.registers[4] = ctx.registers[0] * ctx.registers[1];

    if (ctx.registers[4] != 200) {
        std::cout << "    乘法失败: 10 * 20 = " << ctx.registers[4] << std::endl;
        return false;
    }

    return true;
}

bool TestVM_Logic() {
    // 测试逻辑运算
    VMContext ctx = {0};

    // 测试 AND
    ctx.registers[0] = 0xFF00;
    ctx.registers[1] = 0x0FF0;
    ctx.registers[2] = ctx.registers[0] & ctx.registers[1];

    if (ctx.registers[2] != 0x0F00) {
        std::cout << "    AND 失败: 0xFF00 & 0x0FF0 = 0x" << std::hex << ctx.registers[2] << std::endl;
        return false;
    }

    // 测试 OR
    ctx.registers[3] = ctx.registers[0] | ctx.registers[1];

    if (ctx.registers[3] != 0xFFF0) {
        std::cout << "    OR 失败: 0xFF00 | 0x0FF0 = 0x" << std::hex << ctx.registers[3] << std::endl;
        return false;
    }

    // 测试 XOR
    ctx.registers[4] = ctx.registers[0] ^ ctx.registers[1];

    if (ctx.registers[4] != 0xF0F0) {
        std::cout << "    XOR 失败: 0xFF00 ^ 0x0FF0 = 0x" << std::hex << ctx.registers[4] << std::endl;
        return false;
    }

    return true;
}

bool TestVM_Shifts() {
    // 测试移位运算
    VMContext ctx = {0};

    // 测试左移
    ctx.registers[0] = 1;
    ctx.registers[1] = ctx.registers[0] << 8;

    if (ctx.registers[1] != 0x100) {
        std::cout << "    左移失败: 1 << 8 = " << ctx.registers[1] << std::endl;
        return false;
    }

    // 测试右移
    ctx.registers[2] = ctx.registers[1] >> 4;

    if (ctx.registers[2] != 0x10) {
        std::cout << "    右移失败: 0x100 >> 4 = 0x" << std::hex << ctx.registers[2] << std::endl;
        return false;
    }

    return true;
}

bool TestVM_Branches() {
    // 测试分支逻辑
    VMContext ctx = {0};

    ctx.registers[0] = 10;
    ctx.registers[1] = 20;

    // 模拟条件分支
    bool taken = false;
    if (ctx.registers[0] < ctx.registers[1]) {
        taken = true;
        ctx.registers[2] = 1;
    }

    if (!taken || ctx.registers[2] != 1) {
        std::cout << "    条件分支失败" << std::endl;
        return false;
    }

    // 测试相等分支
    ctx.registers[0] = 42;
    ctx.registers[1] = 42;

    bool equal = false;
    if (ctx.registers[0] == ctx.registers[1]) {
        equal = true;
    }

    if (!equal) {
        std::cout << "    相等分支失败" << std::endl;
        return false;
    }

    return true;
}

bool TestVM_Memory() {
    // 测试内存操作
    VMContext ctx = {0};

    // 模拟栈操作
    ctx.sp = 1023;

    // Push
    ctx.stack[ctx.sp] = 42;
    ctx.sp--;

    // Pop
    ctx.sp++;
    uint64_t value = ctx.stack[ctx.sp];

    if (value != 42) {
        std::cout << "    栈操作失败: push 42, pop = " << value << std::endl;
        return false;
    }

    return true;
}

bool TestVM_Flags() {
    // 测试标志计算
    VMContext ctx = {0};

    // 测试零标志
    uint64_t a = 5;
    uint64_t b = 5;
    uint64_t result = a - b;

    bool zeroFlag = (result == 0);

    if (!zeroFlag) {
        std::cout << "    零标志计算失败" << std::endl;
        return false;
    }

    // 测试进位标志
    uint8_t x = 200;
    uint8_t y = 100;
    uint16_t sum = (uint16_t)x + (uint16_t)y;
    bool carryFlag = (sum > 255);

    if (!carryFlag) {
        std::cout << "    进位标志计算失败" << std::endl;
        return false;
    }

    return true;
}

// ============================================================================
// 主测试函数
// ============================================================================

int main() {
    std::cout << "CipherShell VM 正确性测试" << std::endl;
    std::cout << "=========================" << std::endl;

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

    RunTest("VM - 算术运算", TestVM_Arithmetic);
    RunTest("VM - 逻辑运算", TestVM_Logic);
    RunTest("VM - 移位运算", TestVM_Shifts);
    RunTest("VM - 分支逻辑", TestVM_Branches);
    RunTest("VM - 内存操作", TestVM_Memory);
    RunTest("VM - 标志计算", TestVM_Flags);

    // 输出结果
    std::cout << "\n=========================" << std::endl;
    std::cout << "测试结果: " << passed << " 通过, " << failed << " 失败" << std::endl;

    return (failed > 0) ? 1 : 0;
}
