/**
 * CipherShell 测试样本 - Hello World
 * 简单的控制台程序，用于测试加壳功能
 */

#include <windows.h>
#include <iostream>
#include <string>

// ============================================================================
// 全局变量（测试数据段加密）
// ============================================================================

const char* g_helloMessage = "Hello, World!";
const char* g_cipherShellMessage = "CipherShell Protection Test";
int g_counter = 0;

// ============================================================================
// 测试函数（测试代码段加密）
// ============================================================================

void PrintMessage(const char* message) {
    std::cout << message << std::endl;
}

int AddNumbers(int a, int b) {
    return a + b;
}

int Factorial(int n) {
    if (n <= 1) return 1;
    return n * Factorial(n - 1);
}

// ============================================================================
// 主函数
// ============================================================================

int main() {
    std::cout << "======================================" << std::endl;
    std::cout << "CipherShell 测试程序" << std::endl;
    std::cout << "======================================" << std::endl;

    // 测试字符串输出
    PrintMessage(g_helloMessage);
    PrintMessage(g_cipherShellMessage);

    // 测试算术运算
    int sum = AddNumbers(10, 20);
    std::cout << "10 + 20 = " << sum << std::endl;

    // 测试递归函数
    int fact = Factorial(10);
    std::cout << "10! = " << fact << std::endl;

    // 测试循环
    std::cout << "\n循环测试:" << std::endl;
    for (int i = 0; i < 5; i++) {
        std::cout << "  计数: " << i << std::endl;
        g_counter++;
    }

    // 测试条件分支
    std::cout << "\n条件测试:" << std::endl;
    if (g_counter == 5) {
        std::cout << "  计数器正确: " << g_counter << std::endl;
    } else {
        std::cout << "  计数器错误: " << g_counter << std::endl;
    }

    // 测试 Windows API 调用
    std::cout << "\nWindows API 测试:" << std::endl;
    char computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computerName);
    if (GetComputerNameA(computerName, &size)) {
        std::cout << "  计算机名: " << computerName << std::endl;
    }

    // 测试内存分配
    std::cout << "\n内存测试:" << std::endl;
    int* array = new int[100];
    for (int i = 0; i < 100; i++) {
        array[i] = i * i;
    }
    std::cout << "  array[50] = " << array[50] << std::endl;
    delete[] array;

    std::cout << "\n======================================" << std::endl;
    std::cout << "测试完成!" << std::endl;
    std::cout << "======================================" << std::endl;

    return 0;
}
