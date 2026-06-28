/**
 * CipherShell 控制台 GUI - 实现
 */

#include "console_gui.h"
#include <iostream>
#include <iomanip>
#include <windows.h>

namespace CipherShell {

// ============================================================================
// 构造/析构
// ============================================================================

ConsoleGUI::ConsoleGUI() : m_initialized(false) {}
ConsoleGUI::~ConsoleGUI() {}

// ============================================================================
// 公共接口
// ============================================================================

void ConsoleGUI::Initialize() {
    // 设置控制台标题
    SetConsoleTitleA("CipherShell Protector v0.1");

    // 设置控制台大小
    system("mode con cols=80 lines=50");

    m_initialized = true;
}

void ConsoleGUI::ShowMainMenu() {
    PrintBanner();

    std::vector<MenuItem> items = {
        {"1", "保护 EXE/DLL", [this]() { ShowProtectionWizard(); }},
        {"2", "配置编辑器", [this]() { ShowConfigEditor(); }},
        {"3", "帮助", [this]() { ShowHelp(); }},
        {"4", "关于", [this]() { ShowAbout(); }},
        {"0", "退出", nullptr}
    };

    ShowMenu("主菜单", items);
}

void ConsoleGUI::ShowProtectionWizard() {
    PrintBanner();
    SetColor(ConsoleColor::Cyan);
    std::cout << "  保护向导" << std::endl;
    ResetColor();
    PrintSeparator();

    // 输入文件
    std::string inputFile = ReadInput("  输入文件路径");
    if (inputFile.empty()) {
        PrintStatus("未指定输入文件", false);
        return;
    }

    // 输出文件
    std::string outputFile = ReadInput("  输出文件路径 (默认: <输入文件>_protected)");
    if (outputFile.empty()) {
        outputFile = inputFile;
        size_t dotPos = outputFile.rfind('.');
        if (dotPos != std::string::npos) {
            outputFile = outputFile.substr(0, dotPos) + "_protected" + outputFile.substr(dotPos);
        } else {
            outputFile += "_protected";
        }
    }

    // 保护等级
    std::cout << std::endl;
    SetColor(ConsoleColor::Yellow);
    std::cout << "  保护等级:" << std::endl;
    ResetColor();
    std::cout << "    L1 (Guard)    - 基础加密 (~1.05x 开销)" << std::endl;
    std::cout << "    L2 (Shield)   - 控制流平坦化 (~2-3x)" << std::endl;
    std::cout << "    L3 (Armor)    - 高级混淆 (~5-8x)" << std::endl;
    std::cout << "    L4 (Fortress) - 代码虚拟化 (~15-30x)" << std::endl;
    std::cout << "    L5 (Citadel)  - 多层嵌套VM (~50-100x+)" << std::endl;
    std::cout << std::endl;

    int level = ReadChoice("  选择保护等级 (1-5)", 1, 5);

    // 确认
    std::cout << std::endl;
    PrintSeparator();
    SetColor(ConsoleColor::White);
    std::cout << "  输入:    " << inputFile << std::endl;
    std::cout << "  输出:    " << outputFile << std::endl;
    std::cout << "  等级:    L" << level << std::endl;
    ResetColor();
    PrintSeparator();

    if (!ReadYesNo("  开始保护?")) {
        PrintStatus("已取消保护", false);
        return;
    }

    // 开始保护
    std::cout << std::endl;
    SetColor(ConsoleColor::Green);
    std::cout << "  开始保护..." << std::endl;
    ResetColor();

    // 模拟保护过程
    const char* steps[] = {
        "解析 PE 文件",
        "分析代码结构",
        "构建控制流图",
        "应用变换",
        "生成VM字节码",
        "加密代码段",
        "消除签名",
        "重建 PE 文件",
        "验证输出"
    };

    int stepCount = sizeof(steps) / sizeof(steps[0]);
    for (int i = 0; i < stepCount; i++) {
        PrintProgress(i + 1, stepCount, steps[i]);
        Sleep(500);  // 模拟处理时间
    }

    std::cout << std::endl;
    PrintStatus("保护完成!", true);
    std::cout << std::endl;
    std::cout << "  输出文件: " << outputFile << std::endl;
}

void ConsoleGUI::ShowConfigEditor() {
    PrintBanner();
    SetColor(ConsoleColor::Cyan);
    std::cout << "  配置编辑器" << std::endl;
    ResetColor();
    PrintSeparator();

    std::cout << "  当前设置:" << std::endl;
    std::cout << "    保护等级: L3" << std::endl;
    std::cout << "    反调试: 隐式" << std::endl;
    std::cout << "    字符串加密: 是" << std::endl;
    std::cout << "    导入表混淆: 是" << std::endl;
    std::cout << "    VM寄存器数: 24" << std::endl;
    std::cout << std::endl;

    std::cout << "  从文件加载配置? (Y/N): ";
    char choice;
    std::cin >> choice;
    std::cin.ignore();

    if (choice == 'Y' || choice == 'y') {
        std::string configFile = ReadInput("  配置文件路径");
        if (!configFile.empty()) {
            PrintStatus("已加载配置: " + configFile, true);
        }
    }
}

void ConsoleGUI::ShowHelp() {
    PrintBanner();
    SetColor(ConsoleColor::Cyan);
    std::cout << "  帮助" << std::endl;
    ResetColor();
    PrintSeparator();

    std::cout << "  命令行用法:" << std::endl;
    std::cout << "    ciphershell <输入文件> [选项]" << std::endl;
    std::cout << std::endl;
    std::cout << "  选项:" << std::endl;
    std::cout << "    -o <文件>      输出文件路径" << std::endl;
    std::cout << "    -l <1-5>       保护等级" << std::endl;
    std::cout << "    -c <文件>      配置文件 (TOML格式)" << std::endl;
    std::cout << "    -v             显示详细信息" << std::endl;
    std::cout << "    -h             显示帮助" << std::endl;
    std::cout << std::endl;
    std::cout << "  保护等级:" << std::endl;
    std::cout << "    L1 (Guard)     Section加密 + 基础反调试" << std::endl;
    std::cout << "    L2 (Shield)    + 控制流平坦化" << std::endl;
    std::cout << "    L3 (Armor)     + 虚假控制流 + 不透明谓词" << std::endl;
    std::cout << "    L4 (Fortress)  + 代码虚拟化 (Mirage VM)" << std::endl;
    std::cout << "    L5 (Citadel)   + 多层嵌套VM + Nanomite" << std::endl;
    std::cout << std::endl;

    ReadInput("  按回车键继续...");
}

void ConsoleGUI::ShowAbout() {
    PrintBanner();
    SetColor(ConsoleColor::Cyan);
    std::cout << "  关于" << std::endl;
    ResetColor();
    PrintSeparator();

    SetColor(ConsoleColor::White);
    std::cout << "  CipherShell 代码保护器 v0.1" << std::endl;
    std::cout << "  自研高强度代码保护壳" << std::endl;
    ResetColor();
    std::cout << std::endl;
    std::cout << "  特性:" << std::endl;
    std::cout << "    - 与已知壳零特征重叠" << std::endl;
    std::cout << "    - 最大化反逆向分析" << std::endl;
    std::cout << "    - 可控的保护粒度" << std::endl;
    std::cout << "    - 双模式: PE文件 + 可选源码级保护" << std::endl;
    std::cout << std::endl;
    std::cout << "  Mirage VM 引擎:" << std::endl;
    std::cout << "    - 混合架构 (栈 + 寄存器)" << std::endl;
    std::cout << "    - 每次加壳随机化ISA" << std::endl;
    std::cout << "    - 滚动密钥字节码加密" << std::endl;
    std::cout << "    - 多层嵌套支持" << std::endl;
    std::cout << std::endl;

    ReadInput("  按回车键继续...");
}

// ============================================================================
// 内部实现
// ============================================================================

void ConsoleGUI::PrintBanner() {
    system("cls");
    SetColor(ConsoleColor::Cyan);
    std::cout << R"(
  ╔═══════════════════════════════════════════════════════════════╗
  ║                                                               ║
  ║     ██████╗██╗██████╗ ██╗  ██╗███████╗██████╗                ║
  ║    ██╔════╝██║██╔══██╗██║  ██║██╔════╝██╔══██╗               ║
  ║    ██║     ██║██████╔╝███████║█████╗  ██████╔╝               ║
  ║    ██║     ██║██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗               ║
  ║    ╚██████╗██║██║     ██║  ██║███████╗██║  ██║               ║
  ║     ╚═════╝╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝               ║
  ║                                                               ║
  ║            Shell Protector v0.1                               ║
  ║            Mirage VM Engine                                   ║
  ║                                                               ║
  ╚═══════════════════════════════════════════════════════════════╝
)" << std::endl;
    ResetColor();
}

void ConsoleGUI::PrintSeparator() {
    SetColor(ConsoleColor::DarkGray);
    std::cout << "  ────────────────────────────────────────────────────────────────" << std::endl;
    ResetColor();
}

void ConsoleGUI::PrintStatus(const std::string& message, bool success) {
    if (success) {
        SetColor(ConsoleColor::Green);
        std::cout << "  [OK] ";
    } else {
        SetColor(ConsoleColor::Red);
        std::cout << "  [!] ";
    }
    ResetColor();
    std::cout << message << std::endl;
}

void ConsoleGUI::PrintProgress(int current, int total, const std::string& label) {
    SetColor(ConsoleColor::DarkGray);
    std::cout << "  [";
    SetColor(ConsoleColor::Green);

    int barWidth = 30;
    int filled = (current * barWidth) / total;
    for (int i = 0; i < barWidth; i++) {
        if (i < filled) std::cout << "█";
        else std::cout << "░";
    }

    SetColor(ConsoleColor::DarkGray);
    std::cout << "] ";
    SetColor(ConsoleColor::White);
    std::cout << std::setw(3) << (current * 100 / total) << "% ";
    SetColor(ConsoleColor::Gray);
    std::cout << label << std::endl;
    ResetColor();
}

void ConsoleGUI::SetColor(ConsoleColor foreground, ConsoleColor background) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
        (int)foreground | ((int)background << 4));
}

void ConsoleGUI::ResetColor() {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
        (int)ConsoleColor::Gray);
}

std::string ConsoleGUI::ReadInput(const std::string& prompt) {
    SetColor(ConsoleColor::Yellow);
    std::cout << "  " << prompt << ": ";
    ResetColor();

    std::string input;
    std::getline(std::cin, input);
    return input;
}

int ConsoleGUI::ReadChoice(const std::string& prompt, int min, int max) {
    while (true) {
        SetColor(ConsoleColor::Yellow);
        std::cout << "  " << prompt << ": ";
        ResetColor();

        std::string input;
        std::getline(std::cin, input);

        try {
            int choice = std::stoi(input);
            if (choice >= min && choice <= max) {
                return choice;
            }
        } catch (...) {}

        SetColor(ConsoleColor::Red);
        std::cout << "  无效输入，请输入 " << min << " 到 " << max << " 之间的数字。" << std::endl;
        ResetColor();
    }
}

bool ConsoleGUI::ReadYesNo(const std::string& prompt) {
    while (true) {
        SetColor(ConsoleColor::Yellow);
        std::cout << "  " << prompt << " (Y/N): ";
        ResetColor();

        std::string input;
        std::getline(std::cin, input);

        if (input == "Y" || input == "y" || input == "yes") return true;
        if (input == "N" || input == "n" || input == "no") return false;

        SetColor(ConsoleColor::Red);
        std::cout << "  请输入 Y 或 N。" << std::endl;
        ResetColor();
    }
}

void ConsoleGUI::ShowMenu(const std::string& title, const std::vector<MenuItem>& items) {
    SetColor(ConsoleColor::Cyan);
    std::cout << "  " << title << std::endl;
    ResetColor();
    PrintSeparator();

    for (const auto& item : items) {
        SetColor(ConsoleColor::Yellow);
        std::cout << "  [" << item.key << "] ";
        SetColor(ConsoleColor::White);
        std::cout << item.label << std::endl;
    }

    PrintSeparator();

    while (true) {
        std::string choice = ReadInput("请选择");

        for (const auto& item : items) {
            if (choice == item.key) {
                if (item.action) {
                    item.action();
                    // 返回主菜单
                    ShowMainMenu();
                    return;
                } else {
                    // Exit
                    return;
                }
            }
        }

        SetColor(ConsoleColor::Red);
        std::cout << "  无效选项。" << std::endl;
        ResetColor();
    }
}

} // namespace CipherShell
