/**
 * CipherShell 控制台 GUI - 实现
 */

#include "console_gui.h"
#include <iostream>
#include <iomanip>
#ifdef _WIN32
#include <windows.h>
#else
#include "windows_compat.h"
#endif

namespace CipherShell {

// ============================================================================
// 构造/析构
// ============================================================================

ConsoleGUI::ConsoleGUI() : m_initialized(false) {}
ConsoleGUI::~ConsoleGUI() {}

// ============================================================================
// 公共接口
// ============================================================================

// BUG 14 修复辅助：使用 Win32 API 清屏，替代不安全的 system("cls")
static void ClearConsole() {
#ifdef _WIN32
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    DWORD written;
    DWORD consoleSize;

    if (!GetConsoleScreenBufferInfo(hConsole, &csbi)) return;

    consoleSize = csbi.dwSize.X * csbi.dwSize.Y;
    COORD topLeft = { 0, 0 };

    // 填充空格清除屏幕内容
    FillConsoleOutputCharacterA(hConsole, ' ', consoleSize, topLeft, &written);
    // 重置属性
    FillConsoleOutputAttribute(hConsole, csbi.wAttributes, consoleSize, topLeft, &written);
    // 光标移到左上角
    SetConsoleCursorPosition(hConsole, topLeft);
#else
    // 非 Windows 平台使用 ANSI escape codes
    std::cout << "\033[2J\033[H" << std::flush;
#endif
}

void ConsoleGUI::Initialize() {
    // 设置控制台标题
#ifdef _WIN32
    SetConsoleTitleA("CipherShell Protector v0.1");

    // BUG 14 修复：使用 Win32 API 设置控制台大小，替代 system("mode con")
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SMALL_RECT windowSize = { 0, 0, 79, 49 }; // 80 列 x 50 行
    COORD bufferSize = { 80, 50 };
    SetConsoleScreenBufferSize(hConsole, bufferSize);
    SetConsoleWindowInfo(hConsole, TRUE, &windowSize);
#endif

    m_initialized = true;
}

void ConsoleGUI::ShowMainMenu() {
    // BUG 13 修复：改为循环结构，避免 ShowMenu -> action -> ShowMainMenu -> ShowMenu 的递归
    // 每次选择菜单项后回到循环重新显示菜单，而不是递归调用
    while (true) {
        PrintBanner();

        std::vector<MenuItem> items = {
            {"1", "保护入口说明", [this]() { ShowProtectionWizard(); }},
            {"2", "配置说明（只读）", [this]() { ShowConfigEditor(); }},
            {"3", "帮助", [this]() { ShowHelp(); }},
            {"4", "关于", [this]() { ShowAbout(); }},
            {"0", "退出", nullptr}
        };

        // ShowMenu 返回 false 表示用户选择了退出
        if (!ShowMenu("主菜单", items)) {
            break;
        }
    }
}

void ConsoleGUI::ShowProtectionWizard() {
    PrintBanner();
    SetColor(ConsoleColor::Cyan);
    std::cout << "  保护入口说明" << std::endl;
    ResetColor();
    PrintSeparator();

    PrintStatus(
        "控制台保护向导尚未接入真实打包后端，已拒绝执行；未读取或写出任何文件。",
        false);
    std::cout << std::endl;
    std::cout << "  请改用真实入口:" << std::endl;
    std::cout << "    CLI:        ciphershell [选项] <输入文件>" << std::endl;
    std::cout << "    Win32 GUI:  ciphershell_gui.exe" << std::endl;
    std::cout << std::endl;
    std::cout << "  两个入口都会调用真实打包流程，并对未实现功能执行 fail-closed。"
              << std::endl;

    ReadInput("  按回车键返回...");
}

void ConsoleGUI::ShowConfigEditor() {
    PrintBanner();
    SetColor(ConsoleColor::Cyan);
    std::cout << "  配置说明（只读）" << std::endl;
    ResetColor();
    PrintSeparator();

    PrintStatus(
        "控制台配置编辑器尚未接入真实配置模型，已禁用伪加载和伪保存。",
        false);
    std::cout << std::endl;
    std::cout << "  当前真实语义:" << std::endl;
    std::cout << "    - L1-L3 不会隐式启用尚未闭环的保护模块" << std::endl;
    std::cout << "    - L4/L5 当前进入同一函数级 VM 生产链；不是多层嵌套 VM"
              << std::endl;
    std::cout << "      （两档的 strength 字段不同，但当前尚未改变 Handler 生成）"
              << std::endl;
    std::cout << "    - 字符串、IAT、反调试、反 Dump/Nanomite 等未实现开关"
              << std::endl;
    std::cout << "      被显式请求时会 fail-closed，不会生成伪成功产物" << std::endl;
    std::cout << std::endl;
    std::cout << "  请使用 ciphershell_gui.exe 编辑配置，或用"
              << " ciphershell -c <配置文件> <输入文件> 执行真实打包。"
              << std::endl;

    ReadInput("  按回车键返回...");
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
    std::cout << "    -l, --level <1-5>        快速 preset 等级" << std::endl;
    std::cout << "    -c, --config <文件>      配置文件（显式 protection_level 覆盖 -l）"
              << std::endl;
    std::cout << "    --vm-handler-evidence <文件>" << std::endl;
    std::cout << "                              写出本次真实构建的 handler 比较证据"
              << std::endl;
    std::cout << "    -v             显示详细信息" << std::endl;
    std::cout << "    -h             显示帮助" << std::endl;
    std::cout << std::endl;
    std::cout << "  快速等级的当前语义:" << std::endl;
    std::cout << "    L1-L3           不隐式启用尚未闭环的保护模块" << std::endl;
    std::cout << "    L4 (Fortress)   启用函数级 Mirage VM 预设" << std::endl;
    std::cout << "    L5 (Citadel)    当前使用同一函数级 VM 生产链" << std::endl;
    std::cout << "                     （strength 尚未改变 Handler；非嵌套 VM/Nanomite）"
              << std::endl;
    std::cout << std::endl;
    std::cout << "  Plus 功能状态:" << std::endl;
    std::cout << "    字符串保护、IAT 保护、反调试、反 Dump/Nanomite 等开关"
              << std::endl;
    std::cout << "    尚未接入生产闭环；显式请求时会 fail-closed。" << std::endl;
    std::cout << std::endl;
    std::cout << "  本控制台菜单不执行打包。请使用上述 CLI，或运行"
              << " ciphershell_gui.exe。" << std::endl;
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
    std::cout << "  PE 分析、能力检查与 Mirage VM 生产链" << std::endl;
    ResetColor();
    std::cout << std::endl;
    std::cout << "  当前已接入的预设:" << std::endl;
    std::cout << "    - L1-L3 不隐式开启未闭环模块" << std::endl;
    std::cout << "    - L4/L5 当前进入同一函数级 Mirage VM 生产链" << std::endl;
    std::cout << std::endl;
    std::cout << "  边界:" << std::endl;
    std::cout << "    - L5 不表示多层嵌套 VM 或 Nanomite 已实现" << std::endl;
    std::cout << "    - 字符串、IAT 及其他未闭环 Plus 开关会 fail-closed" << std::endl;
    std::cout << "    - 控制台菜单仅提供状态说明，不会伪造打包成功" << std::endl;
    std::cout << std::endl;

    ReadInput("  按回车键继续...");
}

// ============================================================================
// 内部实现
// ============================================================================

void ConsoleGUI::PrintBanner() {
    // BUG 14 修复：使用安全的 Win32 API 清屏替代 system("cls")
    ClearConsole();
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
  ║            PE / Mirage VM Tool v0.1                           ║
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
        static_cast<WORD>(static_cast<int>(foreground) | (static_cast<int>(background) << 4)));
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

// BUG 13 修复：ShowMenu 改为返回 bool（true=继续循环, false=退出）
// 不再在 action 完成后递归调用 ShowMainMenu，由外层循环负责重新显示菜单
bool ConsoleGUI::ShowMenu(const std::string& title, const std::vector<MenuItem>& items) {
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
                    // 返回 true 让外层循环重新显示菜单
                    return true;
                } else {
                    // 用户选择退出
                    return false;
                }
            }
        }

        SetColor(ConsoleColor::Red);
        std::cout << "  无效选项。" << std::endl;
        ResetColor();
    }
}

} // namespace CipherShell
