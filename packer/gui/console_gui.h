/**
 * CipherShell 控制台 GUI
 * 提供交互式命令行界面
 */

#ifndef CS_CONSOLE_GUI_H
#define CS_CONSOLE_GUI_H

#include <string>
#include <vector>
#include <functional>

namespace CipherShell {

// ============================================================================
// 颜色定义（Windows 控制台）
// ============================================================================

enum class ConsoleColor {
    Black = 0,
    DarkBlue = 1,
    DarkGreen = 2,
    DarkCyan = 3,
    DarkRed = 4,
    DarkMagenta = 5,
    DarkYellow = 6,
    Gray = 7,
    DarkGray = 8,
    Blue = 9,
    Green = 10,
    Cyan = 11,
    Red = 12,
    Magenta = 13,
    Yellow = 14,
    White = 15
};

// ============================================================================
// 菜单项
// ============================================================================

struct MenuItem {
    std::string key;
    std::string label;
    std::function<void()> action;
};

// ============================================================================
// 控制台 GUI 类
// ============================================================================

class ConsoleGUI {
public:
    ConsoleGUI();
    ~ConsoleGUI();

    /**
     * 初始化 GUI
     */
    void Initialize();

    /**
     * 显示主菜单
     */
    void ShowMainMenu();

    /**
     * 显示保护向导
     */
    void ShowProtectionWizard();

    /**
     * 显示配置编辑器
     */
    void ShowConfigEditor();

    /**
     * 显示帮助信息
     */
    void ShowHelp();

    /**
     * 显示关于信息
     */
    void ShowAbout();

private:
    // 显示函数
    void PrintBanner();
    void PrintSeparator();
    void PrintStatus(const std::string& message, bool success);
    void PrintProgress(int current, int total, const std::string& label);

    // 颜色控制
    void SetColor(ConsoleColor foreground, ConsoleColor background = ConsoleColor::Black);
    void ResetColor();

    // 输入处理
    std::string ReadInput(const std::string& prompt);
    int ReadChoice(const std::string& prompt, int min, int max);
    bool ReadYesNo(const std::string& prompt);

    // 菜单显示（返回 true 表示继续循环，false 表示退出）
    bool ShowMenu(const std::string& title, const std::vector<MenuItem>& items);

    // 成员变量
    bool m_initialized;
};

} // namespace CipherShell

#endif // CS_CONSOLE_GUI_H
