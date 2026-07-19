// CipherShell GUI - 控件创建/取值小工具。
//
// 所有控件都是标准 Win32 窗口类（STATIC/BUTTON/EDIT/COMBOBOX）或
// ComCtl32 通用控件（SysTabControl32、msctls_progress32），手写坐标创建，
// 不使用对话框资源模板。界面不分标签页容器窗口——所有控件都是主窗口的直接
// 子窗口，按"当前标签页"整体显示/隐藏（MainWindow 里按 tab 分组持有 HWND
// 列表），这样 WM_CTLCOLORSTATIC 之类的消息都直接落在主窗口的 WndProc 里
// 处理，不需要给每个标签页单独一个子类化窗口。
#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

namespace CipherShellGui {

// 进程范围内只创建一次的界面字体（系统消息字体，比默认 SYSTEM_FONT 更现代）。
HFONT GetUiFont();
HFONT GetUiFontBold();  // 用于分组小标题。

HWND CreateLabelControl(
    HWND parent, int x, int y, int w, int h, const std::wstring& text);

HWND CreateSectionHeaderControl(
    HWND parent, int x, int y, int w, int h, const std::wstring& text);

HWND CreateGroupBoxControl(
    HWND parent, int x, int y, int w, int h, const std::wstring& text);

HWND CreateCheckboxControl(
    HWND parent, int x, int y, int w, int h, const std::wstring& text,
    int id, bool checked, bool enabled = true);

HWND CreateRadioControl(
    HWND parent, int x, int y, int w, int h, const std::wstring& text,
    int id, bool isFirstInGroup, bool checked);

HWND CreateEditControl(
    HWND parent, int x, int y, int w, int h, int id,
    DWORD extraStyle = 0, bool enabled = true);

HWND CreateMultilineEditControl(
    HWND parent, int x, int y, int w, int h, int id);

HWND CreateReadOnlyLogControl(HWND parent, int x, int y, int w, int h);

HWND CreateComboControl(
    HWND parent, int x, int y, int w, int h, int id,
    const std::vector<std::wstring>& items, int selectedIndex,
    bool editable = false);

HWND CreateButtonControl(
    HWND parent, int x, int y, int w, int h, const std::wstring& text, int id);

HWND CreateProgressBarControl(HWND parent, int x, int y, int w, int h);

HWND CreateTabControlWidget(HWND parent, HINSTANCE instance, int x, int y, int w, int h);

// --- 取值 / 赋值 -----------------------------------------------------------

bool GetCheckboxChecked(HWND checkbox);
void SetCheckboxChecked(HWND checkbox, bool checked);

std::wstring GetEditText(HWND edit);
void SetEditText(HWND edit, const std::wstring& text);

// 十进制整数；解析失败时返回 fallback。
int GetEditInt(HWND edit, int fallback);
void SetEditInt(HWND edit, int value);

// 接受 "0x..." 或纯十进制；解析失败时返回 fallback。
uint32_t GetEditHexOrDecimal(HWND edit, uint32_t fallback);
void SetEditHex(HWND edit, uint32_t value);

double GetEditDouble(HWND edit, double fallback);
void SetEditDouble(HWND edit, double value);

// 多行编辑框：每行一个元素，忽略空行、去除首尾空白。
std::vector<std::wstring> GetMultilineEntries(HWND edit);
void SetMultilineEntries(HWND edit, const std::vector<std::wstring>& entries);

int GetComboSelection(HWND combo);
void SetComboSelection(HWND combo, int index);
std::wstring GetComboText(HWND combo);

void AppendLogLine(HWND logEdit, const std::wstring& line);

} // namespace CipherShellGui
