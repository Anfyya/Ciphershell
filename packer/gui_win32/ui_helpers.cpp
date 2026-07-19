#include "ui_helpers.h"

#include <commctrl.h>

#include <algorithm>
#include <cwctype>

#include "control_ids.h"

namespace CipherShellGui {

namespace {

HINSTANCE CurrentModule() {
    return ::GetModuleHandleW(nullptr);
}

} // namespace

HFONT GetUiFont() {
    static HFONT font = [] {
        NONCLIENTMETRICSW metrics{};
        metrics.cbSize = sizeof(metrics);
        if (::SystemParametersInfoW(
                SPI_GETNONCLIENTMETRICS, sizeof(metrics), &metrics, 0)) {
            return ::CreateFontIndirectW(&metrics.lfMessageFont);
        }
        return static_cast<HFONT>(::GetStockObject(DEFAULT_GUI_FONT));
    }();
    return font;
}

HFONT GetUiFontBold() {
    static HFONT font = [] {
        LOGFONTW logFont{};
        if (::GetObjectW(GetUiFont(), sizeof(logFont), &logFont) == 0) {
            NONCLIENTMETRICSW metrics{};
            metrics.cbSize = sizeof(metrics);
            ::SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(metrics), &metrics, 0);
            logFont = metrics.lfMessageFont;
        }
        logFont.lfWeight = FW_BOLD;
        return ::CreateFontIndirectW(&logFont);
    }();
    return font;
}

namespace {

HWND CreateChild(
    const wchar_t* className, const std::wstring& text, DWORD style,
    int x, int y, int w, int h, HWND parent, int id, DWORD exStyle = 0)
{
    HWND hwnd = ::CreateWindowExW(
        exStyle, className, text.c_str(), style | WS_CHILD | WS_VISIBLE,
        x, y, w, h, parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
        CurrentModule(), nullptr);
    if (hwnd) ::SendMessageW(hwnd, WM_SETFONT, reinterpret_cast<WPARAM>(GetUiFont()), TRUE);
    return hwnd;
}

} // namespace

HWND CreateLabelControl(
    HWND parent, int x, int y, int w, int h, const std::wstring& text)
{
    return CreateChild(
        L"STATIC", text, SS_LEFT, x, y, w, h, parent, NextControlId());
}

HWND CreateSectionHeaderControl(
    HWND parent, int x, int y, int w, int h, const std::wstring& text)
{
    HWND hwnd = CreateChild(
        L"STATIC", text, SS_LEFT, x, y, w, h, parent, NextControlId());
    if (hwnd) ::SendMessageW(hwnd, WM_SETFONT, reinterpret_cast<WPARAM>(GetUiFontBold()), TRUE);
    return hwnd;
}

HWND CreateGroupBoxControl(
    HWND parent, int x, int y, int w, int h, const std::wstring& text)
{
    return CreateChild(
        L"BUTTON", text, BS_GROUPBOX, x, y, w, h, parent, NextControlId());
}

HWND CreateCheckboxControl(
    HWND parent, int x, int y, int w, int h, const std::wstring& text,
    int id, bool checked, bool enabled)
{
    HWND hwnd = CreateChild(
        L"BUTTON", text, BS_AUTOCHECKBOX | WS_TABSTOP, x, y, w, h, parent, id);
    if (hwnd) {
        SetCheckboxChecked(hwnd, checked);
        ::EnableWindow(hwnd, enabled);
    }
    return hwnd;
}

HWND CreateRadioControl(
    HWND parent, int x, int y, int w, int h, const std::wstring& text,
    int id, bool isFirstInGroup, bool checked)
{
    DWORD style = BS_AUTORADIOBUTTON | WS_TABSTOP;
    if (isFirstInGroup) style |= WS_GROUP;
    HWND hwnd = CreateChild(L"BUTTON", text, style, x, y, w, h, parent, id);
    if (hwnd) SetCheckboxChecked(hwnd, checked);
    return hwnd;
}

HWND CreateEditControl(
    HWND parent, int x, int y, int w, int h, int id,
    DWORD extraStyle, bool enabled)
{
    HWND hwnd = CreateChild(
        L"EDIT", L"", WS_TABSTOP | WS_BORDER | ES_AUTOHSCROLL | extraStyle,
        x, y, w, h, parent, id, WS_EX_CLIENTEDGE);
    if (hwnd) ::EnableWindow(hwnd, enabled);
    return hwnd;
}

HWND CreateMultilineEditControl(HWND parent, int x, int y, int w, int h, int id) {
    return CreateChild(
        L"EDIT", L"",
        WS_TABSTOP | WS_BORDER | WS_VSCROLL | ES_MULTILINE | ES_WANTRETURN | ES_AUTOVSCROLL,
        x, y, w, h, parent, id, WS_EX_CLIENTEDGE);
}

HWND CreateReadOnlyLogControl(HWND parent, int x, int y, int w, int h) {
    HWND hwnd = CreateChild(
        L"EDIT", L"",
        WS_TABSTOP | WS_BORDER | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
        x, y, w, h, parent, NextControlId(), WS_EX_CLIENTEDGE);
    return hwnd;
}

HWND CreateComboControl(
    HWND parent, int x, int y, int w, int h, int id,
    const std::vector<std::wstring>& items, int selectedIndex, bool editable)
{
    // 下拉列表高度要给足弹出区域；h 只是关闭状态下的可视高度。
    const DWORD style = (editable ? CBS_DROPDOWN : CBS_DROPDOWNLIST) | WS_VSCROLL | CBS_AUTOHSCROLL;
    HWND hwnd = CreateChild(
        L"COMBOBOX", L"", style, x, y, w, h + 200, parent, id);
    if (!hwnd) return hwnd;
    for (const auto& item : items) {
        ::SendMessageW(hwnd, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(item.c_str()));
    }
    if (selectedIndex >= 0) {
        ::SendMessageW(hwnd, CB_SETCURSEL, static_cast<WPARAM>(selectedIndex), 0);
    }
    return hwnd;
}

HWND CreateButtonControl(
    HWND parent, int x, int y, int w, int h, const std::wstring& text, int id)
{
    return CreateChild(
        L"BUTTON", text, BS_PUSHBUTTON | WS_TABSTOP, x, y, w, h, parent, id);
}

HWND CreateProgressBarControl(HWND parent, int x, int y, int w, int h) {
    // PBS_MARQUEE：后端目前没有细粒度进度回调，只能如实展示"正在处理"，
    // 用不确定的跑马灯而不是编造一个假的百分比（PBM_SETMARQUEE 在
    // MainWindow::SetRunningState 里按运行状态开关）。
    return CreateChild(
        PROGRESS_CLASSW, L"", PBS_MARQUEE, x, y, w, h, parent, NextControlId());
}

HWND CreateTabControlWidget(HWND parent, HINSTANCE /*instance*/, int x, int y, int w, int h) {
    return CreateChild(
        WC_TABCONTROLW, L"", WS_TABSTOP | TCS_TABS | TCS_SINGLELINE,
        x, y, w, h, parent, IDC_TAB);
}

bool GetCheckboxChecked(HWND checkbox) {
    return ::SendMessageW(checkbox, BM_GETCHECK, 0, 0) == BST_CHECKED;
}

void SetCheckboxChecked(HWND checkbox, bool checked) {
    ::SendMessageW(checkbox, BM_SETCHECK, checked ? BST_CHECKED : BST_UNCHECKED, 0);
}

std::wstring GetEditText(HWND edit) {
    const int length = ::GetWindowTextLengthW(edit);
    if (length <= 0) return std::wstring();
    std::wstring text(static_cast<size_t>(length), L'\0');
    ::GetWindowTextW(edit, text.data(), length + 1);
    return text;
}

void SetEditText(HWND edit, const std::wstring& text) {
    ::SetWindowTextW(edit, text.c_str());
}

namespace {
std::wstring TrimCopy(const std::wstring& text) {
    size_t begin = 0;
    size_t end = text.size();
    while (begin < end && std::iswspace(text[begin])) ++begin;
    while (end > begin && std::iswspace(text[end - 1])) --end;
    return text.substr(begin, end - begin);
}
}

int GetEditInt(HWND edit, int fallback) {
    const std::wstring text = TrimCopy(GetEditText(edit));
    if (text.empty()) return fallback;
    wchar_t* end = nullptr;
    const long value = wcstol(text.c_str(), &end, 10);
    if (end == text.c_str() || *end != L'\0') return fallback;
    return static_cast<int>(value);
}

void SetEditInt(HWND edit, int value) {
    SetEditText(edit, std::to_wstring(value));
}

uint32_t GetEditHexOrDecimal(HWND edit, uint32_t fallback) {
    const std::wstring text = TrimCopy(GetEditText(edit));
    if (text.empty()) return fallback;
    wchar_t* end = nullptr;
    const unsigned long value = wcstoul(text.c_str(), &end, 0);  // 0 = 自动识别 0x 前缀
    if (end == text.c_str() || *end != L'\0') return fallback;
    return static_cast<uint32_t>(value);
}

void SetEditHex(HWND edit, uint32_t value) {
    wchar_t buffer[32];
    swprintf_s(buffer, L"0x%x", value);
    SetEditText(edit, buffer);
}

double GetEditDouble(HWND edit, double fallback) {
    const std::wstring text = TrimCopy(GetEditText(edit));
    if (text.empty()) return fallback;
    wchar_t* end = nullptr;
    const double value = wcstod(text.c_str(), &end);
    if (end == text.c_str() || *end != L'\0') return fallback;
    return value;
}

void SetEditDouble(HWND edit, double value) {
    wchar_t buffer[64];
    swprintf_s(buffer, L"%.2f", value);
    SetEditText(edit, buffer);
}

std::vector<std::wstring> GetMultilineEntries(HWND edit) {
    std::wstring text = GetEditText(edit);
    std::vector<std::wstring> entries;
    size_t start = 0;
    while (start <= text.size()) {
        size_t lineEnd = text.find(L'\n', start);
        const bool last = lineEnd == std::wstring::npos;
        if (last) lineEnd = text.size();
        std::wstring line = text.substr(start, lineEnd - start);
        if (!line.empty() && line.back() == L'\r') line.pop_back();
        line = TrimCopy(line);
        if (!line.empty()) entries.push_back(std::move(line));
        if (last) break;
        start = lineEnd + 1;
    }
    return entries;
}

void SetMultilineEntries(HWND edit, const std::vector<std::wstring>& entries) {
    std::wstring text;
    for (size_t i = 0; i < entries.size(); ++i) {
        if (i) text += L"\r\n";
        text += entries[i];
    }
    SetEditText(edit, text);
}

int GetComboSelection(HWND combo) {
    return static_cast<int>(::SendMessageW(combo, CB_GETCURSEL, 0, 0));
}

void SetComboSelection(HWND combo, int index) {
    ::SendMessageW(combo, CB_SETCURSEL, static_cast<WPARAM>(index), 0);
}

std::wstring GetComboText(HWND combo) {
    return GetEditText(combo);  // CBS_DROPDOWN 的编辑区取文本方式与 EDIT 相同。
}

void AppendLogLine(HWND logEdit, const std::wstring& line) {
    const int length = ::GetWindowTextLengthW(logEdit);
    ::SendMessageW(logEdit, EM_SETSEL, static_cast<WPARAM>(length), static_cast<LPARAM>(length));
    std::wstring withNewline = line;
    withNewline += L"\r\n";
    ::SendMessageW(logEdit, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(withNewline.c_str()));
}

} // namespace CipherShellGui
