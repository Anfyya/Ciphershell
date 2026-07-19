// CipherShell GUI - 控件 ID。
//
// 绝大多数控件（勾选框、编辑框、下拉框……）不需要用 ID 区分——创建时拿到的
// HWND 直接存进 MainWindow 的成员里，读取/写入配置时按 HWND 操作，Start 时
// 一次性读完所有控件即可。真正需要在 WM_COMMAND/WM_NOTIFY 里按 ID 分支处理
// 的，只有下面这些"点了会触发即时动作"的控件。其余被动控件在创建时用
// NextControlId() 领一个仅用于满足 Win32 API（子窗口需要非零 ID）、彼此不
// 冲突的编号即可。
#pragma once

namespace CipherShellGui {

enum ControlId : int {
    IDC_TAB = 100,
    IDC_BROWSE_INPUT,
    IDC_BROWSE_OUTPUT,
    IDC_BROWSE_EVIDENCE,
    IDC_BROWSE_BACKEND,
    IDC_VM_ENABLED,
    IDC_EVIDENCE_ENABLED,
    IDC_START,
    IDC_CANCEL,
    IDC_OPEN_OUTPUT_FOLDER,
    IDC_FIRST_DYNAMIC = 1000,
};

// 被动控件用的自增 ID 分配器，避免手写常量互相冲突。
int NextControlId();

} // namespace CipherShellGui
