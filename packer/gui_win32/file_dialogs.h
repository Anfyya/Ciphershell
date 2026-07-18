// CipherShell GUI - 文件选择对话框。
//
// 一律使用现代 COM 接口 IFileOpenDialog / IFileSaveDialog（shobjidl.h），
// 不使用旧式的 GetOpenFileName/GetSaveFileName。调用方需已完成
// OleInitialize/CoInitializeEx（本项目在 WinMain 里统一做一次，drag & drop
// 也依赖同一次 OleInitialize）。
#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <string>

namespace CipherShellGui {

// 选择要加壳的输入文件（*.exe;*.dll），IFileOpenDialog。
bool ShowOpenInputFileDialog(HWND owner, std::wstring& outPath);

// 选择输出文件路径（IFileSaveDialog）。defaultFolder/defaultFileName 为空时
// 由系统给默认值。
bool ShowSaveOutputFileDialog(
    HWND owner,
    const std::wstring& defaultFolder,
    const std::wstring& defaultFileName,
    std::wstring& outPath);

// 选择 ciphershell.exe 后端可执行文件（自动探测失败时用于用户手动指定）。
bool ShowSelectBackendExeDialog(HWND owner, std::wstring& outPath);

// 通用"另存为"对话框，用于 --vm-handler-evidence 这类诊断输出路径。
bool ShowSaveGenericFileDialog(
    HWND owner,
    const std::wstring& title,
    const std::wstring& defaultFolder,
    const std::wstring& defaultFileName,
    std::wstring& outPath);

} // namespace CipherShellGui
