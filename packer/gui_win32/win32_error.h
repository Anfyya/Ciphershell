// CipherShell GUI - Win32/HRESULT 错误信息格式化小工具。
#pragma once

#include <windows.h>

#include <string>

namespace CipherShellGui {

std::wstring FormatWin32Error(DWORD errorCode);
std::wstring FormatHResultError(HRESULT hr);

} // namespace CipherShellGui
