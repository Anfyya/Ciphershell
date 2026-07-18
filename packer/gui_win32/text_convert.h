// CipherShell GUI - 宽字符/UTF-8 转换小工具。
//
// GUI 控件一律使用 UNICODE（std::wstring）；写配置文件、构造子进程命令行
// 时按 UTF-8 处理。集中放在这里，避免到处手写 WideCharToMultiByte。
#pragma once

#include <string>

namespace CipherShellGui {

std::string WideToUtf8(const std::wstring& wide);
std::wstring Utf8ToWide(const std::string& utf8);

} // namespace CipherShellGui
