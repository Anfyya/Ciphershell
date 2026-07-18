// CipherShell GUI - 组装调用 ciphershell.exe 的命令行。
//
// 参数拆分方式是既定方案：路径/等级/verbose 走命令行（对应
// packer/cli_options.cpp 里的 -o/-l/-v/--vm-handler-evidence），其余模块化
// 配置（vm.*/control_flow.*/anti_debug.*/anti_dump.*/performance.* 等）写进
// 临时 TOML，用 -c 传入。
#pragma once

#include <string>

#include "config_model.h"

namespace CipherShellGui {

struct RunRequest {
    std::wstring backendExePath;   // ciphershell.exe 的完整路径
    std::wstring inputFilePath;
    std::wstring outputFilePath;
    std::wstring tempConfigPath;   // 已写好的临时 TOML 路径
};

// 构造可直接传给 CreateProcessW 的命令行字符串（含 argv[0]，已做好
// Windows 命令行转义/引用）。
std::wstring BuildCommandLine(const RunRequest& request, const AppConfig& config);

} // namespace CipherShellGui
