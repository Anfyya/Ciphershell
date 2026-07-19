// CipherShell GUI - 配置 -> TOML 序列化。
//
// 生成的文本必须能被 packer/config/config_parser.cpp 里的
// ConfigParser::ValidateProductionSyntax 原样接受：section/key 名称、值的
// 词法（布尔/整数/字符串/数组）都严格照抄该函数里的正则要求。修改这个文件
// 前请先重新核对 config_parser.cpp，不要凭经验假设 TOML 语法。
#pragma once

#include <string>

#include "config_model.h"

namespace CipherShellGui {

// 生成完整的 TOML 文本（UTF-8，无 BOM）。
std::string BuildConfigToml(const AppConfig& config);

// 写入到 path（宽字符路径）。失败时 error 填充可读原因。
bool WriteConfigTomlToFile(
    const AppConfig& config, const std::wstring& path, std::wstring& error);

} // namespace CipherShellGui
