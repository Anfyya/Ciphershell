#include "cli_builder.h"

#include <vector>

namespace CipherShellGui {
namespace {

// 按 Windows / MSVC CRT 的命令行解析规则转义单个参数（反斜杠+双引号的
// 经典算法，与 CPython subprocess.list2cmdline、Chromium
// base::CommandLine::QuoteForCommandLineToArgvW 采用的是同一套规则）。
std::wstring QuoteArgument(const std::wstring& argument) {
    if (!argument.empty() &&
        argument.find_first_of(L" \t\n\v\"") == std::wstring::npos) {
        return argument;
    }

    std::wstring quoted = L"\"";
    for (auto it = argument.begin();; ++it) {
        size_t backslashes = 0;
        while (it != argument.end() && *it == L'\\') {
            ++it;
            ++backslashes;
        }
        if (it == argument.end()) {
            quoted.append(backslashes * 2, L'\\');
            break;
        }
        if (*it == L'"') {
            quoted.append(backslashes * 2 + 1, L'\\');
            quoted.push_back(L'"');
        } else {
            quoted.append(backslashes, L'\\');
            quoted.push_back(*it);
        }
    }
    quoted.push_back(L'"');
    return quoted;
}

void AppendArgument(std::wstring& commandLine, const std::wstring& argument) {
    if (!commandLine.empty()) commandLine.push_back(L' ');
    commandLine += QuoteArgument(argument);
}

} // namespace

std::wstring BuildCommandLine(const RunRequest& request, const AppConfig& config) {
    std::wstring commandLine;

    // argv[0]：即便下面会单独把 backendExePath 作为 lpApplicationName 传给
    // CreateProcessW（避免走 PATH 搜索的歧义），命令行里仍按惯例带上一份。
    AppendArgument(commandLine, request.backendExePath);
    AppendArgument(commandLine, request.inputFilePath);

    AppendArgument(commandLine, L"-o");
    AppendArgument(commandLine, request.outputFilePath);

    AppendArgument(commandLine, L"-l");
    AppendArgument(commandLine, std::to_wstring(config.cli.protectionLevel));

    AppendArgument(commandLine, L"-c");
    AppendArgument(commandLine, request.tempConfigPath);

    if (config.cli.verbose) {
        AppendArgument(commandLine, L"-v");
    }

    if (config.cli.exportVmHandlerEvidence &&
        !config.cli.vmHandlerEvidencePath.empty()) {
        AppendArgument(commandLine, L"--vm-handler-evidence");
        AppendArgument(commandLine, config.cli.vmHandlerEvidencePath);
    }

    return commandLine;
}

} // namespace CipherShellGui
