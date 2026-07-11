#include "cli_options.h"

#include <charconv>
#include <string_view>

namespace CipherShell {
namespace {

bool ReadOptionValue(
    int argc,
    char* argv[],
    int& index,
    std::string_view option,
    std::string& value,
    std::string& error)
{
    if (index + 1 >= argc) {
        error = "选项 " + std::string(option) + " 需要指定参数";
        return false;
    }
    value = argv[++index];
    return true;
}

bool ParseProtectionLevel(std::string_view value, int& level) {
    const char* begin = value.data();
    const char* end = begin + value.size();
    const auto result = std::from_chars(begin, end, level);
    return result.ec == std::errc{} && result.ptr == end && level >= 1 && level <= 5;
}

} // namespace

bool ParseCommandLine(
    int argc,
    char* argv[],
    CommandLineOptions& options,
    std::string& error)
{
    options = {};
    error.clear();
    bool positionalOnly = false;

    for (int i = 1; i < argc; ++i) {
        const std::string_view argument(argv[i]);
        if (!positionalOnly && argument == "--") {
            positionalOnly = true;
            continue;
        }
        if (!positionalOnly && (argument == "-h" || argument == "--help")) {
            options.showHelp = true;
            continue;
        }
        if (!positionalOnly && (argument == "-v" || argument == "--verbose")) {
            options.verbose = true;
            continue;
        }
        if (!positionalOnly && (argument == "-o" || argument == "--output")) {
            if (!ReadOptionValue(argc, argv, i, argument, options.outputFile, error)) return false;
            continue;
        }
        if (!positionalOnly && (argument == "-c" || argument == "--config")) {
            if (!ReadOptionValue(argc, argv, i, argument, options.configFile, error)) return false;
            continue;
        }
        if (!positionalOnly && (argument == "-l" || argument == "--level")) {
            std::string value;
            if (!ReadOptionValue(argc, argv, i, argument, value, error)) return false;
            if (!ParseProtectionLevel(value, options.protectionLevel)) {
                error = "保护等级必须是 1-5 之间的整数";
                return false;
            }
            continue;
        }
        if (!positionalOnly && !argument.empty() && argument.front() == '-') {
            error = "未知选项 '" + std::string(argument) + "'";
            return false;
        }
        if (!options.inputFile.empty()) {
            error = "只能指定一个输入文件；多余参数为 '" + std::string(argument) + "'";
            return false;
        }
        options.inputFile = argument;
    }

    if (!options.showHelp && options.inputFile.empty()) {
        error = "未指定输入文件";
        return false;
    }
    return true;
}

} // namespace CipherShell
