#include "packer/cli_options.h"

#include <iostream>
#include <string>
#include <vector>

namespace {

bool Parse(
    std::vector<std::string> arguments,
    CipherShell::CommandLineOptions& options,
    std::string& error)
{
    std::vector<char*> argv;
    argv.reserve(arguments.size());
    for (auto& argument : arguments) argv.push_back(argument.data());
    return CipherShell::ParseCommandLine(
        static_cast<int>(argv.size()), argv.data(), options, error);
}

bool Expect(bool condition, const char* message) {
    if (!condition) std::cerr << "[FAIL] " << message << '\n';
    return condition;
}

} // namespace

int main() {
    CipherShell::CommandLineOptions options;
    std::string error;

    if (!Expect(Parse({"ciphershell", "input.exe", "-l", "4", "-v"}, options, error),
            "valid arguments must parse")) return 1;
    if (!Expect(options.inputFile == "input.exe" && options.protectionLevel == 4 && options.verbose,
            "parsed values must match")) return 1;

    if (!Expect(!Parse({"ciphershell", "input.exe", "-l", "abc"}, options, error),
            "non-numeric protection level must fail")) return 1;
    if (!Expect(!Parse({"ciphershell", "--unknown", "input.exe"}, options, error),
            "unknown option must fail")) return 1;
    if (!Expect(Parse({"ciphershell", "--", "-input.exe"}, options, error) &&
            options.inputFile == "-input.exe", "-- must end option parsing")) return 1;
    if (!Expect(Parse({"ciphershell", "--help"}, options, error) && options.showHelp,
            "help must not require an input file")) return 1;

    std::cout << "[PASS] CLI option parser\n";
    return 0;
}
