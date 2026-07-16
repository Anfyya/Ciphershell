#pragma once

#include <string>

namespace CipherShell {

struct CommandLineOptions {
    std::string inputFile;
    std::string outputFile;
    std::string configFile;
    std::string vmHandlerEvidenceFile;
    int protectionLevel = 1;
    bool verbose = false;
    bool showHelp = false;
};

bool ParseCommandLine(
    int argc,
    char* argv[],
    CommandLineOptions& options,
    std::string& error);

} // namespace CipherShell
