#ifndef CS_PROTECTION_BUILD_CONTEXT_H
#define CS_PROTECTION_BUILD_CONTEXT_H

#include "config/config_parser.h"
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace CipherShell {

struct FeatureSwitch {
    bool enabled = false;
    int strength = 0;
    std::string mode;
    std::vector<std::string> targetFunctions;
};

struct ProtectionBuildContext {
    int quickLevel = 1;
    bool debugNames = false;
    bool randomizeSectionNames = true;

    FeatureSwitch vm;
    FeatureSwitch stringEncryption;
    FeatureSwitch importProtection;
    FeatureSwitch controlFlow;
    FeatureSwitch flattening;
    FeatureSwitch bogusFlow;
    FeatureSwitch sectionEncryption;

    bool stringAscii = true;
    bool stringUtf16 = true;
    bool stringResources = false;
    bool stringClearAfterUse = false;

    uint32_t isaSeed = 0;
    char vmSectionName[8] = {'.','c','s','v','m',0,0,0};
    char vmRuntimeSectionName[8] = {'.','c','s','v','x',0,0,0};

    std::unordered_map<uint8_t, uint8_t> opcodeMap;
    std::unordered_map<uint8_t, uint8_t> registerMap;

    static ProtectionBuildContext FromConfig(const CipherShellConfig& config, int cliLevel, bool verbose);
};

} // namespace CipherShell

#endif // CS_PROTECTION_BUILD_CONTEXT_H
