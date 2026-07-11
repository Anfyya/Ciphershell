#ifndef CS_PROTECTION_BUILD_CONTEXT_H
#define CS_PROTECTION_BUILD_CONTEXT_H

#include "config/config_parser.h"
#include <array>
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
    std::vector<uint32_t> targetRVAs;
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

    std::array<uint8_t, 32> isaSeed{};
    bool entropyReady = false;
    char vmSectionName[8] = {'.','c','s','v','m',0,0,0};
    char vmRuntimeSectionName[8] = {'.','c','s','v','x',0,0,0};
    char vmUnwindSectionName[8] = {'.','c','s','p','d','t',0,0};
    char vmBridgeSectionName[8] = {'.','c','s','v','b','r',0,0};
    char vmBridgeUnwindSectionName[8] = {'.','c','s','b','u','w',0,0};
    char vmGuardSectionName[8] = {'.','c','s','g','f','t',0,0};
    char vmRelocSectionName[8] = {'.','c','s','r','l','c',0,0};

    std::unordered_map<uint8_t, uint8_t> opcodeMap;
    std::unordered_map<uint8_t, uint8_t> registerMap;

    static ProtectionBuildContext FromConfig(const CipherShellConfig& config, int cliLevel, bool verbose);
};

} // namespace CipherShell

#endif // CS_PROTECTION_BUILD_CONTEXT_H
