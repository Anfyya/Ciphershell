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
    char vmSafeSehSectionName[8] = {'.','c','s','s','e','h',0,0};
    char vmRuntimeApiSectionName[8] = {'.','c','s','v','a','p','i',0};
    char cfgCodeSectionName[8] = {'.','c','f','g','x',0,0,0};
    char cfgUnwindSectionName[8] = {'.','c','f','g','u','w',0,0};
    char cfgExceptionSectionName[8] = {'.','c','f','g','p','d',0,0};
    char cfgRelocSectionName[8] = {'.','c','f','g','r','l',0,0};

    std::unordered_map<uint8_t, uint8_t> opcodeMap;
    std::unordered_map<uint8_t, uint8_t> registerMap;

    static ProtectionBuildContext FromConfig(const CipherShellConfig& config, int cliLevel, bool verbose);

    // 多 VM Variant Group 场景下，每个 group 需要一套互不冲突的 section
    // 名字。groupId==0 与单 Group 场景下的既有派生结果逐字节一致（salt 不
    // 变），groupId>0 时按 salt^groupId 派生出的名字（随机化模式）或替换
    // 固定名最后一个字符（debug/固定命名模式）来避免撞名。
    static void DeriveGroupSectionName(char out[8], const ProtectionBuildContext& ctx,
        const char base[8], uint32_t salt, uint32_t groupId);
};

} // namespace CipherShell

#endif // CS_PROTECTION_BUILD_CONTEXT_H
