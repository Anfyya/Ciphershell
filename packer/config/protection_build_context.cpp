#include "protection_build_context.h"

#include "../../runtime/common/vm_crypto.h"
#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <random>
#endif
#include <cstring>

namespace CipherShell {

namespace {
void CopyName(char out[8], const char* in) {
    for (int i = 0; i < 8; i++) out[i] = 0;
    for (int i = 0; i < 8 && in[i]; i++) out[i] = in[i];
}

void MakeSectionName(char out[8], const std::array<uint8_t, 32>& seed, uint32_t salt) {
    static const char alphabet[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    out[0] = '.';
    uint8_t message[8] = {
        static_cast<uint8_t>(salt), static_cast<uint8_t>(salt >> 8),
        static_cast<uint8_t>(salt >> 16), static_cast<uint8_t>(salt >> 24),
        'C', 'S', 'V', 'M'
    };
    uint64_t stream = vm_siphash24(message, sizeof(message), seed.data());
    for (int i = 1; i < 8; i++) {
        out[i] = alphabet[stream % (sizeof(alphabet) - 1)];
        stream /= sizeof(alphabet) - 1;
    }
    std::memset(message, 0, sizeof(message));
}

FeatureSwitch PresetFeature(bool enabled, int strength, const char* mode = "") {
    FeatureSwitch f;
    f.enabled = enabled;
    f.strength = strength;
    f.mode = mode ? mode : "";
    return f;
}
}

ProtectionBuildContext ProtectionBuildContext::FromConfig(
    const CipherShellConfig& config,
    int cliLevel,
    bool verbose)
{
    ProtectionBuildContext ctx;
    ctx.quickLevel = config.global.protectionLevelSet
        ? config.global.protectionLevel
        : cliLevel;
    ctx.debugNames = verbose;
    ctx.randomizeSectionNames = config.global.randomizeSections;
#ifdef _WIN32
    ctx.entropyReady = BCryptGenRandom(nullptr, ctx.isaSeed.data(),
        static_cast<ULONG>(ctx.isaSeed.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0;
#else
    try {
        std::random_device source;
        for (auto& byte : ctx.isaSeed) byte = static_cast<uint8_t>(source());
        ctx.entropyReady = true;
    } catch (...) {
        ctx.entropyReady = false;
    }
#endif

    // 以下模块当前不具备完整生产语义闭环，预设绝不隐式开启：
    //   section encryption / startup string encryption / import protection /
    //   bogus flow
    // 仅当用户在配置中显式设置 enabled 时才会被打开，并由 CapabilityChecker
    // 在任何 PE 修改之前以 fatal issue 拒绝。
    // CFG flattening 现在有独立的本地代码/重定位/unwind/入口修补闭环，
    // 但仍只在用户显式开启时使用，不改变现有等级预设。
    ctx.sectionEncryption = PresetFeature(false, 50 + ctx.quickLevel * 8, "startup");
    ctx.stringEncryption = PresetFeature(false, 60, "startup");
    ctx.importProtection = PresetFeature(false, 50, "metadata");
    ctx.controlFlow = PresetFeature(false, 55, "mixed");
    ctx.flattening = PresetFeature(false, 55, "basic");
    ctx.bogusFlow = PresetFeature(false, 50, "safe_nop_only");
    // VM 具备完整语义闭环（ISA + runtime + 静态链接验证），允许按等级预设开启。
    ctx.vm = PresetFeature(ctx.quickLevel >= 4, 80 + (ctx.quickLevel >= 5 ? 10 : 0), "function_vm");

    if (config.vm.enabledSet) ctx.vm.enabled = config.vm.enabled;
    if (config.vm.strength > 0) ctx.vm.strength = config.vm.strength;
    if (!config.vm.targetFunctions.empty()) ctx.vm.targetFunctions = config.vm.targetFunctions;
    if (!config.vm.targetRVAs.empty()) ctx.vm.targetRVAs = config.vm.targetRVAs;

    if (config.stringEncryption.enabledSet) ctx.stringEncryption.enabled = config.stringEncryption.enabled;
    if (config.stringEncryption.strength > 0) ctx.stringEncryption.strength = config.stringEncryption.strength;
    if (!config.stringEncryption.mode.empty()) ctx.stringEncryption.mode = config.stringEncryption.mode;
    ctx.stringAscii = config.stringEncryption.ascii;
    ctx.stringUtf16 = config.stringEncryption.utf16;
    ctx.stringResources = config.stringEncryption.resources;
    ctx.stringClearAfterUse = config.stringEncryption.clearAfterUse;

    if (config.importProtection.enabledSet) ctx.importProtection.enabled = config.importProtection.enabled;
    if (config.importProtection.strength > 0) ctx.importProtection.strength = config.importProtection.strength;

    if (config.sectionEncryption.enabledSet) {
        ctx.sectionEncryption.enabled = config.sectionEncryption.enabled;
    }
    if (config.sectionEncryption.strength > 0) {
        ctx.sectionEncryption.strength = config.sectionEncryption.strength;
    }
    if (!config.sectionEncryption.mode.empty()) {
        ctx.sectionEncryption.mode = config.sectionEncryption.mode;
    }

    if (config.controlFlow.enabledSet) ctx.controlFlow.enabled = config.controlFlow.enabled;
    if (config.controlFlow.strength > 0) ctx.controlFlow.strength = config.controlFlow.strength;
    if (config.controlFlow.flatteningEnabledSet) ctx.flattening.enabled = config.controlFlow.flatteningEnabled;
    if (config.controlFlow.flatteningStrength > 0) ctx.flattening.strength = config.controlFlow.flatteningStrength;
    if (config.controlFlow.bogusEnabledSet) ctx.bogusFlow.enabled = config.controlFlow.bogusEnabled;
    if (config.controlFlow.bogusStrength > 0) ctx.bogusFlow.strength = config.controlFlow.bogusStrength;
    ctx.flattening.targetFunctions = config.controlFlow.flatteningTargets;

    if (ctx.randomizeSectionNames && !ctx.debugNames) {
        MakeSectionName(ctx.vmSectionName, ctx.isaSeed, 0xC0DEu);
        MakeSectionName(ctx.vmRuntimeSectionName, ctx.isaSeed, 0x51A7u);
        MakeSectionName(ctx.vmUnwindSectionName, ctx.isaSeed, 0xDA7Au);
        MakeSectionName(ctx.vmBridgeSectionName, ctx.isaSeed, 0xB21Du);
        MakeSectionName(ctx.vmBridgeUnwindSectionName, ctx.isaSeed, 0xB117u);
        MakeSectionName(ctx.vmGuardSectionName, ctx.isaSeed, 0x6CF7u);
        MakeSectionName(ctx.vmRelocSectionName, ctx.isaSeed, 0x2E10u);
        MakeSectionName(ctx.vmRuntimeApiSectionName, ctx.isaSeed, 0xA91Fu);
        MakeSectionName(ctx.cfgCodeSectionName, ctx.isaSeed, 0xCF61u);
        MakeSectionName(ctx.cfgUnwindSectionName, ctx.isaSeed, 0xCF62u);
        MakeSectionName(ctx.cfgExceptionSectionName, ctx.isaSeed, 0xCF63u);
        MakeSectionName(ctx.cfgRelocSectionName, ctx.isaSeed, 0xCF64u);
    } else {
        CopyName(ctx.vmSectionName, ".csvm");
        CopyName(ctx.vmRuntimeSectionName, ".csvx");
        CopyName(ctx.vmUnwindSectionName, ".cspdt");
        CopyName(ctx.vmBridgeSectionName, ".csvbr");
        CopyName(ctx.vmBridgeUnwindSectionName, ".csbuw");
        CopyName(ctx.vmGuardSectionName, ".csgft");
        CopyName(ctx.vmRelocSectionName, ".csrlc");
        CopyName(ctx.vmRuntimeApiSectionName, ".csvapi");
        CopyName(ctx.cfgCodeSectionName, ".cfgx");
        CopyName(ctx.cfgUnwindSectionName, ".cfguw");
        CopyName(ctx.cfgExceptionSectionName, ".cfgpd");
        CopyName(ctx.cfgRelocSectionName, ".cfgrl");
    }

    return ctx;
}

void ProtectionBuildContext::DeriveGroupSectionName(char out[8],
    const ProtectionBuildContext& ctx, const char base[8], uint32_t salt, uint32_t groupId)
{
    if (ctx.randomizeSectionNames && !ctx.debugNames) {
        // groupId==0 reuses the untouched salt, so it is byte-for-byte the
        // same name a single-group build would have produced.
        MakeSectionName(out, ctx.isaSeed, salt ^ (groupId * 0x1000001u));
        return;
    }
    CopyName(out, base);
    if (groupId > 0) {
        int len = 0;
        while (len < 8 && out[len]) ++len;
        const int index = len > 0 ? len - 1 : 0;
        out[index] = static_cast<char>('0' + (groupId % 10));
    }
}

} // namespace CipherShell
