#include "capability_checker.h"
#include "../pe_parser/pe_utils.h"
#include <algorithm>

namespace CipherShell {

namespace {
void AddIssue(CapabilityReport& report, const char* module, uint32_t rva, const char* reason, bool fatal) {
    CapabilityIssue issue;
    issue.module = module;
    issue.rva = rva;
    issue.reason = reason;
    issue.fatal = fatal;
    report.issues.push_back(issue);
    if (fatal) report.ok = false;
}
}

CapabilityReport CapabilityChecker::CheckImage(const CS_PE_IMAGE* image, const ProtectionBuildContext& ctx) const {
    CapabilityReport report;
    if (!image || !image->isValid) {
        AddIssue(report, "CapabilityChecker", 0, "invalid PE image", true);
        return report;
    }

    if (ctx.vm.enabled) {
        const WORD dllCharacteristics = image->is64Bit
            ? image->ntHeaders64->OptionalHeader.DllCharacteristics
            : image->ntHeaders32->OptionalHeader.DllCharacteristics;
        const bool cfgCharacteristic =
            (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0;
        if (cfgCharacteristic && (!image->loadConfig.valid || !image->loadConfig.hasCFG)) {
            AddIssue(report, "LoadConfig", 0,
                "PE advertises CFG but its Load Config Guard metadata is invalid", true);
        }
        if (image->loadConfig.valid && image->loadConfig.hasCFG) {
            if ((image->loadConfig.guardFlags & IMAGE_GUARD_XFG_ENABLED) != 0) {
                AddIssue(report, "LoadConfig", 0,
                    "XFG requires signature-aware dispatch metadata that the VM native bridge cannot reproduce",
                    true);
            }
            if (image->loadConfig.hasRFGuard) {
                AddIssue(report, "LoadConfig", 0,
                    "Return Flow Guard instrumentation is incompatible with generated VM runtime returns",
                    true);
            }
            const bool guardTargetMissing = image->is64Bit
                ? image->loadConfig.guardCFDispatchFunctionPointer == 0
                : image->loadConfig.guardCFCheckFunctionPointer == 0;
            if (guardTargetMissing) {
                AddIssue(report, "LoadConfig", 0,
                    "CFG image has no architecture-specific Guard check/dispatch pointer", true);
            }
        }
    }

    if (ctx.sectionEncryption.enabled) {
        for (uint32_t i = 0; i < image->numSections; ++i) {
            const uint32_t characteristics = image->sections[i].Characteristics;
            if ((characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 &&
                (characteristics & IMAGE_SCN_MEM_WRITE) != 0) {
                AddIssue(report, "SectionEncryption", image->sections[i].VirtualAddress,
                    "input contains a writable-executable section; final W^X restoration is ambiguous",
                    true);
            }
        }
    }

    if (ctx.importProtection.enabled && ctx.importProtection.strength >= 70) {
        AddIssue(report, "ImportProtection", 0, "runtime resolver callsite rewrite is required for high strength import protection", true);
    }

    if (ctx.stringEncryption.enabled && ctx.stringEncryption.mode == "on_demand") {
        AddIssue(report, "StringEncryption", 0, "on-demand decrypt thunks are not yet available; use startup mode for this build", true);
    }

    return report;
}

bool CapabilityChecker::IsFunctionVmSafe(const CS_PE_IMAGE* image, const Function& func, std::string& reason) const {
    if (!image || !image->isValid) {
        reason = "invalid image";
        return false;
    }
    if (func.size < 5) {
        reason = "function too small for entry trampoline";
        return false;
    }
    if (!func.boundaryTrusted || func.blocks.empty() || func.decodedBytes == 0) {
        reason = "function has no trusted recursive-decoder boundary";
        return false;
    }
    if (func.hasExternalInteriorReference) {
        reason = "another function branches into the protected function interior";
        return false;
    }
    if (func.usesSEH) {
        reason = "function marked as SEH/exception user";
        return false;
    }
    if (image->is64Bit && !image->exceptions.entries.empty()) {
        uint32_t begin = static_cast<uint32_t>(func.entryAddress);
        uint32_t end = begin + func.size;
        for (const auto& entry : image->exceptions.entries) {
            if (begin >= entry.endAddress || end <= entry.beginAddress) continue;
            if (begin != entry.beginAddress || end > entry.endAddress) {
                reason = "function boundary does not match its x64 runtime-function entry";
                return false;
            }
            const uint32_t unwindOffset = PEUtils::RvaToOffset(image, entry.unwindData);
            if (unwindOffset == 0 || unwindOffset >= image->rawSize) {
                reason = "x64 unwind info is outside the PE image";
                return false;
            }
            const uint8_t versionAndFlags = image->rawData[unwindOffset];
            const uint8_t version = versionAndFlags & 0x07u;
            const uint8_t flags = versionAndFlags >> 3;
            if ((version != 1 && version != 2) || (flags & 0x07u) != 0) {
                reason = "x64 function uses exception handlers or chained unwind metadata";
                return false;
            }
        }
    }

    for (const auto& block : func.blocks) {
        for (const auto& instr : block.instructions) {
            if (instr.isIndirectBranch && !instr.IsCall()) {
                reason = "indirect non-call control flow has no statically verifiable VM target";
                return false;
            }
        }
    }
    return true;
}

} // namespace CipherShell
