#include "capability_checker.h"
#include <algorithm>

namespace CipherShell {

namespace {
bool IsLikelyDll(const CS_PE_IMAGE* image) {
    if (!image) return false;
    WORD chars = image->is64Bit ? image->ntHeaders64->FileHeader.Characteristics
                                : image->ntHeaders32->FileHeader.Characteristics;
    return (chars & IMAGE_FILE_DLL) != 0;
}

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
        if (!image->is64Bit) {
            AddIssue(report, "VM", 0, "function VM runtime currently supports x64 targets only", true);
        }
        if (IsLikelyDll(image)) {
            AddIssue(report, "VM", 0, "DLL export/DllMain VM chain is not enabled before x64 EXE VM is complete", true);
        }
        if (image->loadConfig.valid && image->loadConfig.hasCFG) {
            AddIssue(report, "LoadConfig", 0, "CFG Guard target table update is not implemented for VM trampolines", true);
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
    if (func.usesSEH) {
        reason = "function marked as SEH/exception user";
        return false;
    }
    if (image->is64Bit && !image->exceptions.entries.empty()) {
        uint32_t begin = static_cast<uint32_t>(func.entryAddress);
        uint32_t end = begin + func.size;
        for (const auto& entry : image->exceptions.entries) {
            if (begin < entry.endAddress && end > entry.beginAddress) {
                reason = "x64 unwind entry overlaps function; no generated unwind info yet";
                return false;
            }
        }
    }

    for (const auto& block : func.blocks) {
        for (const auto& instr : block.instructions) {
            if (instr.isIndirect) {
                reason = "indirect control flow requires native bridge or user annotation";
                return false;
            }
            if (instr.isCall && !instr.hasTarget) {
                reason = "indirect call requires native bridge";
                return false;
            }
        }
    }
    return true;
}

} // namespace CipherShell
