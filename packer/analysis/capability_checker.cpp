#include "capability_checker.h"
#include "../pe_parser/pe_utils.h"
#include <algorithm>
#include <cstring>
#include <unordered_set>

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

bool WritesStackPointer(const InstructionIR& instruction) {
    if (instruction.IsReturn()) return false;
    switch (instruction.mnemonic) {
        case InstructionMnemonic::Push:
        case InstructionMnemonic::Pop:
        case InstructionMnemonic::PushFlags:
        case InstructionMnemonic::PopFlags:
        case InstructionMnemonic::Leave:
            return true;
        default:
            break;
    }
    for (const OperandIR& operand : instruction.operands) {
        const bool writes = operand.action == OperandAction::Write ||
            operand.action == OperandAction::ReadWrite ||
            operand.action == OperandAction::ConditionalWrite ||
            operand.action == OperandAction::ConditionalReadWrite;
        if (writes && operand.type == OperandType::Register &&
            operand.regInfo.registerClass == RegisterClass::GeneralPurpose &&
            operand.regInfo.family == 4u) return true;
    }
    return false;
}

bool HasEndbrPrefix(const CS_PE_IMAGE* image, uint32_t rva) {
    const uint32_t offset = PEUtils::RvaToOffset(image, rva);
    if (offset == 0u || offset > image->rawSize ||
        4u > image->rawSize - offset) return false;
    const uint8_t* bytes = image->rawData + offset;
    return bytes[0] == 0xF3u && bytes[1] == 0x0Fu && bytes[2] == 0x1Eu &&
        bytes[3] == (image->is64Bit ? 0xFAu : 0xFBu);
}
}

CapabilityReport CapabilityChecker::CheckImage(const CS_PE_IMAGE* image, const ProtectionBuildContext& ctx) const {
    CapabilityReport report;
    if (!image || !image->isValid) {
        AddIssue(report, "CapabilityChecker", 0, "invalid PE image", true);
        return report;
    }

    // ========================================================================
    // Fail-closed 关卡：以下模块当前不具备完整生产语义闭环。
    // 任何显式开启都在此处（任何 PE 内容、section、header、入口点、导入表或
    // 文件偏移被修改之前）以 fatal issue 拒绝。绝不进入 partial / native fallback /
    // 静默跳过 / 产物后提示 unsupported 等路径。
    // ========================================================================
    if (ctx.sectionEncryption.enabled) {
        AddIssue(report, "SectionEncryption", 0,
            "section encryption uses an unauthenticated cipher with a recoverable key; "
            "no production closure exists (reject before any PE modification)",
            true);
    }
    if (ctx.stringEncryption.enabled) {
        AddIssue(report, "StringEncryption", 0,
            "startup string encryption uses an unauthenticated cipher with a recoverable key; "
            "no production closure exists (reject before any PE modification)",
            true);
    }
    if (ctx.importProtection.enabled) {
        AddIssue(report, "ImportProtection", 0,
            "import protection does not rewrite the real IAT callsite; "
            "the original IAT is preserved and only fake imports are appended (reject before any PE modification)",
            true);
    }
    if (ctx.bogusFlow.enabled) {
        AddIssue(report, "ControlFlow", 0,
            "bogus flow cannot prove original function semantics are preserved; "
            "no production closure exists (reject before any PE modification)",
            true);
    }

    // controlFlow 总开关与 flattening/bogus 子开关的一致性。
    // 不得出现：总开关开启但实际什么都不做；子功能开启却绕过 CapabilityChecker；
    // 配置与执行状态互相矛盾。
    const bool anyControlFlowSub = ctx.flattening.enabled || ctx.bogusFlow.enabled;
    if (ctx.controlFlow.enabled && !anyControlFlowSub) {
        AddIssue(report, "ControlFlow", 0,
            "control_flow master switch is enabled but no sub-feature is active (no-op configuration)",
            true);
    }
    if (!ctx.controlFlow.enabled && anyControlFlowSub) {
        AddIssue(report, "ControlFlow", 0,
            "a control_flow sub-feature is enabled while the master switch is off (configuration contradiction)",
            true);
    }

    if (ctx.vm.enabled || ctx.flattening.enabled) {
        const WORD dllCharacteristics = image->is64Bit
            ? image->ntHeaders64->OptionalHeader.DllCharacteristics
            : image->ntHeaders32->OptionalHeader.DllCharacteristics;
        const bool cfgCharacteristic =
            (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0;
        if (cfgCharacteristic && (!image->loadConfig.valid || !image->loadConfig.hasCFG)) {
            AddIssue(report, "LoadConfig", 0,
                "PE advertises CFG but its Load Config Guard metadata is invalid", true);
        }
        if (image->loadConfig.valid && image->loadConfig.hasRFGuard) {
            AddIssue(report, "LoadConfig", 0,
                "Return Flow Guard instrumentation is incompatible with generated VM/CFG returns",
                true);
        }
        if (ctx.flattening.enabled && image->debugDir.hasCetCompat) {
            AddIssue(report, "ControlFlow", 0,
                "CET shadow-stack compatibility forbids CFG dispatcher return-address rewriting",
                true);
        }
        if (image->loadConfig.valid && image->loadConfig.hasCFG) {
            if (ctx.vm.enabled &&
                (image->loadConfig.guardFlags & IMAGE_GUARD_XFG_ENABLED) != 0) {
                AddIssue(report, "LoadConfig", 0,
                    "XFG requires signature-aware dispatch metadata that the VM native bridge cannot reproduce",
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

    return report;
}

bool CapabilityChecker::IsFunctionCfgSafe(
    const CS_PE_IMAGE* image,
    const Function& func,
    std::string& reason) const
{
    if (!image || !image->isValid) {
        reason = "invalid image";
        return false;
    }
    if (func.entryAddress == 0u || func.entryAddress > 0xFFFFFFFFULL ||
        func.size < 5u ||
        static_cast<uint64_t>(func.size) >
            0xFFFFFFFFULL - func.entryAddress) {
        reason = "function is outside the RVA range or too small for an entry trampoline";
        return false;
    }
    if (!func.boundaryTrusted || func.blocks.empty() || func.decodedBytes == 0u) {
        reason = "function has no trusted recursive-decoder boundary";
        return false;
    }
    if (func.hasExternalInteriorReference) {
        reason = "another function branches into the protected function interior";
        return false;
    }
    if (func.usesSEH) {
        reason = "function uses SEH/exception state";
        return false;
    }
    if (image->is64Bit && !func.isLeaf) {
        reason = "x64 CFG closure currently requires a leaf function";
        return false;
    }
    if (image->is64Bit) {
        const uint32_t begin = static_cast<uint32_t>(func.entryAddress);
        const uint64_t end = static_cast<uint64_t>(begin) + func.size;
        for (const CS_RUNTIME_FUNCTION& runtimeFunction : image->exceptions.entries) {
            if (begin < runtimeFunction.endAddress && end > runtimeFunction.beginAddress) {
                reason = "x64 CFG closure currently requires a pdata-free leaf function";
                return false;
            }
        }
    }

    const uint64_t functionEnd = func.entryAddress + func.size;
    std::unordered_set<uint32_t> blockStarts;
    std::unordered_set<uint32_t> decodedInstructionBytes;
    for (const BasicBlock& block : func.blocks) {
        if (block.instructions.empty() || block.startAddress > 0xFFFFFFFFULL ||
            block.startAddress != block.instructions.front().address ||
            block.startAddress != block.instructions.front().rva ||
            block.endAddress != block.instructions.back().address +
                block.instructions.back().length ||
            block.instructionCount != block.instructions.size() ||
            !blockStarts.insert(static_cast<uint32_t>(block.startAddress)).second) {
            reason = "function has an inconsistent, duplicate, or out-of-range basic block";
            return false;
        }
        for (const InstructionIR& instruction : block.instructions) {
            const uint64_t instructionEnd =
                static_cast<uint64_t>(instruction.rva) + instruction.length;
            if (instruction.length == 0u ||
                instruction.address != instruction.rva ||
                instruction.rva < func.entryAddress ||
                instructionEnd > functionEnd) {
                reason = "decoded instruction escapes the trusted function envelope";
                return false;
            }
            const uint32_t instructionOffset =
                PEUtils::RvaToOffset(image, instruction.rva);
            if (instructionOffset == 0u || instructionOffset > image->rawSize ||
                instruction.length > image->rawSize - instructionOffset) {
                reason = "decoded CFG instruction is not wholly file-backed";
                return false;
            }
            for (uint32_t byte = 0u; byte < instruction.length; ++byte) {
                if (!decodedInstructionBytes.insert(
                        instruction.rva + byte).second) {
                    reason = "decoded basic blocks overlap instruction bytes";
                    return false;
                }
            }
        }
    }
    const uint32_t entryRVA = static_cast<uint32_t>(func.entryAddress);
    const uint32_t entryPrefix = HasEndbrPrefix(image, entryRVA) ? 4u : 0u;
    if (func.size < entryPrefix + 5u) {
        reason = "function is too small for a near CFG entry patch after ENDBR";
        return false;
    }
    const uint32_t entryPatchRVA = entryRVA + entryPrefix;
    uint32_t patchCursor = entryPatchRVA;
    const uint32_t requiredPatchEnd = patchCursor + 5u;
    while (patchCursor < requiredPatchEnd) {
        const InstructionIR* owner = nullptr;
        for (const BasicBlock& block : func.blocks) {
            const auto found = std::find_if(block.instructions.begin(),
                block.instructions.end(), [&](const InstructionIR& instruction) {
                    return instruction.rva == patchCursor;
                });
            if (found != block.instructions.end()) {
                owner = &*found;
                break;
            }
        }
        if (!owner) {
            reason = "CFG entry patch does not follow complete decoded instructions";
            return false;
        }
        patchCursor += owner->length;
    }
    const uint64_t imageBase = image->is64Bit
        ? image->ntHeaders64->OptionalHeader.ImageBase
        : image->ntHeaders32->OptionalHeader.ImageBase;
    const uint16_t expectedRelocationType = image->is64Bit ? 10u : 3u;
    const uint32_t relocationWidth = image->is64Bit ? 8u : 4u;
    for (const CS_RELOC_ENTRY& relocation : image->relocs.entries) {
        const uint64_t relocationEnd = relocation.fullRVA + relocationWidth;
        if (relocation.fullRVA < patchCursor &&
            relocationEnd > entryPatchRVA) {
            reason = "base relocation overlaps the decoded CFG entry patch span";
            return false;
        }
    }
    for (const BasicBlock& block : func.blocks) {
        const InstructionIR& terminal = block.instructions.back();
        if (terminal.isIndirectBranch && !terminal.IsCall()) {
            reason = "indirect non-call edge cannot be assigned a verified dispatcher state";
            return false;
        }
        for (const InstructionIR& instruction : block.instructions) {
            if (image->is64Bit && WritesStackPointer(instruction)) {
                reason = "x64 function mutates RSP and needs unsupported unwind rewriting";
                return false;
            }
            if (instruction.IsCall() && !instruction.isIndirectBranch &&
                (!instruction.hasBranchTarget || instruction.immediateSize != 4u ||
                 instruction.immediateOffset == 0u ||
                 instruction.immediateOffset + instruction.immediateSize >
                    instruction.length)) {
                reason = "direct CALL has no relocatable rel32 operand";
                return false;
            }
            uint32_t ripOperands = 0u;
            for (const OperandIR& operand : instruction.operands) {
                if (operand.type == OperandType::Memory && operand.memory.isRipRelative)
                    ++ripOperands;
                if (operand.type == OperandType::Memory &&
                    operand.memory.isImageAddress) {
                    const uint32_t bytes = (std::max)(1u,
                        static_cast<uint32_t>((operand.memory.width + 7u) / 8u));
                    for (uint32_t byte = 0u; byte < bytes &&
                            byte <= 0xFFFFFFFFu - operand.memory.resolvedRVA;
                            ++byte) {
                        if (decodedInstructionBytes.count(
                                operand.memory.resolvedRVA + byte) != 0u) {
                            reason = "image-relative operand points into native bytes that CFG destroys";
                            return false;
                        }
                    }
                }
                if (operand.type == OperandType::Immediate && operand.immediateRelative &&
                    !instruction.IsBranch() && !instruction.IsCall()) {
                    reason = "non-control relative immediate is not relocatable";
                    return false;
                }
            }
            if (ripOperands != 0u && (ripOperands != 1u ||
                    instruction.displacementSize != 4u ||
                    instruction.displacementOffset == 0u ||
                    instruction.displacementOffset +
                        instruction.displacementSize > instruction.length)) {
                reason = "RIP-relative operand has no unique disp32 field";
                return false;
            }
            for (const CS_RELOC_ENTRY& relocation : image->relocs.entries) {
                if (relocation.fullRVA < instruction.rva ||
                    relocation.fullRVA >=
                        static_cast<uint64_t>(instruction.rva) +
                            instruction.length) continue;
                if (relocation.type != expectedRelocationType ||
                    relocation.fullRVA + relocationWidth >
                        static_cast<uint64_t>(instruction.rva) +
                            instruction.length) {
                    reason = "base relocation inside CFG instruction has an unsupported field";
                    return false;
                }
                const uint32_t relocationRVA =
                    static_cast<uint32_t>(relocation.fullRVA);
                const uint32_t offset = PEUtils::RvaToOffset(image, relocationRVA);
                if (offset == 0u || offset > image->rawSize ||
                    relocationWidth > image->rawSize - offset) {
                    reason = "base relocation inside CFG instruction is not file-backed";
                    return false;
                }
                uint64_t absolute = 0u;
                std::memcpy(&absolute, image->rawData + offset,
                    relocationWidth);
                if (absolute >= imageBase &&
                    absolute - imageBase <= 0xFFFFFFFFULL &&
                    decodedInstructionBytes.count(static_cast<uint32_t>(
                        absolute - imageBase)) != 0u) {
                    reason = "relocated absolute pointer targets native bytes that CFG destroys";
                    return false;
                }
            }
        }
        if (terminal.IsConditionalBranch()) {
            if (!terminal.hasBranchTarget || block.successors.size() != 2u ||
                blockStarts.count(terminal.branchTargetRVA) == 0u) {
                reason = "conditional edge is not a closed two-way basic-block edge";
                return false;
            }
        } else if (terminal.IsBranch()) {
            if (!terminal.hasBranchTarget || block.successors.size() != 1u ||
                blockStarts.count(terminal.branchTargetRVA) == 0u) {
                reason = "unconditional edge leaves the trusted function CFG";
                return false;
            }
        } else if (!terminal.IsReturn() && block.successors.size() != 1u) {
            reason = "non-return block has no unique fallthrough successor";
            return false;
        }
        for (uint64_t successor : block.successors) {
            if (successor > 0xFFFFFFFFULL ||
                blockStarts.count(static_cast<uint32_t>(successor)) == 0u) {
                reason = "basic-block successor leaves the trusted function CFG";
                return false;
            }
        }
    }
    return true;
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
            if (!PEUtils::IsValidRuntimeFunction(image, entry)) {
                reason = "x64 runtime-function or unwind metadata is malformed";
                return false;
            }
            uint8_t version = 0;
            uint8_t flags = 0;
            if (!PEUtils::ReadUnwindInfoVersion(image, entry.unwindData, version, flags)) {
                reason = "x64 unwind header is outside the PE image";
                return false;
            }
            // Parser 可完整解析 V1/V2；VM runtime 与重建器当前仅证明了 V1 语义。
            // 因而 V2 必须在函数级 fail-closed，不能把“可解析”误当成“可 VM 化”。
            if (version > PEUtils::kVmUnwindInfoMaxVersion) {
                reason = "x64 unwind version 2 epilog semantics are not supported by the VM runtime";
                return false;
            }
            if (flags != 0) {
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
