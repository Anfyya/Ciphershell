#include "function_discovery.h"

#include "../pe_parser/pe_utils.h"
#include <algorithm>
#include <cstring>
#include <deque>
#include <limits>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <iomanip>
#include <sstream>

namespace CipherShell {
namespace {

const IMAGE_SECTION_HEADER* ExecutableSectionForRva(const CS_PE_IMAGE* image, uint32_t rva) {
    if (!image || !image->sections) return nullptr;
    for (WORD i = 0; i < image->numSections; ++i) {
        const auto& section = image->sections[i];
        const uint32_t span = PEUtils::SectionMappedSpan(section);
        if ((section.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 &&
            rva >= section.VirtualAddress && rva - section.VirtualAddress < span) {
            return &section;
        }
    }
    return nullptr;
}

bool IsFileBackedExecutableRva(const CS_PE_IMAGE* image, uint32_t rva) {
    const IMAGE_SECTION_HEADER* section = ExecutableSectionForRva(image, rva);
    if (!image || !section || rva < section->VirtualAddress) return false;
    const uint32_t sectionOffset = rva - section->VirtualAddress;
    if (sectionOffset >= section->SizeOfRawData) return false;
    const uint64_t rawOffset = static_cast<uint64_t>(section->PointerToRawData) +
        sectionOffset;
    return rawOffset < image->rawSize;
}

void AnnotateImageRelocations(
    const CS_PE_IMAGE* image,
    std::vector<Function>& functions)
{
    if (!image || !image->rawData) return;
    const uint64_t imageBase = image->is64Bit
        ? image->ntHeaders64->OptionalHeader.ImageBase
        : image->ntHeaders32->OptionalHeader.ImageBase;
    const uint32_t imageSize = image->is64Bit
        ? image->ntHeaders64->OptionalHeader.SizeOfImage
        : image->ntHeaders32->OptionalHeader.SizeOfImage;
    const uint16_t expectedType = image->is64Bit
        ? IMAGE_REL_BASED_DIR64 : IMAGE_REL_BASED_HIGHLOW;
    const uint8_t expectedWidth = image->is64Bit ? 8u : 4u;

    std::unordered_map<uint32_t, const CS_RELOC_ENTRY*> relocations;
    std::unordered_set<uint32_t> duplicateRelocations;
    relocations.reserve(image->relocs.entries.size());
    for (const CS_RELOC_ENTRY& relocation : image->relocs.entries) {
        if (relocation.fullRVA <= (std::numeric_limits<uint32_t>::max)()) {
            const uint32_t rva = static_cast<uint32_t>(relocation.fullRVA);
            if (!relocations.emplace(rva, &relocation).second) {
                duplicateRelocations.insert(rva);
            }
        }
    }

    for (Function& function : functions) {
        for (BasicBlock& block : function.blocks) {
            for (InstructionIR& instruction : block.instructions) {
                for (uint32_t byte = 0; byte < instruction.length; ++byte) {
                    const auto found = relocations.find(instruction.rva + byte);
                    if (found == relocations.end()) continue;
                    if (instruction.hasImageRelocation) {
                        instruction.imageRelocationSupported = false;
                        continue;
                    }
                    instruction.hasImageRelocation = true;
                    instruction.imageRelocationOffset = static_cast<uint8_t>(byte);
                    instruction.imageRelocationSize = expectedWidth;
                    const CS_RELOC_ENTRY& relocation = *found->second;
                    if (duplicateRelocations.count(instruction.rva + byte) != 0u ||
                        relocation.type != expectedType ||
                        byte + expectedWidth > instruction.length) {
                        continue;
                    }
                    const uint32_t fileOffset = PEUtils::RvaToOffset(
                        image, static_cast<uint32_t>(relocation.fullRVA));
                    if (fileOffset == 0u || fileOffset > image->rawSize ||
                        expectedWidth > image->rawSize - fileOffset) {
                        continue;
                    }
                    uint64_t absolute = 0;
                    std::memcpy(&absolute, image->rawData + fileOffset, expectedWidth);
                    if (absolute < imageBase || absolute - imageBase >= imageSize) {
                        continue;
                    }
                    const uint32_t targetRVA = static_cast<uint32_t>(absolute - imageBase);
                    bool fieldSupported = false;
                    if (instruction.immediateOffset == byte &&
                        instruction.immediateSize == expectedWidth) {
                        for (OperandIR& operand : instruction.operands) {
                            if (operand.type != OperandType::Immediate ||
                                operand.immediateRelative) continue;
                            operand.immediateIsImageAddress = true;
                            operand.immediateResolvedRVA = targetRVA;
                            fieldSupported = true;
                            break;
                        }
                    } else if (instruction.displacementOffset == byte &&
                               instruction.displacementSize == expectedWidth) {
                        for (OperandIR& operand : instruction.operands) {
                            if (operand.type == OperandType::Memory &&
                                !operand.memory.hasBase &&
                                !operand.memory.hasIndex &&
                                operand.memory.hasDisplacement) {
                                const uint64_t memoryWidth = (std::max)(1u,
                                    static_cast<uint32_t>(
                                        (operand.memory.width + 7u) / 8u));
                                if (targetRVA > imageSize ||
                                    memoryWidth > imageSize - targetRVA) {
                                    break;
                                }
                                operand.memory.isImageAddress = true;
                                operand.memory.resolvedVA = absolute;
                                operand.memory.resolvedRVA = targetRVA;
                                fieldSupported = true;
                                break;
                            }
                        }
                    }
                    instruction.imageRelocationTargetRVA = targetRVA;
                    instruction.imageRelocationSupported = fieldSupported;
                }
            }
        }
    }
}

bool RawRangeForFunction(
    CS_PE_IMAGE* image,
    uint32_t beginRVA,
    uint32_t requestedSize,
    const uint8_t*& code,
    uint32_t& available,
    std::string& error)
{
    const IMAGE_SECTION_HEADER* section = ExecutableSectionForRva(image, beginRVA);
    if (!section || beginRVA < section->VirtualAddress) {
        error = "function RVA is not in an executable section";
        return false;
    }
    const uint32_t sectionOffset = beginRVA - section->VirtualAddress;
    if (sectionOffset >= section->SizeOfRawData) {
        error = "function RVA has no file-backed executable bytes";
        return false;
    }
    available = section->SizeOfRawData - sectionOffset;
    if (requestedSize != 0) {
        if (requestedSize > available) {
            error = "trusted function range exceeds its executable section";
            return false;
        }
        available = requestedSize;
    }
    const uint32_t rawOffset = section->PointerToRawData + sectionOffset;
    if (rawOffset >= image->rawSize || available > image->rawSize - rawOffset) {
        error = "function raw range exceeds the PE file";
        return false;
    }
    code = image->rawData + rawOffset;
    return true;
}

void AddTlsRoots(const CS_PE_IMAGE* image, std::set<uint32_t>& roots) {
    if (!image || !image->tls.valid || image->tls.callbacksAddress == 0 ||
        image->tls.callbackCount == 0) return;
    const uint64_t imageBase = image->is64Bit
        ? image->ntHeaders64->OptionalHeader.ImageBase
        : image->ntHeaders32->OptionalHeader.ImageBase;
    if (image->tls.callbacksAddress < imageBase) return;
    const uint64_t callbackTableRVA64 = image->tls.callbacksAddress - imageBase;
    if (callbackTableRVA64 > std::numeric_limits<uint32_t>::max()) return;
    const uint32_t tableOffset = PEUtils::RvaToOffset(
        image, static_cast<uint32_t>(callbackTableRVA64));
    const uint32_t pointerSize = image->is64Bit ? 8u : 4u;
    if (tableOffset == 0 || image->tls.callbackCount >
            (image->rawSize - tableOffset) / pointerSize) return;
    for (uint32_t i = 0; i < image->tls.callbackCount; ++i) {
        uint64_t callbackVA = 0;
        std::memcpy(&callbackVA, image->rawData + tableOffset + i * pointerSize, pointerSize);
        if (callbackVA >= imageBase && callbackVA - imageBase <=
                std::numeric_limits<uint32_t>::max()) {
            roots.insert(static_cast<uint32_t>(callbackVA - imageBase));
        }
    }
}

std::vector<const InstructionIR*> Instructions(const Function& function) {
    std::vector<const InstructionIR*> result;
    for (const auto& block : function.blocks) {
        for (const auto& instruction : block.instructions) result.push_back(&instruction);
    }
    return result;
}

bool ValidateFunctionOwnership(FunctionDiscoveryResult& result) {
    std::unordered_map<uint32_t, size_t> byteOwner;
    std::unordered_map<uint32_t, size_t> instructionOwner;
    for (size_t index = 0; index < result.functions.size(); ++index) {
        for (const InstructionIR* instruction : Instructions(result.functions[index])) {
            instructionOwner.emplace(instruction->rva, index);
            for (uint32_t byte = 0; byte < instruction->length; ++byte) {
                auto inserted = byteOwner.emplace(instruction->rva + byte, index);
                if (!inserted.second && inserted.first->second != index) {
                    result.error = "trusted functions contain overlapping decoded instructions";
                    return false;
                }
            }
        }
    }

    for (size_t sourceIndex = 0; sourceIndex < result.functions.size(); ++sourceIndex) {
        for (const InstructionIR* instruction : Instructions(result.functions[sourceIndex])) {
            if (!instruction->hasBranchTarget) continue;
            auto target = instructionOwner.find(instruction->branchTargetRVA);
            if (target == instructionOwner.end() || target->second == sourceIndex) continue;
            Function& targetFunction = result.functions[target->second];
            if (instruction->IsCall() &&
                instruction->branchTargetRVA == targetFunction.entryAddress) continue;
            targetFunction.hasExternalInteriorReference = true;
        }
    }
    return true;
}

// 仅识别明确访问 FS:[0]（TIB.ExceptionList 异常链头）的内存操作。
// 不因任意 FS 段访问误判为 SEH：fs:[非零偏移] 是 TEB/TLS/PEB 访问，
// fs:[base] 是 TEB 相对寻址，二者都不是异常链安装/卸载。
bool FunctionAccessesExceptionChain(const Function& function) {
    for (const auto& block : function.blocks) {
        for (const auto& instr : block.instructions) {
            for (const auto& op : instr.operands) {
                if (op.type != OperandType::Memory) continue;
                if (op.memory.segment != RegisterId::FS) continue;
                if (op.memory.hasBase || op.memory.hasIndex) continue;
                if (op.memory.displacement != 0) continue;
                return true;  // fs:[0] = TIB.ExceptionList
            }
        }
    }
    return false;
}

void AssignFunctionNames(const CS_PE_IMAGE* image, std::vector<Function>& functions) {
    std::unordered_map<uint32_t, std::string> exports;
    for (const auto& exported : image->exports.functions) {
        if (exported.isForwarded || exported.functionRVA == 0) continue;
        if (!exported.name.empty()) exports.emplace(exported.functionRVA, exported.name);
        else exports.emplace(exported.functionRVA, "ordinal_" + std::to_string(exported.ordinal));
    }
    for (auto& function : functions) {
        const uint32_t rva = static_cast<uint32_t>(function.entryAddress);
        const auto named = exports.find(rva);
        if (named != exports.end()) {
            function.name = named->second;
            continue;
        }
        std::ostringstream synthetic;
        synthetic << "sub_" << std::hex << std::setw(8) << std::setfill('0') << rva;
        function.name = synthetic.str();
    }
}

} // namespace

FunctionDiscoveryResult FunctionDiscovery::Discover(
    CS_PE_IMAGE* image,
    Disassembler& disassembler,
    const std::vector<uint32_t>& explicitRoots) const
{
    FunctionDiscoveryResult result{};
    if (!image || !image->isValid || !image->rawData) {
        result.error = "invalid PE image";
        return result;
    }

    const uint64_t imageBase = image->is64Bit
        ? image->ntHeaders64->OptionalHeader.ImageBase
        : image->ntHeaders32->OptionalHeader.ImageBase;
    if (!disassembler.Initialize(image->is64Bit != 0, imageBase)) {
        result.error = "unable to initialize Zydis function decoder";
        return result;
    }

    std::map<uint32_t, std::string> rootSources;
    auto addRoot = [&](uint32_t rva, const char* source) {
        if (rva == 0 || !ExecutableSectionForRva(image, rva)) return;
        auto inserted = rootSources.emplace(rva, source);
        if (!inserted.second && std::string(source) == "explicit_rva") {
            inserted.first->second = source;
        }
    };

    addRoot(image->is64Bit
        ? image->ntHeaders64->OptionalHeader.AddressOfEntryPoint
        : image->ntHeaders32->OptionalHeader.AddressOfEntryPoint, "oep");
    for (const auto& exported : image->exports.functions) {
        if (!exported.isForwarded && exported.functionRVA != 0) {
            addRoot(exported.functionRVA, "export");
        }
    }
    std::set<uint32_t> tlsRoots;
    AddTlsRoots(image, tlsRoots);
    for (uint32_t root : tlsRoots) addRoot(root, "tls");
    for (uint32_t root : explicitRoots) {
        if (root == 0 || !ExecutableSectionForRva(image, root)) {
            result.issues.push_back({root,
                "explicit target RVA is not a non-zero executable-section address"});
            continue;
        }
        addRoot(root, "explicit_rva");
    }

    std::set<uint32_t> knownBoundaries;
    for (const auto& root : rootSources) knownBoundaries.insert(root.first);

    if (image->is64Bit) {
        std::vector<CS_RUNTIME_FUNCTION> entries = image->exceptions.entries;
        std::sort(entries.begin(), entries.end(), [](const auto& left, const auto& right) {
            return left.beginAddress < right.beginAddress;
        });
        for (const auto& entry : entries) {
            if (entry.beginAddress >= entry.endAddress) {
                result.error = "x64 runtime-function table contains an invalid range";
                return result;
            }
            knownBoundaries.insert(entry.beginAddress);
            knownBoundaries.insert(entry.endAddress);
            const uint8_t* code = nullptr;
            uint32_t available = 0;
            std::string rangeError;
            const uint32_t size = entry.endAddress - entry.beginAddress;
            if (!RawRangeForFunction(image, entry.beginAddress, size, code, available, rangeError)) {
                result.error = rangeError;
                return result;
            }
            Function function{};
            if (!disassembler.AnalyzeFunctionRange(code, available, entry.beginAddress,
                    size, true, function)) {
                result.issues.push_back({entry.beginAddress, disassembler.GetLastError()});
                continue;
            }
            // Mirrors the same rule applied to the recursive/heuristic path below:
            // a .pdata-declared range can still contain bytes the worklist walk
            // never reached (an inline jump table, padding, or a second entry
            // point). Any such gap must reject the candidate rather than let a
            // downstream patcher destroy unverified bytes as if they were code.
            if (function.decodedBytes != function.size) {
                result.issues.push_back({entry.beginAddress,
                    "pdata-bounded function range contains undecoded gaps and is not safe to destroy"});
                continue;
            }
            function.boundaryTrusted = true;
            function.discoverySource = "pdata";
            result.functions.push_back(std::move(function));
        }
    }

    auto containingFunction = [&](uint32_t rva) -> const Function* {
        for (const auto& function : result.functions) {
            const uint64_t begin = function.entryAddress;
            const uint64_t end = begin + function.size;
            if (rva >= begin && static_cast<uint64_t>(rva) < end) return &function;
        }
        return nullptr;
    };

    std::deque<uint32_t> pending;
    std::unordered_set<uint32_t> queued;
    for (const auto& root : rootSources) {
        pending.push_back(root.first);
        queued.insert(root.first);
    }

    // A successfully recursive-decoded candidate can still be unsafe to destroy:
    // x86 CRT startup functions, for example, contain separately entered SEH
    // funclets that leave gaps in the entry-rooted CFG.  Direct control transfers
    // decoded outside that candidate's own envelope remain credible independent
    // roots, but the gapped candidate itself must stay rejected below.
    auto queueExternalDirectTargets = [&](const Function& function) {
        const uint64_t begin = function.entryAddress;
        const uint64_t end = begin + function.size;
        for (const InstructionIR* instruction : Instructions(function)) {
            if (!instruction->hasBranchTarget || instruction->isIndirectBranch) continue;
            const uint32_t target = instruction->branchTargetRVA;
            if (target >= begin && static_cast<uint64_t>(target) < end) continue;
            const bool isDirectCall = instruction->IsCall();
            const bool isDirectTail = instruction->IsBranch() &&
                !instruction->IsConditionalBranch();
            if ((!isDirectCall && !isDirectTail) ||
                !IsFileBackedExecutableRva(image, target)) continue;
            const char* source = isDirectCall ? "direct_call" : "direct_tail";
            if (rootSources.emplace(target, source).second) knownBoundaries.insert(target);
            if (queued.insert(target).second) pending.push_back(target);
        }
    };

    // Direct calls and direct tail transfers from trusted .pdata functions are
    // also credible independent roots.
    for (const auto& function : result.functions) {
        queueExternalDirectTargets(function);
    }

    std::unordered_set<uint32_t> decodedStarts;
    for (const auto& function : result.functions) {
        decodedStarts.insert(static_cast<uint32_t>(function.entryAddress));
    }

    while (!pending.empty()) {
        const uint32_t root = pending.front();
        pending.pop_front();
        if (decodedStarts.count(root) != 0) continue;

        if (const Function* owner = containingFunction(root)) {
            if (owner->entryAddress != root) {
                result.issues.push_back({root,
                    "candidate root points into an existing trusted function interior"});
            }
            continue;
        }

        const IMAGE_SECTION_HEADER* section = ExecutableSectionForRva(image, root);
        if (!section) {
            result.issues.push_back({root, "function RVA is not in an executable section"});
            continue;
        }
        const uint64_t sectionEnd64 = static_cast<uint64_t>(section->VirtualAddress) +
            section->SizeOfRawData;
        if (sectionEnd64 > std::numeric_limits<uint32_t>::max() || root >= sectionEnd64) {
            result.issues.push_back({root, "function RVA has no file-backed executable bytes"});
            continue;
        }
        uint32_t candidateLimit = static_cast<uint32_t>(sectionEnd64 - root);
        const auto nextBoundary = knownBoundaries.upper_bound(root);
        if (nextBoundary != knownBoundaries.end() && *nextBoundary < sectionEnd64) {
            candidateLimit = (std::min)(candidateLimit, *nextBoundary - root);
        }
        if (candidateLimit < 1) {
            result.issues.push_back({root, "function candidate has an empty bounded range"});
            continue;
        }

        const uint8_t* code = nullptr;
        uint32_t available = 0;
        std::string rangeError;
        if (!RawRangeForFunction(image, root, candidateLimit, code, available, rangeError)) {
            result.issues.push_back({root, rangeError});
            continue;
        }
        Function function{};
        if (!disassembler.AnalyzeFunctionRange(code, available, root, 0,
                image->is64Bit != 0, function)) {
            result.issues.push_back({root, disassembler.GetLastError()});
            continue;
        }
        if (function.size == 0 || function.blocks.empty() || function.decodedBytes == 0) {
            result.issues.push_back({root, "recursive decoder produced an empty function"});
            continue;
        }

        const uint64_t candidateEnd = static_cast<uint64_t>(root) + function.size;
        bool overlaps = false;
        for (const auto& existing : result.functions) {
            const uint64_t existingBegin = existing.entryAddress;
            const uint64_t existingEnd = existingBegin + existing.size;
            if (candidateEnd <= existingBegin || root >= existingEnd) continue;
            overlaps = true;
            break;
        }
        if (overlaps) {
            result.issues.push_back({root, "recursive function boundary overlaps a trusted function"});
            continue;
        }

        // Harvest only external direct roots from the successfully decoded CFG
        // before applying the stricter destroy-safe gap rule.  This lets x86 CRT
        // startup lead discovery to user main without ever accepting the CRT
        // function (and its inline/SEH gaps) as patchable native code.
        queueExternalDirectTargets(function);

        // For a boundary inferred without unwind/symbol metadata, every byte in
        // the destroyed native range must belong to a decoded instruction.  A
        // gap can be an inline table or adjacent data and is therefore rejected.
        if (function.decodedBytes != function.size) {
            result.issues.push_back({root,
                "inferred function range contains undecoded gaps and is not safe to destroy"});
            continue;
        }

        function.boundaryTrusted = true;
        const auto source = rootSources.find(root);
        function.discoverySource = source != rootSources.end() ? source->second : "direct_call";
        decodedStarts.insert(root);

        result.functions.push_back(std::move(function));
    }

    if (result.functions.empty()) {
        result.error = "no trusted function boundaries were discovered";
        return result;
    }
    if (!ValidateFunctionOwnership(result)) return result;
    AssignFunctionNames(image, result.functions);
    AnnotateImageRelocations(image, result.functions);

    // 函数级 SEH 判定：
    // - SafeSEH handler 表中的入口 RVA 对应函数标记 usesSEH（handler 与函数入口
    //   双方均为 RVA 坐标系，不混用 VA/file offset）。
    // - 显式访问 FS:[0] 异常链的函数标记 usesSEH；普通 FS:[非零偏移] 的 TEB/TLS
    //   访问不被误判。
    // 是否允许 VM 化由 CapabilityChecker 在函数级决定（usesSEH 的目标函数拒绝），
    // 不因未设置 IMAGE_DLLCHARACTERISTICS_NO_SEH 全局拒绝整份 x86 映像。
    std::unordered_set<uint32_t> safeSEHHandlers(image->loadConfig.safeSEHHandlerRVAs.begin(),
        image->loadConfig.safeSEHHandlerRVAs.end());
    for (auto& function : result.functions) {
        if (function.entryAddress <= 0xFFFFFFFFull &&
            safeSEHHandlers.count(static_cast<uint32_t>(function.entryAddress)) != 0) {
            function.usesSEH = true;
            continue;
        }
        if (FunctionAccessesExceptionChain(function)) {
            function.usesSEH = true;
        }
    }

    std::sort(result.functions.begin(), result.functions.end(), [](const auto& left, const auto& right) {
        return left.entryAddress < right.entryAddress;
    });
    result.success = true;
    return result;
}

} // namespace CipherShell
