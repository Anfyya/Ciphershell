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
    // Direct calls from trusted .pdata functions are also credible leaf roots.
    for (const auto& function : result.functions) {
        for (const InstructionIR* instruction : Instructions(function)) {
            if (!instruction->IsCall() || !instruction->hasBranchTarget ||
                !ExecutableSectionForRva(image, instruction->branchTargetRVA)) continue;
            const uint32_t target = instruction->branchTargetRVA;
            if (rootSources.emplace(target, "direct_call").second) knownBoundaries.insert(target);
            if (queued.insert(target).second) pending.push_back(target);
        }
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
        // For a boundary inferred without unwind/symbol metadata, every byte in
        // the destroyed native range must belong to a decoded instruction.  A
        // gap can be an inline table or adjacent data and is therefore rejected.
        if (function.decodedBytes != function.size) {
            result.issues.push_back({root,
                "inferred function range contains undecoded gaps and is not safe to destroy"});
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

        function.boundaryTrusted = true;
        const auto source = rootSources.find(root);
        function.discoverySource = source != rootSources.end() ? source->second : "direct_call";
        decodedStarts.insert(root);

        for (const InstructionIR* instruction : Instructions(function)) {
            if (!instruction->IsCall() || !instruction->hasBranchTarget ||
                !ExecutableSectionForRva(image, instruction->branchTargetRVA)) continue;
            const uint32_t target = instruction->branchTargetRVA;
            if (rootSources.emplace(target, "direct_call").second) knownBoundaries.insert(target);
            if (queued.insert(target).second) pending.push_back(target);
        }
        result.functions.push_back(std::move(function));
    }

    if (result.functions.empty()) {
        result.error = "no trusted function boundaries were discovered";
        return result;
    }
    if (!ValidateFunctionOwnership(result)) return result;

    // x86 SEH detection: mark functions that use frame-based SEH
    // (push fs:[0] / mov fs:[0], esp pattern or SafeSEH table match)
    if (!image->is64Bit) {
        std::unordered_set<uint32_t> safeSehHandlers;
        if (image->loadConfig.valid) {
            // SEHandlerTable is stored in Load Config for x86 SafeSEH
            // guardCFFunctionTable doubles as SEH handler table when CFG is absent
            // Parse from Load Config SEHandlerTable field if available
            const DWORD loadConfigOffset = PEUtils::RvaToOffset(image, image->loadConfig.directoryRVA);
            if (loadConfigOffset != 0 && loadConfigOffset + 72 <= image->rawSize) {
                uint32_t sehTableVA = 0, sehCount = 0;
                std::memcpy(&sehTableVA, image->rawData + loadConfigOffset + 64, 4);
                std::memcpy(&sehCount, image->rawData + loadConfigOffset + 68, 4);
                const uint32_t lcImageBase = static_cast<uint32_t>(
                    image->ntHeaders32->OptionalHeader.ImageBase);
                if (sehTableVA >= lcImageBase && sehCount > 0 && sehCount < 0x10000) {
                    uint32_t sehTableRVA = sehTableVA - lcImageBase;
                    DWORD sehOffset = PEUtils::RvaToOffset(image, sehTableRVA);
                    if (sehOffset != 0 && sehOffset + sehCount * 4 <= image->rawSize) {
                        for (uint32_t i = 0; i < sehCount; i++) {
                            uint32_t handlerRVA = 0;
                            std::memcpy(&handlerRVA, image->rawData + sehOffset + i * 4, 4);
                            safeSehHandlers.insert(handlerRVA);
                        }
                    }
                }
            }
        }

        for (auto& function : result.functions) {
            if (safeSehHandlers.count(static_cast<uint32_t>(function.entryAddress))) {
                function.usesSEH = true;
                continue;
            }
            // Detect frame-based SEH: look for fs:[0] segment access
            for (const auto& block : function.blocks) {
                for (const auto& instr : block.instructions) {
                    for (const auto& operand : instr.operands) {
                        if (operand.type == OperandType::Memory &&
                            operand.memory.segment == RegisterId::FS) {
                            function.usesSEH = true;
                            break;
                        }
                    }
                    if (function.usesSEH) break;
                }
                if (function.usesSEH) break;
            }
        }
    }

    AssignFunctionNames(image, result.functions);
    std::sort(result.functions.begin(), result.functions.end(), [](const auto& left, const auto& right) {
        return left.entryAddress < right.entryAddress;
    });
    result.success = true;
    return result;
}

} // namespace CipherShell
