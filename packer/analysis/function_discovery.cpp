#include "function_discovery.h"

#include "../pe_parser/pe_utils.h"
#include <algorithm>
#include <cstring>
#include <deque>
#include <limits>
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
    Disassembler& disassembler) const
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
            result.functions.push_back(std::move(function));
        }
    } else {
        std::set<uint32_t> roots;
        roots.insert(image->ntHeaders32->OptionalHeader.AddressOfEntryPoint);
        for (const auto& exported : image->exports.functions) {
            if (!exported.isForwarded && exported.functionRVA != 0) roots.insert(exported.functionRVA);
        }
        AddTlsRoots(image, roots);

        std::deque<uint32_t> pending(roots.begin(), roots.end());
        std::unordered_set<uint32_t> queued(roots.begin(), roots.end());
        std::unordered_set<uint32_t> decodedStarts;
        while (!pending.empty()) {
            const uint32_t root = pending.front();
            pending.pop_front();
            if (decodedStarts.count(root) != 0) continue;
            const uint8_t* code = nullptr;
            uint32_t available = 0;
            std::string rangeError;
            if (!RawRangeForFunction(image, root, 0, code, available, rangeError)) {
                result.issues.push_back({root, rangeError});
                continue;
            }
            Function function{};
            if (!disassembler.AnalyzeFunctionRange(code, available, root, 0, false, function)) {
                result.error = disassembler.GetLastError();
                return result;
            }
            function.boundaryTrusted = true;
            decodedStarts.insert(root);
            for (const InstructionIR* instruction : Instructions(function)) {
                if (!instruction->IsCall() || !instruction->hasBranchTarget ||
                    !ExecutableSectionForRva(image, instruction->branchTargetRVA)) continue;
                if (queued.insert(instruction->branchTargetRVA).second) {
                    pending.push_back(instruction->branchTargetRVA);
                }
            }
            result.functions.push_back(std::move(function));
        }
    }

    if (result.functions.empty()) {
        result.error = "no trusted function boundaries were discovered";
        return result;
    }
    if (!ValidateFunctionOwnership(result)) return result;
    AssignFunctionNames(image, result.functions);
    std::sort(result.functions.begin(), result.functions.end(), [](const auto& left, const auto& right) {
        return left.entryAddress < right.entryAddress;
    });
    result.success = true;
    return result;
}

} // namespace CipherShell
