#include "../packer/analysis/capability_checker.h"
#include "../packer/analysis/disassembler.h"
#include "../packer/analysis/function_discovery.h"
#include "../packer/pe_parser/pe_parser.h"
#include "../packer/pe_parser/pe_utils.h"

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

void Require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

bool ExportNameMatches(const std::string& actual, const char* expected) {
    if (actual == expected) return true;
    const std::string decorated = std::string("_") + expected;
    return actual == decorated ||
        (actual.size() > decorated.size() &&
         actual.compare(0, decorated.size(), decorated) == 0 &&
         actual[decorated.size()] == '@');
}

uint32_t ExportRva(const CipherShell::CS_PE_IMAGE* image, const char* name) {
    for (const auto& exported : image->exports.functions) {
        if (!exported.isForwarded && exported.functionRVA != 0 &&
            ExportNameMatches(exported.name, name)) {
            return exported.functionRVA;
        }
    }
    return 0;
}

uint32_t EntryRva(const CipherShell::CS_PE_IMAGE* image) {
    return image->is64Bit
        ? image->ntHeaders64->OptionalHeader.AddressOfEntryPoint
        : image->ntHeaders32->OptionalHeader.AddressOfEntryPoint;
}

uint64_t ImageBase(const CipherShell::CS_PE_IMAGE* image) {
    return image->is64Bit
        ? image->ntHeaders64->OptionalHeader.ImageBase
        : image->ntHeaders32->OptionalHeader.ImageBase;
}

bool RawCodeRange(
    const CipherShell::CS_PE_IMAGE* image,
    uint32_t rva,
    const uint8_t*& code,
    uint32_t& available)
{
    code = nullptr;
    available = 0;
    if (!image || !image->sections || !image->rawData) return false;
    for (WORD index = 0; index < image->numSections; ++index) {
        const IMAGE_SECTION_HEADER& section = image->sections[index];
        if ((section.Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0 ||
            rva < section.VirtualAddress) {
            continue;
        }
        const uint32_t sectionOffset = rva - section.VirtualAddress;
        if (sectionOffset >= section.SizeOfRawData) continue;
        const uint32_t rawOffset = CipherShell::PEUtils::RvaToOffset(image, rva);
        if (rawOffset == 0 || rawOffset >= image->rawSize) return false;
        available = (std::min)(section.SizeOfRawData - sectionOffset,
            image->rawSize - rawOffset);
        code = image->rawData + rawOffset;
        return available != 0;
    }
    return false;
}

const CipherShell::Function* FindFunction(
    const CipherShell::FunctionDiscoveryResult& result,
    uint32_t rva)
{
    const auto found = std::find_if(result.functions.begin(), result.functions.end(),
        [=](const CipherShell::Function& function) {
            return function.entryAddress == rva;
        });
    return found == result.functions.end() ? nullptr : &*found;
}

bool HasIssue(
    const CipherShell::FunctionDiscoveryResult& result,
    uint32_t rva,
    const char* fragment)
{
    return std::any_of(result.issues.begin(), result.issues.end(),
        [=](const CipherShell::FunctionDiscoveryIssue& issue) {
            return issue.rva == rva &&
                issue.reason.find(fragment) != std::string::npos;
        });
}

CipherShell::Function AnalyzeUnboundedRva(
    const CipherShell::CS_PE_IMAGE* image,
    CipherShell::Disassembler& disassembler,
    uint32_t rva)
{
    const uint8_t* code = nullptr;
    uint32_t available = 0;
    Require(RawCodeRange(image, rva, code, available),
        "RVA has no real file-backed executable range");
    CipherShell::Function function{};
    Require(disassembler.AnalyzeFunctionRange(
            code, available, rva, 0u, false, function),
        "recursive decoding of real MSVC RVA failed: " +
            disassembler.GetLastError());
    return function;
}

void VerifyInterruptBoundary(
    const CipherShell::CS_PE_IMAGE* image,
    CipherShell::Disassembler& disassembler)
{
    const uint32_t interruptRva = ExportRva(image, "cs_int3_boundary");
    Require(interruptRva != 0,
        "real MSVC fixture is missing cs_int3_boundary export");
    const CipherShell::Function interrupt =
        AnalyzeUnboundedRva(image, disassembler, interruptRva);
    Require(!interrupt.blocks.empty(),
        "INT3 export produced no basic block");
    const auto& terminal = interrupt.blocks.back();
    Require(!terminal.instructions.empty() &&
            terminal.instructions.back().IsInterrupt() &&
            terminal.successors.empty(),
        "compiler-emitted INT3 did not terminate recursive descent");
}

void VerifyX86CrtAndGapRoots(
    CipherShell::CS_PE_IMAGE* image,
    CipherShell::Disassembler& disassembler,
    const CipherShell::FunctionDiscoveryResult& result)
{
    Require(!image->is64Bit, "PE32 regression received a PE32+ fixture");
    const uint32_t oepRva = EntryRva(image);
    const CipherShell::Function oepCandidate =
        AnalyzeUnboundedRva(image, disassembler, oepRva);
    const CipherShell::Function* oep = FindFunction(result, oepRva);
    Require((oep && oep->discoverySource == "oep" && oep->boundaryTrusted) ||
            HasIssue(result, oepRva, "undecoded gaps"),
        "real MSVC x86 CRT OEP was neither retained as a trusted root nor "
        "rejected by the exact destroy-safety gap rule");

    uint32_t crtTailRva = 0;
    const uint64_t oepEnd =
        oepCandidate.entryAddress + oepCandidate.size;
    for (const auto& block : oepCandidate.blocks) {
        for (const auto& instruction : block.instructions) {
            if (instruction.IsBranch() && !instruction.IsConditionalBranch() &&
                !instruction.isIndirectBranch && instruction.hasBranchTarget &&
                (instruction.branchTargetRVA < oepCandidate.entryAddress ||
                 instruction.branchTargetRVA >= oepEnd)) {
                crtTailRva = instruction.branchTargetRVA;
            }
        }
    }
    Require(crtTailRva != 0,
        "real MSVC x86 OEP contains no external direct CRT tail");
    const CipherShell::Function* crtTail = FindFunction(result, crtTailRva);
    Require((crtTail && crtTail->discoverySource == "direct_tail") ||
            HasIssue(result, crtTailRva, "undecoded gaps"),
        "x86 OEP CRT tail was neither accepted as an independent root nor "
        "rejected with the required gap diagnostic");

    if (oep) {
        CipherShell::CapabilityChecker checker;
        std::string reason;
        Require(!checker.IsFunctionCfgSafe(image, *oep, reason) &&
                reason.find("unconditional edge leaves") != std::string::npos,
            "external CRT tail was incorrectly accepted as intra-function CFG");
    }

    const uint32_t gapRva = ExportRva(image, "cs_gap_root");
    Require(gapRva != 0,
        "real MSVC fixture is missing cs_gap_root export");
    const CipherShell::Function gapCandidate =
        AnalyzeUnboundedRva(image, disassembler, gapRva);
    uint32_t derivedLeafRva = 0;
    const uint64_t gapEnd = gapCandidate.entryAddress + gapCandidate.size;
    for (const auto& block : gapCandidate.blocks) {
        for (const auto& instruction : block.instructions) {
            if (instruction.IsCall() && !instruction.isIndirectBranch &&
                instruction.hasBranchTarget &&
                (instruction.branchTargetRVA < gapCandidate.entryAddress ||
                 instruction.branchTargetRVA >= gapEnd)) {
                derivedLeafRva = instruction.branchTargetRVA;
                break;
            }
        }
    }
    Require(gapCandidate.decodedBytes < gapCandidate.size && derivedLeafRva != 0,
        "real PE32 gap fixture did not retain its skipped bytes/direct call");
    Require(FindFunction(result, gapRva) == nullptr &&
            HasIssue(result, gapRva, "undecoded gaps"),
        "gapped x86 candidate was incorrectly accepted as destroy-safe");
    const CipherShell::Function* derivedLeaf =
        FindFunction(result, derivedLeafRva);
    Require(derivedLeaf &&
            derivedLeaf->discoverySource == "direct_call" &&
            derivedLeaf->boundaryTrusted,
        "rejected x86 gap candidate did not derive its external direct-call root");
}

void VerifyX64Pdata(
    CipherShell::CS_PE_IMAGE* image,
    const CipherShell::FunctionDiscoveryResult& result)
{
    Require(image->is64Bit, "PE32+ regression received a PE32 fixture");
    const uint32_t nonLeafRva = ExportRva(image, "cs_gap_root");
    Require(nonLeafRva != 0,
        "real MSVC fixture is missing x64 non-leaf export");
    const auto pdata = std::find_if(
        image->exceptions.entries.begin(), image->exceptions.entries.end(),
        [=](const CipherShell::CS_RUNTIME_FUNCTION& entry) {
            return entry.beginAddress == nonLeafRva;
        });
    Require(pdata != image->exceptions.entries.end() &&
            CipherShell::PEUtils::IsValidRuntimeFunction(image, *pdata),
        "MSVC PE32+ non-leaf export has no valid .pdata/unwind record");
    const CipherShell::Function* function = FindFunction(result, nonLeafRva);
    Require(function && function->boundaryTrusted &&
            function->discoverySource == "pdata" &&
            function->size == pdata->endAddress - pdata->beginAddress,
        "FunctionDiscovery did not use the real PE32+ .pdata boundary");
}

} // namespace

int main(int argc, char** argv) {
    try {
        Require(argc == 2 && argv[1] && argv[1][0] != '\0',
            "usage: test_function_discovery <real-msvc-pe>");
        CipherShell::PEParser parser;
        CipherShell::CS_PE_IMAGE* image = parser.LoadFromFile(argv[1]);
        Require(image && image->isValid,
            "failed to parse the real MSVC fixture PE");

        CipherShell::Disassembler disassembler;
        Require(disassembler.Initialize(image->is64Bit != 0, ImageBase(image)),
            "failed to initialize the architecture-matched disassembler");
        CipherShell::FunctionDiscovery discovery;
        const auto result = discovery.Discover(image, disassembler);
        Require(result.success,
            "function discovery failed on the real MSVC fixture: " + result.error);

        VerifyInterruptBoundary(image, disassembler);
        if (image->is64Bit) {
            VerifyX64Pdata(image, result);
        } else {
            VerifyX86CrtAndGapRoots(image, disassembler, result);
        }

        parser.FreeImage(image);
        std::cout << "real MSVC PE function-discovery regression passed" << std::endl;
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "function-discovery regression failed: "
                  << error.what() << std::endl;
        return 1;
    }
}
