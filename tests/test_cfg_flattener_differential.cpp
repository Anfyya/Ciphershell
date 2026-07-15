#include "packer/transforms/cfg_flattener.h"
#ifdef CS_CFG_FULL_PE_TEST
#include "packer/pe_parser/pe_parser.h"
#endif

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <limits>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

class TestFailure : public std::runtime_error {
public:
    explicit TestFailure(const std::string& message) : std::runtime_error(message) {}
};

void Require(bool condition, const std::string& message) {
    if (!condition) throw TestFailure(message);
}

class ExecutableBytes {
public:
    explicit ExecutableBytes(const std::vector<uint8_t>& bytes) {
        Require(!bytes.empty(), "cannot execute an empty byte sequence");
        size_ = bytes.size();
#ifdef _WIN32
        memory_ = static_cast<uint8_t*>(VirtualAlloc(
            nullptr, size_, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        Require(memory_ != nullptr, "VirtualAlloc failed for CFG differential code");
        std::memcpy(memory_, bytes.data(), bytes.size());
        DWORD oldProtection = 0;
        if (!VirtualProtect(memory_, size_, PAGE_EXECUTE_READ, &oldProtection) ||
            !FlushInstructionCache(GetCurrentProcess(), memory_, size_)) {
            VirtualFree(memory_, 0, MEM_RELEASE);
            memory_ = nullptr;
            throw TestFailure("CFG differential code could not be sealed RX");
        }
#else
        const long pageSize = sysconf(_SC_PAGESIZE);
        Require(pageSize > 0, "sysconf(_SC_PAGESIZE) failed");
        mappedSize_ = (size_ + static_cast<size_t>(pageSize) - 1u) &
            ~(static_cast<size_t>(pageSize) - 1u);
        memory_ = static_cast<uint8_t*>(mmap(nullptr, mappedSize_,
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
        Require(memory_ != MAP_FAILED, "mmap failed for CFG differential code");
        std::memcpy(memory_, bytes.data(), bytes.size());
        if (mprotect(memory_, mappedSize_, PROT_READ | PROT_EXEC) != 0) {
            munmap(memory_, mappedSize_);
            memory_ = nullptr;
            throw TestFailure("CFG differential code could not be sealed RX");
        }
        __builtin___clear_cache(reinterpret_cast<char*>(memory_),
            reinterpret_cast<char*>(memory_ + size_));
#endif
    }

    ~ExecutableBytes() {
#ifdef _WIN32
        if (memory_) VirtualFree(memory_, 0, MEM_RELEASE);
#else
        if (memory_) munmap(memory_, mappedSize_);
#endif
    }

    ExecutableBytes(const ExecutableBytes&) = delete;
    ExecutableBytes& operator=(const ExecutableBytes&) = delete;

    template <typename FunctionPointer>
    FunctionPointer Entry() const {
        return reinterpret_cast<FunctionPointer>(memory_);
    }

private:
    uint8_t* memory_ = nullptr;
    size_t size_ = 0;
#ifndef _WIN32
    size_t mappedSize_ = 0;
#endif
};

#ifdef CS_CFG_FULL_PE_TEST
class ExecutablePeImage {
public:
    explicit ExecutablePeImage(const CipherShell::CS_PE_IMAGE* image) {
        Require(image && image->isValid && image->rawData,
            "cannot map an invalid protected PE image");
        const uint32_t imageSize = image->is64Bit
            ? image->ntHeaders64->OptionalHeader.SizeOfImage
            : image->ntHeaders32->OptionalHeader.SizeOfImage;
        Require(imageSize != 0u, "protected PE has a zero SizeOfImage");
        size_ = imageSize;
#ifdef _WIN32
        memory_ = static_cast<uint8_t*>(VirtualAlloc(
            nullptr, size_, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        Require(memory_ != nullptr, "VirtualAlloc failed for protected PE mapping");
#else
        const long pageSize = sysconf(_SC_PAGESIZE);
        Require(pageSize > 0, "sysconf(_SC_PAGESIZE) failed for protected PE");
        mappedSize_ = (size_ + static_cast<size_t>(pageSize) - 1u) &
            ~(static_cast<size_t>(pageSize) - 1u);
        memory_ = static_cast<uint8_t*>(mmap(nullptr, mappedSize_,
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
        Require(memory_ != MAP_FAILED, "mmap failed for protected PE mapping");
#endif
        std::memset(memory_, 0, size_);
        for (WORD index = 0; index < image->numSections; ++index) {
            const IMAGE_SECTION_HEADER& section = image->sections[index];
            if (section.SizeOfRawData == 0u) continue;
            Require(section.PointerToRawData <= image->rawSize &&
                    section.SizeOfRawData <=
                        image->rawSize - section.PointerToRawData &&
                    section.VirtualAddress <= size_ &&
                    section.SizeOfRawData <= size_ - section.VirtualAddress,
                "protected PE section cannot be mapped at its RVA");
            std::memcpy(memory_ + section.VirtualAddress,
                image->rawData + section.PointerToRawData,
                section.SizeOfRawData);
        }
#ifdef _WIN32
        DWORD oldProtection = 0;
        if (!VirtualProtect(memory_, size_, PAGE_EXECUTE_READ, &oldProtection) ||
            !FlushInstructionCache(GetCurrentProcess(), memory_, size_)) {
            VirtualFree(memory_, 0, MEM_RELEASE);
            memory_ = nullptr;
            throw TestFailure("protected PE mapping could not be sealed RX");
        }
#else
        if (mprotect(memory_, mappedSize_, PROT_READ | PROT_EXEC) != 0) {
            munmap(memory_, mappedSize_);
            memory_ = nullptr;
            throw TestFailure("protected PE mapping could not be sealed RX");
        }
        __builtin___clear_cache(reinterpret_cast<char*>(memory_),
            reinterpret_cast<char*>(memory_ + size_));
#endif
    }

    ~ExecutablePeImage() {
#ifdef _WIN32
        if (memory_) VirtualFree(memory_, 0, MEM_RELEASE);
#else
        if (memory_) munmap(memory_, mappedSize_);
#endif
    }

    template <typename FunctionPointer>
    FunctionPointer AtRVA(uint32_t rva) const {
        Require(rva < size_, "protected PE entry RVA is outside its image");
        return reinterpret_cast<FunctionPointer>(memory_ + rva);
    }

private:
    uint8_t* memory_ = nullptr;
    size_t size_ = 0;
#ifndef _WIN32
    size_t mappedSize_ = 0;
#endif
};
#endif

#if defined(_M_X64) || defined(__x86_64__)
using Word = uint64_t;
constexpr bool kIs64Bit = true;
#elif defined(_M_IX86) || defined(__i386__)
using Word = uint32_t;
constexpr bool kIs64Bit = false;
#else
#error CFG native differential test requires an x86 or x64 target
#endif

#ifdef _WIN32
using BinaryFunction = Word(__cdecl*)(Word, Word);
#else
using BinaryFunction = Word(*)(Word, Word);
#endif

CipherShell::InstructionIR Instruction(
    uint32_t rva,
    const std::vector<uint8_t>& bytes,
    CipherShell::InstructionMnemonic mnemonic,
    CipherShell::InstructionCategory category)
{
    Require(!bytes.empty() && bytes.size() <= 15u,
        "test instruction byte count is invalid");
    CipherShell::InstructionIR instruction{};
    instruction.address = rva;
    instruction.rva = rva;
    instruction.length = static_cast<uint8_t>(bytes.size());
    std::copy(bytes.begin(), bytes.end(), instruction.rawBytes.begin());
    instruction.mnemonic = mnemonic;
    instruction.category = category;
    instruction.machineMode = kIs64Bit
        ? CipherShell::MachineMode::X64 : CipherShell::MachineMode::X86;
    instruction.encoding = CipherShell::InstructionEncoding::Legacy;
    instruction.instructionSet = CipherShell::InstructionSetClass::Scalar;
    return instruction;
}

CipherShell::BasicBlock Block(
    std::vector<CipherShell::InstructionIR> instructions,
    std::vector<uint64_t> successors)
{
    Require(!instructions.empty(), "test basic block is empty");
    CipherShell::BasicBlock block{};
    block.startAddress = instructions.front().address;
    block.endAddress = instructions.back().address + instructions.back().length;
    block.instructionCount = static_cast<uint32_t>(instructions.size());
    block.instructions = std::move(instructions);
    block.successors = std::move(successors);
    return block;
}

CipherShell::Function SignedBranchFunction(std::vector<uint8_t>& nativeBytes) {
    constexpr uint32_t base = 0x1000u;
    CipherShell::Function function{};
    function.entryAddress = base;
    function.name = "cfg_signed_branch_boundary";
    function.discoverySource = "execution_differential_fixture";
    function.isLeaf = true;
    function.boundaryTrusted = true;

    if constexpr (kIs64Bit) {
#ifdef _WIN32
        // Windows x64: RCX/RDX arguments.  The taken target is the final block.
        nativeBytes = {
            0x48,0x89,0xC8,             // mov rax,rcx
            0x48,0x39,0xD1,             // cmp rcx,rdx
            0x7C,0x04,                  // jl tail
            0x48,0x29,0xD0,0xC3,        // sub rax,rdx; ret
            0x48,0x01,0xD0,0xC3         // tail: add rax,rdx; ret
        };
        auto branch = Instruction(base + 6u, {0x7C,0x04},
            CipherShell::InstructionMnemonic::Jl,
            CipherShell::InstructionCategory::ConditionalBranch);
        branch.branchKind = CipherShell::BranchKind::Less;
        branch.hasBranchTarget = true;
        branch.branchTargetRVA = base + 12u;
        function.blocks.push_back(Block({
            Instruction(base, {0x48,0x89,0xC8}, CipherShell::InstructionMnemonic::Mov,
                CipherShell::InstructionCategory::DataTransfer),
            Instruction(base + 3u, {0x48,0x39,0xD1}, CipherShell::InstructionMnemonic::Cmp,
                CipherShell::InstructionCategory::Compare),
            branch}, {base + 12u, base + 8u}));
        function.blocks.push_back(Block({
            Instruction(base + 8u, {0x48,0x29,0xD0}, CipherShell::InstructionMnemonic::Sub,
                CipherShell::InstructionCategory::Arithmetic),
            Instruction(base + 11u, {0xC3}, CipherShell::InstructionMnemonic::Ret,
                CipherShell::InstructionCategory::Return)}, {}));
        function.blocks.push_back(Block({
            Instruction(base + 12u, {0x48,0x01,0xD0}, CipherShell::InstructionMnemonic::Add,
                CipherShell::InstructionCategory::Arithmetic),
            Instruction(base + 15u, {0xC3}, CipherShell::InstructionMnemonic::Ret,
                CipherShell::InstructionCategory::Return)}, {}));
#else
        // System V x64: RDI/RSI arguments; block layout matches the Windows form.
        nativeBytes = {
            0x48,0x89,0xF8,
            0x48,0x39,0xF7,
            0x7C,0x04,
            0x48,0x29,0xF0,0xC3,
            0x48,0x01,0xF0,0xC3
        };
        auto branch = Instruction(base + 6u, {0x7C,0x04},
            CipherShell::InstructionMnemonic::Jl,
            CipherShell::InstructionCategory::ConditionalBranch);
        branch.branchKind = CipherShell::BranchKind::Less;
        branch.hasBranchTarget = true;
        branch.branchTargetRVA = base + 12u;
        function.blocks.push_back(Block({
            Instruction(base, {0x48,0x89,0xF8}, CipherShell::InstructionMnemonic::Mov,
                CipherShell::InstructionCategory::DataTransfer),
            Instruction(base + 3u, {0x48,0x39,0xF7}, CipherShell::InstructionMnemonic::Cmp,
                CipherShell::InstructionCategory::Compare),
            branch}, {base + 12u, base + 8u}));
        function.blocks.push_back(Block({
            Instruction(base + 8u, {0x48,0x29,0xF0}, CipherShell::InstructionMnemonic::Sub,
                CipherShell::InstructionCategory::Arithmetic),
            Instruction(base + 11u, {0xC3}, CipherShell::InstructionMnemonic::Ret,
                CipherShell::InstructionCategory::Return)}, {}));
        function.blocks.push_back(Block({
            Instruction(base + 12u, {0x48,0x01,0xF0}, CipherShell::InstructionMnemonic::Add,
                CipherShell::InstructionCategory::Arithmetic),
            Instruction(base + 15u, {0xC3}, CipherShell::InstructionMnemonic::Ret,
                CipherShell::InstructionCategory::Return)}, {}));
#endif
    } else {
        // x86 cdecl: arguments at [esp+4]/[esp+8].
        nativeBytes = {
            0x8B,0x44,0x24,0x04,         // mov eax,[esp+4]
            0x8B,0x4C,0x24,0x08,         // mov ecx,[esp+8]
            0x39,0xC8,                   // cmp eax,ecx
            0x7C,0x03,                   // jl tail
            0x29,0xC8,0xC3,              // sub eax,ecx; ret
            0x01,0xC8,0xC3               // tail: add eax,ecx; ret
        };
        auto branch = Instruction(base + 10u, {0x7C,0x03},
            CipherShell::InstructionMnemonic::Jl,
            CipherShell::InstructionCategory::ConditionalBranch);
        branch.branchKind = CipherShell::BranchKind::Less;
        branch.hasBranchTarget = true;
        branch.branchTargetRVA = base + 15u;
        function.blocks.push_back(Block({
            Instruction(base, {0x8B,0x44,0x24,0x04}, CipherShell::InstructionMnemonic::Mov,
                CipherShell::InstructionCategory::DataTransfer),
            Instruction(base + 4u, {0x8B,0x4C,0x24,0x08}, CipherShell::InstructionMnemonic::Mov,
                CipherShell::InstructionCategory::DataTransfer),
            Instruction(base + 8u, {0x39,0xC8}, CipherShell::InstructionMnemonic::Cmp,
                CipherShell::InstructionCategory::Compare),
            branch}, {base + 15u, base + 12u}));
        function.blocks.push_back(Block({
            Instruction(base + 12u, {0x29,0xC8}, CipherShell::InstructionMnemonic::Sub,
                CipherShell::InstructionCategory::Arithmetic),
            Instruction(base + 14u, {0xC3}, CipherShell::InstructionMnemonic::Ret,
                CipherShell::InstructionCategory::Return)}, {}));
        function.blocks.push_back(Block({
            Instruction(base + 15u, {0x01,0xC8}, CipherShell::InstructionMnemonic::Add,
                CipherShell::InstructionCategory::Arithmetic),
            Instruction(base + 17u, {0xC3}, CipherShell::InstructionMnemonic::Ret,
                CipherShell::InstructionCategory::Return)}, {}));
    }
    function.size = static_cast<uint32_t>(nativeBytes.size());
    function.decodedBytes = function.size;
    function.blocks.front().isFunctionEntry = true;
    return function;
}

CipherShell::Function FlagFlowFunction(std::vector<uint8_t>& nativeBytes) {
    constexpr uint32_t base = 0x2000u;
    CipherShell::Function function{};
    function.entryAddress = base;
    function.name = "cfg_flags_across_dispatch";
    function.discoverySource = "execution_differential_fixture";
    function.isLeaf = true;
    function.boundaryTrusted = true;

    if constexpr (kIs64Bit) {
#ifdef _WIN32
        nativeBytes = {
            0x48,0x89,0xC8,              // mov rax,rcx
            0x48,0x01,0xD0,              // add rax,rdx
            0xEB,0x00,                    // jmp tail
            0x9F,                         // tail: lahf
            0x0F,0x90,0xC0,              // seto al
            0xC3
        };
        auto jump = Instruction(base + 6u, {0xEB,0x00},
            CipherShell::InstructionMnemonic::Jmp,
            CipherShell::InstructionCategory::UnconditionalBranch);
        jump.branchKind = CipherShell::BranchKind::Unconditional;
        jump.hasBranchTarget = true;
        jump.branchTargetRVA = base + 8u;
        function.blocks.push_back(Block({
            Instruction(base, {0x48,0x89,0xC8}, CipherShell::InstructionMnemonic::Mov,
                CipherShell::InstructionCategory::DataTransfer),
            Instruction(base + 3u, {0x48,0x01,0xD0}, CipherShell::InstructionMnemonic::Add,
                CipherShell::InstructionCategory::Arithmetic),
            jump}, {base + 8u}));
        function.blocks.push_back(Block({
            Instruction(base + 8u, {0x9F}, CipherShell::InstructionMnemonic::Lahf,
                CipherShell::InstructionCategory::DataTransfer),
            Instruction(base + 9u, {0x0F,0x90,0xC0}, CipherShell::InstructionMnemonic::Setcc,
                CipherShell::InstructionCategory::SetCondition),
            Instruction(base + 12u, {0xC3}, CipherShell::InstructionMnemonic::Ret,
                CipherShell::InstructionCategory::Return)}, {}));
#else
        nativeBytes = {
            0x48,0x89,0xF8,              // mov rax,rdi
            0x48,0x01,0xF0,              // add rax,rsi
            0xEB,0x00,
            0x9F,
            0x0F,0x90,0xC0,
            0xC3
        };
        auto jump = Instruction(base + 6u, {0xEB,0x00},
            CipherShell::InstructionMnemonic::Jmp,
            CipherShell::InstructionCategory::UnconditionalBranch);
        jump.branchKind = CipherShell::BranchKind::Unconditional;
        jump.hasBranchTarget = true;
        jump.branchTargetRVA = base + 8u;
        function.blocks.push_back(Block({
            Instruction(base, {0x48,0x89,0xF8}, CipherShell::InstructionMnemonic::Mov,
                CipherShell::InstructionCategory::DataTransfer),
            Instruction(base + 3u, {0x48,0x01,0xF0}, CipherShell::InstructionMnemonic::Add,
                CipherShell::InstructionCategory::Arithmetic),
            jump}, {base + 8u}));
        function.blocks.push_back(Block({
            Instruction(base + 8u, {0x9F}, CipherShell::InstructionMnemonic::Lahf,
                CipherShell::InstructionCategory::DataTransfer),
            Instruction(base + 9u, {0x0F,0x90,0xC0}, CipherShell::InstructionMnemonic::Setcc,
                CipherShell::InstructionCategory::SetCondition),
            Instruction(base + 12u, {0xC3}, CipherShell::InstructionMnemonic::Ret,
                CipherShell::InstructionCategory::Return)}, {}));
#endif
    } else {
        nativeBytes = {
            0x8B,0x44,0x24,0x04,         // mov eax,[esp+4]
            0x03,0x44,0x24,0x08,         // add eax,[esp+8]
            0xEB,0x00,                    // jmp tail
            0x9F,                         // tail: lahf
            0x0F,0x90,0xC0,              // seto al
            0xC3
        };
        auto jump = Instruction(base + 8u, {0xEB,0x00},
            CipherShell::InstructionMnemonic::Jmp,
            CipherShell::InstructionCategory::UnconditionalBranch);
        jump.branchKind = CipherShell::BranchKind::Unconditional;
        jump.hasBranchTarget = true;
        jump.branchTargetRVA = base + 10u;
        function.blocks.push_back(Block({
            Instruction(base, {0x8B,0x44,0x24,0x04}, CipherShell::InstructionMnemonic::Mov,
                CipherShell::InstructionCategory::DataTransfer),
            Instruction(base + 4u, {0x03,0x44,0x24,0x08}, CipherShell::InstructionMnemonic::Add,
                CipherShell::InstructionCategory::Arithmetic),
            jump}, {base + 10u}));
        function.blocks.push_back(Block({
            Instruction(base + 10u, {0x9F}, CipherShell::InstructionMnemonic::Lahf,
                CipherShell::InstructionCategory::DataTransfer),
            Instruction(base + 11u, {0x0F,0x90,0xC0}, CipherShell::InstructionMnemonic::Setcc,
                CipherShell::InstructionCategory::SetCondition),
            Instruction(base + 14u, {0xC3}, CipherShell::InstructionMnemonic::Ret,
                CipherShell::InstructionCategory::Return)}, {}));
    }
    function.size = static_cast<uint32_t>(nativeBytes.size());
    function.decodedBytes = function.size;
    function.blocks.front().isFunctionEntry = true;
    return function;
}

std::vector<std::array<Word, 2>> Corpus() {
    const Word highBit = static_cast<Word>(Word{1} << (sizeof(Word) * 8u - 1u));
    const Word maximum = (std::numeric_limits<Word>::max)();
    return {
        {0,0}, {0,1}, {1,0}, {1,1},
        {7,3}, {3,7}, {0x7F,1}, {0xFF,1},
        {0x0F,1}, {0x10,static_cast<Word>(-1)},
        {highBit,0}, {highBit,1}, {highBit,maximum},
        {highBit - 1u,1}, {maximum,1}, {maximum,maximum},
        {static_cast<Word>(0x5555555555555555ULL),
         static_cast<Word>(0xAAAAAAAAAAAAAAAAULL)}
    };
}

void RunDifferential(
    const CipherShell::Function& function,
    const std::vector<uint8_t>& nativeBytes,
    const char* label)
{
    ExecutableBytes nativeCode(nativeBytes);
    const BinaryFunction native = nativeCode.Entry<BinaryFunction>();
    std::set<std::vector<uint8_t>> generatedLayouts;

    for (uint64_t seed = 1u; seed <= 24u; ++seed) {
        CipherShell::FlatteningConfig config{};
        config.buildSeed = 0xC1F3E00000000000ULL ^ seed;
        config.junkCaseCount = 2u + static_cast<uint32_t>(seed % 5u);
        const uint32_t generatedRVA = 0x400000u + static_cast<uint32_t>(seed * 0x1000u);
        CipherShell::CFGFlattener flattener;
        const CipherShell::CFGFlattenedFunction flattened = flattener.Generate(
            function, kIs64Bit, generatedRVA, config);
        Require(flattened.success,
            std::string(label) + ": generation failed: " + flattened.error);
        std::string structuralError;
        Require(CipherShell::CFGFlattener::ValidateGeneratedFunction(
            flattened, structuralError),
            std::string(label) + ": structural validation failed: " + structuralError);
        Require(flattened.blocks.size() == function.blocks.size(),
            std::string(label) + ": a real block body was omitted");
        Require(flattened.dispatchCases.size() >= flattened.blocks.size() + 2u,
            std::string(label) + ": dispatcher lacks live/junk state coverage");
        generatedLayouts.insert(flattened.code);

        ExecutableBytes generatedCode(flattened.code);
        const BinaryFunction protectedFunction =
            generatedCode.Entry<BinaryFunction>();
        for (const auto& values : Corpus()) {
            const Word expected = native(values[0], values[1]);
            const Word actual = protectedFunction(values[0], values[1]);
            if (expected != actual) {
                throw TestFailure(std::string(label) +
                    ": native/CFG differential mismatch at seed=" +
                    std::to_string(seed));
            }
        }
    }
    Require(generatedLayouts.size() > 12u,
        std::string(label) + ": per-build CFG layouts did not materially vary");
}

#ifdef CS_CFG_FULL_PE_TEST
CipherShell::CS_PE_IMAGE* BuildNativeFixturePe(
    const std::vector<uint8_t>& nativeBytes)
{
    constexpr DWORD rawSize = 0x400u;
    constexpr size_t ntOffset = 0x80u;
    BYTE* bytes = new BYTE[rawSize];
    std::memset(bytes, 0, rawSize);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(bytes);
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = static_cast<LONG>(ntOffset);
    std::memcpy(bytes + ntOffset, "PE\0\0", 4u);

    auto* fileHeader = reinterpret_cast<IMAGE_FILE_HEADER*>(
        bytes + ntOffset + sizeof(DWORD));
    fileHeader->Machine = static_cast<WORD>(kIs64Bit
        ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_MACHINE_I386);
    fileHeader->NumberOfSections = static_cast<WORD>(1u);
    constexpr WORD kExecutableImage = 0x0002u;
    constexpr WORD k32BitMachine = 0x0100u;
    fileHeader->Characteristics = static_cast<WORD>(kExecutableImage |
        (kIs64Bit ? 0u : k32BitMachine));

    size_t sectionOffset = 0u;
    if constexpr (kIs64Bit) {
        fileHeader->SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
        auto* optional = reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(
            reinterpret_cast<uint8_t*>(fileHeader) + sizeof(*fileHeader));
        optional->Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        optional->ImageBase = 0x140000000ULL;
        optional->AddressOfEntryPoint = 0x1000u;
        optional->SectionAlignment = 0x1000u;
        optional->FileAlignment = 0x200u;
        optional->SizeOfHeaders = 0x200u;
        optional->SizeOfImage = 0x2000u;
        optional->NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        sectionOffset = static_cast<size_t>(
            reinterpret_cast<uint8_t*>(optional + 1) - bytes);
    } else {
        fileHeader->SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);
        auto* optional = reinterpret_cast<IMAGE_OPTIONAL_HEADER32*>(
            reinterpret_cast<uint8_t*>(fileHeader) + sizeof(*fileHeader));
        optional->Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
        optional->ImageBase = 0x400000u;
        optional->AddressOfEntryPoint = 0x1000u;
        optional->SectionAlignment = 0x1000u;
        optional->FileAlignment = 0x200u;
        optional->SizeOfHeaders = 0x200u;
        optional->SizeOfImage = 0x2000u;
        optional->NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        sectionOffset = static_cast<size_t>(
            reinterpret_cast<uint8_t*>(optional + 1) - bytes);
    }
    Require(sectionOffset + sizeof(IMAGE_SECTION_HEADER) <= 0x200u,
        "fixture PE headers exceed their declared range");
    auto* section = reinterpret_cast<IMAGE_SECTION_HEADER*>(bytes + sectionOffset);
    std::memcpy(section->Name, ".text", 5u);
    section->VirtualAddress = 0x1000u;
    section->Misc.VirtualSize = static_cast<DWORD>(nativeBytes.size());
    section->SizeOfRawData = 0x200u;
    section->PointerToRawData = 0x200u;
    section->Characteristics = IMAGE_SCN_CNT_CODE |
        IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
    Require(nativeBytes.size() <= section->SizeOfRawData,
        "native CFG fixture does not fit its text section");
    std::copy(nativeBytes.begin(), nativeBytes.end(),
        bytes + section->PointerToRawData);

    CipherShell::PEParser parser;
    CipherShell::CS_PE_IMAGE* image = parser.LoadFromBuffer(bytes, rawSize);
    Require(image && image->isValid, "native CFG fixture PE did not parse");
    return image;
}

void RunFullPeEntryDifferential(
    const CipherShell::Function& function,
    const std::vector<uint8_t>& nativeBytes)
{
    ExecutableBytes nativeCode(nativeBytes);
    const BinaryFunction native = nativeCode.Entry<BinaryFunction>();
    CipherShell::CS_PE_IMAGE* image = BuildNativeFixturePe(nativeBytes);
    CipherShell::FlatteningConfig config{};
    config.buildSeed = 0xE0CF6A3B7142D995ULL;
    config.junkCaseCount = 4u;
    const char codeName[8] = {'.','c','f','g','x',0,0,0};
    const char unwindName[8] = {'.','c','f','g','u','w',0,0};
    const char exceptionName[8] = {'.','c','f','g','p','d',0,0};
    const char relocationName[8] = {'.','c','f','g','r','l',0,0};
    CipherShell::CFGFlattener flattener;
    const CipherShell::CFGProtectionResult protectedResult = flattener.Protect(
        image, {function}, config, codeName, unwindName,
        exceptionName, relocationName);
    Require(protectedResult.success,
        "full PE CFG protection failed: " + protectedResult.error);
    std::string verifyError;
    Require(CipherShell::CFGFlattener::VerifyAppliedProtection(
            image, protectedResult, verifyError),
        "full PE CFG verification failed: " + verifyError);
    Require(protectedResult.patchResults.size() == 1u &&
            protectedResult.patchResults.front().nativeBodyDestroyed,
        "full PE CFG path did not patch and destroy the native body");

    ExecutablePeImage mapped(image);
    const BinaryFunction protectedEntry =
        mapped.AtRVA<BinaryFunction>(0x1000u);
    for (const auto& values : Corpus()) {
        Require(native(values[0], values[1]) ==
                protectedEntry(values[0], values[1]),
            "patched PE entry differs from its native oracle");
    }
    CipherShell::PEParser parser;
    parser.FreeImage(image);
}
#endif

} // namespace

int main() {
    try {
        std::vector<uint8_t> nativeBranch;
        const CipherShell::Function branch = SignedBranchFunction(nativeBranch);
        RunDifferential(branch, nativeBranch,
            "conditional true/false and entry/tail target corpus");

        std::vector<uint8_t> nativeFlags;
        const CipherShell::Function flags = FlagFlowFunction(nativeFlags);
        RunDifferential(flags, nativeFlags,
            "AF/PF/CF/ZF/SF/OF preservation across dispatcher");

#ifdef CS_CFG_FULL_PE_TEST
        RunFullPeEntryDifferential(branch, nativeBranch);
#endif

        std::cout << "[PASS] CFG native execution differential: 2 functions, "
                     "24 layouts each, boundary/arithmetic-flag corpus"
#ifdef CS_CFG_FULL_PE_TEST
                     ", plus patched PE entry\n";
#else
                     "\n";
#endif
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "[FAIL] " << error.what() << '\n';
        return 1;
    }
}
