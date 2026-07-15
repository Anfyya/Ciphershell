#include "packer/transforms/vm_handler_entry_codegen.h"

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
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace CipherShell;

class TestFailure : public std::runtime_error {
public:
    explicit TestFailure(const std::string& message) : std::runtime_error(message) {}
};

void Require(bool condition, const std::string& message) {
    if (!condition) throw TestFailure(message);
}

constexpr uint32_t AlignUp(uint32_t value, uint32_t alignment) {
    return (value + alignment - 1u) & ~(alignment - 1u);
}

uint8_t Rotl8(uint8_t value, uint8_t count) {
    return static_cast<uint8_t>((value << count) |
        (value >> static_cast<uint8_t>(8u - count)));
}

std::vector<uint8_t> EncryptOracle(
    const std::vector<uint8_t>& plaintext,
    const VMHandlerEntryCipher& cipher)
{
    std::vector<uint8_t> ciphertext = plaintext;
    uint64_t state = cipher.initialState;
    for (uint8_t& byte : ciphertext) {
        state ^= state << cipher.shiftLeftA;
        state ^= state >> cipher.shiftRightB;
        state ^= state << cipher.shiftLeftC;
        state = state * cipher.multiplier + cipher.addend;
        byte = Rotl8(static_cast<uint8_t>(
            (byte ^ static_cast<uint8_t>(state)) + cipher.addByte),
            cipher.rotate);
    }
    return ciphertext;
}

struct CallbackTrace {
    uint8_t* handler = nullptr;
    size_t handlerSize = 0;
    uint32_t protectCalls = 0;
    uint32_t flushCalls = 0;
    std::array<uint32_t, 4> requestedProtections{};
    bool rangeValid = true;
};

CallbackTrace gTrace{};

#ifdef _WIN32
BOOL WINAPI CoverageVirtualProtect(
    LPVOID address,
    SIZE_T size,
    DWORD protection,
    PDWORD oldProtection)
{
    if (address != gTrace.handler || size != gTrace.handlerSize ||
        gTrace.protectCalls >= gTrace.requestedProtections.size()) {
        gTrace.rangeValid = false;
    } else {
        gTrace.requestedProtections[gTrace.protectCalls] = protection;
    }
    ++gTrace.protectCalls;
    return ::VirtualProtect(address, size, protection, oldProtection);
}

BOOL WINAPI CoverageFlushInstructionCache(
    HANDLE process,
    LPCVOID address,
    SIZE_T size)
{
    if (address != gTrace.handler || size != gTrace.handlerSize)
        gTrace.rangeValid = false;
    ++gTrace.flushCalls;
    return ::FlushInstructionCache(process, address, size);
}
#else
uint32_t __attribute__((ms_abi)) CoverageVirtualProtect(
    void* address,
    size_t size,
    uint32_t protection,
    uint32_t* oldProtection)
{
    if (address != gTrace.handler || size != gTrace.handlerSize ||
        gTrace.protectCalls >= gTrace.requestedProtections.size()) {
        gTrace.rangeValid = false;
    } else {
        gTrace.requestedProtections[gTrace.protectCalls] = protection;
    }
    ++gTrace.protectCalls;
    const long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) return 0u;
    const uintptr_t begin = reinterpret_cast<uintptr_t>(address) &
        ~(static_cast<uintptr_t>(page) - 1u);
    const uintptr_t end = AlignUp(static_cast<uint32_t>(
        reinterpret_cast<uintptr_t>(address) - begin + size),
        static_cast<uint32_t>(page)) + begin;
    const int nativeProtection = protection == 0x04u
        ? (PROT_READ | PROT_WRITE) : (PROT_READ | PROT_EXEC);
    if (oldProtection) *oldProtection = 0x20u;
    return mprotect(reinterpret_cast<void*>(begin), end - begin,
        nativeProtection) == 0 ? 1u : 0u;
}

uint32_t __attribute__((ms_abi)) CoverageFlushInstructionCache(
    uintptr_t,
    const void* address,
    size_t size)
{
    if (address != gTrace.handler || size != gTrace.handlerSize)
        gTrace.rangeValid = false;
    ++gTrace.flushCalls;
    auto* begin = const_cast<char*>(reinterpret_cast<const char*>(address));
    __builtin___clear_cache(begin, begin + size);
    return 1u;
}
#endif

class CoverageImage {
public:
    explicit CoverageImage(size_t size) : size_(size) {
#ifdef _WIN32
        base_ = static_cast<uint8_t*>(VirtualAlloc(
            nullptr, size_, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        Require(base_ != nullptr, "VirtualAlloc failed for decryptor coverage image");
#else
        base_ = static_cast<uint8_t*>(mmap(nullptr, size_,
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
        Require(base_ != MAP_FAILED, "mmap failed for decryptor coverage image");
#endif
        std::memset(base_, 0, size_);
    }

    ~CoverageImage() {
#ifdef _WIN32
        if (base_) VirtualFree(base_, 0, MEM_RELEASE);
#else
        if (base_) munmap(base_, size_);
#endif
    }

    CoverageImage(const CoverageImage&) = delete;
    CoverageImage& operator=(const CoverageImage&) = delete;

    uint8_t* Base() const { return base_; }

    void Seal(uint32_t stateOffset) {
#ifdef _WIN32
        DWORD oldProtection = 0;
        Require(VirtualProtect(base_, size_, PAGE_EXECUTE_READ, &oldProtection) != 0,
            "coverage image could not be sealed RX");
        Require(VirtualProtect(base_ + stateOffset, 0x1000u,
            PAGE_READWRITE, &oldProtection) != 0,
            "decryptor state page could not be made RW");
        Require(FlushInstructionCache(GetCurrentProcess(), base_, size_) != 0,
            "coverage image instruction-cache flush failed");
#else
        Require(mprotect(base_, size_, PROT_READ | PROT_EXEC) == 0,
            "coverage image could not be sealed RX");
        Require(mprotect(base_ + stateOffset, 0x1000u,
            PROT_READ | PROT_WRITE) == 0,
            "decryptor state page could not be made RW");
        __builtin___clear_cache(reinterpret_cast<char*>(base_),
            reinterpret_cast<char*>(base_ + size_));
#endif
    }

private:
    uint8_t* base_ = nullptr;
    size_t size_ = 0;
};

VMHandlerEntryCodegenConfig MakeConfig(
    size_t shiftPlan,
    uint8_t instructionPlan)
{
    VMHandlerEntryCodegenConfig config{};
#if defined(_M_X64) || defined(__x86_64__)
    config.architecture = VM_ARCH_X64;
#elif defined(_M_IX86) || defined(__i386__)
    config.architecture = VM_ARCH_X86;
#else
#error decryptor native coverage requires x86 or x64
#endif
    for (size_t index = 0; index < config.buildSeed.size(); ++index) {
        config.buildSeed[index] = static_cast<uint8_t>(
            0x31u + index * 13u + shiftPlan * 17u + instructionPlan * 7u);
    }
    config.variantCount = 4u;
    config.layout.publicEntryOffset = 0u;
    config.layout.validationEntryOffset = 0x4000u;
    config.layout.decryptorOffset = 0x5000u;
    config.layout.operandDecoderOffset = 0x6000u;
    config.layout.flagMaterializerOffset = 0x8000u;
    config.layout.decryptionStateOffset = 0xA000u;
    config.layout.keyMarkerOffset = 0xA010u;
    config.layout.decodePlanTableOffset = 0xA030u;
    config.functionPlanCount = 1u;
    config.layout.decodePlanTableSize = static_cast<uint32_t>(
        sizeof(uint32_t) + sizeof(VM_OPERAND_CODEC) +
        sizeof(VM_RUNTIME_DECODE_PLAN) * VM_UOP_COUNT);
    const uint32_t pointerSize = config.architecture == VM_ARCH_X64 ? 8u : 4u;
    config.layout.dispatchTableOffset = AlignUp(
        config.layout.decodePlanTableOffset + config.layout.decodePlanTableSize,
        pointerSize);
    const uint32_t dispatchSize = VM_HANDLER_TABLE_SIZE *
        config.variantCount * pointerSize;
    config.layout.encryptedHandlerOffset = AlignUp(
        config.layout.dispatchTableOffset + dispatchSize, 0x1000u);
    config.layout.encryptedHandlerSize = 0x301u;

    config.cipher.initialState = 0x0123456789ABCDEFULL ^
        (static_cast<uint64_t>(shiftPlan) << 52u) ^ instructionPlan;
    config.cipher.multiplier = 0x000000007F4A7C15ULL;
    config.cipher.addend = 0x13579BDF2468ACE0ULL ^
        (static_cast<uint64_t>(instructionPlan) << 33u);
    config.cipher.addByte = static_cast<uint8_t>(instructionPlan * 2u + 1u);
    config.cipher.rotate = static_cast<uint8_t>(instructionPlan % 7u + 1u);
    config.cipher.shiftLeftA = VM_DECRYPTOR_SHIFT_PLANS[shiftPlan][0];
    config.cipher.shiftRightB = VM_DECRYPTOR_SHIFT_PLANS[shiftPlan][1];
    config.cipher.shiftLeftC = VM_DECRYPTOR_SHIFT_PLANS[shiftPlan][2];
    config.cipher.instructionVariant = instructionPlan;
    config.virtualProtectIatRVA = 0x100u;
    config.flushInstructionCacheIatRVA = 0x108u;
    config.emitCetLandingPads = true;
    return config;
}

#if defined(_M_X64)
using DecryptorEntry = uint32_t (__fastcall*)(VM_MICRO_EXECUTION_CONTEXT*);
#elif defined(_M_IX86)
using DecryptorEntry = uint32_t (__cdecl*)(VM_MICRO_EXECUTION_CONTEXT*);
#elif defined(__x86_64__)
using DecryptorEntry = uint32_t (__attribute__((ms_abi)) *)(
    VM_MICRO_EXECUTION_CONTEXT*);
#else
using DecryptorEntry = uint32_t (*)(VM_MICRO_EXECUTION_CONTEXT*);
#endif

void ExecutePlan(
    const VMHandlerEntryCodegenConfig& config,
    const VMHandlerEntryCodegenResult& generated)
{
    const size_t imageSize = AlignUp(
        config.layout.encryptedHandlerOffset +
            config.layout.encryptedHandlerSize,
        0x1000u);
    CoverageImage image(imageSize);
    Require(generated.decryptorCode.size() <= 0x1000u,
        "generated decryptor exceeds its production reserve");
    std::memcpy(image.Base() + config.layout.decryptorOffset,
        generated.decryptorCode.data(), generated.decryptorCode.size());

    std::vector<uint8_t> plaintext(config.layout.encryptedHandlerSize);
    for (size_t index = 0; index < plaintext.size(); ++index) {
        plaintext[index] = static_cast<uint8_t>(
            index * 29u + config.cipher.instructionVariant * 11u +
            config.cipher.shiftLeftA);
    }
    const std::vector<uint8_t> ciphertext =
        EncryptOracle(plaintext, config.cipher);
    std::memcpy(image.Base() + config.layout.encryptedHandlerOffset,
        ciphertext.data(), ciphertext.size());

    VM_MICRO_EXECUTION_CONTEXT context{};
    context.virtualProtect = reinterpret_cast<uintptr_t>(
        &CoverageVirtualProtect);
    context.flushInstructionCache = reinterpret_cast<uintptr_t>(
        &CoverageFlushInstructionCache);
    gTrace = {};
    gTrace.handler = image.Base() + config.layout.encryptedHandlerOffset;
    gTrace.handlerSize = config.layout.encryptedHandlerSize;
    image.Seal(config.layout.decryptionStateOffset);

    const auto decrypt = reinterpret_cast<DecryptorEntry>(
        image.Base() + config.layout.decryptorOffset);
    const uint32_t status = decrypt(&context);
    Require(status == VM_MICRO_ERR_NONE && context.error == VM_MICRO_ERR_NONE &&
            context.halted == 0u,
        "generated decryptor returned an error");
    Require(image.Base()[config.layout.decryptionStateOffset] == 2u,
        "generated decryptor did not publish ready state");
    Require(std::equal(plaintext.begin(), plaintext.end(),
            image.Base() + config.layout.encryptedHandlerOffset),
        "generated decryptor output differs from plaintext oracle");
    Require(gTrace.rangeValid && gTrace.protectCalls == 2u &&
            gTrace.flushCalls == 1u &&
            gTrace.requestedProtections[0] == 0x04u &&
            gTrace.requestedProtections[1] == 0x20u,
        "generated decryptor did not execute the exact RW -> flush -> RX path");
}

void TestAllPlans() {
    constexpr size_t expectedPairs =
        VM_DECRYPTOR_SHIFT_PLANS.size() *
        VM_DECRYPTOR_INSTRUCTION_PLAN_COUNT;
    static_assert(expectedPairs == 384u,
        "decryptor coverage cardinality changed");
    std::set<std::pair<size_t, uint8_t>> covered;
    std::set<std::vector<uint8_t>> activeLoops;
    VMHandlerEntryCodegen generator;

    for (size_t shiftPlan = 0u;
            shiftPlan < VM_DECRYPTOR_SHIFT_PLANS.size(); ++shiftPlan) {
        for (uint8_t instructionPlan = 0u;
                instructionPlan < VM_DECRYPTOR_INSTRUCTION_PLAN_COUNT;
                ++instructionPlan) {
            const VMHandlerEntryCodegenConfig config =
                MakeConfig(shiftPlan, instructionPlan);
            const VMHandlerEntryCodegenResult generated = generator.Generate(config);
            Require(generated.success,
                "decryptor generation failed at shift=" +
                std::to_string(shiftPlan) + ", instruction=" +
                std::to_string(instructionPlan) + ": " + generated.error);
            std::string byteEvidenceError;
            Require(VMHandlerEntryCodegen::ValidateDecryptorMutationEncoding(
                    config, generated, byteEvidenceError),
                "decryptor byte evidence failed: " + byteEvidenceError);
            covered.emplace(shiftPlan, instructionPlan);
            activeLoops.emplace(
                generated.decryptorCode.begin() + generated.decryptorLoopOffset,
                generated.decryptorCode.begin() + generated.decryptorLoopOffset +
                    generated.decryptorLoopSize);
            ExecutePlan(config, generated);

            if (shiftPlan == 0u && instructionPlan == 0u) {
                VMHandlerEntryCodegenResult corruptShift = generated;
                const uint32_t firstShiftImmediate =
                    config.architecture == VM_ARCH_X64 ? 6u : 10u;
                corruptShift.decryptorCode[
                    generated.decryptorLoopOffset + firstShiftImmediate] ^= 1u;
                std::string negativeError;
                Require(!VMHandlerEntryCodegen::ValidateDecryptorMutationEncoding(
                        config, corruptShift, negativeError),
                    "shift-immediate corruption escaped byte validation");

                VMHandlerEntryCodegenResult corruptInstruction = generated;
                const std::array<uint8_t, 2> loadByte = {0x8A,0x06};
                const size_t suffix = std::search(
                    corruptInstruction.decryptorCode.begin() +
                        generated.decryptorLoopOffset,
                    corruptInstruction.decryptorCode.begin() +
                        generated.decryptorLoopOffset + generated.decryptorLoopSize,
                    loadByte.begin(), loadByte.end()) -
                    corruptInstruction.decryptorCode.begin();
                Require(suffix < corruptInstruction.decryptorCode.size(),
                    "negative test could not locate decryptor instruction suffix");
                corruptInstruction.decryptorCode[suffix + 2u] ^= 1u;
                negativeError.clear();
                Require(!VMHandlerEntryCodegen::ValidateDecryptorMutationEncoding(
                        config, corruptInstruction, negativeError),
                    "instruction-form corruption escaped byte validation");
            }
        }
    }
    Require(covered.size() == expectedPairs,
        "not every shift/instruction plan pair was executed");
    Require(activeLoops.size() == expectedPairs,
        "two declared decryptor plans emitted identical active-loop bytes");
}

} // namespace

int main() {
    try {
        TestAllPlans();
        std::cout << "[PASS] decryptor coverage: 8 xorshift triples x 48 "
                     "live instruction layouts = 384 native executions\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "[FAIL] " << error.what() << '\n';
        return 1;
    }
}
