#include "vm_native_differential_worker_harness.h"
#include "vm_native_exec_trampoline.h"

#include "../../runtime/common/vm_micro_runtime_abi.h"
#include "../vm/micro_semantics.h"

#include <array>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <vector>

#ifdef _WIN32
#include <Windows.h>
#endif

namespace CipherShell {

#ifdef _WIN32

namespace {

#define CS_NDIFF_CHECKPOINT(msg) \
    do { if (std::getenv("CS_NATIVE_DIFFERENTIAL_DEBUG")) { \
        std::fprintf(stderr, "[worker-debug] %s\n", msg); std::fflush(stderr); } } while (0)

#if defined(_M_X64)
using ContextEntry = uint32_t(__fastcall*)(VM_MICRO_EXECUTION_CONTEXT*);
#elif defined(_M_IX86)
using ContextEntry = uint32_t(__cdecl*)(VM_MICRO_EXECUTION_CONTEXT*);
#endif

std::atomic<bool> g_nativeGuardActive{false};
uintptr_t g_nativeRecoveryRip = 0;
DWORD g_nativeExceptionCode = 0;
uintptr_t g_nativeExceptionAddress = 0;
// Family-ordered (rax,rcx,rdx,rbx,rsp,rbp,rsi,rdi,r8..r15; see
// vm_native_exec_trampoline_x64/x86.asm) GPR/RFLAGS snapshot taken from the
// exception CONTEXT itself, i.e. the architectural state that was live at
// the very instant the fault fired -- not the (never reached) post-fault
// trampoline state. This is what lets the caller prove the native side
// never mutated guest-visible state before the CPU trapped.
std::array<uint64_t, 16> g_nativeFaultGpr{};
uint64_t g_nativeFaultRflags = 0;

LONG CALLBACK NativeDifferentialVectoredHandler(EXCEPTION_POINTERS* info) {
    if (!g_nativeGuardActive.load(std::memory_order_acquire)) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    g_nativeExceptionCode = info->ExceptionRecord->ExceptionCode;
    g_nativeExceptionAddress =
        reinterpret_cast<uintptr_t>(info->ExceptionRecord->ExceptionAddress);
#if defined(_M_X64)
    {
        const CONTEXT& ctx = *info->ContextRecord;
        g_nativeFaultGpr = {ctx.Rax, ctx.Rcx, ctx.Rdx, ctx.Rbx, ctx.Rsp, ctx.Rbp,
            ctx.Rsi, ctx.Rdi, ctx.R8, ctx.R9, ctx.R10, ctx.R11, ctx.R12, ctx.R13,
            ctx.R14, ctx.R15};
        g_nativeFaultRflags = ctx.EFlags;
    }
    info->ContextRecord->Rip = g_nativeRecoveryRip;
#elif defined(_M_IX86)
    {
        const CONTEXT& ctx = *info->ContextRecord;
        g_nativeFaultGpr = {ctx.Eax, ctx.Ecx, ctx.Edx, ctx.Ebx, ctx.Esp, ctx.Ebp,
            ctx.Esi, ctx.Edi, 0, 0, 0, 0, 0, 0, 0, 0};
        g_nativeFaultRflags = ctx.EFlags;
    }
    info->ContextRecord->Eip = static_cast<DWORD>(g_nativeRecoveryRip);
#endif
    g_nativeGuardActive.store(false, std::memory_order_release);
    return EXCEPTION_CONTINUE_EXECUTION;
}

bool EnsureNativeVectoredHandlerRegistered() {
    static PVOID handle = AddVectoredExceptionHandler(1, NativeDifferentialVectoredHandler);
    return handle != nullptr;
}

bool RunNativeHalf(
    const VMNativeDifferentialRequestHeader& header,
    const uint8_t* nativeCode,
    const VMNativeDifferentialCodeFixup* nativeCodeFixups,
    uint8_t* corpusMemory,
    VMNativeDifferentialWorkerOutcome& outcome,
    std::string& error)
{
    CS_NDIFF_CHECKPOINT("RunNativeHalf: begin");
    if (!EnsureNativeVectoredHandlerRegistered()) {
        error = "native differential worker could not install a vectored exception handler";
        return false;
    }
    if (header.nativeCodeSize == 0) {
        error = "native differential worker received an empty native code region";
        return false;
    }

    void* preferredCodeBase = nullptr;
    if (header.nativeCodeFixupsCount != 0u) {
        const uint64_t afterCorpus = header.memoryBase + header.memorySize;
        if (afterCorpus < header.memoryBase ||
            afterCorpus > (std::numeric_limits<uintptr_t>::max)() - 0xFFFFu) {
            error = "native differential near-code allocation address overflows";
            return false;
        }
        const uintptr_t aligned = (static_cast<uintptr_t>(afterCorpus) + 0xFFFFu) &
            ~static_cast<uintptr_t>(0xFFFFu);
        preferredCodeBase = reinterpret_cast<void*>(aligned);
    }
    void* codeBuffer = VirtualAlloc(preferredCodeBase, header.nativeCodeSize,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!codeBuffer) {
        error = header.nativeCodeFixupsCount == 0u
            ? "native differential worker could not allocate the native code buffer"
            : "native differential worker could not allocate native code within RIP-rel32 range";
        return false;
    }
    std::memcpy(codeBuffer, nativeCode, header.nativeCodeSize);
    for (uint32_t index = 0; index < header.nativeCodeFixupsCount; ++index) {
        const VMNativeDifferentialCodeFixup& fixup = nativeCodeFixups[index];
        if (fixup.kind != VM_NATIVE_CODE_FIXUP_RIP_REL32 ||
            fixup.fieldSize != 4u || fixup.reserved != 0u ||
            fixup.fieldOffset > header.nativeCodeSize ||
            4u > header.nativeCodeSize - fixup.fieldOffset ||
            fixup.nextInstructionOffset > header.nativeCodeSize ||
            fixup.targetRVA >= header.memorySize) {
            VirtualFree(codeBuffer, 0, MEM_RELEASE);
            error = "native differential RIP-relative fixup is malformed";
            return false;
        }
        const uint64_t target = header.memoryBase + fixup.targetRVA;
        const uint64_t next = reinterpret_cast<uintptr_t>(codeBuffer) +
            fixup.nextInstructionOffset;
        const int64_t displacement = static_cast<int64_t>(target) -
            static_cast<int64_t>(next);
        if (displacement < (std::numeric_limits<int32_t>::min)() ||
            displacement > (std::numeric_limits<int32_t>::max)()) {
            VirtualFree(codeBuffer, 0, MEM_RELEASE);
            error = "native differential RIP-relative target exceeds signed disp32 range";
            return false;
        }
        const int32_t encoded = static_cast<int32_t>(displacement);
        std::memcpy(static_cast<uint8_t*>(codeBuffer) + fixup.fieldOffset,
            &encoded, sizeof(encoded));
    }
    DWORD oldProtect = 0;
    if (!VirtualProtect(codeBuffer, header.nativeCodeSize, PAGE_EXECUTE_READ, &oldProtect) ||
        !FlushInstructionCache(GetCurrentProcess(), codeBuffer, header.nativeCodeSize)) {
        VirtualFree(codeBuffer, 0, MEM_RELEASE);
        error = "native differential worker could not make the native code buffer executable";
        return false;
    }

    VMNativeExecTrampolineState state{};
    state.gpr = header.initialGpr;
    state.rflags = header.initialRflags;
    state.entryPoint = reinterpret_cast<uint64_t>(codeBuffer);

    // entryPoint is entered with a genuine CALL so its own RET works.  The
    // assembly trampoline invokes from initialGpr[4] + pointerSize, therefore
    // CALL writes its return address at initialGpr[4] and the callee observes
    // exactly initialGpr[4] as its architectural entry SP, matching the VM.
    // That is an artifact of how this harness invokes the function, not a
    // side effect the function itself produced, so it must not appear in
    // the memory snapshot compared against the VM side, which never
    // touches real memory to drive its own internal dispatch.  Save and
    // restore those bytes around the call.
#if defined(_M_X64)
    constexpr uint64_t kReturnSlotSize = 8u;
#else
    constexpr uint64_t kReturnSlotSize = 4u;
#endif
    uint8_t returnSlotSaved[kReturnSlotSize] = {};
    uint8_t* returnSlot = nullptr;
    const uint64_t returnSlotAddress = header.initialGpr[4];
    if (returnSlotAddress >= header.memoryBase &&
        returnSlotAddress <= header.memoryBase + header.memorySize - kReturnSlotSize) {
        returnSlot = corpusMemory + (returnSlotAddress - header.memoryBase);
        std::memcpy(returnSlotSaved, returnSlot, sizeof(returnSlotSaved));
    }

    g_nativeExceptionCode = 0;
    g_nativeRecoveryRip = reinterpret_cast<uintptr_t>(&VMNativeExecTrampolineFaultRecoveryLabel);
    g_nativeGuardActive.store(true, std::memory_order_release);
    VMNativeExecTrampolineInvoke(&state);
    g_nativeGuardActive.store(false, std::memory_order_release);

    if (returnSlot) {
        std::memcpy(returnSlot, returnSlotSaved, sizeof(returnSlotSaved));
    }

    const bool faulted = VMNativeExecTrampolineFaulted() != 0;
    VirtualFree(codeBuffer, 0, MEM_RELEASE);

    outcome.nativeExecuted = true;
    outcome.nativeFaulted = faulted;
    outcome.nativeExceptionCode = faulted ? g_nativeExceptionCode : 0;
    outcome.nativeFaultOffset = faulted ?
        g_nativeExceptionAddress - reinterpret_cast<uintptr_t>(codeBuffer) : 0;
    if (!faulted) {
        outcome.nativeFinalGpr = state.gpr;
        outcome.nativeFinalRflags = state.rflags;
        if (!header.architectureIsX64) {
            for (auto& value : outcome.nativeFinalGpr) value &= 0xFFFFFFFFu;
            outcome.nativeFinalRflags &= 0xFFFFFFFFu;
        }
    } else {
        // state.gpr was never written back (the trampoline only does that
        // on a normal return, which a fault preempts), so it is still
        // exactly the pre-call value for every family -- including families
        // 8..15 on x86, which have no real physical register and therefore
        // no CONTEXT field to read at all. Use it as the base and overwrite
        // only the families this architecture actually has with what the
        // CONTEXT really measured, instead of zero-filling the nonexistent
        // x86 R8..R15 (which would wrongly read as "corrupted" against the
        // pristine input).
        outcome.nativeFaultGpr = state.gpr;
        const size_t realFamilies = header.architectureIsX64 ? 16u : 8u;
        for (size_t i = 0; i < realFamilies; ++i) {
            outcome.nativeFaultGpr[i] = g_nativeFaultGpr[i];
        }
        outcome.nativeFaultRflags = g_nativeFaultRflags;
        if (!header.architectureIsX64) {
            for (auto& value : outcome.nativeFaultGpr) value &= 0xFFFFFFFFu;
            outcome.nativeFaultRflags &= 0xFFFFFFFFu;
        }
    }
    outcome.nativeFinalMemory.assign(corpusMemory, corpusMemory + header.memorySize);
    CS_NDIFF_CHECKPOINT("RunNativeHalf: end");
    return true;
}

class LoadedHandlerImage {
public:
    ~LoadedHandlerImage() {
#if defined(_M_X64)
        if (m_functionTableRegistered && !m_unwind.empty()) {
            RtlDeleteFunctionTable(m_unwind.data());
        }
#endif
        if (m_base) VirtualFree(m_base, 0, MEM_RELEASE);
    }

    bool Load(
        const VMNativeDifferentialRequestHeader& header,
        const uint8_t* image,
        const VMNativeDifferentialRelocation* relocations,
        const VMNativeDifferentialUnwindEntry* unwindEntries,
        std::string& error)
    {
        m_size = header.handlerImageSize;
        m_base = static_cast<uint8_t*>(VirtualAlloc(
            nullptr, m_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (!m_base) {
            error = "native differential worker could not allocate the handler image";
            return false;
        }
        std::memcpy(m_base, image, m_size);
        for (uint32_t index = 0; index < header.handlerRelocationsCount; ++index) {
            const auto& relocation = relocations[index];
            if (relocation.type == IMAGE_REL_BASED_DIR64) {
                if (relocation.offset > m_size || sizeof(uint64_t) > m_size - relocation.offset) {
                    error = "native differential worker DIR64 relocation is out of range";
                    return false;
                }
                uint64_t value = 0;
                std::memcpy(&value, m_base + relocation.offset, sizeof(value));
                value += reinterpret_cast<uintptr_t>(m_base);
                std::memcpy(m_base + relocation.offset, &value, sizeof(value));
            } else if (relocation.type == IMAGE_REL_BASED_HIGHLOW) {
                if (relocation.offset > m_size || sizeof(uint32_t) > m_size - relocation.offset) {
                    error = "native differential worker HIGHLOW relocation is out of range";
                    return false;
                }
                uint32_t value = 0;
                std::memcpy(&value, m_base + relocation.offset, sizeof(value));
                value += static_cast<uint32_t>(reinterpret_cast<uintptr_t>(m_base));
                std::memcpy(m_base + relocation.offset, &value, sizeof(value));
            } else {
                error = "native differential worker handler image has an unknown relocation type";
                return false;
            }
        }
        DWORD oldProtect = 0;
        if (!VirtualProtect(m_base, m_size, PAGE_EXECUTE_READ, &oldProtect) ||
            !FlushInstructionCache(GetCurrentProcess(), m_base, m_size)) {
            error = "native differential worker could not make the handler image executable";
            return false;
        }
#if defined(_M_X64)
        if (header.architectureIsX64) {
            m_unwind.reserve(header.handlerUnwindCount);
            for (uint32_t index = 0; index < header.handlerUnwindCount; ++index) {
                const auto& unwind = unwindEntries[index];
                if (unwind.beginOffset >= unwind.endOffset ||
                    unwind.endOffset > m_size || unwind.unwindOffset >= m_size) {
                    error = "native differential worker handler unwind entry is out of range";
                    return false;
                }
                RUNTIME_FUNCTION function{};
                function.BeginAddress = unwind.beginOffset;
                function.EndAddress = unwind.endOffset;
                function.UnwindData = unwind.unwindOffset;
                m_unwind.push_back(function);
            }
            if (m_unwind.empty() || !RtlAddFunctionTable(
                    m_unwind.data(), static_cast<DWORD>(m_unwind.size()),
                    reinterpret_cast<DWORD64>(m_base))) {
                error = "native differential worker could not register the handler unwind table";
                return false;
            }
            m_functionTableRegistered = true;
        }
#endif
        return true;
    }

    uint8_t* Base() const { return m_base; }

private:
    uint8_t* m_base = nullptr;
    size_t m_size = 0;
#if defined(_M_X64)
    std::vector<RUNTIME_FUNCTION> m_unwind;
    bool m_functionTableRegistered = false;
#endif
};

uint32_t InvokeContextEntry(
    ContextEntry entry,
    VM_MICRO_EXECUTION_CONTEXT* context,
    const std::array<uint8_t, 16>& familyToVregSlot,
    bool architectureIsX64,
    DWORD* exceptionCode,
    uintptr_t* exceptionAddress,
    std::array<uint64_t, 16>* faultGpr,
    uint64_t* faultRflags)
{
    *exceptionCode = 0;
    *exceptionAddress = 0;
    __try {
        return entry(context);
    } __except((*exceptionCode = GetExceptionCode(),
        *exceptionAddress = reinterpret_cast<uintptr_t>(
            GetExceptionInformation()->ExceptionRecord->ExceptionAddress),
        EXCEPTION_EXECUTE_HANDLER)) {
        // context is a stack-local of RunVmHalf (a frame below this one, never
        // unwound by an exception this function itself handles), so it still
        // holds exactly the guest register/flags state that was live the
        // instant the fault fired -- proving (or disproving) that the VM
        // never wrote a partial/incorrect result before signalling the fault.
        for (uint8_t family = 0; family < 16; ++family) {
            uint64_t value = context->vregs[familyToVregSlot[family]];
            if (!architectureIsX64) value &= 0xFFFFFFFFu;
            (*faultGpr)[family] = value;
        }
        *faultRflags = architectureIsX64
            ? context->virtualFlags : (context->virtualFlags & 0xFFFFFFFFu);
        return VM_MICRO_ERR_HANDLER_BUG;
    }
}

bool RunVmHalf(
    const VMNativeDifferentialRequestHeader& header,
    const uint8_t* vmBytecode,
    uint8_t* corpusMemory,
    const uint8_t* handlerImage,
    const VMNativeDifferentialRelocation* handlerRelocations,
    const VMNativeDifferentialUnwindEntry* handlerUnwindEntries,
    VMNativeDifferentialWorkerOutcome& outcome,
    std::string& error)
{
    LoadedHandlerImage loaded;
    if (!loaded.Load(header, handlerImage, handlerRelocations, handlerUnwindEntries, error)) {
        return false;
    }

    /*
     * The decryptor fetches VirtualProtect/FlushInstructionCache through
     * [imageBase + IatRVA], exactly like it will in the shipped PE (the OS
     * loader resolves the real IAT at process start; the packer only ever
     * knows the RVA).  imageBase must also equal the corpus arena base for
     * VM_UOP_PUSH_IMAGE_BASE / RVA-relative operands to agree with the
     * software oracle's convention, so the two real API pointers are placed
     * just past the corpus-verified `memorySize` bytes of `corpusMemory` -- a
     * range PrepareOracleMemoryRegisters already refuses to let any real
     * operand resolve into, so no legitimate access from the tested
     * function can ever land there.
     */
    const uint32_t virtualProtectIatRVA = header.memorySize;
    const uint32_t flushInstructionCacheIatRVA = header.memorySize + 8u;
    const uintptr_t virtualProtectPointer = reinterpret_cast<uintptr_t>(&VirtualProtect);
    const uintptr_t flushInstructionCachePointer =
        reinterpret_cast<uintptr_t>(&FlushInstructionCache);
    std::memcpy(corpusMemory + virtualProtectIatRVA, &virtualProtectPointer,
        sizeof(virtualProtectPointer));
    std::memcpy(corpusMemory + flushInstructionCacheIatRVA, &flushInstructionCachePointer,
        sizeof(flushInstructionCachePointer));
    VM_METADATA_HEADER metadata{};
    metadata.imageSize = header.memorySize + 16u;

    std::array<uint8_t, VM_REGISTER_MAP_SIZE> identityRegisterMap{};
    for (uint16_t index = 0; index < identityRegisterMap.size(); ++index) {
        identityRegisterMap[index] = static_cast<uint8_t>(index);
    }

    VM_MICRO_EXECUTION_CONTEXT context{};
    for (uint8_t family = 0; family < 16; ++family) {
        const uint8_t slot = header.familyToVregSlot[family];
        if (slot >= VM_RUNTIME_REGISTER_COUNT) {
            error = "native differential worker register map slot is out of range";
            return false;
        }
        uint64_t value = header.initialGpr[family];
        if (!header.architectureIsX64) value &= 0xFFFFFFFFu;
        context.vregs[slot] = value;
    }
    context.vip = reinterpret_cast<uintptr_t>(vmBytecode);
    context.bytecodeBegin = context.vip;
    context.bytecodeEnd = context.vip + header.vmBytecodeSize;
    context.reverseOpcodeMap = reinterpret_cast<uintptr_t>(header.reverseOpcodeMap.data());
    context.registerMap = reinterpret_cast<uintptr_t>(identityRegisterMap.data());
    context.handlerSemanticToSlot = reinterpret_cast<uintptr_t>(header.handlerSemanticToSlot.data());
    context.imageBase = reinterpret_cast<uintptr_t>(corpusMemory);
    context.metadata = reinterpret_cast<uintptr_t>(&metadata);
    context.operandCodec = header.operandCodec;
    context.virtualFlags = header.initialRflags;
    context.architecture = header.architectureIsX64 ? VM_ARCH_X64 : VM_ARCH_X86;

    const auto entry = reinterpret_cast<ContextEntry>(loaded.Base() + header.contextEntryOffset);
    DWORD exceptionCode = 0;
    uintptr_t exceptionAddress = 0;
    std::array<uint64_t, 16> faultGpr{};
    uint64_t faultRflags = 0;
    const uint32_t runtimeError = InvokeContextEntry(entry, &context,
        header.familyToVregSlot, header.architectureIsX64 != 0,
        &exceptionCode, &exceptionAddress, &faultGpr, &faultRflags);

    outcome.vmExecuted = true;
    outcome.vmFaulted = exceptionCode != 0;
    outcome.vmExceptionCode = exceptionCode;
    outcome.vmFaultOffset = exceptionCode != 0
        ? exceptionAddress - reinterpret_cast<uintptr_t>(loaded.Base()) : 0;
    outcome.vmRuntimeError = (context.error != VM_MICRO_ERR_NONE)
        ? context.error : runtimeError;
    outcome.vmCurrentSemantic = context.currentSemantic;
    outcome.vmCurrentVariant = context.currentVariant;
    outcome.vmVipOffset = context.vip - context.bytecodeBegin;
    if (!outcome.vmFaulted) {
        for (uint8_t family = 0; family < 16; ++family) {
            const uint8_t slot = header.familyToVregSlot[family];
            uint64_t value = context.vregs[slot];
            if (!header.architectureIsX64) value &= 0xFFFFFFFFu;
            outcome.vmFinalGpr[family] = value;
        }
        outcome.vmFinalRflags = header.architectureIsX64
            ? context.virtualFlags : (context.virtualFlags & 0xFFFFFFFFu);
    } else {
        outcome.vmFaultGpr = faultGpr;
        outcome.vmFaultRflags = faultRflags;
    }
    outcome.vmFinalMemory.assign(corpusMemory, corpusMemory + header.memorySize);
    return true;
}

} // namespace

bool RunNativeDifferentialWorkerCase(
    const VMNativeDifferentialRequestHeader& header,
    const uint8_t* nativeCode,
    const VMNativeDifferentialCodeFixup* nativeCodeFixups,
    const uint8_t* corpusMemory,
    const uint8_t* vmBytecode,
    const uint8_t* handlerImage,
    const VMNativeDifferentialRelocation* handlerRelocations,
    const VMNativeDifferentialUnwindEntry* handlerUnwindEntries,
    VMNativeDifferentialWorkerOutcome& outcome,
    std::string& error)
{
    outcome = VMNativeDifferentialWorkerOutcome{};
    if (header.memorySize < 0x1000u ||
        header.memorySize > VM_NATIVE_DIFFERENTIAL_MAX_MEMORY_SIZE ||
        (header.nativeCodeFixupsCount != 0u && !nativeCodeFixups) ||
        (!header.architectureIsX64 &&
         (header.memoryBase > (std::numeric_limits<uint32_t>::max)() ||
          header.memorySize + 16u >
            (std::numeric_limits<uint32_t>::max)() - header.memoryBase))) {
        error = "native differential worker received an invalid corpus/fixup range";
        return false;
    }

    void* nativeMemory = VirtualAlloc(
        reinterpret_cast<void*>(static_cast<uintptr_t>(header.memoryBase)),
        header.memorySize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!nativeMemory) {
        error = "native differential worker could not reserve the corpus arena for the "
            "native run at the address the corpus was generated against";
        return false;
    }
    std::memcpy(nativeMemory, corpusMemory, header.memorySize);
    if (!RunNativeHalf(header, nativeCode, nativeCodeFixups,
            static_cast<uint8_t*>(nativeMemory), outcome, error)) {
        VirtualFree(nativeMemory, 0, MEM_RELEASE);
        return false;
    }
    VirtualFree(nativeMemory, 0, MEM_RELEASE);

    // +16: scratch for the VirtualProtect/FlushInstructionCache pointers the
    // synthesized decryptor fetches via [imageBase + IatRVA]; see RunVmHalf.
    void* vmMemory = VirtualAlloc(
        reinterpret_cast<void*>(static_cast<uintptr_t>(header.memoryBase)),
        static_cast<size_t>(header.memorySize) + 16u, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!vmMemory) {
        error = "native differential worker could not reserve the corpus arena for the "
            "VM run at the address the corpus was generated against";
        return false;
    }
    std::memcpy(vmMemory, corpusMemory, header.memorySize);
    if (!RunVmHalf(header, vmBytecode, static_cast<uint8_t*>(vmMemory), handlerImage,
            handlerRelocations, handlerUnwindEntries, outcome, error)) {
        VirtualFree(vmMemory, 0, MEM_RELEASE);
        return false;
    }
    VirtualFree(vmMemory, 0, MEM_RELEASE);
    return true;
}

#else // !_WIN32

bool RunNativeDifferentialWorkerCase(
    const VMNativeDifferentialRequestHeader&,
    const uint8_t*,
    const VMNativeDifferentialCodeFixup*,
    const uint8_t*,
    const uint8_t*,
    const uint8_t*,
    const VMNativeDifferentialRelocation*,
    const VMNativeDifferentialUnwindEntry*,
    VMNativeDifferentialWorkerOutcome&,
    std::string& error)
{
    error = "native differential worker is Windows-only";
    return false;
}

#endif // _WIN32

} // namespace CipherShell
