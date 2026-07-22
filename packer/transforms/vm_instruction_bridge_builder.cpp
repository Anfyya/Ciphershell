#include "vm_instruction_bridge_builder.h"

#include "../analysis/disassembler.h"
#include "../pe_parser/pe_utils.h"
#include "../vm/vm_schema.h"
#include "../../runtime/common/vm_micro_runtime_abi.h"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <limits>
#include <unordered_set>

namespace CipherShell {
namespace {

// Returns UINT32_MAX (never a value a real caller could legitimately land on
// -- blob sizes here stay far below 4 GiB) to signal overflow/misuse.  An
// earlier version returned 0 for both "already aligned to offset 0" (the
// correct result for the very first thunk in an empty blob) and "overflow",
// which made every Build() call with at least one bridge request fail
// immediately with a false "thunk layout overflow": AlignUp(0, 16) computes
// (0 + 15) & ~15 == 0 through the normal, non-error path, and the caller's
// `if (aligned == 0)` treated that legitimate zero the same as the error
// sentinel.  See docs/zydis_encoder_pilot.md batch 16.
uint32_t AlignUp(uint32_t value, uint32_t alignment) {
    if (!alignment || value > std::numeric_limits<uint32_t>::max() - (alignment - 1u))
        return std::numeric_limits<uint32_t>::max();
    return (value + alignment - 1u) & ~(alignment - 1u);
}

// Checked helpers used throughout Build(): every RVA/offset/size computed
// from data that is not a compile-time-bounded constant (blob accumulation
// across an arbitrary number of bridge requests; RVAs composed from a
// PEEmitter-reported section RVA and a caller-supplied instruction's
// displacementOffset) must go through one of these instead of a raw
// static_cast/`+`, and fail closed on overflow rather than silently wrap.
// See docs/zydis_encoder_pilot.md batch 17.
bool CheckedAddU32(uint32_t left, uint32_t right, uint32_t& result) {
    const uint64_t sum = static_cast<uint64_t>(left) + static_cast<uint64_t>(right);
    if (sum > std::numeric_limits<uint32_t>::max()) return false;
    result = static_cast<uint32_t>(sum);
    return true;
}

bool CheckedSizeToU32(size_t value, uint32_t& result) {
    if (value > std::numeric_limits<uint32_t>::max()) return false;
    result = static_cast<uint32_t>(value);
    return true;
}

// Register index 4 encodes RSP (x64) / ESP (x86) throughout this codebase's
// GPR numbering (see CtxRegisterMap / MOVZX family lookup in
// vm_handler_semantic_codegen.cpp and BuildX64Thunk/BuildX86Thunk's own local
// kRsp/kEsp aliases below).  It can never be a legal hiddenNativeRegister:
// both thunk builders need a *separate* register that stays live across the
// whole thunk holding the pointer to `state`, distinct from the actual
// stack pointer, which is independently threaded through its own
// state.hostStack / state.gpr[4] slots and used directly by
// PushMemory/PopMemory/PushFlags/PopFlags/Ret throughout the thunk body. If
// hidden aliased the stack pointer, moving the state pointer into it at
// thunk entry would overwrite the live stack pointer for every one of those
// push/pop/ret instructions in the same thunk. This was never reachable
// through the real translator (LowerExtendedBridge's candidate lists never
// contain register 4), which is exactly why Build() must reject it
// independently rather than trust that invariant implicitly. See
// docs/zydis_encoder_pilot.md batch 17.
constexpr uint8_t kBridgeReservedStackPointerRegister = 4u;

class CodeBuffer {
public:
    std::vector<uint8_t> bytes;
    void U8(uint8_t value) { bytes.push_back(value); }
    void U32(uint32_t value) {
        for (uint32_t i = 0; i < 4; ++i) U8(static_cast<uint8_t>(value >> (i * 8u)));
    }
    void Raw(const uint8_t* data, size_t size) { bytes.insert(bytes.end(), data, data + size); }
    uint32_t Offset() const { return static_cast<uint32_t>(bytes.size()); }
};

class X64Assembler : public CodeBuffer {
public:
    void Endbr() { static constexpr uint8_t kCode[] = {0xF3, 0x0F, 0x1E, 0xFA}; Raw(kCode, sizeof(kCode)); }
    void Rex(bool width64, uint8_t reg, uint8_t base) {
        const uint8_t rex = static_cast<uint8_t>(0x40u | (width64 ? 8u : 0u) |
            (reg >= 8 ? 4u : 0u) | (base >= 8 ? 1u : 0u));
        if (rex != 0x40u) U8(rex);
    }
    void MemoryInstruction(uint8_t opcode, uint8_t regField, uint8_t base,
                           uint32_t displacement, bool width64 = true) {
        Rex(width64, regField, base);
        U8(opcode);
        U8(static_cast<uint8_t>(0x80u | ((regField & 7u) << 3u) | (base & 7u)));
        if ((base & 7u) == 4u) U8(0x24);
        U32(displacement);
    }
    void Store(uint8_t base, uint32_t displacement, uint8_t reg) {
        MemoryInstruction(0x89, reg, base, displacement);
    }
    void Load(uint8_t reg, uint8_t base, uint32_t displacement) {
        MemoryInstruction(0x8B, reg, base, displacement);
    }
    void Move(uint8_t destination, uint8_t source) {
        Rex(true, source, destination);
        U8(0x89);
        U8(static_cast<uint8_t>(0xC0u | ((source & 7u) << 3u) | (destination & 7u)));
    }
    void PushMemory(uint8_t base, uint32_t displacement) {
        Rex(false, 0, base);
        U8(0xFF);
        U8(static_cast<uint8_t>(0xB0u | (base & 7u)));
        if ((base & 7u) == 4u) U8(0x24);
        U32(displacement);
    }
    void PopMemory(uint8_t base, uint32_t displacement) {
        Rex(false, 0, base);
        U8(0x8F);
        U8(static_cast<uint8_t>(0x80u | (base & 7u)));
        if ((base & 7u) == 4u) U8(0x24);
        U32(displacement);
    }
    void PushFlags() { U8(0x9C); }
    void PopFlags() { U8(0x9D); }
    void MovEax(uint32_t value) { U8(0xB8); U32(value); }
    void XorEdx() { U8(0x31); U8(0xD2); }
    void Extended(uint8_t base, uint8_t operation, bool width64) {
        Rex(width64, 0, base);
        U8(0x0F); U8(0xAE);
        U8(static_cast<uint8_t>((operation << 3u) | (base & 7u)));
    }
    void Fxrstor(uint8_t base) { Extended(base, 1, true); }
    void Fxsave(uint8_t base) { Extended(base, 0, true); }
    void Xrstor(uint8_t base) { Extended(base, 5, true); }
    void Xsave(uint8_t base) { Extended(base, 4, true); }
    void Ret() { U8(0xC3); }
};

class X86Assembler : public CodeBuffer {
public:
    void Endbr() { static constexpr uint8_t kCode[] = {0xF3, 0x0F, 0x1E, 0xFB}; Raw(kCode, sizeof(kCode)); }
    void MemoryInstruction(uint8_t opcode, uint8_t regField, uint8_t base, uint32_t displacement) {
        U8(opcode);
        U8(static_cast<uint8_t>(0x80u | ((regField & 7u) << 3u) | (base & 7u)));
        if ((base & 7u) == 4u) U8(0x24);
        U32(displacement);
    }
    void Store(uint8_t base, uint32_t displacement, uint8_t reg) {
        MemoryInstruction(0x89, reg, base, displacement);
    }
    void Load(uint8_t reg, uint8_t base, uint32_t displacement) {
        MemoryInstruction(0x8B, reg, base, displacement);
    }
    void Move(uint8_t destination, uint8_t source) {
        U8(0x89);
        U8(static_cast<uint8_t>(0xC0u | ((source & 7u) << 3u) | (destination & 7u)));
    }
    void LoadStateFromStack() { U8(0x8B); U8(0x4C); U8(0x24); U8(0x04); }
    void PushMemory(uint8_t base, uint32_t displacement) {
        U8(0xFF); U8(static_cast<uint8_t>(0xB0u | (base & 7u)));
        if ((base & 7u) == 4u) U8(0x24);
        U32(displacement);
    }
    void PopMemory(uint8_t base, uint32_t displacement) {
        U8(0x8F); U8(static_cast<uint8_t>(0x80u | (base & 7u)));
        if ((base & 7u) == 4u) U8(0x24);
        U32(displacement);
    }
    void PushFlags() { U8(0x9C); }
    void PopFlags() { U8(0x9D); }
    void MovEax(uint32_t value) { U8(0xB8); U32(value); }
    void XorEdx() { U8(0x31); U8(0xD2); }
    void Extended(uint8_t base, uint8_t operation) {
        U8(0x0F); U8(0xAE);
        U8(static_cast<uint8_t>((operation << 3u) | (base & 7u)));
    }
    void Fxrstor(uint8_t base) { Extended(base, 1); }
    void Fxsave(uint8_t base) { Extended(base, 0); }
    void Xrstor(uint8_t base) { Extended(base, 5); }
    void Xsave(uint8_t base) { Extended(base, 4); }
    void Ret() { U8(0xC3); }
};

struct BuiltThunk {
    std::vector<uint8_t> code;
    uint32_t nativeOffset = 0;
    uint32_t unwindBeginOffset = 0;
};

// Restores the host's non-volatile GPRs from state.hostNonvolatile[].  If
// `hidden` (which still holds the live pointer to `state` at this point) is
// itself one of the non-volatile registers, its own slot must be restored
// *last*: overwriting it mid-loop would destroy the base pointer every later
// iteration in the same loop still needs. Before this fix, a `hidden` value
// equal to any non-last kNonvolatile member (any of them but the highest
// index) clobbered the state pointer partway through, so every subsequent
// register in the loop was loaded through a bogus base address --
// unmapped-address crash or, worse, a silent wrong-register-value return to
// the host thread, entirely independent of the caller/architecture's
// register-index numbering. This was never reachable through the real
// translator (LowerExtendedBridge's fixed candidate lists never select a
// non-volatile register as hidden), which is exactly why it went unnoticed:
// no test ever drove VMInstructionBridgeBuilder::Build with such a value
// until this batch. See docs/zydis_encoder_pilot.md batch 17.
template <typename Assembler, size_t N>
void RestoreHostNonvolatile(
    Assembler& assembler,
    const std::array<uint8_t, N>& nonvolatile,
    uint8_t hidden,
    uint32_t hostNonvolatileBase)
{
    size_t hiddenIndex = nonvolatile.size();
    for (size_t i = 0; i < nonvolatile.size(); ++i) {
        if (nonvolatile[i] == hidden) { hiddenIndex = i; continue; }
        assembler.Load(nonvolatile[i], hidden,
            hostNonvolatileBase + static_cast<uint32_t>(i) * 8u);
    }
    if (hiddenIndex < nonvolatile.size()) {
        assembler.Load(hidden, hidden,
            hostNonvolatileBase + static_cast<uint32_t>(hiddenIndex) * 8u);
    }
}

BuiltThunk BuildX64Thunk(const VMBridgeRequest& request, uint8_t originalPrologSize) {
    constexpr uint8_t kRsp = 4;
    constexpr uint8_t kStateArgument = 1;
    constexpr std::array<uint8_t, 8> kNonvolatile = {3, 5, 6, 7, 12, 13, 14, 15};
    const uint8_t hidden = request.hiddenNativeRegister;
    const uint8_t extendedTemp = hidden == 10 ? 11 : 10;
    X64Assembler assembler;
    assembler.Endbr();
    for (size_t i = 0; i < kNonvolatile.size(); ++i) {
        assembler.Store(kStateArgument,
            static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, hostNonvolatile) + i * 8u),
            kNonvolatile[i]);
    }
    assembler.Store(kStateArgument,
        static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, hostStack)), kRsp);
    if (hidden != kStateArgument) assembler.Move(hidden, kStateArgument);

    assembler.Load(extendedTemp, hidden,
        static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, extendedState)));
    if (request.usesAvx) {
        assembler.MovEax(7); assembler.XorEdx(); assembler.Xrstor(extendedTemp);
    } else assembler.Fxrstor(extendedTemp);

    for (uint8_t reg = 0; reg < 16; ++reg) {
        if (reg == hidden || reg == kRsp) continue;
        assembler.Load(reg, hidden,
            static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, gpr) + reg * 8u));
    }
    assembler.PushMemory(hidden,
        static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, rflags)));
    assembler.PopFlags();
    assembler.Load(kRsp, hidden,
        static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, gpr) + kRsp * 8u));
    const uint32_t unwindBeginOffset = assembler.Offset();
    for (uint32_t i = 0; i <= originalPrologSize; ++i) assembler.U8(0x90);
    const uint32_t nativeOffset = assembler.Offset();
    assembler.Raw(request.instruction.rawBytes.data(), request.instruction.length);
    assembler.Store(hidden,
        static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, gpr) + kRsp * 8u), kRsp);
    assembler.Load(kRsp, hidden,
        static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, hostStack)));
    assembler.PushFlags();
    assembler.PopMemory(hidden,
        static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, rflags)));
    for (uint8_t reg = 0; reg < 16; ++reg) {
        if (reg == hidden || reg == kRsp) continue;
        assembler.Store(hidden,
            static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, gpr) + reg * 8u), reg);
    }
    assembler.Load(extendedTemp, hidden,
        static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, extendedState)));
    if (request.usesAvx) {
        assembler.MovEax(7); assembler.XorEdx(); assembler.Xsave(extendedTemp);
    } else assembler.Fxsave(extendedTemp);
    RestoreHostNonvolatile(assembler, kNonvolatile, hidden,
        static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, hostNonvolatile)));
    assembler.Ret();
    return {std::move(assembler.bytes), nativeOffset, unwindBeginOffset};
}

BuiltThunk BuildX86Thunk(const VMBridgeRequest& request) {
    constexpr uint8_t kEsp = 4;
    constexpr uint8_t kInitialState = 1;
    constexpr std::array<uint8_t, 4> kNonvolatile = {3, 5, 6, 7};
    const uint8_t hidden = request.hiddenNativeRegister;
    // Same reasoning as BuildX64Thunk's extendedTemp: must never alias
    // `hidden`, which is still the live pointer to `state` at every point
    // this temp register is used.  Before this fix, kExtendedTemp was the
    // fixed constant 6 (ESI): a request with hiddenNativeRegister == 6 would
    // silently overwrite the state pointer with state.extendedState's own
    // *value* (a guest buffer address) the first time it was used, so every
    // GPR the thunk "restored" afterward was read through that unrelated
    // address instead of `state.gpr[]` -- wrong values returned to the
    // guest/host with no crash to signal it. Unreachable through the real
    // translator today (LowerExtendedBridge's x86 candidates are {2,1,0}),
    // caught only because this batch's Build()-level tests drive the
    // Builder directly instead of only through the translator's narrow
    // candidate list. See docs/zydis_encoder_pilot.md batch 17.
    const uint8_t kExtendedTemp = hidden == 6u ? 7u : 6u;
    X86Assembler assembler;
    assembler.Endbr();
    assembler.LoadStateFromStack();
    for (size_t i = 0; i < kNonvolatile.size(); ++i) {
        assembler.Store(kInitialState,
            static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, hostNonvolatile) + i * 8u),
            kNonvolatile[i]);
    }
    assembler.Store(kInitialState,
        static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, hostStack)), kEsp);
    if (hidden != kInitialState) assembler.Move(hidden, kInitialState);
    assembler.Load(kExtendedTemp, hidden,
        static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, extendedState)));
    if (request.usesAvx) {
        assembler.MovEax(7); assembler.XorEdx(); assembler.Xrstor(kExtendedTemp);
    } else assembler.Fxrstor(kExtendedTemp);
    for (uint8_t reg = 0; reg < 8; ++reg) {
        if (reg == hidden || reg == kEsp) continue;
        assembler.Load(reg, hidden,
            static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, gpr) + reg * 8u));
    }
    assembler.PushMemory(hidden,
        static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, rflags)));
    assembler.PopFlags();
    assembler.Load(kEsp, hidden,
        static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, gpr) + kEsp * 8u));
    const uint32_t nativeOffset = assembler.Offset();
    assembler.Raw(request.instruction.rawBytes.data(), request.instruction.length);
    assembler.Store(hidden,
        static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, gpr) + kEsp * 8u), kEsp);
    assembler.Load(kEsp, hidden,
        static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, hostStack)));
    assembler.PushFlags();
    assembler.PopMemory(hidden,
        static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, rflags)));
    for (uint8_t reg = 0; reg < 8; ++reg) {
        if (reg == hidden || reg == kEsp) continue;
        assembler.Store(hidden,
            static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, gpr) + reg * 8u), reg);
    }
    assembler.Load(kExtendedTemp, hidden,
        static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, extendedState)));
    if (request.usesAvx) {
        assembler.MovEax(7); assembler.XorEdx(); assembler.Xsave(kExtendedTemp);
    } else assembler.Fxsave(kExtendedTemp);
    RestoreHostNonvolatile(assembler, kNonvolatile, hidden,
        static_cast<uint32_t>(offsetof(VM_INSTRUCTION_BRIDGE_STATE, hostNonvolatile)));
    assembler.Ret();
    return {std::move(assembler.bytes), nativeOffset, nativeOffset};
}

bool ReadSimpleUnwind(
    const CS_PE_IMAGE* image,
    const Function& function,
    const InstructionIR& instruction,
    std::vector<uint8_t>& unwind,
    uint8_t& prologSizeOut,
    std::string& error)
{
    const CS_RUNTIME_FUNCTION* runtimeFunction = nullptr;
    for (const auto& entry : image->exceptions.entries) {
        if (entry.beginAddress == function.entryAddress &&
            entry.endAddress >= function.entryAddress + function.size) {
            runtimeFunction = &entry;
            break;
        }
    }
    if (!runtimeFunction) {
        error = "bridge source function has no exact x64 runtime-function entry";
        return false;
    }
    const uint32_t offset = PEUtils::RvaToOffset(image, runtimeFunction->unwindData);
    if (offset == 0 || offset > image->rawSize || 4u > image->rawSize - offset) {
        error = "bridge source unwind header is outside the PE file";
        return false;
    }
    const uint8_t versionAndFlags = image->rawData[offset];
    const uint8_t version = versionAndFlags & 7u;
    const uint8_t flags = versionAndFlags >> 3u;
    const uint8_t prologSize = image->rawData[offset + 1u];
    const uint8_t codeCount = image->rawData[offset + 2u];
    // CapabilityChecker 已在函数级拒绝 V2；桥接重建器仍保留同样的本地防线，避免未来
    // 调用路径绕过 CapabilityChecker 后把 V2 epilog 元数据按 V1 原样复制。
    if (version < PEUtils::kParserUnwindInfoMinVersion ||
        version > PEUtils::kVmUnwindInfoMaxVersion || flags != 0u) {
        if (version == 2u) {
            error = "bridge source uses unsupported x64 unwind version 2 epilog semantics";
            return false;
        }
        error = "bridge source unwind uses handlers or chained metadata";
        return false;
    }
    if (instruction.rva < function.entryAddress ||
        instruction.rva - function.entryAddress < prologSize) {
        error = "extended-state instruction is inside the original x64 prolog";
        return false;
    }
    const size_t unwindSize = 4u + static_cast<size_t>((codeCount + 1u) & ~1u) * 2u;
    if (unwindSize > image->rawSize - offset) {
        error = "bridge source unwind codes are truncated";
        return false;
    }
    unwind.assign(image->rawData + offset, image->rawData + offset + unwindSize);
    prologSizeOut = prologSize;
    return true;
}

bool RipTarget(const InstructionIR& instruction, bool& hasTarget,
               uint32_t& targetRVA, std::string& error) {
    hasTarget = false;
    targetRVA = 0;
    for (const auto& operand : instruction.operands) {
        if (operand.type != OperandType::Memory || !operand.memory.isRipRelative) continue;
        if (hasTarget && targetRVA != operand.memory.resolvedRVA) {
            error = "bridge instruction contains inconsistent RIP-relative targets";
            return false;
        }
        hasTarget = true;
        targetRVA = operand.memory.resolvedRVA;
    }
    return true;
}

struct PendingThunk {
    size_t translationIndex = 0;
    size_t requestIndex = 0;
    uint32_t thunkOffset = 0;
    uint32_t thunkSize = 0;
    uint32_t nativeOffset = 0;
    uint32_t unwindBeginOffset = 0;
    uint32_t unwindOffset = 0;
};

// Point-in-time copy of everything Build() might mutate on `image`, taken
// immediately before the first call that can actually change it
// (PEEmitter::AppendSection).  `bytes` is an independent heap copy of the
// raw file image (not just the pointer -- AppendSection frees and replaces
// `image->rawData` on success, so a snapshot that merely aliased the old
// pointer would dangle the moment that happens).  `fields` is a plain struct
// copy of *image: every std::vector/std::string member is deep-copied by its
// own copy constructor, so this alone is enough to faithfully restore
// imports/exports/relocs/resources/tls/exceptions/loadConfig/debugDir/
// delayImports/filePath/etc. -- the only fields that must NOT be copied back
// verbatim are the handful of raw pointers that alias into the byte buffer
// (rawData itself, dosHeader, ntHeaders64/32, sections), because by the time
// a restore is needed those addresses may already have been freed by a
// mutation that ran (and succeeded) before the one that ultimately failed.
struct BuildImageSnapshot {
    std::vector<uint8_t> bytes;
    CS_PE_IMAGE fields;
};

BuildImageSnapshot CaptureImageSnapshot(const CS_PE_IMAGE* image) {
    BuildImageSnapshot snapshot;
    snapshot.bytes.assign(image->rawData, image->rawData + image->rawSize);
    snapshot.fields = *image;
    return snapshot;
}

// Puts *image back into exactly the state CaptureImageSnapshot observed --
// same bytes, same parsed metadata, same non-byte-backed fields such as
// filePath -- so that a Build() call that fails after already having
// appended a section (or further, after having rebuilt the exception
// directory / Guard CF table too) is completely invisible to the caller.
//
// A plain reparse of the snapshot bytes via PEParser::LoadFromBuffer was
// considered instead of this struct-copy-plus-pointer-fixup approach: it was
// rejected because it would silently drop any field a caller had set
// in-memory on *image without a corresponding on-disk representation (today
// only filePath, but the contract must not depend on that remaining true) --
// a full struct snapshot has no such gap because it copies whatever was
// actually there, byte for byte and field for field, rather than
// re-deriving a plausible approximation of it from the file bytes alone.
void RestoreImageSnapshot(CS_PE_IMAGE* image, const BuildImageSnapshot& snapshot) {
    BYTE* restored = new(std::nothrow) BYTE[snapshot.bytes.size()];
    if (!restored) {
        // Cannot honor the "left completely unchanged" guarantee without
        // memory to hold a copy of what it used to be. Fail closed: mark the
        // image unusable rather than risk the caller treating a
        // partially-mutated image as if it were the pristine original.
        image->isValid = FALSE;
        image->errorMessage =
            "VM_BRIDGE: out of memory while rolling back a failed Build() call";
        return;
    }
    std::memcpy(restored, snapshot.bytes.data(), snapshot.bytes.size());
    delete[] image->rawData;
    *image = snapshot.fields;
    image->rawData = restored;
    image->rawSize = static_cast<DWORD>(snapshot.bytes.size());
    // The struct copy above carried over dosHeader/ntHeaders64/ntHeaders32/
    // sections pointer *values* from the snapshot, which pointed into the
    // buffer that existed at CaptureImageSnapshot time -- already freed by
    // the `delete[]` two lines up if any mutation had reallocated rawData.
    // Re-derive them against the freshly (re)allocated, byte-identical
    // buffer instead of trusting the copied values, mirroring exactly what
    // PEEmitter::RefreshPointers does after AppendSection replaces rawData.
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(restored);
    const uint32_t ntOffset = static_cast<uint32_t>(dos->e_lfanew);
    image->dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(restored);
    if (image->is64Bit) {
        image->ntHeaders64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(restored + ntOffset);
        image->ntHeaders32 = nullptr;
        image->sections = IMAGE_FIRST_SECTION(image->ntHeaders64);
    } else {
        image->ntHeaders32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(restored + ntOffset);
        image->ntHeaders64 = nullptr;
        image->sections = IMAGE_FIRST_SECTION(image->ntHeaders32);
    }
}

} // namespace

VMInstructionBridgeBuildResult VMInstructionBridgeBuilder::Build(
    CS_PE_IMAGE* image,
    const std::vector<Function>& functions,
    std::vector<TranslationResult>& translations,
    const char sectionName[8],
    const char unwindSectionName[8],
    const char guardSectionName[8])
{
    VMInstructionBridgeBuildResult result{};
    if (!image || !image->isValid || functions.size() != translations.size() ||
        !sectionName || !unwindSectionName || !guardSectionName) {
        result.error = "VM_BRIDGE: invalid image, program list, or section names";
        return result;
    }
    size_t requestCount = 0;
    for (const auto& translation : translations) requestCount += translation.bridgeRequests.size();
    if (requestCount == 0) {
        result.success = result.cfgTableVerified = result.unwindVerified = true;
        return result;
    }

    std::vector<uint8_t> blob;
    std::vector<PendingThunk> pending;
    pending.reserve(requestCount);
    // Bytecode edits are staged here rather than applied to `translations`
    // directly as each request passes its own checks: Build() must guarantee
    // `translations` is left completely untouched on any failure, including
    // one discovered while validating a *later* request after an *earlier*
    // one already passed every check that precedes this point. The staged
    // edits are only ever committed after every fallible step in this
    // function -- including every PEEmitter call below -- has already
    // succeeded; see the single commit loop at the very end.
    struct StagedBytecodeEdit {
        size_t translationIndex = 0;
        size_t microOpIndex = 0;
        uint64_t operand0 = 0;
        uint64_t operand1 = 0;
    };
    std::vector<StagedBytecodeEdit> stagedEdits;
    stagedEdits.reserve(requestCount);

    for (size_t functionIndex = 0; functionIndex < translations.size(); ++functionIndex) {
        auto& translation = translations[functionIndex];
        for (size_t requestIndex = 0; requestIndex < translation.bridgeRequests.size(); ++requestIndex) {
            const auto& request = translation.bridgeRequests[requestIndex];
            if (request.functionRVA != functions[functionIndex].entryAddress ||
                request.microOpIndex >= translation.instructions.size() ||
                request.hiddenNativeRegister >= (image->is64Bit ? 16u : 8u) ||
                (image->is64Bit && request.instruction.machineMode != MachineMode::X64) ||
                (!image->is64Bit && request.instruction.machineMode != MachineMode::X86)) {
                result.error = "VM_BRIDGE: request does not match its function or target architecture";
                return result;
            }
            // Tighten the Builder's own input contract independently of
            // whatever the current translator happens to produce: register 4
            // (RSP/ESP) can never be a safe hidden register (see
            // kBridgeReservedStackPointerRegister's comment above the
            // thunk builders), and the extracted instruction's declared
            // length must actually fit the fixed 15-byte rawBytes array it
            // is read from -- BuildX64Thunk/BuildX86Thunk copy exactly
            // `length` bytes out of `rawBytes` with no bounds check of their
            // own, so an unchecked oversized length here would read past the
            // end of a stack-resident std::array before any later check ever
            // runs.
            if (request.hiddenNativeRegister == kBridgeReservedStackPointerRegister) {
                result.error = "VM_BRIDGE: hidden register cannot be the stack pointer";
                return result;
            }
            if (request.instruction.length == 0 ||
                request.instruction.length > request.instruction.rawBytes.size()) {
                result.error = "VM_BRIDGE: extracted instruction length is invalid";
                return result;
            }
            uint32_t blobSizeU32 = 0;
            if (!CheckedSizeToU32(blob.size(), blobSizeU32)) {
                result.error = "VM_BRIDGE: thunk layout exceeds addressable size";
                return result;
            }
            const uint32_t aligned = AlignUp(blobSizeU32, 16u);
            if (aligned == std::numeric_limits<uint32_t>::max()) {
                result.error = "VM_BRIDGE: thunk layout overflow";
                return result;
            }
            blob.resize(aligned, 0x90);
            std::vector<uint8_t> unwind;
            uint8_t originalPrologSize = 0;
            if (image->is64Bit && !ReadSimpleUnwind(image, functions[functionIndex],
                    request.instruction, unwind, originalPrologSize, result.error)) {
                result.error = "VM_BRIDGE: " + result.error;
                return result;
            }
            BuiltThunk built = image->is64Bit
                ? BuildX64Thunk(request, originalPrologSize) : BuildX86Thunk(request);
            if (built.code.empty() || built.nativeOffset >= built.code.size() ||
                request.instruction.length > built.code.size() - built.nativeOffset) {
                result.error = "VM_BRIDGE: generated thunk has an invalid native instruction range";
                return result;
            }
            PendingThunk item{};
            item.translationIndex = functionIndex;
            item.requestIndex = requestIndex;
            item.thunkOffset = aligned;
            uint32_t thunkSizeU32 = 0;
            if (!CheckedSizeToU32(built.code.size(), thunkSizeU32)) {
                result.error = "VM_BRIDGE: generated thunk size exceeds addressable size";
                return result;
            }
            item.thunkSize = thunkSizeU32;
            if (!CheckedAddU32(aligned, built.nativeOffset, item.nativeOffset) ||
                !CheckedAddU32(aligned, built.unwindBeginOffset, item.unwindBeginOffset)) {
                result.error = "VM_BRIDGE: thunk offset overflow";
                return result;
            }
            blob.insert(blob.end(), built.code.begin(), built.code.end());
            if (image->is64Bit) {
                uint32_t postThunkSizeU32 = 0;
                if (!CheckedSizeToU32(blob.size(), postThunkSizeU32)) {
                    result.error = "VM_BRIDGE: thunk layout exceeds addressable size";
                    return result;
                }
                item.unwindOffset = AlignUp(postThunkSizeU32, 4u);
                if (item.unwindOffset == std::numeric_limits<uint32_t>::max()) {
                    result.error = "VM_BRIDGE: unwind layout overflow";
                    return result;
                }
                blob.resize(item.unwindOffset, 0);
                blob.insert(blob.end(), unwind.begin(), unwind.end());
            }
            pending.push_back(item);
        }
    }

    // From this point on, PEEmitter calls begin mutating `image` for real.
    // Snapshot it now (nothing above this line has touched `image` or
    // `translations`, so every early return above is trivially already
    // "completely unchanged"). Every failure return from here on must route
    // through `fail`, which restores this snapshot before reporting the
    // error, so that a Build() failure discovered after a successful
    // AppendSection/PatchBytes/RebuildExceptionDirectory/
    // RebuildGuardCFFunctionTable is just as invisible to the caller as one
    // discovered before any of them ran.
    const BuildImageSnapshot snapshot = CaptureImageSnapshot(image);
    auto fail = [&](std::string message) -> VMInstructionBridgeBuildResult {
        RestoreImageSnapshot(image, snapshot);
        VMInstructionBridgeBuildResult failed{};
        failed.error = std::move(message);
        return failed;
    };

    PEEmitter emitter(image);
    const auto appended = emitter.AppendSection(sectionName, blob,
        IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ);
    if (!appended.success) {
        return fail("VM_BRIDGE: " + appended.error);
    }

    Disassembler verifier;
    const uint64_t imageBase = PEUtils::ImageBase(image);
    if (!verifier.Initialize(image->is64Bit != 0, imageBase)) {
        return fail("VM_BRIDGE: unable to initialize Zydis bridge verifier");
    }
    std::vector<uint32_t> guardTargets;
    guardTargets.reserve(pending.size());
    for (const auto& item : pending) {
        auto& translation = translations[item.translationIndex];
        const auto& request = translation.bridgeRequests[item.requestIndex];
        bool hasRipTarget = false;
        uint32_t ripTargetRVA = 0;
        if (!RipTarget(request.instruction, hasRipTarget, ripTargetRVA, result.error)) {
            return fail("VM_BRIDGE: " + result.error);
        }
        if (hasRipTarget) {
            const uint64_t nextRVA = static_cast<uint64_t>(appended.rva) + item.nativeOffset +
                request.instruction.length;
            const int64_t displacement = static_cast<int64_t>(ripTargetRVA) -
                static_cast<int64_t>(nextRVA);
            if (displacement < std::numeric_limits<int32_t>::min() ||
                displacement > std::numeric_limits<int32_t>::max()) {
                return fail("VM_BRIDGE: relocated RIP-relative target exceeds disp32");
            }
            uint32_t patchOffset = 0;
            if (!CheckedAddU32(item.nativeOffset, request.instruction.displacementOffset, patchOffset)) {
                return fail("VM_BRIDGE: RIP-relative displacement patch offset overflow");
            }
            if (patchOffset > blob.size() || 4u > blob.size() - patchOffset) {
                return fail("VM_BRIDGE: RIP-relative displacement patch is outside the thunk");
            }
            const int32_t value = static_cast<int32_t>(displacement);
            std::memcpy(blob.data() + patchOffset, &value, sizeof(value));
        }

        const auto decodedInstructions = verifier.Disassemble(blob.data() + item.nativeOffset,
            request.instruction.length, appended.rva + item.nativeOffset);
        if (decodedInstructions.size() != 1 ||
            decodedInstructions.front().length != request.instruction.length ||
            decodedInstructions.front().mnemonicText != request.instruction.mnemonicText ||
            decodedInstructions.front().instructionSet != request.instruction.instructionSet) {
            return fail("VM_BRIDGE: relocated instruction failed Zydis semantic verification");
        }
        const InstructionIR& decoded = decodedInstructions.front();
        if (hasRipTarget) {
            bool decodedHasTarget = false;
            uint32_t decodedTarget = 0;
            if (!RipTarget(decoded, decodedHasTarget, decodedTarget, result.error) ||
                !decodedHasTarget || decodedTarget != ripTargetRVA) {
                return fail("VM_BRIDGE: relocated RIP-relative target changed semantics");
            }
        }

        if (request.microOpIndex >= translation.instructions.size()) {
            return fail("VM_BRIDGE: linked micro-op index is outside translation");
        }
        const MicroInstruction& existingBytecode = translation.instructions[request.microOpIndex];
        if (existingBytecode.opcode != VM_UOP_BRIDGE_EXTENDED || existingBytecode.operandCount != 3) {
            return fail("VM_BRIDGE: linked request does not reference BRIDGE_EXTENDED");
        }
        uint32_t thunkRVA = 0, nativeInstructionRVA = 0, unwindBeginRVA = 0;
        if (!CheckedAddU32(appended.rva, item.thunkOffset, thunkRVA) ||
            !CheckedAddU32(appended.rva, item.nativeOffset, nativeInstructionRVA) ||
            !CheckedAddU32(appended.rva, item.unwindBeginOffset, unwindBeginRVA)) {
            return fail("VM_BRIDGE: relocated thunk RVA overflow");
        }
        MicroInstruction candidateBytecode = existingBytecode;
        candidateBytecode.operands[0] = thunkRVA;
        candidateBytecode.operands[1] |= VM_MICRO_BRIDGE_LINKED;
        std::string schemaError;
        if (!VMSchema::ValidateInstruction(candidateBytecode, translation.registerCount, schemaError)) {
            return fail("VM_BRIDGE: linked bytecode violates schema: " + schemaError);
        }
        VMInstructionBridgeLink link{};
        link.functionRVA = request.functionRVA;
        link.instructionRVA = request.instruction.rva;
        link.thunkRVA = thunkRVA;
        link.thunkSize = item.thunkSize;
        link.nativeInstructionRVA = nativeInstructionRVA;
        link.nativeInstructionSize = request.instruction.length;
        link.unwindBeginRVA = unwindBeginRVA;
        link.hiddenNativeRegister = request.hiddenNativeRegister;
        link.usesAvx = request.usesAvx;
        link.usesX87 = request.usesX87;
        result.links.push_back(link);
        guardTargets.push_back(link.thunkRVA);
        stagedEdits.push_back({item.translationIndex, request.microOpIndex,
            candidateBytecode.operands[0], candidateBytecode.operands[1]});
        if (image->is64Bit) {
            uint32_t nativeInstructionEnd = 0;
            uint32_t unwindDataRVA = 0;
            if (!CheckedAddU32(link.nativeInstructionRVA, link.nativeInstructionSize, nativeInstructionEnd) ||
                !CheckedAddU32(appended.rva, item.unwindOffset, unwindDataRVA)) {
                return fail("VM_BRIDGE: relocated unwind RVA overflow");
            }
            result.unwindEntries.push_back({link.unwindBeginRVA, nativeInstructionEnd, unwindDataRVA});
        }
    }

    if (!emitter.PatchBytes(appended.rva, blob, &result.error)) {
        return fail("VM_BRIDGE: unable to commit relocated thunk section: " + result.error);
    }
    if (image->is64Bit && (!emitter.RebuildExceptionDirectory(
            result.unwindEntries, unwindSectionName, nullptr, &result.error))) {
        return fail("VM_BRIDGE: unable to rebuild bridge exception entries: " + result.error);
    }
    result.unwindVerified = !image->is64Bit ||
        result.unwindEntries.size() == result.links.size();
    if (!emitter.RebuildGuardCFFunctionTable(
            guardTargets, guardSectionName, nullptr, &result.error)) {
        return fail("VM_BRIDGE: unable to rebuild Guard CF target table: " + result.error);
    }
    result.cfgTableVerified = !image->loadConfig.hasCFG;
    if (image->loadConfig.hasCFG) {
        std::unordered_set<uint32_t> guardSet(image->loadConfig.guardFunctionRVAs.begin(),
            image->loadConfig.guardFunctionRVAs.end());
        result.cfgTableVerified = std::all_of(guardTargets.begin(), guardTargets.end(),
            [&](uint32_t rva) { return guardSet.count(rva) != 0; });
    }
    if (!result.cfgTableVerified || !result.unwindVerified) {
        return fail("VM_BRIDGE: CFG or unwind linkage verification failed");
    }

    // Every fallible step has now succeeded -- this is the sole point past
    // which Build() is guaranteed to report success, so it is the only place
    // that may durably mutate `translations`. Everything below is
    // infallible: `stagedEdits` indices were validated against
    // `translation.instructions.size()` above, before `translations` had a
    // chance to change shape again.
    for (const auto& edit : stagedEdits) {
        MicroInstruction& bytecode =
            translations[edit.translationIndex].instructions[edit.microOpIndex];
        bytecode.operands[0] = edit.operand0;
        bytecode.operands[1] = edit.operand1;
    }
    result.sectionRVA = appended.rva;
    result.sectionRawOffset = image->sections[appended.sectionIndex].PointerToRawData;
    result.sectionSize = image->sections[appended.sectionIndex].SizeOfRawData;
    result.success = true;
    return result;
}

} // namespace CipherShell
