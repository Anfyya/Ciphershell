#include "vm_runtime_builder.h"
#include "../pe_parser/pe_emitter.h"
#include <cstring>
#include <limits>
#include <utility>
#include <vector>

namespace CipherShell {

void VMRuntimeBuilder::Emit8(std::vector<uint8_t>& out, uint8_t value) { out.push_back(value); }
void VMRuntimeBuilder::Emit32(std::vector<uint8_t>& out, uint32_t value) {
    out.push_back(static_cast<uint8_t>(value));
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value >> 16));
    out.push_back(static_cast<uint8_t>(value >> 24));
}
size_t VMRuntimeBuilder::Emit32Placeholder(std::vector<uint8_t>& out) {
    size_t pos = out.size();
    Emit32(out, 0);
    return pos;
}
void VMRuntimeBuilder::Patch32(std::vector<uint8_t>& out, size_t pos, uint32_t value) {
    for (int i = 0; i < 4; i++) out[pos + i] = static_cast<uint8_t>(value >> (i * 8));
}
void VMRuntimeBuilder::PatchRel32(std::vector<uint8_t>& out, size_t immPos, size_t target) {
    int32_t disp = static_cast<int32_t>(static_cast<int64_t>(target) - static_cast<int64_t>(immPos + 4));
    Patch32(out, immPos, static_cast<uint32_t>(disp));
}

namespace {
constexpr uint32_t kLocalSize = 0x180;
constexpr uint32_t kVmRegs = 0x000;
constexpr uint32_t kFlagZF = 0x100;
constexpr uint32_t kFlagSF = 0x101;
constexpr uint32_t kFlagCF = 0x102;
constexpr uint32_t kFlagOF = 0x103;
constexpr uint32_t kMemScale = 0x104;
constexpr uint32_t kMemWidth = 0x105;
constexpr uint32_t kMemKind = 0x106;
constexpr uint32_t kMemIndexRaw = 0x107;
constexpr uint32_t kBytecodeSize = 0x108;
constexpr uint32_t kSaveBase = kLocalSize;
constexpr uint32_t kSavedRflags = kLocalSize + 120;
constexpr uint32_t kOrigRsp = kLocalSize + 0x80;

struct Label {
    size_t pos = static_cast<size_t>(-1);
    std::vector<size_t> rel32Fixups;
};

class X64Emitter {
public:
    std::vector<uint8_t> code;

    void U8(uint8_t v) { code.push_back(v); }
    void U32(uint32_t v) {
        code.push_back(static_cast<uint8_t>(v));
        code.push_back(static_cast<uint8_t>(v >> 8));
        code.push_back(static_cast<uint8_t>(v >> 16));
        code.push_back(static_cast<uint8_t>(v >> 24));
    }
    void Bytes(std::initializer_list<uint8_t> bs) { code.insert(code.end(), bs.begin(), bs.end()); }

    void Bind(Label& l) {
        l.pos = code.size();
        for (size_t p : l.rel32Fixups) PatchRel32(p, l.pos);
        l.rel32Fixups.clear();
    }
    void Rel32(Label& l) {
        size_t p = code.size();
        U32(0);
        if (l.pos == static_cast<size_t>(-1)) l.rel32Fixups.push_back(p);
        else PatchRel32(p, l.pos);
    }
    void Jmp(Label& l) { U8(0xE9); Rel32(l); }
    void Call(Label& l) { U8(0xE8); Rel32(l); }
    void Jcc(uint8_t cc, Label& l) { U8(0x0F); U8(static_cast<uint8_t>(0x80 | (cc & 0x0F))); Rel32(l); }

    void MovRdxFromFrame(uint32_t disp) { Bytes({0x48, 0x8B, 0x95}); U32(disp); }
    void MovFrameFromRdx(uint32_t disp) { Bytes({0x48, 0x89, 0x95}); U32(disp); }
    void LeaRdxFrame(uint32_t disp) { Bytes({0x48, 0x8D, 0x95}); U32(disp); }

private:
    void PatchRel32(size_t immPos, size_t target) {
        int64_t rel64 = static_cast<int64_t>(target) - static_cast<int64_t>(immPos + 4);
        int32_t rel = static_cast<int32_t>(rel64);
        for (int i = 0; i < 4; i++) code[immPos + i] = static_cast<uint8_t>(static_cast<uint32_t>(rel) >> (i * 8));
    }
};

uint32_t SaveSlotForNativeReg(uint8_t reg) {
    switch (reg) {
        case 0:  return kSaveBase + 112;
        case 1:  return kSaveBase + 104;
        case 2:  return kSaveBase + 96;
        case 3:  return kSaveBase + 88;
        case 5:  return kSaveBase + 80;
        case 6:  return kSaveBase + 72;
        case 7:  return kSaveBase + 64;
        case 8:  return kSaveBase + 56;
        case 9:  return kSaveBase + 48;
        case 10: return kSaveBase + 40;
        case 11: return kSaveBase + 32;
        case 12: return kSaveBase + 24;
        case 13: return kSaveBase + 16;
        case 14: return kSaveBase + 8;
        case 15: return kSaveBase + 0;
        default: return 0;
    }
}

void EmitReadRegMapToEcx(X64Emitter& e, uint8_t nativeReg) {
    e.Bytes({0x41, 0x0F, 0xB6, 0x48, nativeReg});
    e.Bytes({0x83, 0xE1, 0x1F});
}

void EmitStoreVmRegFromRdxToEcx(X64Emitter& e) { e.Bytes({0x49, 0x89, 0x14, 0xCF}); }
void EmitLoadVmRegToRdxFromEcx(X64Emitter& e) { e.Bytes({0x49, 0x8B, 0x14, 0xCF}); }
void EmitLoadVmRegToRdxFromEbx(X64Emitter& e) { e.Bytes({0x49, 0x8B, 0x14, 0xDF}); }
void EmitLoadVmRegToRaxFromEbx(X64Emitter& e) { e.Bytes({0x49, 0x8B, 0x04, 0xDF}); }
void EmitStoreVmRegFromRaxToEbx(X64Emitter& e) { e.Bytes({0x49, 0x89, 0x04, 0xDF}); }
void EmitStoreVmRegFromRdxToEbx(X64Emitter& e) { e.Bytes({0x49, 0x89, 0x14, 0xDF}); }

void EmitSetccToFrame(X64Emitter& e, uint8_t cc, uint32_t disp) {
    e.U8(0x0F);
    e.U8(static_cast<uint8_t>(0x90 | (cc & 0x0F)));
    e.U8(0x85);
    e.U32(disp);
}

void EmitSetFrameByte(X64Emitter& e, uint32_t disp, uint8_t value) {
    e.Bytes({0xC6, 0x85});
    e.U32(disp);
    e.U8(value);
}

void EmitSetArithmeticFlags(X64Emitter& e) {
    EmitSetccToFrame(e, 0x4, kFlagZF);
    EmitSetccToFrame(e, 0x8, kFlagSF);
    EmitSetccToFrame(e, 0x2, kFlagCF);
    EmitSetccToFrame(e, 0x0, kFlagOF);
}

void EmitSetLogicFlags(X64Emitter& e) {
    EmitSetccToFrame(e, 0x4, kFlagZF);
    EmitSetccToFrame(e, 0x8, kFlagSF);
    EmitSetFrameByte(e, kFlagCF, 0);
    EmitSetFrameByte(e, kFlagOF, 0);
}

void EmitInitFlagFromRdx(X64Emitter& e, uint8_t bit, uint32_t disp) {
    e.Bytes({0x48, 0x0F, 0xBA, 0xE2, bit});
    EmitSetccToFrame(e, 0x2, disp);
}

void EmitFetchDstToEbx(X64Emitter& e, Label& fetchReg) {
    e.Call(fetchReg);
    e.Bytes({0x8B, 0xD9});
}

void EmitInitNativeReg(X64Emitter& e, uint8_t nativeReg) {
    EmitReadRegMapToEcx(e, nativeReg);
    if (nativeReg == 4) e.LeaRdxFrame(kOrigRsp);
    else e.MovRdxFromFrame(SaveSlotForNativeReg(nativeReg));
    EmitStoreVmRegFromRdxToEcx(e);
}

void EmitWriteBackNativeReg(X64Emitter& e, uint8_t nativeReg) {
    if (nativeReg == 4) return;
    EmitReadRegMapToEcx(e, nativeReg);
    EmitLoadVmRegToRdxFromEcx(e);
    e.MovFrameFromRdx(SaveSlotForNativeReg(nativeReg));
}

void EmitCommitFlagsToSavedRflags(X64Emitter& e) {
    Label zf0, sf0, cf0, of0;
    e.MovRdxFromFrame(kSavedRflags);
    e.Bytes({0x48, 0x81, 0xE2}); e.U32(0xFFFFF73Eu); // clear CF/ZF/SF/OF, preserve all other bits.
    e.Bytes({0x80, 0xBD}); e.U32(kFlagCF); e.U8(0x00); e.Jcc(0x4, cf0);
    e.Bytes({0x48, 0x81, 0xCA}); e.U32(0x00000001u);
    e.Bind(cf0);
    e.Bytes({0x80, 0xBD}); e.U32(kFlagZF); e.U8(0x00); e.Jcc(0x4, zf0);
    e.Bytes({0x48, 0x81, 0xCA}); e.U32(0x00000040u);
    e.Bind(zf0);
    e.Bytes({0x80, 0xBD}); e.U32(kFlagSF); e.U8(0x00); e.Jcc(0x4, sf0);
    e.Bytes({0x48, 0x81, 0xCA}); e.U32(0x00000080u);
    e.Bind(sf0);
    e.Bytes({0x80, 0xBD}); e.U32(kFlagOF); e.U8(0x00); e.Jcc(0x4, of0);
    e.Bytes({0x48, 0x81, 0xCA}); e.U32(0x00000800u);
    e.Bind(of0);
    e.MovFrameFromRdx(kSavedRflags);
}

void EmitBinaryRR(X64Emitter& e, Label& fetchReg, uint8_t op1, uint8_t op2, bool logicFlags) {
    EmitFetchDstToEbx(e, fetchReg);
    e.Call(fetchReg);
    EmitLoadVmRegToRaxFromEbx(e);
    EmitLoadVmRegToRdxFromEcx(e);
    e.Bytes({0x48, op1, op2});
    EmitStoreVmRegFromRaxToEbx(e);
    if (logicFlags) EmitSetLogicFlags(e); else EmitSetArithmeticFlags(e);
}

void EmitBinaryRC(X64Emitter& e, Label& fetchReg, Label& fetchImm64, uint8_t op1, uint8_t op2, bool logicFlags) {
    EmitFetchDstToEbx(e, fetchReg);
    e.Call(fetchImm64);
    EmitLoadVmRegToRdxFromEbx(e);
    e.Bytes({0x48, op1, op2});
    EmitStoreVmRegFromRdxToEbx(e);
    if (logicFlags) EmitSetLogicFlags(e); else EmitSetArithmeticFlags(e);
}

void EmitMoveEsiEax(X64Emitter& e) { e.Bytes({0x8B, 0xF0}); }

void EmitConditionalJumpByFlag(X64Emitter& e, Label& fetchImm32, uint32_t flagDisp, bool takeWhenSet, Label& dispatch) {
    Label skip;
    e.Call(fetchImm32);
    e.Bytes({0x80, 0xBD}); e.U32(flagDisp); e.U8(0x00);
    e.Jcc(takeWhenSet ? 0x4 : 0x5, skip);
    EmitMoveEsiEax(e);
    e.Bind(skip);
    e.Jmp(dispatch);
}
}

std::vector<uint8_t> VMRuntimeBuilder::BuildX64RuntimeInterpreter(uint32_t metadataRVA) {
    (void)metadataRVA;
    X64Emitter e;
    e.code.reserve(4096);

    Label fail, restore, writeback, dispatch, foundRecord, recordLoop;
    Label fetchByte, fetchReg, fetchImm32, fetchImm64, fetchOpcode, fetchMemAddress;
    Label memNoBase, memNoIndex, memScaleCheck4, memScaleCheck8, memScaleDone, memNoImageBase;
    Label opNop, opMovRR, opMovRC, opMovRM, opMovMR, opLea;
    Label opAddRR, opAddRC, opSubRR, opSubRC, opAndRR, opAndRC, opOrRR, opOrRC, opXorRR, opXorRC;
    Label opCmpRR, opCmpRC, opTestRR, opTestRC;
    Label opJmp, opJz, opJnz, opJa, opJae, opJb, opJbe, opJg, opJge, opJl, opJle, opRet;
    Label movRmW2, movRmW4, movRmW8, movRmStore;
    Label movMrW2, movMrW4, movMrW8, movMrDone;
    Label jccSkip1, jccSkip2, jccTake1, jccTake2, jccSkip3, jccSkip4, jccSkip5, jccSkip6;

    e.Bytes({0x9C, 0x50, 0x51, 0x52, 0x53, 0x55, 0x56, 0x57});
    e.Bytes({0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53});
    e.Bytes({0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57});
    e.Bytes({0x48, 0x81, 0xEC}); e.U32(kLocalSize);
    e.Bytes({0x48, 0x89, 0xE5});

    e.Bytes({0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00});
    e.Bytes({0x48, 0x8B, 0x58, 0x10});
    e.Bytes({0x41, 0x8B, 0xC3});
    e.Bytes({0x48, 0x01, 0xD8});
    e.Bytes({0x49, 0x89, 0xC4});

    e.Bytes({0x41, 0x8B, 0x04, 0x24});
    e.Bytes({0x41, 0x8B, 0x4C, 0x24, 0x04});
    e.Bytes({0x31, 0xC1});

    e.Bytes({0x8B, 0xD0, 0xC1, 0xC2, 0x03, 0x41, 0x33, 0x54, 0x24, 0x08});
    e.Bytes({0x4D, 0x89, 0xE5, 0x49, 0x01, 0xD5});
    e.Bytes({0x8B, 0xD0, 0xC1, 0xC2, 0x07, 0x41, 0x33, 0x54, 0x24, 0x0C});
    e.Bytes({0x4D, 0x89, 0xE1, 0x49, 0x01, 0xD1});
    e.Bytes({0x8B, 0xD0, 0xC1, 0xC2, 0x0B, 0x41, 0x33, 0x54, 0x24, 0x10});
    e.Bytes({0x4D, 0x89, 0xE0, 0x49, 0x01, 0xD0});
    e.Bytes({0x8B, 0xD0, 0xC1, 0xC2, 0x11, 0x41, 0x33, 0x54, 0x24, 0x14});
    e.Bytes({0x4D, 0x89, 0xE6, 0x49, 0x01, 0xD6});

    e.Bind(recordLoop);
    e.Bytes({0x85, 0xC9}); e.Jcc(0x4, fail);
    e.Bytes({0x41, 0x8B, 0x55, 0x00});
    e.Bytes({0x31, 0xC2});
    e.Bytes({0x44, 0x39, 0xD2});
    e.Jcc(0x4, foundRecord);
    e.Bytes({0x49, 0x83, 0xC5, 0x1C});
    e.Bytes({0xFF, 0xC9});
    e.Jmp(recordLoop);

    e.Bind(foundRecord);
    e.Bytes({0x8B, 0xD0, 0xC1, 0xC2, 0x05, 0x41, 0x33, 0x55, 0x08});
    e.Bytes({0x49, 0x01, 0xD6});
    e.Bytes({0x8B, 0xF8, 0xC1, 0xC7, 0x09, 0x41, 0x33, 0x7D, 0x0C});
    e.Bytes({0x48, 0x89, 0xBD}); e.U32(kBytecodeSize);
    e.Bytes({0x41, 0x89, 0xC3});
    e.Bytes({0x49, 0x89, 0xDC}); // r12 = image base, so RBX can be used as VM dst scratch.

    e.Bytes({0x4C, 0x8D, 0xBD}); e.U32(kVmRegs);
    e.Bytes({0x31, 0xC0, 0xB9, 0x20, 0x00, 0x00, 0x00});
    e.Bytes({0x48, 0x8D, 0xBD}); e.U32(kVmRegs);
    e.Bytes({0xF3, 0x48, 0xAB});

    const uint8_t nativeRegsInit[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    for (uint8_t r : nativeRegsInit) EmitInitNativeReg(e, r);
    e.MovRdxFromFrame(kSavedRflags);
    EmitInitFlagFromRdx(e, 6, kFlagZF);
    EmitInitFlagFromRdx(e, 7, kFlagSF);
    EmitInitFlagFromRdx(e, 0, kFlagCF);
    EmitInitFlagFromRdx(e, 11, kFlagOF);
    e.Bytes({0x48, 0x31, 0xF6});
    e.Jmp(dispatch);

    e.Bind(fetchByte);
    e.Bytes({0x48, 0x3B, 0xB5}); e.U32(kBytecodeSize);
    e.Jcc(0x3, fail);
    e.Bytes({0x41, 0x0F, 0xB6, 0x04, 0x36});
    e.Bytes({0x8B, 0xCE, 0x83, 0xE1, 0x03});
    e.Bytes({0x44, 0x89, 0xDA});
    e.Bytes({0xC1, 0xE1, 0x03, 0xD3, 0xEA});
    e.Bytes({0x30, 0xD0});
    e.Bytes({0x8B, 0xCE, 0x69, 0xC9, 0x83, 0x00, 0x00, 0x00});
    e.Bytes({0x30, 0xC8});
    e.Bytes({0x48, 0xFF, 0xC6});
    e.U8(0xC3);

    e.Bind(fetchReg);
    e.Call(fetchByte);
    e.Bytes({0x0F, 0xB6, 0xC8, 0x83, 0xE1, 0x1F});
    e.U8(0xC3);

    e.Bind(fetchImm32);
    e.Bytes({0x45, 0x31, 0xD2});
    const uint8_t imm32Shifts[] = {0,8,16,24};
    for (uint8_t shift : imm32Shifts) {
        e.Call(fetchByte);
        e.Bytes({0x0F, 0xB6, 0xC0});
        if (shift) e.Bytes({0xC1, 0xE0, shift});
        e.Bytes({0x41, 0x09, 0xC2});
    }
    e.Bytes({0x44, 0x89, 0xD0, 0xC3});

    e.Bind(fetchImm64);
    e.Bytes({0x4D, 0x31, 0xD2});
    const uint8_t imm64Shifts[] = {0,8,16,24,32,40,48,56};
    for (uint8_t shift : imm64Shifts) {
        e.Call(fetchByte);
        e.Bytes({0x48, 0x0F, 0xB6, 0xC0});
        if (shift) e.Bytes({0x48, 0xC1, 0xE0, shift});
        e.Bytes({0x49, 0x09, 0xC2});
    }
    e.Bytes({0x4C, 0x89, 0xD0, 0xC3});

    e.Bind(fetchOpcode);
    e.Call(fetchByte);
    e.Bytes({0x0F, 0xB6, 0xC0});
    e.Bytes({0x41, 0x0F, 0xB6, 0x04, 0x01});
    e.U8(0xC3);

    e.Bind(fetchMemAddress);
    e.Call(fetchByte); e.Bytes({0x0F, 0xB6, 0xF8});
    e.Call(fetchByte); e.Bytes({0x88, 0x85}); e.U32(kMemIndexRaw);
    e.Call(fetchByte); e.Bytes({0x88, 0x85}); e.U32(kMemScale);
    e.Call(fetchByte); e.Bytes({0x88, 0x85}); e.U32(kMemWidth);
    e.Call(fetchByte); e.Bytes({0x88, 0x85}); e.U32(kMemKind);
    e.Call(fetchImm64);
    e.Bytes({0x81, 0xFF}); e.U32(0x000000FFu); e.Jcc(0x4, memNoBase);
    e.Bytes({0x83, 0xE7, 0x1F});
    e.Bytes({0x49, 0x8B, 0x14, 0xFF});
    e.Bytes({0x48, 0x01, 0xD0});
    e.Bind(memNoBase);
    e.Bytes({0x0F, 0xB6, 0x95}); e.U32(kMemIndexRaw);
    e.Bytes({0x81, 0xFA}); e.U32(0x000000FFu); e.Jcc(0x4, memNoIndex);
    e.Bytes({0x83, 0xE2, 0x1F});
    e.Bytes({0x49, 0x8B, 0x14, 0xD7});
    e.Bytes({0x80, 0xBD}); e.U32(kMemScale); e.U8(0x02); e.Jcc(0x5, memScaleCheck4);
    e.Bytes({0x48, 0xD1, 0xE2}); e.Jmp(memScaleDone);
    e.Bind(memScaleCheck4);
    e.Bytes({0x80, 0xBD}); e.U32(kMemScale); e.U8(0x04); e.Jcc(0x5, memScaleCheck8);
    e.Bytes({0x48, 0xC1, 0xE2, 0x02}); e.Jmp(memScaleDone);
    e.Bind(memScaleCheck8);
    e.Bytes({0x80, 0xBD}); e.U32(kMemScale); e.U8(0x08); e.Jcc(0x5, memScaleDone);
    e.Bytes({0x48, 0xC1, 0xE2, 0x03});
    e.Bind(memScaleDone);
    e.Bytes({0x48, 0x01, 0xD0});
    e.Bind(memNoIndex);
    e.Bytes({0x80, 0xBD}); e.U32(kMemKind); e.U8(0x01); e.Jcc(0x5, memNoImageBase);
    e.Bytes({0x4C, 0x01, 0xE0});
    e.Bind(memNoImageBase);
    e.U8(0xC3);

    e.Bind(dispatch);
    e.Call(fetchOpcode);
    const std::pair<uint8_t, Label*> opcodeTargets[] = {
        {static_cast<uint8_t>(VM_NOP), &opNop}, {static_cast<uint8_t>(VM_MOV_RR), &opMovRR}, {static_cast<uint8_t>(VM_MOV_RC), &opMovRC},
        {static_cast<uint8_t>(VM_MOV_RM), &opMovRM}, {static_cast<uint8_t>(VM_MOV_MR), &opMovMR}, {static_cast<uint8_t>(VM_LEA), &opLea},
        {static_cast<uint8_t>(VM_ADD_RR), &opAddRR}, {static_cast<uint8_t>(VM_ADD_RC), &opAddRC}, {static_cast<uint8_t>(VM_SUB_RR), &opSubRR}, {static_cast<uint8_t>(VM_SUB_RC), &opSubRC},
        {static_cast<uint8_t>(VM_AND_RR), &opAndRR}, {static_cast<uint8_t>(VM_AND_RC), &opAndRC}, {static_cast<uint8_t>(VM_OR_RR), &opOrRR}, {static_cast<uint8_t>(VM_OR_RC), &opOrRC},
        {static_cast<uint8_t>(VM_XOR_RR), &opXorRR}, {static_cast<uint8_t>(VM_XOR_RC), &opXorRC},
        {static_cast<uint8_t>(VM_CMP_RR), &opCmpRR}, {static_cast<uint8_t>(VM_CMP_RC), &opCmpRC}, {static_cast<uint8_t>(VM_TEST_RR), &opTestRR}, {static_cast<uint8_t>(VM_TEST_RC), &opTestRC},
        {static_cast<uint8_t>(VM_JMP), &opJmp}, {static_cast<uint8_t>(VM_JZ), &opJz}, {static_cast<uint8_t>(VM_JNZ), &opJnz},
        {static_cast<uint8_t>(VM_JA), &opJa}, {static_cast<uint8_t>(VM_JAE), &opJae}, {static_cast<uint8_t>(VM_JB), &opJb}, {static_cast<uint8_t>(VM_JBE), &opJbe},
        {static_cast<uint8_t>(VM_JG), &opJg}, {static_cast<uint8_t>(VM_JGE), &opJge}, {static_cast<uint8_t>(VM_JL), &opJl}, {static_cast<uint8_t>(VM_JLE), &opJle},
        {static_cast<uint8_t>(VM_RET_VM), &opRet}
    };
    for (auto pair : opcodeTargets) {
        e.Bytes({0x3C, pair.first});
        e.Jcc(0x4, *pair.second);
    }
    e.Jmp(fail);

    e.Bind(opNop); e.Jmp(dispatch);

    e.Bind(opMovRR);
    EmitFetchDstToEbx(e, fetchReg); e.Call(fetchReg);
    EmitLoadVmRegToRdxFromEcx(e); EmitStoreVmRegFromRdxToEbx(e); e.Jmp(dispatch);

    e.Bind(opMovRC);
    EmitFetchDstToEbx(e, fetchReg); e.Call(fetchImm64);
    EmitStoreVmRegFromRaxToEbx(e); e.Jmp(dispatch);

    e.Bind(opMovRM);
    EmitFetchDstToEbx(e, fetchReg);
    e.Call(fetchByte);
    e.Call(fetchMemAddress);
    e.Bytes({0x80, 0xBD}); e.U32(kMemWidth); e.U8(0x01); e.Jcc(0x5, movRmW2);
    e.Bytes({0x0F, 0xB6, 0x10}); e.Jmp(movRmStore);
    e.Bind(movRmW2);
    e.Bytes({0x80, 0xBD}); e.U32(kMemWidth); e.U8(0x02); e.Jcc(0x5, movRmW4);
    e.Bytes({0x0F, 0xB7, 0x10}); e.Jmp(movRmStore);
    e.Bind(movRmW4);
    e.Bytes({0x80, 0xBD}); e.U32(kMemWidth); e.U8(0x04); e.Jcc(0x5, movRmW8);
    e.Bytes({0x8B, 0x10}); e.Jmp(movRmStore);
    e.Bind(movRmW8);
    e.Bytes({0x80, 0xBD}); e.U32(kMemWidth); e.U8(0x08); e.Jcc(0x5, fail);
    e.Bytes({0x48, 0x8B, 0x10});
    e.Bind(movRmStore);
    EmitStoreVmRegFromRdxToEbx(e); e.Jmp(dispatch);

    e.Bind(opMovMR);
    e.Call(fetchByte);
    e.Call(fetchReg); e.Bytes({0x8B, 0xD9});
    e.Call(fetchMemAddress);
    EmitLoadVmRegToRdxFromEbx(e);
    e.Bytes({0x80, 0xBD}); e.U32(kMemWidth); e.U8(0x01); e.Jcc(0x5, movMrW2);
    e.Bytes({0x88, 0x10}); e.Jmp(movMrDone);
    e.Bind(movMrW2);
    e.Bytes({0x80, 0xBD}); e.U32(kMemWidth); e.U8(0x02); e.Jcc(0x5, movMrW4);
    e.Bytes({0x66, 0x89, 0x10}); e.Jmp(movMrDone);
    e.Bind(movMrW4);
    e.Bytes({0x80, 0xBD}); e.U32(kMemWidth); e.U8(0x04); e.Jcc(0x5, movMrW8);
    e.Bytes({0x89, 0x10}); e.Jmp(movMrDone);
    e.Bind(movMrW8);
    e.Bytes({0x80, 0xBD}); e.U32(kMemWidth); e.U8(0x08); e.Jcc(0x5, fail);
    e.Bytes({0x48, 0x89, 0x10});
    e.Bind(movMrDone); e.Jmp(dispatch);

    e.Bind(opLea);
    EmitFetchDstToEbx(e, fetchReg);
    e.Call(fetchByte);
    e.Call(fetchMemAddress);
    EmitStoreVmRegFromRaxToEbx(e); e.Jmp(dispatch);

    e.Bind(opAddRR); EmitBinaryRR(e, fetchReg, 0x01, 0xD0, false); e.Jmp(dispatch);
    e.Bind(opAddRC); EmitBinaryRC(e, fetchReg, fetchImm64, 0x01, 0xC2, false); e.Jmp(dispatch);
    e.Bind(opSubRR); EmitBinaryRR(e, fetchReg, 0x29, 0xD0, false); e.Jmp(dispatch);
    e.Bind(opSubRC); EmitBinaryRC(e, fetchReg, fetchImm64, 0x29, 0xC2, false); e.Jmp(dispatch);
    e.Bind(opAndRR); EmitBinaryRR(e, fetchReg, 0x21, 0xD0, true); e.Jmp(dispatch);
    e.Bind(opAndRC); EmitBinaryRC(e, fetchReg, fetchImm64, 0x21, 0xC2, true); e.Jmp(dispatch);
    e.Bind(opOrRR);  EmitBinaryRR(e, fetchReg, 0x09, 0xD0, true); e.Jmp(dispatch);
    e.Bind(opOrRC);  EmitBinaryRC(e, fetchReg, fetchImm64, 0x09, 0xC2, true); e.Jmp(dispatch);
    e.Bind(opXorRR); EmitBinaryRR(e, fetchReg, 0x31, 0xD0, true); e.Jmp(dispatch);
    e.Bind(opXorRC); EmitBinaryRC(e, fetchReg, fetchImm64, 0x31, 0xC2, true); e.Jmp(dispatch);

    e.Bind(opCmpRR);
    EmitFetchDstToEbx(e, fetchReg); e.Call(fetchReg);
    EmitLoadVmRegToRaxFromEbx(e); EmitLoadVmRegToRdxFromEcx(e);
    e.Bytes({0x48, 0x39, 0xD0}); EmitSetArithmeticFlags(e); e.Jmp(dispatch);

    e.Bind(opCmpRC);
    EmitFetchDstToEbx(e, fetchReg); e.Call(fetchImm64);
    EmitLoadVmRegToRdxFromEbx(e);
    e.Bytes({0x48, 0x39, 0xC2}); EmitSetArithmeticFlags(e); e.Jmp(dispatch);

    e.Bind(opTestRR);
    EmitFetchDstToEbx(e, fetchReg); e.Call(fetchReg);
    EmitLoadVmRegToRaxFromEbx(e); EmitLoadVmRegToRdxFromEcx(e);
    e.Bytes({0x48, 0x85, 0xD0}); EmitSetLogicFlags(e); e.Jmp(dispatch);

    e.Bind(opTestRC);
    EmitFetchDstToEbx(e, fetchReg); e.Call(fetchImm64);
    EmitLoadVmRegToRdxFromEbx(e);
    e.Bytes({0x48, 0x85, 0xC2}); EmitSetLogicFlags(e); e.Jmp(dispatch);

    e.Bind(opJmp);
    e.Call(fetchImm32); EmitMoveEsiEax(e); e.Jmp(dispatch);
    e.Bind(opJz);  EmitConditionalJumpByFlag(e, fetchImm32, kFlagZF, true, dispatch);
    e.Bind(opJnz); EmitConditionalJumpByFlag(e, fetchImm32, kFlagZF, false, dispatch);
    e.Bind(opJae); EmitConditionalJumpByFlag(e, fetchImm32, kFlagCF, false, dispatch);
    e.Bind(opJb);  EmitConditionalJumpByFlag(e, fetchImm32, kFlagCF, true, dispatch);

    e.Bind(opJa);
    e.Call(fetchImm32);
    e.Bytes({0x80, 0xBD}); e.U32(kFlagCF); e.U8(0x00); e.Jcc(0x5, jccSkip1);
    e.Bytes({0x80, 0xBD}); e.U32(kFlagZF); e.U8(0x00); e.Jcc(0x5, jccSkip1);
    EmitMoveEsiEax(e); e.Bind(jccSkip1); e.Jmp(dispatch);

    e.Bind(opJbe);
    e.Call(fetchImm32);
    e.Bytes({0x80, 0xBD}); e.U32(kFlagCF); e.U8(0x00); e.Jcc(0x5, jccTake1);
    e.Bytes({0x80, 0xBD}); e.U32(kFlagZF); e.U8(0x00); e.Jcc(0x4, jccSkip2);
    e.Bind(jccTake1); EmitMoveEsiEax(e); e.Bind(jccSkip2); e.Jmp(dispatch);

    e.Bind(opJg);
    e.Call(fetchImm32);
    e.Bytes({0x80, 0xBD}); e.U32(kFlagZF); e.U8(0x00); e.Jcc(0x5, jccSkip3);
    e.Bytes({0x8A, 0x95}); e.U32(kFlagSF);
    e.Bytes({0x3A, 0x95}); e.U32(kFlagOF);
    e.Jcc(0x5, jccSkip3);
    EmitMoveEsiEax(e); e.Bind(jccSkip3); e.Jmp(dispatch);

    e.Bind(opJge);
    e.Call(fetchImm32);
    e.Bytes({0x8A, 0x95}); e.U32(kFlagSF);
    e.Bytes({0x3A, 0x95}); e.U32(kFlagOF);
    e.Jcc(0x5, jccSkip4);
    EmitMoveEsiEax(e); e.Bind(jccSkip4); e.Jmp(dispatch);

    e.Bind(opJl);
    e.Call(fetchImm32);
    e.Bytes({0x8A, 0x95}); e.U32(kFlagSF);
    e.Bytes({0x3A, 0x95}); e.U32(kFlagOF);
    e.Jcc(0x4, jccSkip5);
    EmitMoveEsiEax(e); e.Bind(jccSkip5); e.Jmp(dispatch);

    e.Bind(opJle);
    e.Call(fetchImm32);
    e.Bytes({0x80, 0xBD}); e.U32(kFlagZF); e.U8(0x00); e.Jcc(0x5, jccTake2);
    e.Bytes({0x8A, 0x95}); e.U32(kFlagSF);
    e.Bytes({0x3A, 0x95}); e.U32(kFlagOF);
    e.Jcc(0x4, jccSkip6);
    e.Bind(jccTake2); EmitMoveEsiEax(e); e.Bind(jccSkip6); e.Jmp(dispatch);

    e.Bind(opRet);
    e.Jmp(writeback);

    e.Bind(writeback);
    EmitCommitFlagsToSavedRflags(e);
    const uint8_t nativeRegsWriteback[] = {0,1,2,3,5,6,7,8,9,10,11,12,13,14,15};
    for (uint8_t r : nativeRegsWriteback) EmitWriteBackNativeReg(e, r);
    e.Jmp(restore);

    e.Bind(fail);
    e.Jmp(restore);

    e.Bind(restore);
    e.Bytes({0x48, 0x81, 0xC4}); e.U32(kLocalSize);
    e.Bytes({0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C});
    e.Bytes({0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58});
    e.Bytes({0x5F, 0x5E, 0x5D, 0x5B, 0x5A, 0x59, 0x58, 0x9D, 0xC3});

    return e.code;
}

std::vector<uint8_t> VMRuntimeBuilder::BuildX64Trampoline(uint32_t functionRVA, uint32_t metadataRVA) {
    std::vector<uint8_t> c;
    c.reserve(32);
    Emit8(c, 0x41); Emit8(c, 0xBA); Emit32(c, functionRVA);
    Emit8(c, 0x41); Emit8(c, 0xBB); Emit32(c, metadataRVA);
    Emit8(c, 0xE9); Emit32(c, 0);
    return c;
}

VMRuntimeBuildResult VMRuntimeBuilder::Build(
    CS_PE_IMAGE* image,
    const std::vector<VMFunctionRecord>& records,
    uint32_t metadataRVA,
    const char sectionName[8])
{
    VMRuntimeBuildResult result;
    if (!image || !image->isValid) {
        result.error = "invalid PE image";
        return result;
    }
    if (!image->is64Bit) {
        result.error = "VM runtime builder currently supports x64 only";
        return result;
    }
    if (records.empty()) {
        result.error = "no VM function records";
        return result;
    }

    std::vector<uint8_t> blob = BuildX64RuntimeInterpreter(metadataRVA);
    uint32_t runtimeOffset = 0;
    std::vector<uint32_t> trampolineOffsets;
    trampolineOffsets.reserve(records.size());

    for (const auto& record : records) {
        while ((blob.size() & 0x0F) != 0) blob.push_back(0x90);
        uint32_t trampOffset = static_cast<uint32_t>(blob.size());
        auto tramp = BuildX64Trampoline(record.functionRVA, metadataRVA);
        size_t relPos = tramp.size() - 4;
        int64_t rel64 = static_cast<int64_t>(runtimeOffset) - static_cast<int64_t>(trampOffset + tramp.size());
        if (rel64 < (std::numeric_limits<int32_t>::min)() || rel64 > (std::numeric_limits<int32_t>::max)()) {
            result.error = "VM trampoline is out of rel32 range inside runtime section";
            return result;
        }
        Patch32(tramp, relPos, static_cast<uint32_t>(static_cast<int32_t>(rel64)));
        blob.insert(blob.end(), tramp.begin(), tramp.end());
        trampolineOffsets.push_back(trampOffset);
    }

    char name[8] = {'.','c','s','v','x',0,0,0};
    if (sectionName) memcpy(name, sectionName, 8);

    PEEmitter emitter(image);
    auto append = emitter.AppendSection(name, blob, IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ);
    if (!append.success) {
        result.error = append.error;
        return result;
    }

    result.success = true;
    result.executionReady = true;
    result.sectionRVA = append.rva;
    result.runtimeEntryRVA = append.rva + runtimeOffset;
    for (size_t i = 0; i < records.size(); i++) {
        VMTrampolineRecord tr;
        tr.functionRVA = records[i].functionRVA;
        tr.trampolineRVA = append.rva + trampolineOffsets[i];
        tr.trampolineSize = 17;
        result.trampolines.push_back(tr);
    }
    return result;
}

} // namespace CipherShell