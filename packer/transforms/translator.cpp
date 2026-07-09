/**
 * CipherShell x86/x64 鈫?Mirage Bytecode 杞瘧鍣?- 瀹炵幇
 */

#include "translator.h"
#include "../../third_party/chacha20.h"
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <algorithm>
#include <iomanip>
#include <random>
#include <sstream>

namespace CipherShell {

// ============================================================================
// 鏋勯€?鏋愭瀯
// ============================================================================

struct DecodedModRM {
    bool ok = false;
    uint8_t opcode = 0;
    uint8_t rex = 0;
    bool rexW = false;
    bool operand16 = false;
    uint32_t opcodeOffset = 0;
    uint8_t mod = 0;
    uint8_t reg = 0;
    uint8_t rm = VM_REG_INVALID;
    uint8_t index = VM_REG_INVALID;
    uint8_t scale = 1;
    bool hasBase = false;
    bool hasIndex = false;
    bool memory = false;
    bool ripRelative = false;
    int64_t disp = 0;
    uint32_t immOffset = 0;
};

static std::string FormatInstructionBytes(const Instruction& instr) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint32_t i = 0; i < instr.length; i++) {
        if (i) oss << ' ';
        oss << std::setw(2) << static_cast<unsigned>(instr.bytes[i]);
    }
    return oss.str();
}

static uint8_t MemoryWidthForOpcode(const DecodedModRM& d, uint8_t opcode) {
    if (opcode == 0x88 || opcode == 0x8A) return 1;
    if (d.operand16) return 2;
    return d.rexW ? 8 : 4;
}

static bool IsSupportedMemoryWidth(uint8_t width) {
    return width == 1 || width == 2 || width == 4 || width == 8;
}

static uint8_t RegisterWidthForOperand(const DecodedModRM& d) {
    if (d.operand16) return 2;
    return d.rexW ? 8 : 4;
}

static bool IsSupportedRegisterWidth(uint8_t width) {
    return width == 2 || width == 4 || width == 8;
}

static DecodedModRM DecodeModRMInstr(const Instruction& instr) {
    DecodedModRM d;
    uint32_t pos = 0;

    while (pos < instr.length) {
        uint8_t b = instr.bytes[pos];
        if (b == 0x66) {
            d.operand16 = true;
            pos++;
            continue;
        }
        if (b == 0x67) {
            return d; // 32-bit addressing in x64 is not expressible by the current VM memory model.
        }
        if ((b & 0xF0) == 0x40) {
            d.rex = b;
            d.rexW = (b & 0x08) != 0;
            pos++;
            continue;
        }
        break;
    }

    d.opcodeOffset = pos;
    if (pos >= instr.length) return d;
    d.opcode = instr.bytes[pos++];
    if (d.opcode == 0x0F) {
        if (pos >= instr.length) return d;
        d.opcode = instr.bytes[pos++];
    }
    if (pos >= instr.length) return d;

    uint8_t modrm = instr.bytes[pos++];
    d.mod = (modrm >> 6) & 3;
    d.reg = static_cast<uint8_t>(((modrm >> 3) & 7) | ((d.rex & 0x04) ? 8 : 0));
    uint8_t rmLow = modrm & 7;
    d.rm = static_cast<uint8_t>(rmLow | ((d.rex & 0x01) ? 8 : 0));
    d.memory = d.mod != 3;

    if (d.memory && rmLow == 4) {
        if (pos >= instr.length) return d;
        uint8_t sib = instr.bytes[pos++];
        d.scale = static_cast<uint8_t>(1u << ((sib >> 6) & 3));

        uint8_t indexLow = (sib >> 3) & 7;
        if (indexLow != 4) {
            d.hasIndex = true;
            d.index = static_cast<uint8_t>(indexLow | ((d.rex & 0x02) ? 8 : 0));
        }

        uint8_t baseLow = sib & 7;
        if (d.mod == 0 && baseLow == 5) {
            d.hasBase = false;
            d.rm = VM_REG_INVALID;
            if (pos + 4 > instr.length) return d;
            d.disp = *reinterpret_cast<const int32_t*>(instr.bytes + pos);
            pos += 4;
        } else {
            d.hasBase = true;
            d.rm = static_cast<uint8_t>(baseLow | ((d.rex & 0x01) ? 8 : 0));
        }
    } else if (d.memory && d.mod == 0 && rmLow == 5) {
        if (pos + 4 > instr.length) return d;
        d.hasBase = false;
        d.rm = VM_REG_INVALID;
        d.disp = *reinterpret_cast<const int32_t*>(instr.bytes + pos);
        d.ripRelative = true;
        pos += 4;
    } else if (d.memory) {
        d.hasBase = true;
    }

    if (d.mod == 1) {
        if (pos + 1 > instr.length) return d;
        d.disp = static_cast<int8_t>(instr.bytes[pos]);
        pos += 1;
    } else if (d.mod == 2) {
        if (pos + 4 > instr.length) return d;
        d.disp = *reinterpret_cast<const int32_t*>(instr.bytes + pos);
        pos += 4;
    }

    d.immOffset = pos;
    d.ok = true;
    return d;
}
Translator::Translator() 
    : m_nextVirtualReg(0)
    , m_initialized(false)
{
    srand((unsigned int)time(nullptr));
}

Translator::~Translator() {}

// ============================================================================
// 鍏叡鎺ュ彛
// ============================================================================

bool Translator::Initialize(const TranslationConfig& config) {
    m_config = config;
    m_lastFailures.clear();

    // 鍒濆鍖栧瘎瀛樺櫒鏄犲皠
    for (uint8_t i = 0; i < 16; i++) {
        if (config.enableRegisterRemapping) {
            // 闅忔満鏄犲皠
            m_registerMap[i] = static_cast<uint8_t>(i % config.virtualRegisterCount);
        } else {
            m_registerMap[i] = i;
        }
    }

    // 鐢熸垚 opcode 鏄犲皠
    m_opcodeMap = GenerateOpcodeMap();

    m_initialized = true;
    return true;
}

TranslationResult Translator::TranslateFunction(const Function& func) {
    TranslationResult result{};
    result.totalSize = 0;
    result.registerCount = m_config.virtualRegisterCount;
    result.success = false;
    m_lastFailures.clear();

    if (!m_initialized) {
        TranslationFailure failure{};
        failure.address = func.entryAddress;
        failure.mnemonic = "<translator>";
        failure.reason = "translator not initialized";
        m_lastFailures.push_back(failure);
        result.failures = m_lastFailures;
        return result;
    }

    result.success = true;
    uint32_t currentOffset = 0;
    std::vector<uint32_t> instrOffsets;

    for (const auto& block : func.blocks) {
        result.addrMap[block.startAddress] = currentOffset;

        for (const auto& instr : block.instructions) {
            result.addrMap[instr.address] = currentOffset;

            BytecodeInstr vmInstr{};
            if (!TranslateInstruction(instr, vmInstr)) {
                result.success = false;
                result.failures = m_lastFailures;
                result.instructions.clear();
                result.totalSize = 0;
                return result;
            }

            instrOffsets.push_back(currentOffset);
            result.instructions.push_back(vmInstr);
            currentOffset += CalculateEncodedSize(vmInstr);

            if (m_config.enableJunkInsertion && (rand() % 100) < (int)m_config.junkRatio) {
                BytecodeInstr junk = GenerateJunkInstruction();
                instrOffsets.push_back(currentOffset);
                result.instructions.push_back(junk);
                currentOffset += CalculateEncodedSize(junk);
            }
        }
    }

    for (auto& vmInstr : result.instructions) {
        if (vmInstr.isJump) {
            auto targetIt = result.addrMap.find(vmInstr.jumpTarget);
            if (targetIt == result.addrMap.end()) {
                result.success = false;
                TranslationFailure failure{};
                failure.address = func.entryAddress;
                failure.mnemonic = "<control-flow>";
                failure.reason = "jump/call target is outside translated function or not block-aligned";
                m_lastFailures.push_back(failure);
                result.failures = m_lastFailures;
                result.instructions.clear();
                result.totalSize = 0;
                return result;
            }
            vmInstr.immediate = targetIt->second;
        }
    }

    result.totalSize = currentOffset;
    result.failures = m_lastFailures;
    return result;
}
TranslationResult Translator::TranslateBlock(const BasicBlock& block, uint32_t baseOffset) {
    TranslationResult result{};
    result.totalSize = baseOffset;
    result.registerCount = m_config.virtualRegisterCount;
    result.success = false;
    m_lastFailures.clear();

    if (!m_initialized) {
        TranslationFailure failure{};
        failure.address = block.startAddress;
        failure.mnemonic = "<translator>";
        failure.reason = "translator not initialized";
        m_lastFailures.push_back(failure);
        result.failures = m_lastFailures;
        return result;
    }

    result.success = true;
    uint32_t currentOffset = baseOffset;

    for (const auto& instr : block.instructions) {
        result.addrMap[instr.address] = currentOffset;

        BytecodeInstr vmInstr{};
        if (!TranslateInstruction(instr, vmInstr)) {
            result.success = false;
            result.failures = m_lastFailures;
            result.instructions.clear();
            result.totalSize = 0;
            return result;
        }

        result.instructions.push_back(vmInstr);
        currentOffset += CalculateEncodedSize(vmInstr);
    }

    result.totalSize = currentOffset - baseOffset;
    result.failures = m_lastFailures;
    return result;
}
std::vector<uint8_t> Translator::GenerateBytecode(
    const TranslationResult& result,
    const uint8_t* key,
    const uint8_t* nonce)
{
    std::vector<uint8_t> bytecode;
    if (!result.success) return bytecode;

    // 缂栫爜姣忔潯鎸囦护
    for (const auto& instr : result.instructions) {
        EncodeInstruction(instr, bytecode);
    }

    // 鍔犲瘑瀛楄妭鐮?
    if (key) {
        EncryptBytecode(bytecode, key, nonce);
    }

    return bytecode;
}

std::unordered_map<uint8_t, uint8_t> Translator::GetRegisterMap() const {
    return m_registerMap;
}

const std::vector<TranslationFailure>& Translator::GetLastFailures() const {
    return m_lastFailures;
}
std::unordered_map<uint8_t, uint8_t> Translator::GetOpcodeMap() const {
    return m_opcodeMap;
}
void Translator::SetOpcodeMap(const std::unordered_map<uint8_t, uint8_t>& opcodeMap) {
    if (!opcodeMap.empty()) m_opcodeMap = opcodeMap;
}

void Translator::SetRegisterMap(const std::unordered_map<uint8_t, uint8_t>& registerMap) {
    if (!registerMap.empty()) m_registerMap = registerMap;
}
std::unordered_map<uint8_t, uint8_t> Translator::GenerateOpcodeMap() {
    std::unordered_map<uint8_t, uint8_t> opcodeMap;

    // 鏍囧噯 opcode 鍒楄〃
    uint8_t standardOpcodes[] = {
        VM_NOP, VM_MOV_RR, VM_MOV_RC, VM_MOV_RM, VM_MOV_MR, VM_LEA,
        VM_PUSH_R, VM_PUSH_C, VM_POP_R, VM_PUSHAD, VM_POPAD,
        VM_ADD_RR, VM_ADD_RC, VM_SUB_RR, VM_SUB_RC,
        VM_AND_RR, VM_AND_RC, VM_OR_RR, VM_OR_RC, VM_XOR_RR, VM_XOR_RC, VM_NOT_R,
        VM_CMP_RR, VM_CMP_RC, VM_TEST_RR, VM_TEST_RC,
        VM_JMP, VM_JZ, VM_JNZ, VM_JA, VM_JB, VM_JAE, VM_JBE, VM_JG, VM_JGE, VM_JL, VM_JLE,
        VM_CALL_VM, VM_RET_VM, VM_CALL_NATIVE, VM_VMEXIT
    };

    int count = sizeof(standardOpcodes) / sizeof(standardOpcodes[0]);

    // 鐢熸垚闅忔満鏄犲皠
    std::vector<uint8_t> randomOpcodes;
    for (int i = 0; i < 256; i++) {
        randomOpcodes.push_back((uint8_t)i);
    }

    // 鎵撲贡
    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(randomOpcodes.begin(), randomOpcodes.end(), g);

    for (int i = 0; i < count; i++) {
        opcodeMap[standardOpcodes[i]] = randomOpcodes[i];
    }

    return opcodeMap;
}

// ============================================================================
// 鎸囦护缈昏瘧
// ============================================================================

bool Translator::TranslateInstruction(const Instruction& instr, BytecodeInstr& outInstr) {
    outInstr.memBaseReg = VM_REG_INVALID;
    outInstr.memIndexReg = VM_REG_INVALID;
    outInstr.memScale = 1;
    outInstr.memWidth = 8;
    outInstr.operandWidth = 8;
    if (instr.mnemonic.empty()) return FailInstruction(instr, "empty or undecoded instruction");

    if (instr.mnemonic == "mov") return TranslateMov(instr, outInstr);
    if (instr.mnemonic == "add") return TranslateAdd(instr, outInstr);
    if (instr.mnemonic == "sub") return TranslateSub(instr, outInstr);
    if (instr.mnemonic == "cmp") return TranslateCmp(instr, outInstr);
    if (instr.mnemonic == "and") return TranslateAnd(instr, outInstr);
    if (instr.mnemonic == "or") return TranslateOr(instr, outInstr);
    if (instr.mnemonic == "test") return TranslateTest(instr, outInstr);
    if (instr.mnemonic == "lea") return TranslateLea(instr, outInstr);
    if (instr.mnemonic == "push") return TranslatePush(instr, outInstr);
    if (instr.mnemonic == "pop") return TranslatePop(instr, outInstr);
    if (instr.mnemonic == "call") return TranslateCall(instr, outInstr);
    if (instr.mnemonic == "ret") return TranslateRet(instr, outInstr);
    if (instr.mnemonic == "nop") return TranslateNop(instr, outInstr);

    if (instr.mnemonic == "xor") {
        DecodedModRM m = DecodeModRMInstr(instr);
        if (!m.ok) return FailInstruction(instr, "invalid XOR ModRM");
        if (m.memory || m.ripRelative) return FailInstruction(instr, "memory_arithmetic_not_supported: XOR memory form requires native bridge");
        if (m.opcode == 0x31 || m.opcode == 0x33) {
            if ((m.opcode == 0x31 && m.rm == 4) || (m.opcode == 0x33 && m.reg == 4)) return FailInstruction(instr, "XOR into RSP requires VM/native stack mapping");
            outInstr.opcode = VM_XOR_RR;
            outInstr.operandWidth = RegisterWidthForOperand(m);
            if (!IsSupportedRegisterWidth(outInstr.operandWidth)) return FailInstruction(instr, "unsupported XOR operand width");
            if (m.opcode == 0x31) {
                outInstr.regDst = MapRegister(m.rm);
                outInstr.regSrc = MapRegister(m.reg);
            } else {
                outInstr.regDst = MapRegister(m.reg);
                outInstr.regSrc = MapRegister(m.rm);
            }
            return true;
        }
        if (m.opcode == 0x83 && m.immOffset < instr.length && ((instr.bytes[m.opcodeOffset + 1] >> 3) & 7) == 6) {
            if (m.rm == 4) return FailInstruction(instr, "XOR into RSP requires VM/native stack mapping");
            outInstr.opcode = VM_XOR_RC;
            outInstr.regDst = MapRegister(m.rm);
            outInstr.operandWidth = RegisterWidthForOperand(m);
            if (!IsSupportedRegisterWidth(outInstr.operandWidth)) return FailInstruction(instr, "unsupported XOR operand width");
            outInstr.immediate = static_cast<int64_t>(static_cast<int8_t>(instr.bytes[m.immOffset]));
            return true;
        }
        return FailInstruction(instr, "unsupported XOR encoding");
    }
    if (instr.mnemonic == "int3") {
        outInstr.opcode = VM_INT3;
        return true;
    }

    if (IsJumpInstruction(instr.mnemonic)) {
        return TranslateJump(instr, outInstr);
    }

    return FailInstruction(instr, "unsupported instruction mnemonic");
}
bool Translator::TranslateMov(const Instruction& instr, BytecodeInstr& outInstr) {
    DecodedModRM m = DecodeModRMInstr(instr);
    uint32_t opPos = m.ok ? m.opcodeOffset : (((instr.bytes[0] & 0xF0) == 0x40 && instr.length > 1) ? 1 : 0);
    uint8_t opcode = m.ok ? m.opcode : instr.bytes[opPos];
    uint8_t rex = 0;
    if (opPos > 0 && (instr.bytes[opPos - 1] & 0xF0) == 0x40) rex = instr.bytes[opPos - 1];

    if (opcode >= 0xB8 && opcode <= 0xBF) {
        uint8_t reg = static_cast<uint8_t>((opcode - 0xB8) | ((rex & 0x01) ? 8 : 0));
        outInstr.opcode = VM_MOV_RC;
        outInstr.regDst = MapRegister(reg);
        outInstr.operandWidth = (rex & 0x08) ? 8 : 4;
        if ((rex & 0x08) && instr.length >= opPos + 9) {
            outInstr.immediate = *reinterpret_cast<const uint64_t*>(instr.bytes + opPos + 1);
        } else if (instr.length >= opPos + 5) {
            outInstr.immediate = *reinterpret_cast<const uint32_t*>(instr.bytes + opPos + 1);
        } else {
            return FailInstruction(instr, "truncated MOV immediate");
        }
        return true;
    }

    if (!m.ok) return FailInstruction(instr, "invalid MOV ModRM");

    auto fillMemory = [&](uint8_t width) -> bool {
        if (!IsSupportedMemoryWidth(width)) return false;
        outInstr.memBaseReg = m.hasBase ? MapRegister(m.rm) : VM_REG_INVALID;
        outInstr.memIndexReg = m.hasIndex ? MapRegister(m.index) : VM_REG_INVALID;
        outInstr.memScale = m.scale;
        outInstr.memWidth = width;
        outInstr.memoryKind = m.ripRelative ? 1u : 0u;
        outInstr.isRipRelative = m.ripRelative;
        outInstr.memDisp = m.ripRelative
            ? static_cast<int64_t>(instr.address + instr.length + m.disp)
            : m.disp;
        return true;
    };

    if (opcode == 0x8B || opcode == 0x8A) {
        if (m.reg == 4) return FailInstruction(instr, "MOV into RSP requires VM/native stack mapping");
        uint8_t width = MemoryWidthForOpcode(m, opcode);
        if (m.memory) {
            if (!fillMemory(width)) return FailInstruction(instr, "unsupported MOV memory width");
            outInstr.opcode = VM_MOV_RM;
            outInstr.regDst = MapRegister(m.reg);
            outInstr.regSrc = 0;
        } else {
            if (width != 4 && width != 8) return FailInstruction(instr, "partial-register MOV is not safe for VM register mapping");
            outInstr.opcode = VM_MOV_RR;
            outInstr.regDst = MapRegister(m.reg);
            outInstr.regSrc = MapRegister(m.rm);
            outInstr.operandWidth = width;
        }
        return true;
    }

    if (opcode == 0x89 || opcode == 0x88) {
        if (!m.memory && m.rm == 4) return FailInstruction(instr, "MOV into RSP requires VM/native stack mapping");
        uint8_t width = MemoryWidthForOpcode(m, opcode);
        if (m.memory) {
            if (!fillMemory(width)) return FailInstruction(instr, "unsupported MOV memory width");
            outInstr.opcode = VM_MOV_MR;
            outInstr.regDst = 0;
            outInstr.regSrc = MapRegister(m.reg);
        } else {
            if (width != 4 && width != 8) return FailInstruction(instr, "partial-register MOV is not safe for VM register mapping");
            outInstr.opcode = VM_MOV_RR;
            outInstr.regDst = MapRegister(m.rm);
            outInstr.regSrc = MapRegister(m.reg);
            outInstr.operandWidth = width;
        }
        return true;
    }

    return FailInstruction(instr, "unsupported MOV encoding");
}
bool Translator::TranslateAdd(const Instruction& instr, BytecodeInstr& outInstr) {
    DecodedModRM m = DecodeModRMInstr(instr);
    if (!m.ok) return FailInstruction(instr, "invalid ADD ModRM");
    if (m.memory || m.ripRelative) return FailInstruction(instr, "memory_arithmetic_not_supported: ADD memory form requires native bridge");
    uint8_t width = RegisterWidthForOperand(m);
    if (!IsSupportedRegisterWidth(width)) return FailInstruction(instr, "unsupported ADD operand width");

    if (m.opcode == 0x03 || m.opcode == 0x01) {
        uint8_t dst = (m.opcode == 0x03) ? m.reg : m.rm;
        uint8_t src = (m.opcode == 0x03) ? m.rm : m.reg;
        if (dst == 4) return FailInstruction(instr, "ADD into RSP requires VM/native stack mapping");
        outInstr.opcode = VM_ADD_RR;
        outInstr.regDst = MapRegister(dst);
        outInstr.regSrc = MapRegister(src);
        outInstr.operandWidth = width;
        return true;
    }
    if ((m.opcode == 0x83 || m.opcode == 0x81) && ((instr.bytes[m.opcodeOffset + 1] >> 3) & 7) == 0 && m.immOffset < instr.length) {
        if (m.rm == 4) return FailInstruction(instr, "ADD into RSP requires VM/native stack mapping");
        outInstr.opcode = VM_ADD_RC;
        outInstr.regDst = MapRegister(m.rm);
        outInstr.operandWidth = width;
        outInstr.immediate = (m.opcode == 0x83)
            ? static_cast<int64_t>(static_cast<int8_t>(instr.bytes[m.immOffset]))
            : static_cast<uint64_t>(*reinterpret_cast<const uint32_t*>(instr.bytes + m.immOffset));
        return true;
    }
    return FailInstruction(instr, "unsupported ADD encoding");
}

bool Translator::TranslateSub(const Instruction& instr, BytecodeInstr& outInstr) {
    DecodedModRM m = DecodeModRMInstr(instr);
    if (!m.ok) return FailInstruction(instr, "invalid SUB ModRM");
    if (m.memory || m.ripRelative) return FailInstruction(instr, "memory_arithmetic_not_supported: SUB memory form requires native bridge");
    uint8_t width = RegisterWidthForOperand(m);
    if (!IsSupportedRegisterWidth(width)) return FailInstruction(instr, "unsupported SUB operand width");

    if (m.opcode == 0x2B || m.opcode == 0x29) {
        uint8_t dst = (m.opcode == 0x2B) ? m.reg : m.rm;
        uint8_t src = (m.opcode == 0x2B) ? m.rm : m.reg;
        if (dst == 4) return FailInstruction(instr, "SUB into RSP requires VM/native stack mapping");
        outInstr.opcode = VM_SUB_RR;
        outInstr.regDst = MapRegister(dst);
        outInstr.regSrc = MapRegister(src);
        outInstr.operandWidth = width;
        return true;
    }
    if ((m.opcode == 0x83 || m.opcode == 0x81) && ((instr.bytes[m.opcodeOffset + 1] >> 3) & 7) == 5 && m.immOffset < instr.length) {
        if (m.rm == 4) return FailInstruction(instr, "SUB into RSP requires VM/native stack mapping");
        outInstr.opcode = VM_SUB_RC;
        outInstr.regDst = MapRegister(m.rm);
        outInstr.operandWidth = width;
        outInstr.immediate = (m.opcode == 0x83)
            ? static_cast<int64_t>(static_cast<int8_t>(instr.bytes[m.immOffset]))
            : static_cast<uint64_t>(*reinterpret_cast<const uint32_t*>(instr.bytes + m.immOffset));
        return true;
    }
    return FailInstruction(instr, "unsupported SUB encoding");
}

bool Translator::TranslateCmp(const Instruction& instr, BytecodeInstr& outInstr) {
    DecodedModRM m = DecodeModRMInstr(instr);
    if (!m.ok) return FailInstruction(instr, "invalid CMP ModRM");
    if (m.memory || m.ripRelative) return FailInstruction(instr, "memory_arithmetic_not_supported: CMP memory form requires native bridge");
    uint8_t width = RegisterWidthForOperand(m);
    if (!IsSupportedRegisterWidth(width)) return FailInstruction(instr, "unsupported CMP operand width");

    if (m.opcode == 0x3B || m.opcode == 0x39) {
        uint8_t lhs = (m.opcode == 0x3B) ? m.reg : m.rm;
        uint8_t rhs = (m.opcode == 0x3B) ? m.rm : m.reg;
        outInstr.opcode = VM_CMP_RR;
        outInstr.regDst = MapRegister(lhs);
        outInstr.regSrc = MapRegister(rhs);
        outInstr.operandWidth = width;
        return true;
    }
    if ((m.opcode == 0x83 || m.opcode == 0x81) && ((instr.bytes[m.opcodeOffset + 1] >> 3) & 7) == 7 && m.immOffset < instr.length) {
        outInstr.opcode = VM_CMP_RC;
        outInstr.regDst = MapRegister(m.rm);
        outInstr.operandWidth = width;
        outInstr.immediate = (m.opcode == 0x83)
            ? static_cast<int64_t>(static_cast<int8_t>(instr.bytes[m.immOffset]))
            : static_cast<uint64_t>(*reinterpret_cast<const uint32_t*>(instr.bytes + m.immOffset));
        return true;
    }
    return FailInstruction(instr, "unsupported CMP encoding");
}

bool Translator::TranslateAnd(const Instruction& instr, BytecodeInstr& outInstr) {
    DecodedModRM m = DecodeModRMInstr(instr);
    if (!m.ok) return FailInstruction(instr, "invalid AND ModRM");
    if (m.memory || m.ripRelative) return FailInstruction(instr, "memory_arithmetic_not_supported: AND memory form requires native bridge");
    uint8_t width = RegisterWidthForOperand(m);
    if (!IsSupportedRegisterWidth(width)) return FailInstruction(instr, "unsupported AND operand width");
    if (m.opcode == 0x23 || m.opcode == 0x21) {
        uint8_t dst = (m.opcode == 0x23) ? m.reg : m.rm;
        uint8_t src = (m.opcode == 0x23) ? m.rm : m.reg;
        if (dst == 4) return FailInstruction(instr, "AND into RSP requires VM/native stack mapping");
        outInstr.opcode = VM_AND_RR;
        outInstr.regDst = MapRegister(dst);
        outInstr.regSrc = MapRegister(src);
        outInstr.operandWidth = width;
        return true;
    }
    if ((m.opcode == 0x83 || m.opcode == 0x81) && ((instr.bytes[m.opcodeOffset + 1] >> 3) & 7) == 4 && m.immOffset < instr.length) {
        if (m.rm == 4) return FailInstruction(instr, "AND into RSP requires VM/native stack mapping");
        outInstr.opcode = VM_AND_RC;
        outInstr.regDst = MapRegister(m.rm);
        outInstr.operandWidth = width;
        outInstr.immediate = (m.opcode == 0x83)
            ? static_cast<int64_t>(static_cast<int8_t>(instr.bytes[m.immOffset]))
            : static_cast<uint64_t>(*reinterpret_cast<const uint32_t*>(instr.bytes + m.immOffset));
        return true;
    }
    return FailInstruction(instr, "unsupported AND encoding");
}

bool Translator::TranslateOr(const Instruction& instr, BytecodeInstr& outInstr) {
    DecodedModRM m = DecodeModRMInstr(instr);
    if (!m.ok) return FailInstruction(instr, "invalid OR ModRM");
    if (m.memory || m.ripRelative) return FailInstruction(instr, "memory_arithmetic_not_supported: OR memory form requires native bridge");
    uint8_t width = RegisterWidthForOperand(m);
    if (!IsSupportedRegisterWidth(width)) return FailInstruction(instr, "unsupported OR operand width");
    if (m.opcode == 0x0B || m.opcode == 0x09) {
        uint8_t dst = (m.opcode == 0x0B) ? m.reg : m.rm;
        uint8_t src = (m.opcode == 0x0B) ? m.rm : m.reg;
        if (dst == 4) return FailInstruction(instr, "OR into RSP requires VM/native stack mapping");
        outInstr.opcode = VM_OR_RR;
        outInstr.regDst = MapRegister(dst);
        outInstr.regSrc = MapRegister(src);
        outInstr.operandWidth = width;
        return true;
    }
    if ((m.opcode == 0x83 || m.opcode == 0x81) && ((instr.bytes[m.opcodeOffset + 1] >> 3) & 7) == 1 && m.immOffset < instr.length) {
        if (m.rm == 4) return FailInstruction(instr, "OR into RSP requires VM/native stack mapping");
        outInstr.opcode = VM_OR_RC;
        outInstr.regDst = MapRegister(m.rm);
        outInstr.operandWidth = width;
        outInstr.immediate = (m.opcode == 0x83)
            ? static_cast<int64_t>(static_cast<int8_t>(instr.bytes[m.immOffset]))
            : static_cast<uint64_t>(*reinterpret_cast<const uint32_t*>(instr.bytes + m.immOffset));
        return true;
    }
    return FailInstruction(instr, "unsupported OR encoding");
}

bool Translator::TranslateTest(const Instruction& instr, BytecodeInstr& outInstr) {
    uint32_t opPos = 0;
    bool operand16 = false;
    while (opPos < instr.length) {
        uint8_t b = instr.bytes[opPos];
        if (b == 0x66) {
            operand16 = true;
            opPos++;
            continue;
        }
        if ((b & 0xF0) == 0x40) {
            opPos++;
            continue;
        }
        break;
    }
    if (opPos >= instr.length) return FailInstruction(instr, "empty_instruction_bytes");

    uint8_t opcode = instr.bytes[opPos];
    if (opcode == 0xA8) {
        if (opPos + 2 > instr.length) return FailInstruction(instr, "truncated TEST imm8");
        outInstr.opcode = VM_TEST_RC;
        outInstr.regDst = MapRegister(0);
        outInstr.operandWidth = 1;
        outInstr.immediate = instr.bytes[opPos + 1];
        return true;
    }
    if (opcode == 0xA9) {
        uint32_t immSize = operand16 ? 2u : 4u;
        if (opPos + 1 + immSize > instr.length) return FailInstruction(instr, "truncated TEST imm32");
        outInstr.opcode = VM_TEST_RC;
        outInstr.regDst = MapRegister(0);
        outInstr.operandWidth = static_cast<uint8_t>(immSize);
        outInstr.immediate = (immSize == 2)
            ? static_cast<uint64_t>(*reinterpret_cast<const uint16_t*>(instr.bytes + opPos + 1))
            : static_cast<uint64_t>(*reinterpret_cast<const uint32_t*>(instr.bytes + opPos + 1));
        return true;
    }

    DecodedModRM m = DecodeModRMInstr(instr);
    if (!m.ok) return FailInstruction(instr, "invalid TEST ModRM");
    if (m.memory || m.ripRelative) return FailInstruction(instr, "memory_arithmetic_not_supported: TEST memory form requires native bridge");

    if (m.opcode == 0x85) {
        outInstr.opcode = VM_TEST_RR;
        outInstr.regDst = MapRegister(m.reg);
        outInstr.regSrc = MapRegister(m.rm);
        outInstr.operandWidth = RegisterWidthForOperand(m);
        return true;
    }

    if ((m.opcode == 0xF6 || m.opcode == 0xF7) && ((m.reg & 7u) == 0u)) {
        uint32_t immSize = (m.opcode == 0xF6) ? 1u : (m.operand16 ? 2u : 4u);
        if (m.immOffset + immSize > instr.length) return FailInstruction(instr, "truncated TEST immediate");
        outInstr.opcode = VM_TEST_RC;
        outInstr.regDst = MapRegister(m.rm);
        outInstr.operandWidth = (m.opcode == 0xF6) ? 1 : RegisterWidthForOperand(m);
        if (immSize == 1) {
            outInstr.immediate = instr.bytes[m.immOffset];
        } else if (immSize == 2) {
            outInstr.immediate = static_cast<uint64_t>(*reinterpret_cast<const uint16_t*>(instr.bytes + m.immOffset));
        } else {
            outInstr.immediate = m.rexW
                ? static_cast<uint64_t>(static_cast<int64_t>(*reinterpret_cast<const int32_t*>(instr.bytes + m.immOffset)))
                : static_cast<uint64_t>(*reinterpret_cast<const uint32_t*>(instr.bytes + m.immOffset));
        }
        return true;
    }

    return FailInstruction(instr, "unsupported TEST encoding");
}

bool Translator::TranslateLea(const Instruction& instr, BytecodeInstr& outInstr) {
    DecodedModRM m = DecodeModRMInstr(instr);
    if (!m.ok || !m.memory) return FailInstruction(instr, "LEA requires memory addressing operand");
    if (!IsSupportedMemoryWidth(8)) return FailInstruction(instr, "unsupported LEA address width");

    outInstr.opcode = VM_LEA;
    outInstr.regDst = MapRegister(m.reg);
    outInstr.regSrc = 0;
    outInstr.memBaseReg = m.hasBase ? MapRegister(m.rm) : VM_REG_INVALID;
    outInstr.memIndexReg = m.hasIndex ? MapRegister(m.index) : VM_REG_INVALID;
    outInstr.memScale = m.scale;
    outInstr.memWidth = RegisterWidthForOperand(m);
    outInstr.memoryKind = m.ripRelative ? 1u : 0u;
    outInstr.isRipRelative = m.ripRelative;
    outInstr.memDisp = m.ripRelative
        ? static_cast<int64_t>(instr.address + instr.length + m.disp)
        : m.disp;
    return true;
}
bool Translator::TranslatePush(const Instruction& instr, BytecodeInstr& outInstr) {
    uint32_t opPos = 0;
    uint8_t rex = 0;
    if (instr.length > 1 && (instr.bytes[0] & 0xF0) == 0x40) {
        rex = instr.bytes[0];
        opPos = 1;
    }
    if (opPos >= instr.length) return FailInstruction(instr, "truncated PUSH");
    uint8_t opcode = instr.bytes[opPos];
    if (opcode >= 0x50 && opcode <= 0x57) {
        uint8_t reg = static_cast<uint8_t>((opcode - 0x50) | ((rex & 0x01) ? 8 : 0));
        outInstr.opcode = VM_PUSH_R;
        outInstr.regDst = MapRegister(reg);
        outInstr.operandWidth = 8;
        return true;
    }
    if (opcode == 0x68 && opPos + 5 <= instr.length) {
        outInstr.opcode = VM_PUSH_C;
        outInstr.regDst = 0;
        outInstr.operandWidth = 8;
        outInstr.immediate = static_cast<uint64_t>(static_cast<int64_t>(*reinterpret_cast<const int32_t*>(instr.bytes + opPos + 1)));
        return true;
    }
    if (opcode == 0x6A && opPos + 2 <= instr.length) {
        outInstr.opcode = VM_PUSH_C;
        outInstr.regDst = 0;
        outInstr.operandWidth = 8;
        outInstr.immediate = static_cast<uint64_t>(static_cast<int64_t>(static_cast<int8_t>(instr.bytes[opPos + 1])));
        return true;
    }
    return FailInstruction(instr, "unsupported PUSH encoding");
}
bool Translator::TranslatePop(const Instruction& instr, BytecodeInstr& outInstr) {
    uint32_t opPos = 0;
    uint8_t rex = 0;
    if (instr.length > 1 && (instr.bytes[0] & 0xF0) == 0x40) {
        rex = instr.bytes[0];
        opPos = 1;
    }
    if (opPos >= instr.length) return FailInstruction(instr, "truncated POP");
    uint8_t opcode = instr.bytes[opPos];
    if (opcode >= 0x58 && opcode <= 0x5F) {
        uint8_t reg = static_cast<uint8_t>((opcode - 0x58) | ((rex & 0x01) ? 8 : 0));
        outInstr.opcode = VM_POP_R;
        outInstr.regDst = MapRegister(reg);
        outInstr.operandWidth = 8;
        return true;
    }
    return FailInstruction(instr, "unsupported POP encoding");
}
bool Translator::TranslateJump(const Instruction& instr, BytecodeInstr& outInstr) {
    if (!instr.hasTarget) return FailInstruction(instr, "jump instruction has no decoded target");

    if (instr.bytes[0] == 0xEB || instr.bytes[0] == 0xE9) {
        outInstr.opcode = VM_JMP;
        outInstr.jumpTarget = static_cast<uint32_t>(instr.targetAddress);
        outInstr.isJump = true;
        return true;
    }

    uint8_t cond = 0xFF;
    if (instr.bytes[0] >= 0x70 && instr.bytes[0] <= 0x7F) {
        cond = instr.bytes[0] - 0x70;
    } else if (instr.bytes[0] == 0x0F && instr.bytes[1] >= 0x80 && instr.bytes[1] <= 0x8F) {
        cond = instr.bytes[1] - 0x80;
    }

    if (cond != 0xFF) {
        switch (cond) {
            case 0x0: outInstr.opcode = VM_JO;  break;
            case 0x1: outInstr.opcode = VM_JNO; break;
            case 0x2: outInstr.opcode = VM_JB;  break;
            case 0x3: outInstr.opcode = VM_JAE; break;
            case 0x4: outInstr.opcode = VM_JZ;  break;
            case 0x5: outInstr.opcode = VM_JNZ; break;
            case 0x6: outInstr.opcode = VM_JBE; break;
            case 0x7: outInstr.opcode = VM_JA;  break;
            case 0x8: outInstr.opcode = VM_JS;  break;
            case 0x9: outInstr.opcode = VM_JNS; break;
            case 0xA: return FailInstruction(instr, "JP/JPE requires parity flag bridge that is not implemented");
            case 0xB: return FailInstruction(instr, "JNP/JPO requires parity flag bridge that is not implemented");
            case 0xC: outInstr.opcode = VM_JL;  break;
            case 0xD: outInstr.opcode = VM_JGE; break;
            case 0xE: outInstr.opcode = VM_JLE; break;
            case 0xF: outInstr.opcode = VM_JG;  break;
        }
        outInstr.jumpTarget = static_cast<uint32_t>(instr.targetAddress);
        outInstr.isJump = true;
        return true;
    }

    return FailInstruction(instr, "unsupported jump encoding");
}
bool Translator::TranslateCall(const Instruction& instr, BytecodeInstr& outInstr) {
    if (instr.isIndirect || !instr.hasTarget) {
        return FailInstruction(instr, "indirect CALL requires annotated native bridge target");
    }
    if (instr.targetAddress > 0xFFFFFFFFULL) {
        return FailInstruction(instr, "CALL target RVA is outside 32-bit PE RVA range");
    }
    outInstr.opcode = VM_CALL_NATIVE;
    outInstr.immediate = static_cast<uint32_t>(instr.targetAddress);
    outInstr.operandWidth = 8;
    return true;
}
bool Translator::TranslateRet(const Instruction& instr, BytecodeInstr& outInstr) {
    // RET
    if (instr.bytes[0] == 0xC3) {
        outInstr.opcode = VM_RET_VM;
        return true;
    }
    // RET imm16
    if (instr.bytes[0] == 0xC2) {
        outInstr.opcode = VM_RET_VM;
        outInstr.immediate = *(uint16_t*)(instr.bytes + 1);
        return true;
    }

    outInstr.opcode = VM_RET_VM;
    return true;
}

bool Translator::TranslateNop(const Instruction& instr, BytecodeInstr& outInstr) {
    outInstr.opcode = VM_NOP;
    return true;
}

// ============================================================================
// 鍐呴儴瀹炵幇
// ============================================================================

uint8_t Translator::MapRegister(uint8_t x86Reg) {
    auto it = m_registerMap.find(x86Reg);
    if (it != m_registerMap.end()) {
        return it->second;
    }
    return x86Reg % m_config.virtualRegisterCount;
}

void Translator::EncodeInstruction(const BytecodeInstr& instr, std::vector<uint8_t>& bytecode) {
    // 濡傛灉鍚敤浜?opcode 闅忔満鍖栵紝鏄犲皠 opcode
    uint8_t encodedOpcode = instr.opcode;
    if (m_config.enableOpcodeRandomization) {
        auto it = m_opcodeMap.find(instr.opcode);
        if (it != m_opcodeMap.end()) {
            encodedOpcode = it->second;
        }
    }

    // 缂栫爜 opcode
    EncodeOpcode(encodedOpcode, bytecode);

    // 鏍规嵁鎸囦护绫诲瀷缂栫爜鎿嶄綔鏁?
    switch (instr.opcode) {
        case VM_NOP:
            break;

        case VM_MOV_RR:
        case VM_ADD_RR:
        case VM_SUB_RR:
        case VM_AND_RR:
        case VM_OR_RR:
        case VM_XOR_RR:
        case VM_CMP_RR:
        case VM_TEST_RR:
        case VM_SHL_RR:
        case VM_SHR_RR:
        case VM_SAR_RR:
        case VM_ADC_RR:
        case VM_SBB_RR:
        case VM_XCHG:
            EncodeRegister(instr.regDst, bytecode);
            EncodeRegister(instr.regSrc, bytecode);
            bytecode.push_back(instr.operandWidth);
            break;

        case VM_MOV_RC:
        case VM_ADD_RC:
        case VM_SUB_RC:
        case VM_AND_RC:
        case VM_OR_RC:
        case VM_XOR_RC:
        case VM_CMP_RC:
        case VM_TEST_RC:
        case VM_PUSH_C:
            EncodeRegister(instr.regDst, bytecode);
            EncodeImmediate64(instr.immediate, bytecode);
            bytecode.push_back(instr.operandWidth);
            break;

        case VM_PUSH_R:
        case VM_POP_R:
        case VM_INC_R:
        case VM_DEC_R:
        case VM_NEG_R:
        case VM_NOT_R:
            EncodeRegister(instr.regDst, bytecode);
            bytecode.push_back(instr.operandWidth);
            break;

        case VM_MOV_RM:
        case VM_MOV_MR:
        case VM_LEA:
            EncodeRegister(instr.regDst, bytecode);
            EncodeRegister(instr.regSrc, bytecode);
            bytecode.push_back(instr.memBaseReg);
            bytecode.push_back(instr.memIndexReg);
            bytecode.push_back(instr.memScale);
            bytecode.push_back(instr.memWidth);
            bytecode.push_back(instr.memoryKind);
            EncodeImmediate64(static_cast<uint64_t>(instr.memDisp), bytecode);
            break;

        case VM_JMP:
        case VM_JZ:
        case VM_JNZ:
        case VM_JA:
        case VM_JB:
        case VM_JAE:
        case VM_JBE:
        case VM_JG:
        case VM_JL:
        case VM_JGE:
        case VM_JLE:
        case VM_JO:
        case VM_JNO:
        case VM_JS:
        case VM_JNS:
        case VM_CALL_VM:
            EncodeImmediate32((uint32_t)instr.immediate, bytecode);
            break;

        case VM_PUSHAD:
        case VM_POPAD:
        case VM_PUSHF:
        case VM_POPF:
        case VM_RET_VM:
        case VM_VMEXIT:
            break;

        case VM_CALL_NATIVE:
            EncodeImmediate32((uint32_t)instr.immediate, bytecode);
            break;

        case VM_INT3:
            break;

        default:
            break;
    }
}

void Translator::EncodeOpcode(uint8_t opcode, std::vector<uint8_t>& bytecode) {
    bytecode.push_back(opcode);
}

void Translator::EncodeRegister(uint8_t reg, std::vector<uint8_t>& bytecode) {
    bytecode.push_back(reg);
}

void Translator::EncodeImmediate32(uint32_t imm, std::vector<uint8_t>& bytecode) {
    bytecode.push_back((uint8_t)(imm));
    bytecode.push_back((uint8_t)(imm >> 8));
    bytecode.push_back((uint8_t)(imm >> 16));
    bytecode.push_back((uint8_t)(imm >> 24));
}

void Translator::EncodeImmediate64(uint64_t imm, std::vector<uint8_t>& bytecode) {
    for (int i = 0; i < 8; i++) {
        bytecode.push_back((uint8_t)(imm >> (i * 8)));
    }
}

void Translator::EncryptBytecode(std::vector<uint8_t>& bytecode, const uint8_t* key, const uint8_t* nonce) {
    if (!key || bytecode.empty()) return;

    // 浣跨敤婊氬姩瀵嗛挜鍔犲瘑
    uint32_t rollingKey = 0;
    for (int i = 0; i < 4; i++) {
        rollingKey |= ((uint32_t)key[i]) << (i * 8);
    }

    for (size_t i = 0; i < bytecode.size(); i++) {
        uint8_t keyByte = (uint8_t)(rollingKey & 0xFF);
        bytecode[i] ^= keyByte;

        // 鏇存柊婊氬姩瀵嗛挜
        rollingKey = (rollingKey >> 8) | (rollingKey << 24);
        rollingKey ^= (uint32_t)bytecode[i];
    }
}

BytecodeInstr Translator::GenerateJunkInstruction() {
    BytecodeInstr junk;
    memset(&junk, 0, sizeof(junk));
    junk.opcode = VM_NOP;
    return junk;
}

bool Translator::FailInstruction(const Instruction& instr, const std::string& reason) {
    TranslationFailure failure{};
    failure.address = instr.address;
    failure.mnemonic = instr.mnemonic.empty() ? "<unknown>" : instr.mnemonic;
    failure.bytes = FormatInstructionBytes(instr);
    if (instr.length == 0) {
        failure.reason = (reason == "empty_instruction_bytes")
            ? "empty_instruction_bytes"
            : "empty_instruction_bytes: " + reason;
    } else {
        failure.reason = reason;
    }
    m_lastFailures.push_back(failure);
    return false;
}uint8_t Translator::GetOpcodeForInstruction(const std::string& mnemonic) {
    if (mnemonic == "mov") return VM_MOV_RR;
    if (mnemonic == "add") return VM_ADD_RR;
    if (mnemonic == "sub") return VM_SUB_RR;
    if (mnemonic == "and") return VM_AND_RR;
    if (mnemonic == "or")  return VM_OR_RR;
    if (mnemonic == "xor") return VM_XOR_RR;
    if (mnemonic == "cmp") return VM_CMP_RR;
    if (mnemonic == "push") return VM_PUSH_R;
    if (mnemonic == "pop") return VM_POP_R;
    if (mnemonic == "call") return VM_CALL_VM;
    if (mnemonic == "ret") return VM_RET_VM;
    if (mnemonic == "nop") return VM_NOP;
    if (mnemonic == "int3") return VM_INT3;
    return 0xFF;
}

bool Translator::IsJumpInstruction(const std::string& mnemonic) {
    return (mnemonic[0] == 'j' || mnemonic == "jmp" || mnemonic == "call");
}

// BUG 1 淇杈呭姪锛氭牴鎹寚浠ょ被鍨嬭绠楃紪鐮佸悗鐨勫疄闄呭瓧鑺傞暱搴?
uint32_t Translator::CalculateEncodedSize(const BytecodeInstr& instr) {
    switch (instr.opcode) {
        // 鏃犳搷浣滄暟锛氫粎 opcode (1 瀛楄妭)
        case VM_NOP:
        case VM_PUSHAD:
        case VM_POPAD:
        case VM_PUSHF:
        case VM_POPF:
        case VM_RET_VM:
        case VM_VMEXIT:
        case VM_INT3:
            return 1;

        // 鍙屽瘎瀛樺櫒鎿嶄綔鏁帮細opcode + regDst + regSrc (3 瀛楄妭)
        case VM_MOV_RR:
        case VM_ADD_RR:
        case VM_SUB_RR:
        case VM_AND_RR:
        case VM_OR_RR:
        case VM_XOR_RR:
        case VM_CMP_RR:
        case VM_TEST_RR:
        case VM_SHL_RR:
        case VM_SHR_RR:
        case VM_SAR_RR:
        case VM_ADC_RR:
        case VM_SBB_RR:
        case VM_XCHG:
            return 4;

        // Register + immediate: opcode + reg + imm64 + width (11 bytes)
        case VM_MOV_RC:
        case VM_ADD_RC:
        case VM_SUB_RC:
        case VM_AND_RC:
        case VM_OR_RC:
        case VM_XOR_RC:
        case VM_CMP_RC:
        case VM_TEST_RC:
        case VM_PUSH_C:
            return 11;

        // Single register operand: opcode + reg + width (3 bytes)
        case VM_PUSH_R:
        case VM_POP_R:
        case VM_INC_R:
        case VM_DEC_R:
        case VM_NEG_R:
        case VM_NOT_R:
            return 3;

        // Memory operands: opcode + dst + src + base + index + scale + width + kind + disp64.
        case VM_MOV_RM:
        case VM_MOV_MR:
        case VM_LEA:
            return 16;

        // 璺宠浆/璋冪敤锛堢珛鍗虫暟32锛夛細opcode + imm32 (5 瀛楄妭)
        case VM_JMP:
        case VM_JZ:
        case VM_JNZ:
        case VM_JA:
        case VM_JB:
        case VM_JAE:
        case VM_JBE:
        case VM_JG:
        case VM_JL:
        case VM_JGE:
        case VM_JLE:
        case VM_JO:
        case VM_JNO:
        case VM_JS:
        case VM_JNS:
        case VM_CALL_VM:
            return 5;

        // CALL_NATIVE锛歰pcode + dllHash(imm32) + funcHash(imm32) (9 瀛楄妭)
        case VM_CALL_NATIVE:
            return 5;

        default:
            return 1;  // 瀹夊叏榛樿鍊?
    }
}

} // namespace CipherShell





