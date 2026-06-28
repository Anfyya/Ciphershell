/**
 * CipherShell 虚假控制流 - 实现
 */

#include "bogus_flow.h"
#include <algorithm>
#include <random>
#include <ctime>

namespace CipherShell {

// ============================================================================
// 构造/析构
// ============================================================================

BogusFlowInjector::BogusFlowInjector() 
    : m_nextBlockId(1000)
{
    srand((unsigned int)time(nullptr));
}

BogusFlowInjector::~BogusFlowInjector() {}

// ============================================================================
// 公共接口
// ============================================================================

BogusFlowResult BogusFlowInjector::Inject(const ControlFlowGraph& cfg, const BogusFlowConfig& config) {
    BogusFlowResult result;
    result.totalBlocks = 0;
    result.bogusCount = 0;
    result.duplicateCount = 0;

    // 处理每个真实块
    for (const auto& node : cfg.nodes) {
        // 添加原始块
        BogusBlock realBlock;
        realBlock.id = node.id;
        realBlock.originalId = node.id;
        realBlock.isBogus = false;
        realBlock.isDuplicate = false;
        realBlock.block = node.block;

        result.allBlocks.push_back(realBlock);
        result.realBlockIds.push_back(node.id);
        result.totalBlocks++;

        // 插入假块
        for (uint32_t i = 0; i < config.bogusBlocksPerReal; i++) {
            BogusBlock bogus = CreateBogusBlock(node.id, node.block);
            result.allBlocks.push_back(bogus);
            result.bogusBlockIds.push_back(bogus.id);
            result.bogusCount++;
            result.totalBlocks++;
        }

        // 复制代码
        if (config.duplicateCode && ShouldDuplicate(config.duplicateRatio)) {
            BogusBlock duplicate = CreateDuplicateBlock(node.id, node.block);
            result.allBlocks.push_back(duplicate);
            result.duplicateCount++;
            result.totalBlocks++;
        }
    }

    // 插入死代码块
    if (config.insertDeadCode) {
        for (uint32_t i = 0; i < config.bogusBlocksPerReal; i++) {
            BogusBlock deadBlock;
            deadBlock.id = GenerateBlockId();
            deadBlock.originalId = (uint64_t)-1;
            deadBlock.isBogus = true;
            deadBlock.isDuplicate = false;
            deadBlock.block = GenerateDeadCode();
            deadBlock.guardPredicate = m_predicateGen.GenerateAlwaysFalse();

            result.allBlocks.push_back(deadBlock);
            result.bogusBlockIds.push_back(deadBlock.id);
            result.bogusCount++;
            result.totalBlocks++;
        }
    }

    // 随机重排序
    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(result.allBlocks.begin(), result.allBlocks.end(), g);

    return result;
}

BogusFlowResult BogusFlowInjector::InjectIntoFunction(const Function& func, const BogusFlowConfig& config) {
    CFGBuilder builder;
    ControlFlowGraph cfg = builder.Build(func.blocks);

    return Inject(cfg, config);
}

BYTE* BogusFlowInjector::GenerateBogusCode(const BogusFlowResult& result, bool is64Bit, DWORD* codeSize) {
    if (!codeSize) return nullptr;

    // 估算代码大小
    DWORD estimatedSize = result.totalBlocks * 100;

    BYTE* code = new(std::nothrow) BYTE[estimatedSize];
    if (!code) return nullptr;

    DWORD offset = 0;

    // 生成每个块的代码
    for (const auto& bogusBlock : result.allBlocks) {
        // 为假块生成不透明谓词检查
        if (bogusBlock.isBogus) {
            DWORD predSize = 0;
            BYTE* predCode = m_predicateGen.GenerateConditionalJump(
                bogusBlock.guardPredicate,
                0,  // 目标地址稍后填充
                is64Bit,
                &predSize
            );

            if (predCode && offset + predSize < estimatedSize) {
                memcpy(code + offset, predCode, predSize);
                offset += predSize;
                delete[] predCode;
            }
        }

        // 生成块代码（简化）
        // 实际实现需要复制原始块的指令
    }

    *codeSize = offset;
    return code;
}

void BogusFlowInjector::Cleanup(BogusFlowResult& result) {
    result.allBlocks.clear();
    result.realBlockIds.clear();
    result.bogusBlockIds.clear();
    result.totalBlocks = 0;
    result.bogusCount = 0;
    result.duplicateCount = 0;
}

// ============================================================================
// 内部实现
// ============================================================================

BogusBlock BogusFlowInjector::CreateBogusBlock(uint64_t originalId, const BasicBlock& originalBlock) {
    BogusBlock bogus;
    bogus.id = GenerateBlockId();
    bogus.originalId = originalId;
    bogus.isBogus = true;
    bogus.isDuplicate = false;

    // 创建假的基本块（使用死代码生成器生成逼真的代码）
    bogus.block = GenerateDeadCode();
    bogus.block.startAddress = bogus.id * 0x100;

    // 生成守护谓词（恒假，所以这段代码永远不会执行）
    bogus.guardPredicate = m_predicateGen.GenerateAlwaysFalse();

    return bogus;
}

BogusBlock BogusFlowInjector::CreateDuplicateBlock(uint64_t originalId, const BasicBlock& originalBlock) {
    BogusBlock duplicate;
    duplicate.id = GenerateBlockId();
    duplicate.originalId = originalId;
    duplicate.isBogus = false;
    duplicate.isDuplicate = true;

    // 复制并变异原始块
    duplicate.block = MutateBlock(originalBlock);
    duplicate.block.startAddress = duplicate.id * 0x100;

    // 生成随机守护谓词
    duplicate.guardPredicate = m_predicateGen.GenerateAlwaysTrue();

    return duplicate;
}

BasicBlock BogusFlowInjector::GenerateDeadCode() {
    BasicBlock deadBlock;
    deadBlock.startAddress = GenerateBlockId() * 0x100;
    deadBlock.instructionCount = 0;

    // 随机选择一种死代码模式（看起来像真实计算但永远不会执行）
    uint32_t pattern = rand() % 5;
    uint64_t addr = deadBlock.startAddress;

    auto addInstr = [&](const char* mnem, std::initializer_list<uint8_t> bytes) {
        Instruction instr;
        memset(&instr, 0, sizeof(instr));
        instr.address = addr;
        instr.length = (uint8_t)bytes.size();
        int i = 0;
        for (uint8_t b : bytes) instr.bytes[i++] = b;
        instr.mnemonic = mnem;
        deadBlock.instructions.push_back(instr);
        deadBlock.instructionCount++;
        addr += instr.length;
    };

    switch (pattern) {
        case 0:
            // 模拟循环计数器：mov ecx, N; dec ecx; jnz -2（但不跳）
            addInstr("push", {0x51});                          // push ecx
            addInstr("mov",  {0xB9, 0x0A, 0x00, 0x00, 0x00}); // mov ecx, 10
            addInstr("dec",  {0x49});                          // dec ecx
            addInstr("lea",  {0x8D, 0x04, 0x09});              // lea eax, [ecx+ecx]
            addInstr("xor",  {0x31, 0xD2});                    // xor edx, edx
            addInstr("add",  {0x01, 0xC2});                    // add edx, eax
            addInstr("pop",  {0x59});                          // pop ecx
            break;

        case 1:
            // 模拟内存操作：push/pop 序列
            addInstr("push", {0x50});                          // push eax
            addInstr("push", {0x53});                          // push ebx
            addInstr("mov",  {0xB8, 0xFF, 0x00, 0x00, 0x00}); // mov eax, 0xFF
            addInstr("mov",  {0xBB, 0x01, 0x00, 0x00, 0x00}); // mov ebx, 1
            addInstr("xor",  {0x31, 0xD8});                    // xor eax, ebx
            addInstr("shl",  {0xC1, 0xE0, 0x03});              // shl eax, 3
            addInstr("pop",  {0x5B});                          // pop ebx
            addInstr("pop",  {0x58});                          // pop eax
            break;

        case 2:
            // 模拟哈希计算
            addInstr("push", {0x50});                          // push eax
            addInstr("mov",  {0xB8, 0x35, 0x00, 0x00, 0x00}); // mov eax, 0x35
            addInstr("imul", {0x6B, 0xC0, 0x25});              // imul eax, eax, 0x25
            addInstr("add",  {0x05, 0x11, 0x22, 0x33, 0x44}); // add eax, 0x44332211
            addInstr("ror",  {0xC1, 0xC8, 0x07});              // ror eax, 7
            addInstr("xor",  {0x35, 0xAA, 0xBB, 0xCC, 0xDD}); // xor eax, 0xDDCCBBAA
            addInstr("pop",  {0x58});                          // pop eax
            break;

        case 3:
            // 模拟条件设置
            addInstr("push", {0x50});                          // push eax
            addInstr("push", {0x51});                          // push ecx
            addInstr("mov",  {0xB8, 0x42, 0x00, 0x00, 0x00}); // mov eax, 0x42
            addInstr("mov",  {0xB9, 0x42, 0x00, 0x00, 0x00}); // mov ecx, 0x42
            addInstr("cmp",  {0x39, 0xC8});                    // cmp eax, ecx
            addInstr("setz", {0x0F, 0x94, 0xC0});              // setz al
            addInstr("pop",  {0x59});                          // pop ecx
            addInstr("pop",  {0x58});                          // pop eax
            break;

        case 4:
            // 位扫描模式
            addInstr("push", {0x50});                          // push eax
            addInstr("push", {0x52});                          // push edx
            addInstr("mov",  {0xB8, 0xFF, 0x00, 0x00, 0x00}); // mov eax, 0xFF
            addInstr("bsf",  {0x0F, 0xBC, 0xD0});             // bsf edx, eax
            addInstr("bsr",  {0x0F, 0xBD, 0xD0});             // bsr edx, eax
            addInstr("xor",  {0x31, 0xC0});                    // xor eax, eax
            addInstr("pop",  {0x5A});                          // pop edx
            addInstr("pop",  {0x58});                          // pop eax
            break;

        default:
            // 默认: NOP 滑梯
            for (int i = 0; i < 4; i++) {
                addInstr("nop", {0x90});
            }
            break;
    }

    return deadBlock;
}

// ============================================================================
// 块变异
// ============================================================================

BasicBlock BogusFlowInjector::MutateBlock(const BasicBlock& block) {
    BasicBlock mutated = block;

    // 在指令序列中插入 NOP
    if (!mutated.instructions.empty()) {
        Instruction nop;
        memset(&nop, 0, sizeof(nop));
        nop.address = mutated.startAddress;
        nop.length = 1;
        nop.bytes[0] = 0x90;
        nop.mnemonic = "nop";
        mutated.instructions.insert(mutated.instructions.begin(), nop);
        mutated.instructionCount++;
    }

    return mutated;
}

// ============================================================================
// 寄存器重映射
// ============================================================================

void BogusFlowInjector::RemapRegisters(BasicBlock& block) {
    // 简化版：在块内的指令字节中交换 EAX<->ECX
    for (auto& instr : block.instructions) {
        for (uint32_t i = 0; i < instr.length; i++) {
            if (i + 1 < instr.length) {
                if (instr.bytes[i] == 0x31 || instr.bytes[i] == 0x33) {
                    uint8_t modrm = instr.bytes[i + 1];
                    uint8_t reg = (modrm >> 3) & 7;
                    uint8_t rm = modrm & 7;
                    if (reg == 0) reg = 1; else if (reg == 1) reg = 0;
                    if (rm == 0) rm = 1; else if (rm == 1) rm = 0;
                    instr.bytes[i + 1] = (modrm & 0xC0) | (reg << 3) | rm;
                }
            }
        }
    }
}

// ============================================================================
// 指令重排
// ============================================================================

void BogusFlowInjector::RearrangeInstructions(BasicBlock& block) {
    // 在不改变语义的前提下重排
    // 简化版：在开头插入 XCHG EAX,EAX (等效 NOP)
    if (!block.instructions.empty()) {
        Instruction xchg;
        memset(&xchg, 0, sizeof(xchg));
        xchg.address = block.startAddress;
        xchg.length = 2;
        xchg.bytes[0] = 0x87;
        xchg.bytes[1] = 0xC0;
        xchg.mnemonic = "xchg";
        block.instructions.insert(block.instructions.begin(), xchg);
        block.instructionCount++;
    }
}

// ============================================================================
// 块 ID 生成
// ============================================================================

uint64_t BogusFlowInjector::GenerateBlockId() {
    std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<uint64_t> dist(0x10000, 0x7FFFFFFF);
    return dist(rng);
}

// ============================================================================
// 是否需要复制块
// ============================================================================

bool BogusFlowInjector::ShouldDuplicate(float ratio) {
    float r = (float)rand() / (float)RAND_MAX;
    return r < ratio;
}

} // namespace CipherShell
