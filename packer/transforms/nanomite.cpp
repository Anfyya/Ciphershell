/**
 * CipherShell Nanomite 技术 - 实现
 */

#include "nanomite.h"
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <algorithm>
#include <random>

namespace CipherShell {

// ============================================================================
// 构造/析构
// ============================================================================

NanomiteInjector::NanomiteInjector()
    : m_nextId(1)
    , m_encryptionKey(0xCAFEBABE)
{
    srand((unsigned int)time(nullptr));
}

NanomiteInjector::~NanomiteInjector() {}

// ============================================================================
// 公共接口
// ============================================================================

NanomiteResult NanomiteInjector::Inject(
    const std::vector<BasicBlock>& blocks,
    const NanomiteConfig& config)
{
    NanomiteResult result;
    result.jumpTableData = nullptr;
    result.jumpTableSize = 0;
    result.vehHandlerCode = nullptr;
    result.vehHandlerSize = 0;

    // 扫描所有基本块中的跳转指令
    for (const auto& block : blocks) {
        for (const auto& instr : block.instructions) {
            if (!ShouldReplace(instr, config)) continue;

            NanomiteEntry entry;
            entry.id = GenerateId();
            entry.address = instr.address;
            entry.originalOpcode = instr.bytes[0];
            entry.isConditional = instr.isConditional;

            if (instr.isConditional) {
                // 条件跳转：两个可能的目标
                entry.conditionType = AnalyzeCondition(instr);
                entry.targetTrue = instr.targetAddress;
                entry.targetFalse = instr.address + instr.length;
            } else {
                // 无条件跳转
                entry.conditionType = 0xFF;  // 总是跳转
                entry.targetTrue = instr.targetAddress;
                entry.targetFalse = instr.address + instr.length;
            }

            result.entries.push_back(entry);
            result.addrMap[entry.address] = (uint32_t)(result.entries.size() - 1);
        }
    }

    // 随机化表顺序
    if (config.randomizeTableOrder) {
        std::random_device rd;
        std::mt19937 g(rd());
        std::shuffle(result.entries.begin(), result.entries.end(), g);

        // 重建映射
        result.addrMap.clear();
        for (size_t i = 0; i < result.entries.size(); i++) {
            result.addrMap[result.entries[i].address] = (uint32_t)i;
        }
    }

    // 生成跳转表
    result.jumpTableData = GenerateJumpTable(result.entries, config.encryptJumpTable, &result.jumpTableSize);

    return result;
}

BYTE* NanomiteInjector::GenerateVEHHandler(
    const std::vector<NanomiteEntry>& entries,
    bool is64Bit,
    DWORD* handlerSize)
{
    if (!handlerSize) return nullptr;

    // VEH 处理器的简化实现
    // 实际实现需要更复杂的代码

    if (is64Bit) {
        // x64 VEH handler stub
        static const BYTE x64_handler[] = {
            // rcx = PEXCEPTION_POINTERS
            0x48, 0x89, 0xC8,                   // mov rax, rcx
            // 获取异常记录
            0x48, 0x8B, 0x08,                   // mov rcx, [rax]  ; ExceptionRecord
            0x48, 0x8B, 0x50, 0x08,             // mov rdx, [rax+8] ; ContextRecord
            // 检查异常类型
            0x8B, 0x01,                         // mov eax, [rcx]  ; ExceptionCode
            0x3D, 0x80, 0x00, 0x00, 0xC0,       // cmp eax, 0xC0000080  ; STATUS_SINGLE_STEP
            0x74, 0x0B,                         // jz .handle
            0x3D, 0x03, 0x00, 0x00, 0xC0,       // cmp eax, 0xC0000003  ; STATUS_BREAKPOINT
            0x74, 0x04,                         // jz .handle
            0x31, 0xC0,                         // xor eax, eax    ; EXCEPTION_CONTINUE_SEARCH
            0xC3,                               // ret
            // .handle:
            // 查找跳转表，修改 RIP
            0xB8, 0x01, 0x00, 0x00, 0x00,       // mov eax, 1  ; EXCEPTION_CONTINUE_EXECUTION
            0xC3                                // ret
        };

        *handlerSize = sizeof(x64_handler);
        BYTE* output = new BYTE[sizeof(x64_handler)];
        memcpy(output, x64_handler, sizeof(x64_handler));
        return output;
    } else {
        // x86 VEH handler stub
        static const BYTE x86_handler[] = {
            // [esp+4] = PEXCEPTION_POINTERS
            0x55,                               // push ebp
            0x89, 0xE5,                         // mov ebp, esp
            0x53,                               // push ebx
            0x8B, 0x45, 0x08,                   // mov eax, [ebp+8]
            0x8B, 0x08,                         // mov ecx, [eax]  ; ExceptionRecord
            0x8B, 0x50, 0x04,                   // mov edx, [eax+4] ; ContextRecord
            0x8B, 0x01,                         // mov eax, [ecx]
            0x3D, 0x03, 0x00, 0x00, 0xC0,       // cmp eax, 0xC0000003
            0x74, 0x07,                         // jz .handle
            0x31, 0xC0,                         // xor eax, eax
            0x5B,                               // pop ebx
            0x5D,                               // pop ebp
            0xC3,                               // ret
            // .handle:
            0xB8, 0x01, 0x00, 0x00, 0x00,       // mov eax, 1
            0x5B,                               // pop ebx
            0x5D,                               // pop ebp
            0xC3                                // ret
        };

        *handlerSize = sizeof(x86_handler);
        BYTE* output = new BYTE[sizeof(x86_handler)];
        memcpy(output, x86_handler, sizeof(x86_handler));
        return output;
    }
}

BYTE* NanomiteInjector::GenerateJumpTable(
    const std::vector<NanomiteEntry>& entries,
    bool encrypt,
    DWORD* tableSize)
{
    if (!tableSize) return nullptr;

    // 跳转表格式：[count:4][entries:N*20]
    // 每个条目：[address:8][targetTrue:8][conditionType:1][isConditional:1][padding:2]
    DWORD entrySize = 8 + 8 + 1 + 1 + 2;  // 20 bytes per entry
    DWORD totalSize = 4 + (DWORD)entries.size() * entrySize;

    BYTE* table = new(std::nothrow) BYTE[totalSize];
    if (!table) return nullptr;

    DWORD offset = 0;

    // 写入条目数量
    *(DWORD*)(table + offset) = (DWORD)entries.size();
    offset += 4;

    uint32_t encKey = encrypt ? m_encryptionKey : 0;

    for (const auto& entry : entries) {
        // 写入地址
        uint64_t addr = encrypt ? (entry.address ^ encKey) : entry.address;
        *(uint64_t*)(table + offset) = addr;
        offset += 8;

        // 写入目标
        uint64_t target = encrypt ? (entry.targetTrue ^ encKey) : entry.targetTrue;
        *(uint64_t*)(table + offset) = target;
        offset += 8;

        // 写入条件类型
        table[offset++] = encrypt ? (entry.conditionType ^ (uint8_t)encKey) : entry.conditionType;
        table[offset++] = entry.isConditional ? 1 : 0;
        offset += 2;  // padding
    }

    *tableSize = totalSize;
    return table;
}

void NanomiteInjector::Cleanup(NanomiteResult& result) {
    result.entries.clear();
    result.addrMap.clear();

    if (result.jumpTableData) {
        delete[] result.jumpTableData;
        result.jumpTableData = nullptr;
    }
    if (result.vehHandlerCode) {
        delete[] result.vehHandlerCode;
        result.vehHandlerCode = nullptr;
    }
}

// ============================================================================
// 内部实现
// ============================================================================

uint8_t NanomiteInjector::AnalyzeCondition(const Instruction& instr) {
    // 根据跳转指令类型返回条件编码
    uint8_t opcode = instr.bytes[0];

    // 条件跳转 0x70-0x7F
    if (opcode >= 0x70 && opcode <= 0x7F) {
        return opcode - 0x70;
    }

    return 0xFF;
}

bool NanomiteInjector::ShouldReplace(const Instruction& instr, const NanomiteConfig& config) {
    if (instr.mnemonic.empty()) return false;

    // 条件跳转
    if (instr.isConditional && config.replaceConditionalJumps) {
        // 检查跳转距离
        if (instr.hasTarget) {
            int64_t distance = (int64_t)instr.targetAddress - (int64_t)instr.address;
            if (distance < 0) distance = -distance;
            if (distance < config.minJumpDistance) return false;
        }
        return true;
    }

    // 无条件跳转
    if (!instr.isConditional && instr.isBranch && config.replaceUnconditionalJumps) {
        return true;
    }

    return false;
}

uint32_t NanomiteInjector::GenerateId() {
    return m_nextId++;
}

uint32_t NanomiteInjector::EncryptEntryId(uint32_t id, uint32_t key) {
    return id ^ key;
}

} // namespace CipherShell
