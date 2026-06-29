/**
 * CipherShell VM 嵌套器
 * 将部分 handler 的实现本身也虚拟化（用另一套不同 ISA 的 VM 执行）
 */

#ifndef CS_VM_NESTER_H
#define CS_VM_NESTER_H

#ifdef _WIN32
#include <windows.h>
#else
#include "windows_compat.h"
#endif
#include "../../stub/vm/vm_context.h"
#include "../mutation/mutation_engine.h"
#include <cstdint>
#include <vector>
#include <unordered_map>

namespace CipherShell {

// ============================================================================
// 嵌套层级信息
// ============================================================================

struct NestingLayer {
    uint32_t                level;          // 嵌套层级 (0=外层)
    MutatedISA              isa;            // 该层的 ISA
    std::vector<uint8_t>    bytecode;       // 该层的字节码
    uint32_t                handlerStart;   // handler 起始偏移
    uint32_t                handlerSize;    // handler 大小
};

// ============================================================================
// 嵌套配置
// ============================================================================

struct NestingConfig {
    uint32_t    maxNestingDepth;        // 最大嵌套层数
    uint32_t    nestedHandlerCount;     // 被嵌套的 handler 数量
    bool        differentISA;           // 每层使用不同 ISA
    bool        differentDispatch;      // 每层使用不同 dispatch 方式
    bool        differentRegisterCount; // 每层不同寄存器数

    NestingConfig() :
        maxNestingDepth(2),
        nestedHandlerCount(10),
        differentISA(true),
        differentDispatch(true),
        differentRegisterCount(true) {}
};

// ============================================================================
// VM 嵌套器类
// ============================================================================

class VMNester {
public:
    VMNester();
    ~VMNester();

    /**
     * 初始化嵌套器
     * @param config 嵌套配置
     * @return 是否成功
     */
    bool Initialize(const NestingConfig& config);

    /**
     * 创建嵌套 VM
     * @param outerISA 外层 ISA
     * @return 嵌套层级列表
     */
    std::vector<NestingLayer> CreateNestedVM(const MutatedISA& outerISA);

    /**
     * 将 handler 转换为嵌套 VM 字节码
     * @param handlerCode 原始 handler 代码
     * @param handlerSize 代码大小
     * @param layer 嵌套层级
     * @return 嵌套后的字节码
     */
    std::vector<uint8_t> NestHandler(
        const uint8_t* handlerCode,
        uint32_t handlerSize,
        const NestingLayer& layer
    );

    /**
     * 生成嵌套 VM 的 dispatcher 代码
     * @param layer 嵌套层级
     * @param is64Bit 是否 64 位
     * @param codeSize 输出大小
     * @return dispatcher 代码
     */
    BYTE* GenerateNestedDispatcher(
        const NestingLayer& layer,
        bool is64Bit,
        DWORD* codeSize
    );

    /**
     * 获取嵌套层数
     * @return 层数
     */
    uint32_t GetNestingDepth() const;

private:
    // ISA 变异
    MutatedISA MutateISA(const MutatedISA& baseISA, uint32_t level);

    // 字节码转换
    std::vector<uint8_t> TranslateToNestedBytecode(
        const uint8_t* code,
        uint32_t size,
        const MutatedISA& fromISA,
        const MutatedISA& toISA
    );

    // 辅助函数
    uint32_t GenerateNestingSeed(uint32_t level);

    // 成员变量
    NestingConfig m_config;
    std::vector<NestingLayer> m_layers;
    std::vector<MutationEngine> m_mutators;  // 每层一个变异引擎
    bool m_initialized;
};

} // namespace CipherShell

#endif // CS_VM_NESTER_H
