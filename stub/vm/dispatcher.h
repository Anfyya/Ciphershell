/**
 * CipherShell Mirage VM - Dispatcher 头文件
 * 三种 dispatch 模式：跳转表、计算跳转、Threaded
 */

#ifndef CS_DISPATCHER_H
#define CS_DISPATCHER_H

#include "vm_context.h"

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Dispatch 模式
// ============================================================================

typedef enum _DISPATCH_MODE {
    DISPATCH_TABLE     = 0,   // 跳转表 dispatch
    DISPATCH_COMPUTED  = 1,   // 计算跳转 dispatch
    DISPATCH_THREADED  = 2,   // Threaded dispatch
    DISPATCH_MIXED     = 3    // 混合模式（随机）
} DISPATCH_MODE;

// ============================================================================
// Dispatcher 上下文
// ============================================================================

typedef struct _DISPATCH_CONTEXT {
    DISPATCH_MODE   mode;                       // 当前模式
    uintptr_t       dispatchBase;               // 计算跳转基地址
    uintptr_t       dispatchStride;             // 计算跳转步长
    uintptr_t       dispatchOffsets[256];        // 计算跳转偏移表

    // 滚动密钥
    uint32_t        rollingKey;                 // 当前滚动密钥
    uint32_t        keyRotationCount;           // 密钥轮换计数

    // Handler 变异种子
    uint32_t        mutationSeed;               // 变异种子

    // 性能计数
    uint64_t        dispatchCount;              // dispatch 次数
    uint64_t        totalCycles;                // 总周期数
} DISPATCH_CONTEXT;

// ============================================================================
// 函数声明
// ============================================================================

/**
 * 初始化 Dispatcher
 * @param dctx Dispatcher 上下文
 * @param ctx VM 上下文
 * @param mode dispatch 模式
 */
void dispatch_init(DISPATCH_CONTEXT* dctx, VM_CONTEXT* ctx, DISPATCH_MODE mode);

/**
 * 执行 VM（跳转表模式）
 * @param ctx VM 上下文
 * @param dctx Dispatcher 上下文
 * @return 退出原因
 */
uint8_t dispatch_table_execute(VM_CONTEXT* ctx, DISPATCH_CONTEXT* dctx);

/**
 * 执行 VM（计算跳转模式）
 * @param ctx VM 上下文
 * @param dctx Dispatcher 上下文
 * @return 退出原因
 */
uint8_t dispatch_computed_execute(VM_CONTEXT* ctx, DISPATCH_CONTEXT* dctx);

/**
 * 执行 VM（Threaded 模式）
 * @param ctx VM 上下文
 * @param dctx Dispatcher 上下文
 * @return 退出原因
 */
uint8_t dispatch_threaded_execute(VM_CONTEXT* ctx, DISPATCH_CONTEXT* dctx);

/**
 * 执行 VM（混合模式）
 * @param ctx VM 上下文
 * @param dctx Dispatcher 上下文
 * @return 退出原因
 */
uint8_t dispatch_mixed_execute(VM_CONTEXT* ctx, DISPATCH_CONTEXT* dctx);

/**
 * 从 bytecode 流读取并解密下一个字节
 * @param ctx VM 上下文
 * @return 解密后的字节
 */
uint8_t dispatch_fetch_opcode(VM_CONTEXT* ctx);

/**
 * 从 bytecode 流读取并解密一个 32 位立即数
 * @param ctx VM 上下文
 * @return 解密后的 32 位值
 */
uint32_t dispatch_fetch_imm32(VM_CONTEXT* ctx);

/**
 * 从 bytecode 流读取并解密一个 64 位立即数
 * @param ctx VM 上下文
 * @return 解密后的 64 位值
 */
uint64_t dispatch_fetch_imm64(VM_CONTEXT* ctx);

/**
 * 从 bytecode 流读取寄存器索引
 * @param ctx VM 上下文
 * @return 寄存器索引
 */
uint8_t dispatch_fetch_reg_index(VM_CONTEXT* ctx);

/**
 * 更新滚动密钥
 * @param dctx Dispatcher 上下文
 * @param opcode 当前 opcode
 */
void dispatch_update_key(DISPATCH_CONTEXT* dctx, uint8_t opcode);

#ifdef __cplusplus
}
#endif

#endif // CS_DISPATCHER_H
