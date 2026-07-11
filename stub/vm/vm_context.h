/**
 * CipherShell Mirage VM - 虚拟 CPU 上下文
 * 混合架构虚拟机（栈+寄存器）
 */

#ifndef CS_VM_CONTEXT_H
#define CS_VM_CONTEXT_H

#include <stdint.h>
#include "../../runtime/common/vm_isa.h"

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// 配置常量
// ============================================================================

#define VM_MAX_REGISTERS    32      // 最大虚拟寄存器数
#define VM_STACK_SIZE       0x20000 // 虚拟栈大小
#define VM_MAX_OPCODE       256     // 最大 opcode 数
#define VM_KEY_SIZE         32      // 密钥大小
#define VM_NONCE_SIZE       12      // nonce 大小

// ============================================================================
// VM EFLAGS 模拟结构
// ============================================================================

typedef struct _VM_FLAGS {
    uint8_t     CF;     // Carry Flag
    uint8_t     ZF;     // Zero Flag
    uint8_t     SF;     // Sign Flag
    uint8_t     OF;     // Overflow Flag
    uint8_t     PF;     // Parity Flag
    uint8_t     AF;     // Auxiliary Flag
    uint8_t     DF;     // Direction Flag
    uint8_t     TF;     // Trap Flag
} VM_FLAGS;

// ============================================================================
// VM 寄存器上下文
// ============================================================================

typedef struct _VM_REGISTERS {
    uint64_t    r[VM_MAX_REGISTERS]; // 虚拟寄存器组
    uint64_t    sp;                 // 虚拟栈指针
    uint64_t    bp;                 // 虚拟基址指针
    uint64_t    ip;                 // 虚拟指令指针（bytecode偏移）
    uint64_t    flags;              // 虚拟EFLAGS（原始格式）
    VM_FLAGS    vflags;             // 虚拟EFLAGS（分离格式）
} VM_REGISTERS;

// ============================================================================
// VM 上下文
// ============================================================================

typedef struct _VM_CONTEXT {
    // 虚拟寄存器
    VM_REGISTERS    regs;

    // 虚拟栈
    uint8_t         stack[VM_STACK_SIZE];

    // Bytecode 流
    const uint8_t*  bytecode;       // bytecode 数据指针
    uint32_t        bytecodeSize;   // bytecode 大小

    // Bytecode 解密
    uint8_t         decryptKey[VM_KEY_SIZE];    // 当前解密密钥
    uint8_t         decryptNonce[VM_NONCE_SIZE]; // nonce
    uint32_t        decryptCounter;             // 计数器（滚动密钥用）
    uint32_t        rollingKey;                 // 滚动密钥状态

    // Handler 跳转表
    void**          handlerTable;   // handler 函数指针表
    uint32_t        handlerCount;   // handler 数量

    // 投毒/反调试
    uint32_t        poisonCountdown;    // 投毒倒计时
    uint32_t        pendingPoison;      // 待应用的投毒值
    uint32_t        detectionFlags;     // 检测标志

    // 保存的真实 CPU 状态（VMENTER/VMEXIT 用）
    uint64_t        nativeRegs[16];     // 原始寄存器快照
    uint64_t        nativeFlags;        // 原始 EFLAGS
    uint64_t        nativeStack[32];    // 原始栈快照（用于VMEXIT恢复）
    uint32_t        nativeStackSize;    // 保存的栈大小

    // 性能计数
    uint64_t        instrCount;         // 已执行指令数
    uint64_t        cyclesCount;        // 模拟周期数

    // 嵌套 VM 支持
    struct _VM_CONTEXT* parentCtx;  // 父 VM 上下文（嵌套用）
    uint32_t        nestingLevel;       // 嵌套层级

    // 运行状态
    uint8_t         running;            // 是否运行中
    uint8_t         exitReason;         // 退出原因
    uint32_t        errorCode;          // 错误码
} VM_CONTEXT;

// ============================================================================
// 退出原因
// ============================================================================

#define VM_EXIT_NORMAL      0x00    // 正常退出
#define VM_EXIT_ERROR       0x01    // 错误退出
#define VM_EXIT_NATIVE      0x02    // 退出到native执行
#define VM_EXIT_HALT        0x03    // 停机
#define VM_EXIT_DEBUG       0x04    // 调试断点
#define VM_EXIT_NESTED      0x05    // 嵌套VM调用

// ============================================================================
// 函数声明
// ============================================================================

/**
 * 初始化 VM 上下文
 * @param ctx VM 上下文
 * @param bytecode bytecode 数据
 * @param bytecodeSize bytecode 大小
 * @param handlerTable handler 跳转表
 * @param handlerCount handler 数量
 */
void vm_init(VM_CONTEXT* ctx, const uint8_t* bytecode, uint32_t bytecodeSize,
             void** handlerTable, uint32_t handlerCount);

/**
 * 设置解密密钥
 * @param ctx VM 上下文
 * @param key 密钥
 * @param nonce nonce
 */
void vm_set_key(VM_CONTEXT* ctx, const uint8_t* key, const uint8_t* nonce);

/**
 * 从 native 状态初始化 VM
 * @param ctx VM 上下文
 * @param nativeRegs 原始寄存器数组 (RAX, RBX, RCX, ...)
 * @param nativeFlags 原始 EFLAGS
 * @param nativeStack 原始栈数据
 * @param stackSize 栈大小
 */
void vm_enter(VM_CONTEXT* ctx, const uint64_t* nativeRegs, uint64_t nativeFlags,
              const uint8_t* nativeStack, uint32_t stackSize);

/**
 * 退出 VM，恢复 native 状态
 * @param ctx VM 上下文
 * @param outRegs 输出寄存器数组
 * @param outFlags 输出 EFLAGS
 * @param outStack 输出栈数据
 * @param stackSize 栈缓冲区大小
 */
void vm_exit(VM_CONTEXT* ctx, uint64_t* outRegs, uint64_t* outFlags,
             uint8_t* outStack, uint32_t stackSize);

/**
 * 执行 VM（主循环）
 * @param ctx VM 上下文
 * @return 退出原因
 */
uint8_t vm_execute(VM_CONTEXT* ctx);

/**
 * 获取 VM flags 的 EFLAGS 格式
 * @param vflags VM 分离 flags
 * @return EFLAGS 值
 */
uint64_t vm_flags_to_eflags(const VM_FLAGS* vflags);

/**
 * 从 EFLAGS 设置 VM flags
 * @param vflags VM 分离 flags
 * @param eflags EFLAGS 值
 */
void vm_eflags_to_flags(VM_FLAGS* vflags, uint64_t eflags);

#ifdef __cplusplus
}
#endif

#endif // CS_VM_CONTEXT_H
