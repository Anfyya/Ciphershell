/**
 * CipherShell Mirage VM - 上下文管理实现
 */

#include "vm_context.h"
#include <string.h>

// ============================================================================
// 初始化
// ============================================================================

void vm_init(VM_CONTEXT* ctx, const uint8_t* bytecode, uint32_t bytecodeSize,
             void** handlerTable, uint32_t handlerCount)
{
    if (!ctx) return;

    // 清零上下文
    memset(ctx, 0, sizeof(VM_CONTEXT));

    // 设置 bytecode
    ctx->bytecode = bytecode;
    ctx->bytecodeSize = bytecodeSize;

    // 设置 handler 表
    ctx->handlerTable = handlerTable;
    ctx->handlerCount = handlerCount;

    // 初始化滚动密钥
    ctx->rollingKey = 0x12345678;
    ctx->decryptCounter = 0;

    // 初始化栈指针（指向栈顶）
    ctx->regs.sp = VM_STACK_SIZE - 8;
    ctx->regs.bp = ctx->regs.sp;

    // 设置运行状态
    ctx->running = 1;
    ctx->exitReason = VM_EXIT_NORMAL;
    ctx->errorCode = 0;
    ctx->instrCount = 0;
    ctx->cyclesCount = 0;
    ctx->nestingLevel = 0;
    ctx->parentCtx = (void*)0;
}

void vm_set_key(VM_CONTEXT* ctx, const uint8_t* key, const uint8_t* nonce)
{
    if (!ctx || !key) return;

    memcpy(ctx->decryptKey, key, VM_KEY_SIZE);
    if (nonce) {
        memcpy(ctx->decryptNonce, nonce, VM_NONCE_SIZE);
    }

    // 初始化滚动密钥
    ctx->rollingKey = 0;
    for (int i = 0; i < 4; i++) {
        ctx->rollingKey |= ((uint32_t)key[i]) << (i * 8);
    }
}

// ============================================================================
// VMENTER / VMEXIT
// ============================================================================

void vm_enter(VM_CONTEXT* ctx, const uint64_t* nativeRegs, uint64_t nativeFlags,
              const uint8_t* nativeStack, uint32_t stackSize)
{
    if (!ctx) return;

    // 保存原始 CPU 状态
    if (nativeRegs) {
        memcpy(ctx->nativeRegs, nativeRegs, 16 * sizeof(uint64_t));

        // 映射 native 寄存器到虚拟寄存器
        // x64: RAX=0, RBX=1, RCX=2, RDX=3, RSI=4, RDI=5, RBP=6, RSP=7
        //       R8=8, R9=9, R10=10, R11=11, R12=12, R13=13, R14=14, R15=15
        for (int i = 0; i < 16; i++) {
            ctx->regs.r[i] = nativeRegs[i];
        }
    }

    ctx->nativeFlags = nativeFlags;

    // 转换 EFLAGS 到 VM flags
    vm_eflags_to_flags(&ctx->regs.vflags, nativeFlags);
    ctx->regs.flags = nativeFlags;

    // 保存原始栈
    if (nativeStack && stackSize > 0) {
        uint32_t copySize = (stackSize > sizeof(ctx->nativeStack)) ?
                            sizeof(ctx->nativeStack) : stackSize;
        memcpy(ctx->nativeStack, nativeStack, copySize);
        ctx->nativeStackSize = copySize;
    }

    // 初始化虚拟栈
    ctx->regs.sp = VM_STACK_SIZE - 8;

    // 设置指令指针为 0（bytecode 起始）
    ctx->regs.ip = 0;

    // 标记运行
    ctx->running = 1;
}

void vm_exit(VM_CONTEXT* ctx, uint64_t* outRegs, uint64_t* outFlags,
             uint8_t* outStack, uint32_t stackSize)
{
    if (!ctx) return;

    // 将虚拟寄存器映射回 native 寄存器
    if (outRegs) {
        for (int i = 0; i < 16; i++) {
            outRegs[i] = ctx->regs.r[i];
        }
    }

    // 转换 VM flags 回 EFLAGS
    uint64_t eflags = vm_flags_to_eflags(&ctx->regs.vflags);
    if (outFlags) {
        *outFlags = eflags;
    }

    // 恢复栈（如果需要）
    if (outStack && stackSize > 0) {
        uint32_t copySize = (stackSize > ctx->nativeStackSize) ?
                            ctx->nativeStackSize : stackSize;
        memcpy(outStack, ctx->nativeStack, copySize);
    }

    // 安全清除敏感数据
    memset(ctx->decryptKey, 0, VM_KEY_SIZE);
    memset(ctx->stack, 0, VM_STACK_SIZE);

    ctx->running = 0;
}

// ============================================================================
// Flags 转换
// ============================================================================

uint64_t vm_flags_to_eflags(const VM_FLAGS* vflags)
{
    uint64_t eflags = 0;

    if (vflags->CF) eflags |= VM_FLAG_CF;
    if (vflags->PF) eflags |= VM_FLAG_PF;
    if (vflags->AF) eflags |= VM_FLAG_AF;
    if (vflags->ZF) eflags |= VM_FLAG_ZF;
    if (vflags->SF) eflags |= VM_FLAG_SF;
    if (vflags->TF) eflags |= VM_FLAG_TF;
    if (vflags->DF) eflags |= VM_FLAG_DF;
    if (vflags->OF) eflags |= VM_FLAG_OF;

    // 固定标志位
    eflags |= 0x02;  // IF always set

    return eflags;
}

void vm_eflags_to_flags(VM_FLAGS* vflags, uint64_t eflags)
{
    vflags->CF = (eflags & VM_FLAG_CF) ? 1 : 0;
    vflags->PF = (eflags & VM_FLAG_PF) ? 1 : 0;
    vflags->AF = (eflags & VM_FLAG_AF) ? 1 : 0;
    vflags->ZF = (eflags & VM_FLAG_ZF) ? 1 : 0;
    vflags->SF = (eflags & VM_FLAG_SF) ? 1 : 0;
    vflags->TF = (eflags & VM_FLAG_TF) ? 1 : 0;
    vflags->DF = (eflags & VM_FLAG_DF) ? 1 : 0;
    vflags->OF = (eflags & VM_FLAG_OF) ? 1 : 0;
}
