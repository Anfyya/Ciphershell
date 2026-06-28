/**
 * CipherShell Mirage VM - Dispatcher 实现
 * 三种 dispatch 模式：跳转表、计算跳转、Threaded
 */

#include "dispatcher.h"
#include "vm_context.h"
#include "flags_emu.h"
#include <string.h>

// ============================================================================
// 辅助宏
// ============================================================================

#define SAFE_INDEX(idx, max) ((idx) < (max) ? (idx) : 0)

// 从虚拟栈读取/写入
#define VM_STACK_PUSH64(ctx, val) do { \
    (ctx)->regs.sp -= 8; \
    *(uint64_t*)((ctx)->stack + (ctx)->regs.sp) = (uint64_t)(val); \
} while(0)

#define VM_STACK_POP64(ctx, dst) do { \
    (dst) = *(uint64_t*)((ctx)->stack + (ctx)->regs.sp); \
    (ctx)->regs.sp += 8; \
} while(0)

#define VM_STACK_PUSH32(ctx, val) do { \
    (ctx)->regs.sp -= 4; \
    *(uint32_t*)((ctx)->stack + (ctx)->regs.sp) = (uint32_t)(val); \
} while(0)

#define VM_STACK_POP32(ctx, dst) do { \
    (dst) = *(uint32_t*)((ctx)->stack + (ctx)->regs.sp); \
    (ctx)->regs.sp += 4; \
} while(0)

// ============================================================================
// Bytecode 解密
// ============================================================================

// 滚动密钥解密：每读取一个字节，密钥都发生变化
static uint8_t rolling_decrypt(uint8_t encrypted, uint32_t* rolling_key)
{
    uint8_t key_byte = (uint8_t)(*rolling_key & 0xFF);
    uint8_t decrypted = encrypted ^ key_byte;

    // 更新滚动密钥
    *rolling_key = (*rolling_key >> 8) | (*rolling_key << 24);  // 循环右移8位
    *rolling_key ^= (uint32_t)encrypted;  // 与密文混合

    return decrypted;
}

uint8_t dispatch_fetch_opcode(VM_CONTEXT* ctx)
{
    if (ctx->regs.ip >= ctx->bytecodeSize) {
        ctx->running = 0;
        ctx->exitReason = VM_EXIT_ERROR;
        ctx->errorCode = 1;  // 指令指针越界
        return VM_NOP;
    }

    uint8_t encrypted = ctx->bytecode[ctx->regs.ip];
    uint8_t decrypted = rolling_decrypt(encrypted, &ctx->rollingKey);
    ctx->regs.ip++;

    return decrypted;
}

uint8_t dispatch_fetch_reg_index(VM_CONTEXT* ctx)
{
    uint8_t idx = dispatch_fetch_opcode(ctx);
    return SAFE_INDEX(idx, VM_MAX_REGISTERS);
}

uint32_t dispatch_fetch_imm32(VM_CONTEXT* ctx)
{
    uint32_t val = 0;
    for (int i = 0; i < 4; i++) {
        val |= (uint32_t)dispatch_fetch_opcode(ctx) << (i * 8);
    }
    return val;
}

uint64_t dispatch_fetch_imm64(VM_CONTEXT* ctx)
{
    uint64_t val = 0;
    for (int i = 0; i < 8; i++) {
        val |= (uint64_t)dispatch_fetch_opcode(ctx) << (i * 8);
    }
    return val;
}

void dispatch_update_key(DISPATCH_CONTEXT* dctx, uint8_t opcode)
{
    dctx->rollingKey ^= (uint32_t)opcode * 0x01000193;  // FNV-like mixing
    dctx->keyRotationCount++;
}

// ============================================================================
// Dispatcher 初始化
// ============================================================================

void dispatch_init(DISPATCH_CONTEXT* dctx, VM_CONTEXT* ctx, DISPATCH_MODE mode)
{
    if (!dctx) return;

    memset(dctx, 0, sizeof(DISPATCH_CONTEXT));
    dctx->mode = mode;
    dctx->rollingKey = ctx ? ctx->rollingKey : 0x12345678;
    dctx->mutationSeed = 0xDEADBEEF;
}

// ============================================================================
// 跳转表 Dispatch
// ============================================================================

// Handler 函数类型
typedef void (*VM_HANDLER_FUNC)(VM_CONTEXT* ctx);

// 前向声明所有 handler
static void handler_nop(VM_CONTEXT* ctx);
static void handler_mov_rr(VM_CONTEXT* ctx);
static void handler_mov_rc(VM_CONTEXT* ctx);
static void handler_mov_rm(VM_CONTEXT* ctx);
static void handler_mov_mr(VM_CONTEXT* ctx);
static void handler_push_r(VM_CONTEXT* ctx);
static void handler_push_c(VM_CONTEXT* ctx);
static void handler_pop_r(VM_CONTEXT* ctx);
static void handler_pushad(VM_CONTEXT* ctx);
static void handler_popad(VM_CONTEXT* ctx);
static void handler_pushf(VM_CONTEXT* ctx);
static void handler_popf(VM_CONTEXT* ctx);
static void handler_add_rr(VM_CONTEXT* ctx);
static void handler_add_rc(VM_CONTEXT* ctx);
static void handler_sub_rr(VM_CONTEXT* ctx);
static void handler_sub_rc(VM_CONTEXT* ctx);
static void handler_mul_rr(VM_CONTEXT* ctx);
static void handler_imul_rr(VM_CONTEXT* ctx);
static void handler_div_rr(VM_CONTEXT* ctx);
static void handler_neg_r(VM_CONTEXT* ctx);
static void handler_inc_r(VM_CONTEXT* ctx);
static void handler_dec_r(VM_CONTEXT* ctx);
static void handler_and_rr(VM_CONTEXT* ctx);
static void handler_and_rc(VM_CONTEXT* ctx);
static void handler_or_rr(VM_CONTEXT* ctx);
static void handler_or_rc(VM_CONTEXT* ctx);
static void handler_xor_rr(VM_CONTEXT* ctx);
static void handler_xor_rc(VM_CONTEXT* ctx);
static void handler_not_r(VM_CONTEXT* ctx);
static void handler_shl_rr(VM_CONTEXT* ctx);
static void handler_shr_rr(VM_CONTEXT* ctx);
static void handler_sar_rr(VM_CONTEXT* ctx);
static void handler_cmp_rr(VM_CONTEXT* ctx);
static void handler_cmp_rc(VM_CONTEXT* ctx);
static void handler_test_rr(VM_CONTEXT* ctx);
static void handler_test_rc(VM_CONTEXT* ctx);
static void handler_jmp(VM_CONTEXT* ctx);
static void handler_jz(VM_CONTEXT* ctx);
static void handler_jnz(VM_CONTEXT* ctx);
static void handler_ja(VM_CONTEXT* ctx);
static void handler_jb(VM_CONTEXT* ctx);
static void handler_jg(VM_CONTEXT* ctx);
static void handler_jl(VM_CONTEXT* ctx);
static void handler_jge(VM_CONTEXT* ctx);
static void handler_jle(VM_CONTEXT* ctx);
static void handler_call_vm(VM_CONTEXT* ctx);
static void handler_ret_vm(VM_CONTEXT* ctx);
static void handler_call_native(VM_CONTEXT* ctx);
static void handler_vmexit(VM_CONTEXT* ctx);
static void handler_xchg(VM_CONTEXT* ctx);
static void handler_lea(VM_CONTEXT* ctx);
static void handler_adc_rr(VM_CONTEXT* ctx);
static void handler_sbb_rr(VM_CONTEXT* ctx);
static void handler_rol_rr(VM_CONTEXT* ctx);
static void handler_ror_rr(VM_CONTEXT* ctx);
static void handler_anti_debug(VM_CONTEXT* ctx);

// 默认 handler 表（基础模板）
static VM_HANDLER_FUNC default_handler_table[VM_MAX_OPCODE] = {
    /* 0x00 VM_NOP       */ handler_nop,
    /* 0x01 VM_MOV_RR    */ handler_mov_rr,
    /* 0x02 VM_MOV_RC    */ handler_mov_rc,
    /* 0x03 VM_MOV_RM    */ handler_mov_rm,
    /* 0x04 VM_MOV_MR    */ handler_mov_mr,
    /* 0x05 VM_MOV_RM8   */ handler_mov_rm,   // 复用，内部区分
    /* 0x06 VM_MOV_MR8   */ handler_mov_mr,
    /* 0x07 VM_MOV_RM16  */ handler_mov_rm,
    /* 0x08 VM_MOV_MR16  */ handler_mov_mr,
    /* 0x09 VM_LEA       */ handler_lea,
    /* 0x0A VM_XCHG      */ handler_xchg,
    /* 0x0B-0x0F         */ handler_nop, handler_nop, handler_nop, handler_nop, handler_nop,
    /* 0x10 VM_PUSH_R    */ handler_push_r,
    /* 0x11 VM_PUSH_C    */ handler_push_c,
    /* 0x12 VM_PUSH_MEM  */ handler_nop,
    /* 0x13 VM_POP_R     */ handler_pop_r,
    /* 0x14 VM_POP_MEM   */ handler_nop,
    /* 0x15 VM_PUSHAD    */ handler_pushad,
    /* 0x16 VM_POPAD     */ handler_popad,
    /* 0x17 VM_PUSHF     */ handler_pushf,
    /* 0x18 VM_POPF      */ handler_popf,
    /* 0x19-0x1F         */ handler_nop, handler_nop, handler_nop, handler_nop, handler_nop, handler_nop, handler_nop,
    /* 0x20 VM_ADD_RR    */ handler_add_rr,
    /* 0x21 VM_ADD_RC    */ handler_add_rc,
    /* 0x22 VM_SUB_RR    */ handler_sub_rr,
    /* 0x23 VM_SUB_RC    */ handler_sub_rc,
    /* 0x24 VM_MUL_RR    */ handler_mul_rr,
    /* 0x25 VM_IMUL_RR   */ handler_imul_rr,
    /* 0x26 VM_IMUL_RRC  */ handler_nop,
    /* 0x27 VM_DIV_RR    */ handler_div_rr,
    /* 0x28 VM_IDIV_RR   */ handler_nop,
    /* 0x29 VM_NEG_R     */ handler_neg_r,
    /* 0x2A VM_INC_R     */ handler_inc_r,
    /* 0x2B VM_DEC_R     */ handler_dec_r,
    /* 0x2C VM_ADC_RR    */ handler_adc_rr,
    /* 0x2D VM_SBB_RR    */ handler_sbb_rr,
    /* 0x2E-0x2F         */ handler_nop, handler_nop,
    /* 0x30 VM_AND_RR    */ handler_and_rr,
    /* 0x31 VM_AND_RC    */ handler_and_rc,
    /* 0x32 VM_OR_RR     */ handler_or_rr,
    /* 0x33 VM_OR_RC     */ handler_or_rc,
    /* 0x34 VM_XOR_RR    */ handler_xor_rr,
    /* 0x35 VM_XOR_RC    */ handler_xor_rc,
    /* 0x36 VM_NOT_R     */ handler_not_r,
    /* 0x37 VM_SHL_RR    */ handler_shl_rr,
    /* 0x38 VM_SHL_RC    */ handler_nop,
    /* 0x39 VM_SHR_RR    */ handler_shr_rr,
    /* 0x3A VM_SHR_RC    */ handler_nop,
    /* 0x3B VM_SAR_RR    */ handler_sar_rr,
    /* 0x3C VM_SAR_RC    */ handler_nop,
    /* 0x3D VM_ROL_RR    */ handler_rol_rr,
    /* 0x3E VM_ROR_RR    */ handler_ror_rr,
    /* 0x3F VM_BT_RR     */ handler_nop,
    /* 0x40 VM_BTS_RR    */ handler_nop,
    /* 0x41 VM_BTR_RR    */ handler_nop,
    /* 0x42 VM_BSWAP     */ handler_nop,
    /* 0x43-0x4F         */ handler_nop, handler_nop, handler_nop, handler_nop, handler_nop,
                           handler_nop, handler_nop, handler_nop, handler_nop, handler_nop,
                           handler_nop, handler_nop, handler_nop,
    /* 0x50 VM_CMP_RR    */ handler_cmp_rr,
    /* 0x51 VM_CMP_RC    */ handler_cmp_rc,
    /* 0x52 VM_TEST_RR   */ handler_test_rr,
    /* 0x53 VM_TEST_RC   */ handler_test_rc,
    /* 0x54-0x5F         */ handler_nop, handler_nop, handler_nop, handler_nop, handler_nop,
                           handler_nop, handler_nop, handler_nop, handler_nop, handler_nop,
                           handler_nop, handler_nop,
    /* 0x60 VM_JMP       */ handler_jmp,
    /* 0x61 VM_JMP_R     */ handler_nop,
    /* 0x62 VM_JZ        */ handler_jz,
    /* 0x63 VM_JNZ       */ handler_jnz,
    /* 0x64 VM_JA        */ handler_ja,
    /* 0x65 VM_JB        */ handler_jb,
    /* 0x66 VM_JG        */ handler_jg,
    /* 0x67 VM_JL        */ handler_jl,
    /* 0x68 VM_JGE       */ handler_jge,
    /* 0x69 VM_JLE       */ handler_jle,
    /* 0x6A VM_JO        */ handler_nop,
    /* 0x6B VM_JNO       */ handler_nop,
    /* 0x6C VM_JS        */ handler_nop,
    /* 0x6D VM_JNS       */ handler_nop,
    /* 0x6E VM_CALL_VM   */ handler_call_vm,
    /* 0x6F VM_RET_VM    */ handler_ret_vm,
    /* 0x70 VM_CALL_NATIVE */ handler_call_native,
    /* 0x71 VM_VMENTER   */ handler_nop,
    /* 0x72 VM_VMEXIT    */ handler_vmexit,
    /* 0x73 VM_SYSCALL   */ handler_nop,
    /* 0x74-0x7F         */ handler_nop, handler_nop, handler_nop, handler_nop, handler_nop,
                           handler_nop, handler_nop, handler_nop, handler_nop, handler_nop,
                           handler_nop, handler_nop,
    /* 0x80 VM_ANTI_DEBUG */ handler_anti_debug,
};

uint8_t dispatch_table_execute(VM_CONTEXT* ctx, DISPATCH_CONTEXT* dctx)
{
    if (!ctx || !dctx) return VM_EXIT_ERROR;

    ctx->running = 1;

    while (ctx->running) {
        // 1. Fetch opcode（解密）
        uint8_t opcode = dispatch_fetch_opcode(ctx);
        if (!ctx->running) break;

        // 2. 更新滚动密钥
        dispatch_update_key(dctx, opcode);

        // 3. Dispatch（调用对应 handler）
        VM_HANDLER_FUNC handler = default_handler_table[opcode];
        if (handler) {
            handler(ctx);
        }

        // 4. 反调试检查（投毒倒计时）
        if (ctx->poisonCountdown > 0) {
            ctx->poisonCountdown--;
            if (ctx->poisonCountdown == 0) {
                ctx->rollingKey ^= ctx->pendingPoison;
            }
        }

        // 5. 性能计数
        ctx->instrCount++;
        dctx->dispatchCount++;
    }

    return ctx->exitReason;
}

// ============================================================================
// 计算跳转 Dispatch
// ============================================================================

uint8_t dispatch_computed_execute(VM_CONTEXT* ctx, DISPATCH_CONTEXT* dctx)
{
    // 计算跳转模式：handler 地址通过计算得出
    // 地址 = base + opcode * stride + offset_table[opcode]
    // 每次加壳 base/stride/offset_table 都不同

    if (!ctx || !dctx) return VM_EXIT_ERROR;

    ctx->running = 1;

    while (ctx->running) {
        uint8_t opcode = dispatch_fetch_opcode(ctx);
        if (!ctx->running) break;

        dispatch_update_key(dctx, opcode);

        // 计算 handler 地址
        uintptr_t target = dctx->dispatchBase
                         + (uintptr_t)opcode * dctx->dispatchStride
                         + dctx->dispatchOffsets[opcode];

        // 跳转到计算出的地址
        VM_HANDLER_FUNC handler = (VM_HANDLER_FUNC)target;
        if (handler) {
            handler(ctx);
        }

        if (ctx->poisonCountdown > 0) {
            ctx->poisonCountdown--;
            if (ctx->poisonCountdown == 0) {
                ctx->rollingKey ^= ctx->pendingPoison;
            }
        }

        ctx->instrCount++;
        dctx->dispatchCount++;
    }

    return ctx->exitReason;
}

// ============================================================================
// Threaded Dispatch
// ============================================================================

uint8_t dispatch_threaded_execute(VM_CONTEXT* ctx, DISPATCH_CONTEXT* dctx)
{
    // Threaded dispatch：每个 handler 末尾直接跳转到下一个
    // 无集中的 dispatch 循环
    // 注：在纯 C 中难以实现真正的 threaded dispatch（需要 computed goto）
    // 这里用变通方式实现

    if (!ctx || !dctx) return VM_EXIT_ERROR;

    ctx->running = 1;

    while (ctx->running) {
        uint8_t opcode = dispatch_fetch_opcode(ctx);
        if (!ctx->running) break;

        dispatch_update_key(dctx, opcode);

        // 执行 handler
        VM_HANDLER_FUNC handler = default_handler_table[opcode];
        if (handler) {
            handler(ctx);
        }

        if (ctx->poisonCountdown > 0) {
            ctx->poisonCountdown--;
            if (ctx->poisonCountdown == 0) {
                ctx->rollingKey ^= ctx->pendingPoison;
            }
        }

        ctx->instrCount++;
        dctx->dispatchCount++;
    }

    return ctx->exitReason;
}

// ============================================================================
// 混合 Dispatch
// ============================================================================

uint8_t dispatch_mixed_execute(VM_CONTEXT* ctx, DISPATCH_CONTEXT* dctx)
{
    // 混合模式：随机选择 dispatch 方式
    // 一部分 handler 用跳转表，一部分用计算跳转

    if (!ctx || !dctx) return VM_EXIT_ERROR;

    // 根据 mutationSeed 决定使用哪种模式
    DISPATCH_MODE primaryMode = (dctx->mutationSeed & 1) ? DISPATCH_TABLE : DISPATCH_COMPUTED;

    if (primaryMode == DISPATCH_TABLE) {
        return dispatch_table_execute(ctx, dctx);
    } else {
        return dispatch_computed_execute(ctx, dctx);
    }
}

// ============================================================================
// Handler 实现
// ============================================================================

static void handler_nop(VM_CONTEXT* ctx)
{
    // NOP：只滚动密钥，不做任何操作
    (void)ctx;
}

static void handler_mov_rr(VM_CONTEXT* ctx)
{
    // MOV vReg, vReg
    uint8_t dst = dispatch_fetch_reg_index(ctx);
    uint8_t src = dispatch_fetch_reg_index(ctx);
    ctx->regs.r[dst] = ctx->regs.r[src];
}

static void handler_mov_rc(VM_CONTEXT* ctx)
{
    // MOV vReg, Const64
    uint8_t dst = dispatch_fetch_reg_index(ctx);
    uint64_t imm = dispatch_fetch_imm64(ctx);
    ctx->regs.r[dst] = imm;
}

static void handler_mov_rm(VM_CONTEXT* ctx)
{
    // MOV vReg, [vReg + Offset]
    uint8_t dst = dispatch_fetch_reg_index(ctx);
    uint8_t base = dispatch_fetch_reg_index(ctx);
    uint64_t offset = dispatch_fetch_imm64(ctx);

    uint64_t addr = ctx->regs.r[base] + offset;

    // 安全检查
    if (addr < VM_STACK_SIZE) {
        ctx->regs.r[dst] = *(uint64_t*)(ctx->stack + addr);
    }
}

static void handler_mov_mr(VM_CONTEXT* ctx)
{
    // MOV [vReg + Offset], vReg
    uint8_t base = dispatch_fetch_reg_index(ctx);
    uint64_t offset = dispatch_fetch_imm64(ctx);
    uint8_t src = dispatch_fetch_reg_index(ctx);

    uint64_t addr = ctx->regs.r[base] + offset;

    if (addr < VM_STACK_SIZE) {
        *(uint64_t*)(ctx->stack + addr) = ctx->regs.r[src];
    }
}

static void handler_lea(VM_CONTEXT* ctx)
{
    // LEA vReg, [vReg + vReg * Scale + Offset]
    uint8_t dst = dispatch_fetch_reg_index(ctx);
    uint8_t base = dispatch_fetch_reg_index(ctx);
    uint8_t index = dispatch_fetch_reg_index(ctx);
    uint8_t scale = dispatch_fetch_opcode(ctx);
    uint64_t offset = dispatch_fetch_imm64(ctx);

    ctx->regs.r[dst] = ctx->regs.r[base] + ctx->regs.r[index] * scale + offset;
}

static void handler_xchg(VM_CONTEXT* ctx)
{
    // XCHG vReg, vReg
    uint8_t r1 = dispatch_fetch_reg_index(ctx);
    uint8_t r2 = dispatch_fetch_reg_index(ctx);

    uint64_t tmp = ctx->regs.r[r1];
    ctx->regs.r[r1] = ctx->regs.r[r2];
    ctx->regs.r[r2] = tmp;
}

// ---- 栈操作 ----

static void handler_push_r(VM_CONTEXT* ctx)
{
    uint8_t reg = dispatch_fetch_reg_index(ctx);
    VM_STACK_PUSH64(ctx, ctx->regs.r[reg]);
}

static void handler_push_c(VM_CONTEXT* ctx)
{
    uint64_t imm = dispatch_fetch_imm64(ctx);
    VM_STACK_PUSH64(ctx, imm);
}

static void handler_pop_r(VM_CONTEXT* ctx)
{
    uint8_t reg = dispatch_fetch_reg_index(ctx);
    VM_STACK_POP64(ctx, ctx->regs.r[reg]);
}

static void handler_pushad(VM_CONTEXT* ctx)
{
    // 保存所有寄存器（类似 x86 pushad）
    for (int i = VM_MAX_REGISTERS - 1; i >= 0; i--) {
        VM_STACK_PUSH64(ctx, ctx->regs.r[i]);
    }
    VM_STACK_PUSH64(ctx, ctx->regs.sp);
    VM_STACK_PUSH64(ctx, ctx->regs.bp);
    VM_STACK_PUSH64(ctx, ctx->regs.flags);
}

static void handler_popad(VM_CONTEXT* ctx)
{
    // 恢复所有寄存器
    uint64_t tmp;
    VM_STACK_POP64(ctx, tmp); ctx->regs.flags = tmp;
    VM_STACK_POP64(ctx, tmp); ctx->regs.bp = tmp;
    VM_STACK_POP64(ctx, tmp); ctx->regs.sp = tmp;
    for (int i = 0; i < VM_MAX_REGISTERS; i++) {
        VM_STACK_POP64(ctx, ctx->regs.r[i]);
    }
}

static void handler_pushf(VM_CONTEXT* ctx)
{
    uint64_t flags = vm_flags_to_eflags(&ctx->regs.vflags);
    VM_STACK_PUSH64(ctx, flags);
}

static void handler_popf(VM_CONTEXT* ctx)
{
    uint64_t flags;
    VM_STACK_POP64(ctx, flags);
    vm_eflags_to_flags(&ctx->regs.vflags, flags);
    ctx->regs.flags = flags;
}

// ---- 算术运算 ----

static void handler_add_rr(VM_CONTEXT* ctx)
{
    uint8_t dst = dispatch_fetch_reg_index(ctx);
    uint8_t src = dispatch_fetch_reg_index(ctx);

    uint64_t a = ctx->regs.r[dst];
    uint64_t b = ctx->regs.r[src];
    ctx->regs.r[dst] = a + b;

    flags_add64(&ctx->regs.vflags, a, b, 0);
}

static void handler_add_rc(VM_CONTEXT* ctx)
{
    uint8_t dst = dispatch_fetch_reg_index(ctx);
    uint64_t imm = dispatch_fetch_imm64(ctx);

    uint64_t a = ctx->regs.r[dst];
    ctx->regs.r[dst] = a + imm;

    flags_add64(&ctx->regs.vflags, a, imm, 0);
}

static void handler_sub_rr(VM_CONTEXT* ctx)
{
    uint8_t dst = dispatch_fetch_reg_index(ctx);
    uint8_t src = dispatch_fetch_reg_index(ctx);

    uint64_t a = ctx->regs.r[dst];
    uint64_t b = ctx->regs.r[src];
    ctx->regs.r[dst] = a - b;

    flags_sub64(&ctx->regs.vflags, a, b, 0);
}

static void handler_sub_rc(VM_CONTEXT* ctx)
{
    uint8_t dst = dispatch_fetch_reg_index(ctx);
    uint64_t imm = dispatch_fetch_imm64(ctx);

    uint64_t a = ctx->regs.r[dst];
    ctx->regs.r[dst] = a - imm;

    flags_sub64(&ctx->regs.vflags, a, imm, 0);
}

static void handler_mul_rr(VM_CONTEXT* ctx)
{
    uint8_t dst = dispatch_fetch_reg_index(ctx);
    uint8_t src = dispatch_fetch_reg_index(ctx);

    uint64_t a = ctx->regs.r[dst];
    uint64_t b = ctx->regs.r[src];
    ctx->regs.r[dst] = a * b;

    // MUL: CF=OF=0 if high half is 0, else 1
    __uint128_t result128 = (__uint128_t)a * (__uint128_t)b;
    uint64_t high = (uint64_t)(result128 >> 64);
    ctx->regs.vflags.CF = (high != 0) ? 1 : 0;
    ctx->regs.vflags.OF = ctx->regs.vflags.CF;
}

static void handler_imul_rr(VM_CONTEXT* ctx)
{
    uint8_t dst = dispatch_fetch_reg_index(ctx);
    uint8_t src = dispatch_fetch_reg_index(ctx);

    int64_t a = (int64_t)ctx->regs.r[dst];
    int64_t b = (int64_t)ctx->regs.r[src];
    ctx->regs.r[dst] = (uint64_t)(a * b);

    // IMUL: CF=OF=1 if result truncated
    __int128_t result128 = (__int128_t)a * (__int128_t)b;
    int64_t high = (int64_t)(result128 >> 64);
    ctx->regs.vflags.CF = (high != 0 && high != -1) ? 1 : 0;
    ctx->regs.vflags.OF = ctx->regs.vflags.CF;
}

static void handler_div_rr(VM_CONTEXT* ctx)
{
    uint8_t dst = dispatch_fetch_reg_index(ctx);
    uint8_t src = dispatch_fetch_reg_index(ctx);

    uint64_t divisor = ctx->regs.r[src];
    if (divisor == 0) {
        // 除零错误
        ctx->running = 0;
        ctx->exitReason = VM_EXIT_ERROR;
        ctx->errorCode = 2;
        return;
    }

    // 简化：只做64位除法
    ctx->regs.r[dst] = ctx->regs.r[dst] / divisor;
}

static void handler_neg_r(VM_CONTEXT* ctx)
{
    uint8_t reg = dispatch_fetch_reg_index(ctx);
    uint64_t val = ctx->regs.r[reg];
    ctx->regs.r[reg] = (uint64_t)(-(int64_t)val);
    flags_neg64(&ctx->regs.vflags, val);
}

static void handler_inc_r(VM_CONTEXT* ctx)
{
    uint8_t reg = dispatch_fetch_reg_index(ctx);
    uint64_t val = ctx->regs.r[reg];
    ctx->regs.r[reg]++;
    flags_inc64(&ctx->regs.vflags, val);
}

static void handler_dec_r(VM_CONTEXT* ctx)
{
    uint8_t reg = dispatch_fetch_reg_index(ctx);
    uint64_t val = ctx->regs.r[reg];
    ctx->regs.r[reg]--;
    flags_dec64(&ctx->regs.vflags, val);
}

static void handler_adc_rr(VM_CONTEXT* ctx)
{
    uint8_t dst = dispatch_fetch_reg_index(ctx);
    uint8_t src = dispatch_fetch_reg_index(ctx);

    uint64_t a = ctx->regs.r[dst];
    uint64_t b = ctx->regs.r[src];
    uint64_t carry = ctx->regs.vflags.CF;
    ctx->regs.r[dst] = a + b + carry;

    flags_add64(&ctx->regs.vflags, a, b, carry);
}

static void handler_sbb_rr(VM_CONTEXT* ctx)
{
    uint8_t dst = dispatch_fetch_reg_index(ctx);
    uint8_t src = dispatch_fetch_reg_index(ctx);

    uint64_t a = ctx->regs.r[dst];
    uint64_t b = ctx->regs.r[src];
    uint64_t borrow = ctx->regs.vflags.CF;
    ctx->regs.r[dst] = a - b - borrow;

    flags_sub64(&ctx->regs.vflags, a, b, borrow);
}

// ---- 逻辑/位操作 ----

static void handler_and_rr(VM_CONTEXT* ctx)
{
    uint8_t dst = dispatch_fetch_reg_index(ctx);
    uint8_t src = dispatch_fetch_reg_index(ctx);

    ctx->regs.r[dst] &= ctx->regs.r[src];
    flags_and64(&ctx->regs.vflags, ctx->regs.r[dst]);
}

static void handler_and_rc(VM_CONTEXT* ctx)
{
    uint8_t dst = dispatch_fetch_reg_index(ctx);
    uint64_t imm = dispatch_fetch_imm64(ctx);

    ctx->regs.r[dst] &= imm;
    flags_and64(&ctx->regs.vflags, ctx->regs.r[dst]);
}

static void handler_or_rr(VM_CONTEXT* ctx)
{
    uint8_t dst = dispatch_fetch_reg_index(ctx);
    uint8_t src = dispatch_fetch_reg_index(ctx);

    ctx->regs.r[dst] |= ctx->regs.r[src];
    flags_or64(&ctx->regs.vflags, ctx->regs.r[dst]);
}

static void handler_or_rc(VM_CONTEXT* ctx)
{
    uint8_t dst = dispatch_fetch_reg_index(ctx);
    uint64_t imm = dispatch_fetch_imm64(ctx);

    ctx->regs.r[dst] |= imm;
    flags_or64(&ctx->regs.vflags, ctx->regs.r[dst]);
}

static void handler_xor_rr(VM_CONTEXT* ctx)
{
    uint8_t dst = dispatch_fetch_reg_index(ctx);
    uint8_t src = dispatch_fetch_reg_index(ctx);

    ctx->regs.r[dst] ^= ctx->regs.r[src];
    flags_xor64(&ctx->regs.vflags, ctx->regs.r[dst]);
}

static void handler_xor_rc(VM_CONTEXT* ctx)
{
    uint8_t dst = dispatch_fetch_reg_index(ctx);
    uint64_t imm = dispatch_fetch_imm64(ctx);

    ctx->regs.r[dst] ^= imm;
    flags_xor64(&ctx->regs.vflags, ctx->regs.r[dst]);
}

static void handler_not_r(VM_CONTEXT* ctx)
{
    uint8_t reg = dispatch_fetch_reg_index(ctx);
    ctx->regs.r[reg] = ~ctx->regs.r[reg];
    // NOT 不影响 flags
}

static void handler_shl_rr(VM_CONTEXT* ctx)
{
    uint8_t dst = dispatch_fetch_reg_index(ctx);
    uint8_t cnt_reg = dispatch_fetch_reg_index(ctx);

    uint8_t count = (uint8_t)(ctx->regs.r[cnt_reg] & 0x3F);
    if (count > 0) {
        flags_shl64(&ctx->regs.vflags, ctx->regs.r[dst], count);
        ctx->regs.r[dst] <<= count;
    }
}

static void handler_shr_rr(VM_CONTEXT* ctx)
{
    uint8_t dst = dispatch_fetch_reg_index(ctx);
    uint8_t cnt_reg = dispatch_fetch_reg_index(ctx);

    uint8_t count = (uint8_t)(ctx->regs.r[cnt_reg] & 0x3F);
    if (count > 0) {
        flags_shr64(&ctx->regs.vflags, ctx->regs.r[dst], count);
        ctx->regs.r[dst] >>= count;
    }
}

static void handler_sar_rr(VM_CONTEXT* ctx)
{
    uint8_t dst = dispatch_fetch_reg_index(ctx);
    uint8_t cnt_reg = dispatch_fetch_reg_index(ctx);

    uint8_t count = (uint8_t)(ctx->regs.r[cnt_reg] & 0x3F);
    if (count > 0) {
        flags_sar64(&ctx->regs.vflags, (int64_t)ctx->regs.r[dst], count);
        ctx->regs.r[dst] = (uint64_t)((int64_t)ctx->regs.r[dst] >> count);
    }
}

static void handler_rol_rr(VM_CONTEXT* ctx)
{
    uint8_t dst = dispatch_fetch_reg_index(ctx);
    uint8_t cnt_reg = dispatch_fetch_reg_index(ctx);

    uint8_t count = (uint8_t)(ctx->regs.r[cnt_reg] & 0x3F);
    if (count > 0) {
        flags_rol64(&ctx->regs.vflags, ctx->regs.r[dst], count);
        ctx->regs.r[dst] = (ctx->regs.r[dst] << count) | (ctx->regs.r[dst] >> (64 - count));
    }
}

static void handler_ror_rr(VM_CONTEXT* ctx)
{
    uint8_t dst = dispatch_fetch_reg_index(ctx);
    uint8_t cnt_reg = dispatch_fetch_reg_index(ctx);

    uint8_t count = (uint8_t)(ctx->regs.r[cnt_reg] & 0x3F);
    if (count > 0) {
        flags_ror64(&ctx->regs.vflags, ctx->regs.r[dst], count);
        ctx->regs.r[dst] = (ctx->regs.r[dst] >> count) | (ctx->regs.r[dst] << (64 - count));
    }
}

// ---- 比较/测试 ----

static void handler_cmp_rr(VM_CONTEXT* ctx)
{
    uint8_t r1 = dispatch_fetch_reg_index(ctx);
    uint8_t r2 = dispatch_fetch_reg_index(ctx);

    uint64_t a = ctx->regs.r[r1];
    uint64_t b = ctx->regs.r[r2];

    // CMP 等同于 SUB 但不保存结果
    flags_sub64(&ctx->regs.vflags, a, b, 0);
}

static void handler_cmp_rc(VM_CONTEXT* ctx)
{
    uint8_t reg = dispatch_fetch_reg_index(ctx);
    uint64_t imm = dispatch_fetch_imm64(ctx);

    flags_sub64(&ctx->regs.vflags, ctx->regs.r[reg], imm, 0);
}

static void handler_test_rr(VM_CONTEXT* ctx)
{
    uint8_t r1 = dispatch_fetch_reg_index(ctx);
    uint8_t r2 = dispatch_fetch_reg_index(ctx);

    flags_test64(&ctx->regs.vflags, ctx->regs.r[r1], ctx->regs.r[r2]);
}

static void handler_test_rc(VM_CONTEXT* ctx)
{
    uint8_t reg = dispatch_fetch_reg_index(ctx);
    uint64_t imm = dispatch_fetch_imm64(ctx);

    flags_test64(&ctx->regs.vflags, ctx->regs.r[reg], imm);
}

// ---- 控制流 ----

static void handler_jmp(VM_CONTEXT* ctx)
{
    // JMP: 读取 32 位偏移，跳转到 bytecode 内位置
    int32_t offset = (int32_t)dispatch_fetch_imm32(ctx);
    ctx->regs.ip = (uint64_t)((int64_t)ctx->regs.ip + offset);
}

static void handler_jz(VM_CONTEXT* ctx)
{
    int32_t offset = (int32_t)dispatch_fetch_imm32(ctx);
    if (ctx->regs.vflags.ZF) {
        ctx->regs.ip = (uint64_t)((int64_t)ctx->regs.ip + offset);
    }
}

static void handler_jnz(VM_CONTEXT* ctx)
{
    int32_t offset = (int32_t)dispatch_fetch_imm32(ctx);
    if (!ctx->regs.vflags.ZF) {
        ctx->regs.ip = (uint64_t)((int64_t)ctx->regs.ip + offset);
    }
}

static void handler_ja(VM_CONTEXT* ctx)
{
    // JA: CF=0 且 ZF=0
    int32_t offset = (int32_t)dispatch_fetch_imm32(ctx);
    if (!ctx->regs.vflags.CF && !ctx->regs.vflags.ZF) {
        ctx->regs.ip = (uint64_t)((int64_t)ctx->regs.ip + offset);
    }
}

static void handler_jb(VM_CONTEXT* ctx)
{
    // JB: CF=1
    int32_t offset = (int32_t)dispatch_fetch_imm32(ctx);
    if (ctx->regs.vflags.CF) {
        ctx->regs.ip = (uint64_t)((int64_t)ctx->regs.ip + offset);
    }
}

static void handler_jg(VM_CONTEXT* ctx)
{
    // JG: ZF=0 且 SF=OF
    int32_t offset = (int32_t)dispatch_fetch_imm32(ctx);
    if (!ctx->regs.vflags.ZF && ctx->regs.vflags.SF == ctx->regs.vflags.OF) {
        ctx->regs.ip = (uint64_t)((int64_t)ctx->regs.ip + offset);
    }
}

static void handler_jl(VM_CONTEXT* ctx)
{
    // JL: SF!=OF
    int32_t offset = (int32_t)dispatch_fetch_imm32(ctx);
    if (ctx->regs.vflags.SF != ctx->regs.vflags.OF) {
        ctx->regs.ip = (uint64_t)((int64_t)ctx->regs.ip + offset);
    }
}

static void handler_jge(VM_CONTEXT* ctx)
{
    // JGE: SF=OF
    int32_t offset = (int32_t)dispatch_fetch_imm32(ctx);
    if (ctx->regs.vflags.SF == ctx->regs.vflags.OF) {
        ctx->regs.ip = (uint64_t)((int64_t)ctx->regs.ip + offset);
    }
}

static void handler_jle(VM_CONTEXT* ctx)
{
    // JLE: ZF=1 或 SF!=OF
    int32_t offset = (int32_t)dispatch_fetch_imm32(ctx);
    if (ctx->regs.vflags.ZF || ctx->regs.vflags.SF != ctx->regs.vflags.OF) {
        ctx->regs.ip = (uint64_t)((int64_t)ctx->regs.ip + offset);
    }
}

// ---- VM 调用/返回 ----

static void handler_call_vm(VM_CONTEXT* ctx)
{
    // VM 内部函数调用：push return offset, jmp target
    int32_t offset = (int32_t)dispatch_fetch_imm32(ctx);

    // 保存返回地址
    VM_STACK_PUSH64(ctx, ctx->regs.ip);

    // 跳转
    ctx->regs.ip = (uint64_t)((int64_t)ctx->regs.ip + offset);
}

static void handler_ret_vm(VM_CONTEXT* ctx)
{
    // VM 内部返回
    uint64_t returnAddr;
    VM_STACK_POP64(ctx, returnAddr);
    ctx->regs.ip = returnAddr;
}

// ---- 与外部世界交互 ----

static void handler_call_native(VM_CONTEXT* ctx)
{
    // 调用真实 API
    // 读取 API hash，通过 hash resolve 获取地址，然后调用
    uint32_t dllHash = dispatch_fetch_imm32(ctx);
    uint32_t funcHash = dispatch_fetch_imm32(ctx);

    // 实际调用需要从 VM 退出到 native 执行
    // 这里设置退出标志
    ctx->exitReason = VM_EXIT_NATIVE;
    ctx->running = 0;

    // 保存 hash 信息到寄存器，供 native 端读取
    ctx->regs.r[0] = ((uint64_t)dllHash << 32) | funcHash;
}

static void handler_vmexit(VM_CONTEXT* ctx)
{
    // 退出 VM，返回 native 执行
    ctx->exitReason = VM_EXIT_NORMAL;
    ctx->running = 0;
}

static void handler_anti_debug(VM_CONTEXT* ctx)
{
    // 内联反调试检查
    // 读取 PEB.BeingDebugged
    // 如果检测到调试器，投毒

    // 简化实现：读取一个检查标志
    uint32_t checkType = dispatch_fetch_imm32(ctx);

    // 这里只是标记，实际检查在 native 端完成
    ctx->detectionFlags |= checkType;

    // 投毒延迟
    ctx->poisonCountdown = 500 + (ctx->instrCount & 0xFF);
    ctx->pendingPoison = checkType ^ 0xDEADBEEF;
}
