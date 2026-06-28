/**
 * CipherShell Mirage VM - 虚拟 CPU 上下文
 * 混合架构虚拟机（栈+寄存器）
 */

#ifndef CS_VM_CONTEXT_H
#define CS_VM_CONTEXT_H

#include <stdint.h>

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
// VM 指令操作码定义（基础模板，实际编号每次加壳随机化）
// ============================================================================

// 数据传送
#define VM_NOP              0x00
#define VM_MOV_RR           0x01    // vReg <- vReg
#define VM_MOV_RC           0x02    // vReg <- Const
#define VM_MOV_RM           0x03    // vReg <- [vReg + Offset]
#define VM_MOV_MR           0x04    // [vReg + Offset] <- vReg
#define VM_MOV_RM8          0x05
#define VM_MOV_MR8          0x06
#define VM_MOV_RM16         0x07
#define VM_MOV_MR16         0x08
#define VM_LEA              0x09    // vReg <- vReg + vReg * Scale + Offset
#define VM_XCHG             0x0A    // 交换两个寄存器

// 栈操作
#define VM_PUSH_R           0x10
#define VM_PUSH_C           0x11
#define VM_PUSH_MEM         0x12
#define VM_POP_R            0x13
#define VM_POP_MEM          0x14
#define VM_PUSHAD           0x15    // 保存所有寄存器
#define VM_POPAD            0x16    // 恢复所有寄存器
#define VM_PUSHF            0x17    // 保存 flags
#define VM_POPF             0x18    // 恢复 flags

// 算术
#define VM_ADD_RR           0x20
#define VM_ADD_RC           0x21
#define VM_SUB_RR           0x22
#define VM_SUB_RC           0x23
#define VM_MUL_RR           0x24
#define VM_IMUL_RR          0x25
#define VM_IMUL_RRC         0x26    // vReg = vReg * Const
#define VM_DIV_RR           0x27
#define VM_IDIV_RR          0x28
#define VM_NEG_R            0x29
#define VM_INC_R            0x2A
#define VM_DEC_R            0x2B
#define VM_ADC_RR           0x2C    // 带进位加
#define VM_SBB_RR           0x2D    // 带借位减

// 逻辑/位操作
#define VM_AND_RR           0x30
#define VM_AND_RC           0x31
#define VM_OR_RR            0x32
#define VM_OR_RC            0x33
#define VM_XOR_RR           0x34
#define VM_XOR_RC           0x35
#define VM_NOT_R            0x36
#define VM_SHL_RR           0x37
#define VM_SHL_RC           0x38
#define VM_SHR_RR           0x39
#define VM_SHR_RC           0x3A
#define VM_SAR_RR           0x3B
#define VM_SAR_RC           0x3C
#define VM_ROL_RR           0x3D
#define VM_ROR_RR           0x3E
#define VM_BT_RR            0x3F    // 位测试
#define VM_BTS_RR           0x40    // 位测试并设置
#define VM_BTR_RR           0x41    // 位测试并清除
#define VM_BSWAP            0x42    // 字节交换

// 比较/测试
#define VM_CMP_RR           0x50
#define VM_CMP_RC           0x51
#define VM_TEST_RR          0x52
#define VM_TEST_RC          0x53

// 控制流
#define VM_JMP              0x60    // 无条件跳转（bytecode内偏移）
#define VM_JMP_R            0x61    // 间接跳转 vReg
#define VM_JZ               0x62
#define VM_JNZ              0x63
#define VM_JA               0x64
#define VM_JB               0x65
#define VM_JG               0x66
#define VM_JL               0x67
#define VM_JGE              0x68
#define VM_JLE              0x69
#define VM_JO               0x6A
#define VM_JNO              0x6B
#define VM_JS               0x6C
#define VM_JNS              0x6D
#define VM_CALL_VM          0x6E    // VM内部函数调用
#define VM_RET_VM           0x6F    // VM内部返回

// 与外部世界交互
#define VM_CALL_NATIVE      0x70    // 调用真实API
#define VM_VMENTER          0x71    // native -> VM
#define VM_VMEXIT           0x72    // VM -> native
#define VM_SYSCALL          0x73    // 直接syscall

// 特殊
#define VM_ANTI_DEBUG       0x80    // 内联反调试
#define VM_CRC_CHECK        0x81    // 完整性校验
#define VM_RDTSC            0x82    // 读时间戳
#define VM_CPUID            0x83    // CPUID
#define VM_INT3             0x84    // INT3 断点（用于Nanomite）

// 标志位定义
#define VM_FLAG_CF          0x0001  // Carry
#define VM_FLAG_PF          0x0004  // Parity
#define VM_FLAG_AF          0x0010  // Auxiliary
#define VM_FLAG_ZF          0x0040  // Zero
#define VM_FLAG_SF          0x0080  // Sign
#define VM_FLAG_TF          0x0100  // Trap
#define VM_FLAG_IF          0x0200  // Interrupt Enable
#define VM_FLAG_DF          0x0400  // Direction
#define VM_FLAG_OF          0x0800  // Overflow

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
