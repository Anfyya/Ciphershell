#ifndef CS_RUNTIME_VM_MICRO_RUNTIME_ABI_H
#define CS_RUNTIME_VM_MICRO_RUNTIME_ABI_H

#include "vm_metadata.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Pack-time handler 合成器与 trampoline/native bridge 共享的唯一 ABI。
 * 所有目标地址均使用 uint64_t 槽位；PE32 只读取低 32 位，因此 packer
 * 自身的位数不会改变 x86 目标布局。
 */
#define VM_RUNTIME_REGISTER_COUNT 32u
#define VM_RUNTIME_TEMP_COUNT VM_MICRO_TEMP_COUNT
#define VM_RUNTIME_VALUE_STACK_DEPTH VM_MICRO_STACK_LIMIT
#define VM_RUNTIME_CALL_DEPTH VM_MAX_INTERNAL_CALL_DEPTH
#define VM_XSAVE_AREA_SIZE 832u
#define VM_EXTENDED_STATE_FLAG_AVX 0x00000001u
/* Trampoline native-frame base -> private guest scratch base. */
#define VM_RUNTIME_X64_FRAME_TO_SCRATCH 0x558u
#define VM_RUNTIME_X86_FRAME_TO_SCRATCH 0x4C0u

typedef enum VM_MICRO_RUNTIME_ERROR {
    VM_MICRO_ERR_NONE = 0,
    VM_MICRO_ERR_METADATA_INVALID = 1,
    VM_MICRO_ERR_RECORD_NOT_FOUND = 2,
    VM_MICRO_ERR_BYTECODE_RANGE = 3,
    VM_MICRO_ERR_OPCODE_UNSUPPORTED = 4,
    VM_MICRO_ERR_REGISTER_MAP_INVALID = 5,
    VM_MICRO_ERR_MEMORY_ADDR_INVALID = 6,
    VM_MICRO_ERR_HANDLER_BUG = 7,
    VM_MICRO_ERR_RET_WITHOUT_CONTEXT = 8,
    VM_MICRO_ERR_STACK_ALIGNMENT = 9,
    VM_MICRO_ERR_NATIVE_BRIDGE = 10,
    VM_MICRO_ERR_UNWIND = 11,
    VM_MICRO_ERR_BYTECODE_AUTH = 12,
    VM_MICRO_ERR_SCHEMA_MISMATCH = 13,
    VM_MICRO_ERR_DIVIDE = 14,
    VM_MICRO_ERR_CALL_STACK = 15,
    VM_MICRO_ERR_VALUE_STACK_UNDERFLOW = 16,
    VM_MICRO_ERR_VALUE_STACK_OVERFLOW = 17,
    VM_MICRO_ERR_TEMP_RANGE = 18,
    VM_MICRO_ERR_FLAGS_STATE = 19,
    VM_MICRO_ERR_HANDLER_CIPHER = 20
} VM_MICRO_RUNTIME_ERROR;

#pragma pack(push, 1)
typedef struct VM_NATIVE_FRAME_X64 {
    uint64_t r15;
    uint64_t r14;
    uint64_t r13;
    uint64_t r12;
    uint64_t r11;
    uint64_t r10;
    uint64_t r9;
    uint64_t r8;
    uint64_t rdi;
    uint64_t rsi;
    uint64_t rbp;
    uint64_t rbx;
    uint64_t rdx;
    uint64_t rcx;
    uint64_t rax;
    uint64_t rflags;
    uint64_t returnAddress;
    uint64_t originalRsp;
} VM_NATIVE_FRAME_X64;

typedef struct VM_NATIVE_FRAME_X86 {
    uint32_t edi;
    uint32_t esi;
    uint32_t ebp;
    uint32_t originalEsp;
    uint32_t ebx;
    uint32_t edx;
    uint32_t ecx;
    uint32_t eax;
    uint32_t eflags;
    uint32_t returnAddress;
} VM_NATIVE_FRAME_X86;

typedef struct VM_EXTENDED_STATE {
    uint8_t xsaveArea[VM_XSAVE_AREA_SIZE];
    uint32_t flags;
    uint32_t reserved[3];
} VM_EXTENDED_STATE;

typedef struct VM_NATIVE_CALL_STATE {
    uint64_t gpr[16];
    uint64_t rflags;
    uint64_t stackPointer;
    uint64_t target;
    uint64_t guardTarget;
    uint32_t stackArgumentBytes;
    uint32_t callAbi;
    uint64_t bridgeReserved;
    uint64_t extendedState;
    uint32_t extendedStateFlags;
    uint32_t stateReserved;
    uint64_t hostExtendedState;
    uint8_t hostExtendedStorage[VM_XSAVE_AREA_SIZE + 64u];
} VM_NATIVE_CALL_STATE;

typedef struct VM_INSTRUCTION_BRIDGE_STATE {
    uint64_t gpr[16];
    uint64_t rflags;
    uint64_t target;
    uint64_t guardTarget;
    uint64_t extendedState;
    uint64_t hostExtendedState;
    uint64_t hostStack;
    uint64_t hostNonvolatile[8];
    uint32_t extendedStateFlags;
    uint32_t hiddenRegister;
    uint8_t hostExtendedStorage[VM_XSAVE_AREA_SIZE + 64u];
} VM_INSTRUCTION_BRIDGE_STATE;

/*
 * direct-threaded handler ABI:
 *   x64: R15=context, R14=dispatch table, R13=VIP
 *   x86: EDI=context, EBX=dispatch table, ESI=VIP
 * handler 只能在 EXIT/失败时返回；正常路径必须在自身尾部解码并跳转。
 */
typedef struct VM_MICRO_EXECUTION_CONTEXT {
    uint64_t values[VM_RUNTIME_VALUE_STACK_DEPTH];
    uint64_t vregs[VM_RUNTIME_REGISTER_COUNT];
    uint64_t temps[VM_RUNTIME_TEMP_COUNT];
    uint32_t callStack[VM_RUNTIME_CALL_DEPTH];
    uint32_t valueDepth;
    uint32_t callDepth;
    uint64_t vip;
    uint64_t bytecodeBegin;
    uint64_t bytecodeEnd;
    uint64_t dispatchTable;
    uint64_t reverseOpcodeMap;
    uint64_t registerMap;
    uint64_t handlerSemanticToSlot;
    uint64_t decodePlans;
    uint64_t decodeOperands;
    uint64_t flagMaterializer;
    uint64_t imageBase;
    uint64_t metadata;
    uint64_t record;
    uint64_t nativeFrame;
    uint64_t extendedState;
    uint64_t nativeCallBridge;
    uint64_t instructionBridge;
    uint64_t virtualProtect;
    uint64_t flushInstructionCache;
    uint64_t rollingKey;
    VM_OPERAND_CODEC operandCodec;
    uint64_t decodedOperands[VM_MICRO_MAX_OPERANDS];
    uint8_t decodedOperandCount;
    uint8_t currentSemantic;
    uint8_t currentVariant;
    uint8_t reservedDecodeState;
    uint64_t virtualFlags;
    VM_LAZY_FLAGS_RECORD pendingFlags;
    VM_LAZY_FLAGS_RECORD lastAlu;
    uint32_t architecture;
    uint32_t returnStackCleanup;
    uint32_t error;
    uint32_t halted;
    uint64_t mutationScratch;
} VM_MICRO_EXECUTION_CONTEXT;
#pragma pack(pop)

#ifdef __cplusplus
}

static_assert(sizeof(VM_NATIVE_FRAME_X64) == 144, "x64 native frame layout mismatch");
static_assert(sizeof(VM_NATIVE_FRAME_X86) == 40, "x86 native frame layout mismatch");
static_assert(sizeof(VM_EXTENDED_STATE) == 848, "extended state layout mismatch");
static_assert(sizeof(VM_NATIVE_CALL_STATE) == 1096, "native call state layout mismatch");
static_assert(sizeof(VM_INSTRUCTION_BRIDGE_STATE) == 1144,
              "instruction bridge state layout mismatch");
#endif

#endif // CS_RUNTIME_VM_MICRO_RUNTIME_ABI_H
