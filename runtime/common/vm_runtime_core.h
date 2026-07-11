#ifndef CS_RUNTIME_VM_RUNTIME_CORE_H
#define CS_RUNTIME_VM_RUNTIME_CORE_H

#include "vm_metadata.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VM_RUNTIME_REGISTER_COUNT 32u
#define VM_RUNTIME_CALL_DEPTH VM_MAX_INTERNAL_CALL_DEPTH
#define VM_XSAVE_AREA_SIZE 832u
#define VM_EXTENDED_STATE_FLAG_AVX 0x00000001u

typedef enum VM_RUNTIME_ERROR {
    VM_ERR_NONE = 0,
    VM_ERR_METADATA_INVALID = 1,
    VM_ERR_RECORD_NOT_FOUND = 2,
    VM_ERR_BYTECODE_RANGE = 3,
    VM_ERR_OPCODE_UNSUPPORTED = 4,
    VM_ERR_REGISTER_MAP_INVALID = 5,
    VM_ERR_MEMORY_ADDR_INVALID = 6,
    VM_ERR_HANDLER_BUG = 7,
    VM_ERR_RET_WITHOUT_CONTEXT = 8,
    VM_ERR_STACK_ALIGNMENT = 9,
    VM_ERR_NATIVE_BRIDGE = 10,
    VM_ERR_UNWIND = 11,
    VM_ERR_BYTECODE_AUTH = 12,
    VM_ERR_SCHEMA_MISMATCH = 13,
    VM_ERR_DIVIDE = 14,
    VM_ERR_CALL_STACK = 15
} VM_RUNTIME_ERROR;

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
#pragma pack(pop)

uint32_t vm_runtime_interpret(
    void* nativeFrame,
    uint32_t functionRva,
    VM_METADATA_HEADER* metadata,
    uintptr_t imageBase,
    VM_EXTENDED_STATE* extendedState);

uint32_t vm_native_call_bridge(VM_NATIVE_CALL_STATE* state);
uint32_t vm_instruction_bridge(VM_INSTRUCTION_BRIDGE_STATE* state);
uint64_t vm_atomic_exchange(uintptr_t address, uint64_t value, uint32_t width);
uint32_t vm_atomic_bit_operation(uintptr_t address, uint32_t bitIndex, uint32_t operation, uint32_t width);
void vm_raise_divide_by_zero(void);
void vm_raise_divide_overflow(void);

#ifdef __cplusplus
}
static_assert(sizeof(VM_NATIVE_FRAME_X64) == 144, "x64 native frame layout mismatch");
static_assert(sizeof(VM_NATIVE_FRAME_X86) == 40, "x86 native frame layout mismatch");
static_assert(sizeof(VM_EXTENDED_STATE) == 848, "extended state layout mismatch");
static_assert(sizeof(VM_NATIVE_CALL_STATE) == 1096, "native call state layout mismatch");
static_assert(sizeof(VM_INSTRUCTION_BRIDGE_STATE) == 1144,
              "instruction bridge state layout mismatch");
#endif

#endif // CS_RUNTIME_VM_RUNTIME_CORE_H
