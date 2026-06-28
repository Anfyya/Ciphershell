/**
 * CipherShell Mirage VM - EFLAGS 模拟头文件
 */

#ifndef CS_FLAGS_EMU_H
#define CS_FLAGS_EMU_H

#include "vm_context.h"

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// 8位运算 Flags
// ============================================================================
void flags_add8(VM_FLAGS* f, uint8_t a, uint8_t b, uint8_t carry_in);
void flags_sub8(VM_FLAGS* f, uint8_t a, uint8_t b, uint8_t borrow_in);
void flags_and8(VM_FLAGS* f, uint8_t result);
void flags_or8(VM_FLAGS* f, uint8_t result);
void flags_xor8(VM_FLAGS* f, uint8_t result);
void flags_inc8(VM_FLAGS* f, uint8_t a);
void flags_dec8(VM_FLAGS* f, uint8_t a);

// ============================================================================
// 16位运算 Flags
// ============================================================================
void flags_add16(VM_FLAGS* f, uint16_t a, uint16_t b, uint16_t carry_in);
void flags_sub16(VM_FLAGS* f, uint16_t a, uint16_t b, uint16_t borrow_in);
void flags_and16(VM_FLAGS* f, uint16_t result);
void flags_or16(VM_FLAGS* f, uint16_t result);
void flags_xor16(VM_FLAGS* f, uint16_t result);
void flags_inc16(VM_FLAGS* f, uint16_t a);
void flags_dec16(VM_FLAGS* f, uint16_t a);

// ============================================================================
// 32位运算 Flags
// ============================================================================
void flags_add32(VM_FLAGS* f, uint32_t a, uint32_t b, uint32_t carry_in);
void flags_sub32(VM_FLAGS* f, uint32_t a, uint32_t b, uint32_t borrow_in);
void flags_and32(VM_FLAGS* f, uint32_t result);
void flags_or32(VM_FLAGS* f, uint32_t result);
void flags_xor32(VM_FLAGS* f, uint32_t result);
void flags_inc32(VM_FLAGS* f, uint32_t a);
void flags_dec32(VM_FLAGS* f, uint32_t a);

// ============================================================================
// 64位运算 Flags
// ============================================================================
void flags_add64(VM_FLAGS* f, uint64_t a, uint64_t b, uint64_t carry_in);
void flags_sub64(VM_FLAGS* f, uint64_t a, uint64_t b, uint64_t borrow_in);
void flags_and64(VM_FLAGS* f, uint64_t result);
void flags_or64(VM_FLAGS* f, uint64_t result);
void flags_xor64(VM_FLAGS* f, uint64_t result);
void flags_inc64(VM_FLAGS* f, uint64_t a);
void flags_dec64(VM_FLAGS* f, uint64_t a);

// ============================================================================
// 移位操作 Flags
// ============================================================================
void flags_shl8(VM_FLAGS* f, uint8_t val, uint8_t count);
void flags_shr8(VM_FLAGS* f, uint8_t val, uint8_t count);
void flags_sar8(VM_FLAGS* f, int8_t val, uint8_t count);
void flags_shl32(VM_FLAGS* f, uint32_t val, uint8_t count);
void flags_shr32(VM_FLAGS* f, uint32_t val, uint8_t count);
void flags_sar32(VM_FLAGS* f, int32_t val, uint8_t count);
void flags_shl64(VM_FLAGS* f, uint64_t val, uint8_t count);
void flags_shr64(VM_FLAGS* f, uint64_t val, uint8_t count);
void flags_sar64(VM_FLAGS* f, int64_t val, uint8_t count);

// ============================================================================
// 循环移位 Flags
// ============================================================================
void flags_rol8(VM_FLAGS* f, uint8_t val, uint8_t count);
void flags_ror8(VM_FLAGS* f, uint8_t val, uint8_t count);
void flags_rol32(VM_FLAGS* f, uint32_t val, uint8_t count);
void flags_ror32(VM_FLAGS* f, uint32_t val, uint8_t count);
void flags_rol64(VM_FLAGS* f, uint64_t val, uint8_t count);
void flags_ror64(VM_FLAGS* f, uint64_t val, uint8_t count);

// ============================================================================
// NEG / TEST 操作 Flags
// ============================================================================
void flags_neg8(VM_FLAGS* f, uint8_t val);
void flags_neg32(VM_FLAGS* f, uint32_t val);
void flags_neg64(VM_FLAGS* f, uint64_t val);
void flags_test8(VM_FLAGS* f, uint8_t a, uint8_t b);
void flags_test32(VM_FLAGS* f, uint32_t a, uint32_t b);
void flags_test64(VM_FLAGS* f, uint64_t a, uint64_t b);

#ifdef __cplusplus
}
#endif

#endif // CS_FLAGS_EMU_H
