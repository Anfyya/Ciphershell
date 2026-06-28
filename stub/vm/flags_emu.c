/**
 * CipherShell Mirage VM - EFLAGS 精确模拟
 * 每条算术/逻辑指令都需要精确模拟受影响的 flags
 */

#include "flags_emu.h"

// ============================================================================
// 辅助函数
// ============================================================================

// 计算奇偶标志（PF 只看低8位）
static uint8_t compute_parity(uint8_t value)
{
    // PF = 1 if even number of 1 bits in low byte
    value ^= value >> 4;
    value ^= value >> 2;
    value ^= value >> 1;
    return (~value) & 1;
}

// 计算辅助进位标志（AF = 进位 from bit 3 to bit 4）
static uint8_t compute_auxiliary_carry(uint64_t a, uint64_t b, uint64_t result)
{
    return ((a ^ b ^ result) >> 4) & 1;
}

// ============================================================================
// 8位运算 Flags
// ============================================================================

void flags_add8(VM_FLAGS* f, uint8_t a, uint8_t b, uint8_t carry_in)
{
    uint16_t result16 = (uint16_t)a + (uint16_t)b + (uint16_t)carry_in;
    uint8_t result = (uint8_t)result16;

    f->CF = (result16 > 0xFF) ? 1 : 0;
    f->ZF = (result == 0) ? 1 : 0;
    f->SF = (result >> 7) & 1;
    f->PF = compute_parity(result);
    f->AF = ((a ^ b ^ result) >> 4) & 1;
    // OF = carry into MSB XOR carry out of MSB
    f->OF = (((a ^ result) & (b ^ result)) >> 7) & 1;
}

void flags_sub8(VM_FLAGS* f, uint8_t a, uint8_t b, uint8_t borrow_in)
{
    uint16_t result16 = (uint16_t)a - (uint16_t)b - (uint16_t)borrow_in;
    uint8_t result = (uint8_t)result16;

    f->CF = (result16 > 0xFF) ? 1 : 0;  // borrow
    f->ZF = (result == 0) ? 1 : 0;
    f->SF = (result >> 7) & 1;
    f->PF = compute_parity(result);
    f->AF = ((a ^ b ^ result) >> 4) & 1;
    f->OF = (((a ^ b) & (a ^ result)) >> 7) & 1;
}

void flags_and8(VM_FLAGS* f, uint8_t result)
{
    f->CF = 0;
    f->OF = 0;
    f->ZF = (result == 0) ? 1 : 0;
    f->SF = (result >> 7) & 1;
    f->PF = compute_parity(result);
    f->AF = 0;  // undefined, usually 0
}

void flags_or8(VM_FLAGS* f, uint8_t result)
{
    f->CF = 0;
    f->OF = 0;
    f->ZF = (result == 0) ? 1 : 0;
    f->SF = (result >> 7) & 1;
    f->PF = compute_parity(result);
    f->AF = 0;
}

void flags_xor8(VM_FLAGS* f, uint8_t result)
{
    f->CF = 0;
    f->OF = 0;
    f->ZF = (result == 0) ? 1 : 0;
    f->SF = (result >> 7) & 1;
    f->PF = compute_parity(result);
    f->AF = 0;
}

void flags_inc8(VM_FLAGS* f, uint8_t a)
{
    // INC 不影响 CF
    uint8_t old_cf = f->CF;
    flags_add8(f, a, 1, 0);
    f->CF = old_cf;
}

void flags_dec8(VM_FLAGS* f, uint8_t a)
{
    // DEC 不影响 CF
    uint8_t old_cf = f->CF;
    flags_sub8(f, a, 1, 0);
    f->CF = old_cf;
}

// ============================================================================
// 16位运算 Flags
// ============================================================================

void flags_add16(VM_FLAGS* f, uint16_t a, uint16_t b, uint16_t carry_in)
{
    uint32_t result32 = (uint32_t)a + (uint32_t)b + (uint32_t)carry_in;
    uint16_t result = (uint16_t)result32;

    f->CF = (result32 > 0xFFFF) ? 1 : 0;
    f->ZF = (result == 0) ? 1 : 0;
    f->SF = (result >> 15) & 1;
    f->PF = compute_parity((uint8_t)result);
    f->AF = ((a ^ b ^ result) >> 4) & 1;
    f->OF = (((a ^ result) & (b ^ result)) >> 15) & 1;
}

void flags_sub16(VM_FLAGS* f, uint16_t a, uint16_t b, uint16_t borrow_in)
{
    uint32_t result32 = (uint32_t)a - (uint32_t)b - (uint32_t)borrow_in;
    uint16_t result = (uint16_t)result32;

    f->CF = (result32 > 0xFFFF) ? 1 : 0;
    f->ZF = (result == 0) ? 1 : 0;
    f->SF = (result >> 15) & 1;
    f->PF = compute_parity((uint8_t)result);
    f->AF = ((a ^ b ^ result) >> 4) & 1;
    f->OF = (((a ^ b) & (a ^ result)) >> 15) & 1;
}

void flags_and16(VM_FLAGS* f, uint16_t result)
{
    f->CF = 0;
    f->OF = 0;
    f->ZF = (result == 0) ? 1 : 0;
    f->SF = (result >> 15) & 1;
    f->PF = compute_parity((uint8_t)result);
    f->AF = 0;
}

void flags_or16(VM_FLAGS* f, uint16_t result)
{
    f->CF = 0;
    f->OF = 0;
    f->ZF = (result == 0) ? 1 : 0;
    f->SF = (result >> 15) & 1;
    f->PF = compute_parity((uint8_t)result);
    f->AF = 0;
}

void flags_xor16(VM_FLAGS* f, uint16_t result)
{
    f->CF = 0;
    f->OF = 0;
    f->ZF = (result == 0) ? 1 : 0;
    f->SF = (result >> 15) & 1;
    f->PF = compute_parity((uint8_t)result);
    f->AF = 0;
}

void flags_inc16(VM_FLAGS* f, uint16_t a)
{
    uint8_t old_cf = f->CF;
    flags_add16(f, a, 1, 0);
    f->CF = old_cf;
}

void flags_dec16(VM_FLAGS* f, uint16_t a)
{
    uint8_t old_cf = f->CF;
    flags_sub16(f, a, 1, 0);
    f->CF = old_cf;
}

// ============================================================================
// 32位运算 Flags
// ============================================================================

void flags_add32(VM_FLAGS* f, uint32_t a, uint32_t b, uint32_t carry_in)
{
    uint64_t result64 = (uint64_t)a + (uint64_t)b + (uint64_t)carry_in;
    uint32_t result = (uint32_t)result64;

    f->CF = (result64 > 0xFFFFFFFF) ? 1 : 0;
    f->ZF = (result == 0) ? 1 : 0;
    f->SF = (result >> 31) & 1;
    f->PF = compute_parity((uint8_t)result);
    f->AF = ((a ^ b ^ result) >> 4) & 1;
    f->OF = (((a ^ result) & (b ^ result)) >> 31) & 1;
}

void flags_sub32(VM_FLAGS* f, uint32_t a, uint32_t b, uint32_t borrow_in)
{
    uint64_t result64 = (uint64_t)a - (uint64_t)b - (uint64_t)borrow_in;
    uint32_t result = (uint32_t)result64;

    f->CF = (b > a || (b == a && borrow_in)) ? 1 : 0;
    f->ZF = (result == 0) ? 1 : 0;
    f->SF = (result >> 31) & 1;
    f->PF = compute_parity((uint8_t)result);
    f->AF = ((a ^ b ^ result) >> 4) & 1;
    f->OF = (((a ^ b) & (a ^ result)) >> 31) & 1;
}

void flags_and32(VM_FLAGS* f, uint32_t result)
{
    f->CF = 0;
    f->OF = 0;
    f->ZF = (result == 0) ? 1 : 0;
    f->SF = (result >> 31) & 1;
    f->PF = compute_parity((uint8_t)result);
    f->AF = 0;
}

void flags_or32(VM_FLAGS* f, uint32_t result)
{
    f->CF = 0;
    f->OF = 0;
    f->ZF = (result == 0) ? 1 : 0;
    f->SF = (result >> 31) & 1;
    f->PF = compute_parity((uint8_t)result);
    f->AF = 0;
}

void flags_xor32(VM_FLAGS* f, uint32_t result)
{
    f->CF = 0;
    f->OF = 0;
    f->ZF = (result == 0) ? 1 : 0;
    f->SF = (result >> 31) & 1;
    f->PF = compute_parity((uint8_t)result);
    f->AF = 0;
}

void flags_inc32(VM_FLAGS* f, uint32_t a)
{
    uint8_t old_cf = f->CF;
    flags_add32(f, a, 1, 0);
    f->CF = old_cf;
}

void flags_dec32(VM_FLAGS* f, uint32_t a)
{
    uint8_t old_cf = f->CF;
    flags_sub32(f, a, 1, 0);
    f->CF = old_cf;
}

// ============================================================================
// 64位运算 Flags
// ============================================================================

void flags_add64(VM_FLAGS* f, uint64_t a, uint64_t b, uint64_t carry_in)
{
    // 64位溢出检测需要128位算术
    // 简化实现：使用__int128或手动计算
    uint64_t result = a + b + carry_in;

    // 进位检测：如果结果小于任一操作数，则有进位
    f->CF = (result < a || (result == a && carry_in)) ? 1 : 0;
    f->ZF = (result == 0) ? 1 : 0;
    f->SF = (result >> 63) & 1;
    f->PF = compute_parity((uint8_t)result);
    f->AF = ((a ^ b ^ result) >> 4) & 1;
    f->OF = (((a ^ result) & (b ^ result)) >> 63) & 1;
}

void flags_sub64(VM_FLAGS* f, uint64_t a, uint64_t b, uint64_t borrow_in)
{
    f->CF = (b > a || (b == a && borrow_in)) ? 1 : 0;
    uint64_t result = a - b - borrow_in;

    f->ZF = (result == 0) ? 1 : 0;
    f->SF = (result >> 63) & 1;
    f->PF = compute_parity((uint8_t)result);
    f->AF = ((a ^ b ^ result) >> 4) & 1;
    f->OF = (((a ^ b) & (a ^ result)) >> 63) & 1;
}

void flags_and64(VM_FLAGS* f, uint64_t result)
{
    f->CF = 0;
    f->OF = 0;
    f->ZF = (result == 0) ? 1 : 0;
    f->SF = (result >> 63) & 1;
    f->PF = compute_parity((uint8_t)result);
    f->AF = 0;
}

void flags_or64(VM_FLAGS* f, uint64_t result)
{
    f->CF = 0;
    f->OF = 0;
    f->ZF = (result == 0) ? 1 : 0;
    f->SF = (result >> 63) & 1;
    f->PF = compute_parity((uint8_t)result);
    f->AF = 0;
}

void flags_xor64(VM_FLAGS* f, uint64_t result)
{
    f->CF = 0;
    f->OF = 0;
    f->ZF = (result == 0) ? 1 : 0;
    f->SF = (result >> 63) & 1;
    f->PF = compute_parity((uint8_t)result);
    f->AF = 0;
}

void flags_inc64(VM_FLAGS* f, uint64_t a)
{
    uint8_t old_cf = f->CF;
    flags_add64(f, a, 1, 0);
    f->CF = old_cf;
}

void flags_dec64(VM_FLAGS* f, uint64_t a)
{
    uint8_t old_cf = f->CF;
    flags_sub64(f, a, 1, 0);
    f->CF = old_cf;
}

// ============================================================================
// 移位操作 Flags
// ============================================================================

void flags_shl8(VM_FLAGS* f, uint8_t val, uint8_t count)
{
    if (count == 0) return;  // count=0 不影响flags

    uint16_t result16 = (uint16_t)val << (count & 0x1F);
    uint8_t result = (uint8_t)result16;

    // CF = 最后移出的位
    if ((count & 0x1F) <= 8) {
        f->CF = (val >> (8 - (count & 0x1F))) & 1;
    } else {
        f->CF = 0;
    }

    f->ZF = (result == 0) ? 1 : 0;
    f->SF = (result >> 7) & 1;
    f->PF = compute_parity(result);

    // OF 只在 count=1 时定义
    if ((count & 0x1F) == 1) {
        f->OF = ((result >> 7) ^ f->CF) & 1;
    }
}

void flags_shr8(VM_FLAGS* f, uint8_t val, uint8_t count)
{
    if (count == 0) return;

    // CF = 最后移出的位
    f->CF = (val >> ((count & 0x1F) - 1)) & 1;

    uint8_t result = val >> (count & 0x1F);

    f->ZF = (result == 0) ? 1 : 0;
    f->SF = (result >> 7) & 1;
    f->PF = compute_parity(result);

    if ((count & 0x1F) == 1) {
        f->OF = (val >> 7) & 1;  // SHR: OF = 原始MSB
    }
}

void flags_sar8(VM_FLAGS* f, int8_t val, uint8_t count)
{
    if (count == 0) return;

    f->CF = ((uint8_t)val >> ((count & 0x1F) - 1)) & 1;

    int8_t result = val >> (count & 0x1F);

    f->ZF = (result == 0) ? 1 : 0;
    f->SF = ((uint8_t)result >> 7) & 1;
    f->PF = compute_parity((uint8_t)result);

    if ((count & 0x1F) == 1) {
        f->OF = 0;  // SAR: OF = 0 when count=1
    }
}

void flags_shl32(VM_FLAGS* f, uint32_t val, uint8_t count)
{
    if (count == 0) return;

    uint8_t cnt = count & 0x1F;
    if (cnt == 0) return;

    // CF = 最后移出的位
    f->CF = (val >> (32 - cnt)) & 1;

    uint32_t result = val << cnt;

    f->ZF = (result == 0) ? 1 : 0;
    f->SF = (result >> 31) & 1;
    f->PF = compute_parity((uint8_t)result);

    if (cnt == 1) {
        f->OF = ((result >> 31) ^ f->CF) & 1;
    }
}

void flags_shr32(VM_FLAGS* f, uint32_t val, uint8_t count)
{
    if (count == 0) return;

    uint8_t cnt = count & 0x1F;
    if (cnt == 0) return;

    f->CF = (val >> (cnt - 1)) & 1;

    uint32_t result = val >> cnt;

    f->ZF = (result == 0) ? 1 : 0;
    f->SF = (result >> 31) & 1;
    f->PF = compute_parity((uint8_t)result);

    if (cnt == 1) {
        f->OF = (val >> 31) & 1;
    }
}

void flags_sar32(VM_FLAGS* f, int32_t val, uint8_t count)
{
    if (count == 0) return;

    uint8_t cnt = count & 0x1F;
    if (cnt == 0) return;

    f->CF = ((uint32_t)val >> (cnt - 1)) & 1;

    int32_t result = val >> cnt;

    f->ZF = (result == 0) ? 1 : 0;
    f->SF = ((uint32_t)result >> 31) & 1;
    f->PF = compute_parity((uint8_t)result);

    if (cnt == 1) {
        f->OF = 0;
    }
}

void flags_shl64(VM_FLAGS* f, uint64_t val, uint8_t count)
{
    if (count == 0) return;

    uint8_t cnt = count & 0x3F;
    if (cnt == 0) return;

    f->CF = (val >> (64 - cnt)) & 1;

    uint64_t result = val << cnt;

    f->ZF = (result == 0) ? 1 : 0;
    f->SF = (result >> 63) & 1;
    f->PF = compute_parity((uint8_t)result);

    if (cnt == 1) {
        f->OF = ((result >> 63) ^ f->CF) & 1;
    }
}

void flags_shr64(VM_FLAGS* f, uint64_t val, uint8_t count)
{
    if (count == 0) return;

    uint8_t cnt = count & 0x3F;
    if (cnt == 0) return;

    f->CF = (val >> (cnt - 1)) & 1;

    uint64_t result = val >> cnt;

    f->ZF = (result == 0) ? 1 : 0;
    f->SF = (result >> 63) & 1;
    f->PF = compute_parity((uint8_t)result);

    if (cnt == 1) {
        f->OF = (val >> 63) & 1;
    }
}

void flags_sar64(VM_FLAGS* f, int64_t val, uint8_t count)
{
    if (count == 0) return;

    uint8_t cnt = count & 0x3F;
    if (cnt == 0) return;

    f->CF = ((uint64_t)val >> (cnt - 1)) & 1;

    int64_t result = val >> cnt;

    f->ZF = (result == 0) ? 1 : 0;
    f->SF = ((uint64_t)result >> 63) & 1;
    f->PF = compute_parity((uint8_t)result);

    if (cnt == 1) {
        f->OF = 0;
    }
}

// ============================================================================
// 循环移位 Flags
// ============================================================================

void flags_rol8(VM_FLAGS* f, uint8_t val, uint8_t count)
{
    uint8_t cnt = count & 0x07;
    if (cnt == 0) return;

    uint8_t result = (val << cnt) | (val >> (8 - cnt));
    f->CF = result & 1;
    f->OF = ((result >> 7) ^ f->CF) & 1;
}

void flags_ror8(VM_FLAGS* f, uint8_t val, uint8_t count)
{
    uint8_t cnt = count & 0x07;
    if (cnt == 0) return;

    uint8_t result = (val >> cnt) | (val << (8 - cnt));
    f->CF = (result >> 7) & 1;
    f->OF = ((result >> 7) ^ ((result >> 6) & 1)) & 1;
}

void flags_rol32(VM_FLAGS* f, uint32_t val, uint8_t count)
{
    uint8_t cnt = count & 0x1F;
    if (cnt == 0) return;

    uint32_t result = (val << cnt) | (val >> (32 - cnt));
    f->CF = result & 1;
    f->OF = ((result >> 31) ^ f->CF) & 1;
}

void flags_ror32(VM_FLAGS* f, uint32_t val, uint8_t count)
{
    uint8_t cnt = count & 0x1F;
    if (cnt == 0) return;

    uint32_t result = (val >> cnt) | (val << (32 - cnt));
    f->CF = (result >> 31) & 1;
    f->OF = ((result >> 31) ^ ((result >> 30) & 1)) & 1;
}

void flags_rol64(VM_FLAGS* f, uint64_t val, uint8_t count)
{
    uint8_t cnt = count & 0x3F;
    if (cnt == 0) return;

    uint64_t result = (val << cnt) | (val >> (64 - cnt));
    f->CF = result & 1;
    f->OF = ((result >> 63) ^ f->CF) & 1;
}

void flags_ror64(VM_FLAGS* f, uint64_t val, uint8_t count)
{
    uint8_t cnt = count & 0x3F;
    if (cnt == 0) return;

    uint64_t result = (val >> cnt) | (val << (64 - cnt));
    f->CF = (result >> 63) & 1;
    f->OF = ((result >> 63) ^ ((result >> 62) & 1)) & 1;
}

// ============================================================================
// NEG 操作 Flags
// ============================================================================

void flags_neg8(VM_FLAGS* f, uint8_t val)
{
    f->CF = (val != 0) ? 1 : 0;
    uint8_t result = (uint8_t)(-(int8_t)val);
    f->ZF = (result == 0) ? 1 : 0;
    f->SF = (result >> 7) & 1;
    f->PF = compute_parity(result);
    f->AF = ((val ^ result) >> 4) & 1;
    f->OF = (val == 0x80) ? 1 : 0;
}

void flags_neg32(VM_FLAGS* f, uint32_t val)
{
    f->CF = (val != 0) ? 1 : 0;
    uint32_t result = (uint32_t)(-(int32_t)val);
    f->ZF = (result == 0) ? 1 : 0;
    f->SF = (result >> 31) & 1;
    f->PF = compute_parity((uint8_t)result);
    f->AF = ((val ^ result) >> 4) & 1;
    f->OF = (val == 0x80000000) ? 1 : 0;
}

void flags_neg64(VM_FLAGS* f, uint64_t val)
{
    f->CF = (val != 0) ? 1 : 0;
    uint64_t result = (uint64_t)(-(int64_t)val);
    f->ZF = (result == 0) ? 1 : 0;
    f->SF = (result >> 63) & 1;
    f->PF = compute_parity((uint8_t)result);
    f->AF = ((val ^ result) >> 4) & 1;
    f->OF = (val == 0x8000000000000000ULL) ? 1 : 0;
}

// ============================================================================
// TEST 操作 Flags
// ============================================================================

void flags_test8(VM_FLAGS* f, uint8_t a, uint8_t b)
{
    uint8_t result = a & b;
    f->CF = 0;
    f->OF = 0;
    f->ZF = (result == 0) ? 1 : 0;
    f->SF = (result >> 7) & 1;
    f->PF = compute_parity(result);
    f->AF = 0;
}

void flags_test32(VM_FLAGS* f, uint32_t a, uint32_t b)
{
    uint32_t result = a & b;
    f->CF = 0;
    f->OF = 0;
    f->ZF = (result == 0) ? 1 : 0;
    f->SF = (result >> 31) & 1;
    f->PF = compute_parity((uint8_t)result);
    f->AF = 0;
}

void flags_test64(VM_FLAGS* f, uint64_t a, uint64_t b)
{
    uint64_t result = a & b;
    f->CF = 0;
    f->OF = 0;
    f->ZF = (result == 0) ? 1 : 0;
    f->SF = (result >> 63) & 1;
    f->PF = compute_parity((uint8_t)result);
    f->AF = 0;
}
