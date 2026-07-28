#ifndef CS_RUNTIME_VM_STATE_CHAIN_H
#define CS_RUNTIME_VM_STATE_CHAIN_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline uint32_t vm_state_chain_mask_seed(
    uint64_t operandCodecSeed,
    uint32_t functionRva,
    uint32_t instructionOffset)
{
    uint32_t value = (uint32_t)operandCodecSeed ^
        (uint32_t)(operandCodecSeed >> 32u) ^
        functionRva ^ (instructionOffset * 0x9E3779B9u) ^ 0x53434B31u;
    value ^= value >> 16u;
    value *= 0x7FEB352Du;
    value ^= value >> 15u;
    value *= 0x846CA68Bu;
    value ^= value >> 16u;
    return value != 0u ? value : 0xA5C31F27u;
}

static inline uint8_t vm_state_chain_mask_byte(
    uint32_t seed,
    uint32_t instructionByteOffset)
{
    const uint32_t lane =
        (seed >> ((instructionByteOffset & 3u) * 8u)) & 0xFFu;
    return (uint8_t)(lane ^ (instructionByteOffset * 0x9Du) ^
        (seed >> 24u));
}

#ifdef __cplusplus
}
#endif

#endif
