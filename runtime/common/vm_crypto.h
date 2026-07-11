#ifndef CS_RUNTIME_VM_CRYPTO_H
#define CS_RUNTIME_VM_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct VM_SIPHASH24_CONTEXT {
    uint64_t v0;
    uint64_t v1;
    uint64_t v2;
    uint64_t v3;
    uint64_t totalLength;
    uint64_t tail;
    uint32_t tailLength;
} VM_SIPHASH24_CONTEXT;

void vm_hchacha20(const uint8_t key[32], const uint8_t input[16], uint8_t output[32]);
void vm_derive_record_key(
    const uint8_t masterKey[32],
    const uint8_t buildId[16],
    uint32_t functionRva,
    uint8_t output[32]);

void vm_chacha20_xor(
    const uint8_t* input,
    uint8_t* output,
    size_t length,
    const uint8_t key[32],
    const uint8_t nonce[12],
    uint32_t initialCounter,
    uint64_t streamOffset);

void vm_siphash24_init(VM_SIPHASH24_CONTEXT* context, const uint8_t key[16]);
void vm_siphash24_update(VM_SIPHASH24_CONTEXT* context, const uint8_t* data, size_t length);
uint64_t vm_siphash24_final(VM_SIPHASH24_CONTEXT* context);
uint64_t vm_siphash24(const uint8_t* data, size_t length, const uint8_t key[16]);
int vm_constant_time_equal64(uint64_t lhs, uint64_t rhs);

#ifdef __cplusplus
}
#endif

#endif // CS_RUNTIME_VM_CRYPTO_H
