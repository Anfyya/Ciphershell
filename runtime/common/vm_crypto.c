#include "vm_crypto.h"

static uint32_t load32_le(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t load64_le(const uint8_t* p) {
    uint64_t value = 0;
    unsigned i;
    for (i = 0; i < 8; ++i) value |= (uint64_t)p[i] << (i * 8);
    return value;
}

static void store32_le(uint8_t* p, uint32_t value) {
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
    p[2] = (uint8_t)(value >> 16);
    p[3] = (uint8_t)(value >> 24);
}

static uint32_t rotl32(uint32_t value, unsigned count) {
    return (value << count) | (value >> (32 - count));
}

static uint64_t rotl64(uint64_t value, unsigned count) {
    return (value << count) | (value >> (64 - count));
}

static void quarter_round(uint32_t* a, uint32_t* b, uint32_t* c, uint32_t* d) {
    *a += *b; *d ^= *a; *d = rotl32(*d, 16);
    *c += *d; *b ^= *c; *b = rotl32(*b, 12);
    *a += *b; *d ^= *a; *d = rotl32(*d, 8);
    *c += *d; *b ^= *c; *b = rotl32(*b, 7);
}

static void chacha_rounds(uint32_t state[16]) {
    unsigned i;
    for (i = 0; i < 10; ++i) {
        quarter_round(&state[0], &state[4], &state[8], &state[12]);
        quarter_round(&state[1], &state[5], &state[9], &state[13]);
        quarter_round(&state[2], &state[6], &state[10], &state[14]);
        quarter_round(&state[3], &state[7], &state[11], &state[15]);
        quarter_round(&state[0], &state[5], &state[10], &state[15]);
        quarter_round(&state[1], &state[6], &state[11], &state[12]);
        quarter_round(&state[2], &state[7], &state[8], &state[13]);
        quarter_round(&state[3], &state[4], &state[9], &state[14]);
    }
}

void vm_hchacha20(const uint8_t key[32], const uint8_t input[16], uint8_t output[32]) {
    uint32_t state[16];
    unsigned i;
    state[0] = 0x61707865u;
    state[1] = 0x3320646Eu;
    state[2] = 0x79622D32u;
    state[3] = 0x6B206574u;
    for (i = 0; i < 8; ++i) state[4 + i] = load32_le(key + i * 4);
    for (i = 0; i < 4; ++i) state[12 + i] = load32_le(input + i * 4);
    chacha_rounds(state);
    store32_le(output + 0, state[0]);
    store32_le(output + 4, state[1]);
    store32_le(output + 8, state[2]);
    store32_le(output + 12, state[3]);
    store32_le(output + 16, state[12]);
    store32_le(output + 20, state[13]);
    store32_le(output + 24, state[14]);
    store32_le(output + 28, state[15]);
    for (i = 0; i < 16; ++i) state[i] = 0;
}

void vm_derive_record_key(
    const uint8_t masterKey[32],
    const uint8_t buildId[16],
    uint32_t functionRva,
    uint8_t output[32])
{
    uint8_t input[16];
    unsigned i;
    for (i = 0; i < 16; ++i) input[i] = buildId[i];
    input[12] ^= (uint8_t)functionRva;
    input[13] ^= (uint8_t)(functionRva >> 8);
    input[14] ^= (uint8_t)(functionRva >> 16);
    input[15] ^= (uint8_t)(functionRva >> 24);
    vm_hchacha20(masterKey, input, output);
    for (i = 0; i < 16; ++i) input[i] = 0;
}

static void chacha20_block(
    const uint8_t key[32],
    const uint8_t nonce[12],
    uint32_t counter,
    uint8_t output[64])
{
    uint32_t initial[16];
    uint32_t working[16];
    unsigned i;
    initial[0] = 0x61707865u;
    initial[1] = 0x3320646Eu;
    initial[2] = 0x79622D32u;
    initial[3] = 0x6B206574u;
    for (i = 0; i < 8; ++i) initial[4 + i] = load32_le(key + i * 4);
    initial[12] = counter;
    initial[13] = load32_le(nonce + 0);
    initial[14] = load32_le(nonce + 4);
    initial[15] = load32_le(nonce + 8);
    for (i = 0; i < 16; ++i) working[i] = initial[i];
    chacha_rounds(working);
    for (i = 0; i < 16; ++i) {
        working[i] += initial[i];
        store32_le(output + i * 4, working[i]);
        initial[i] = 0;
        working[i] = 0;
    }
}

void vm_chacha20_xor(
    const uint8_t* input,
    uint8_t* output,
    size_t length,
    const uint8_t key[32],
    const uint8_t nonce[12],
    uint32_t initialCounter,
    uint64_t streamOffset)
{
    uint8_t block[64];
    uint64_t blockIndex = streamOffset / 64u;
    size_t blockOffset = (size_t)(streamOffset % 64u);
    size_t processed = 0;
    unsigned i;
    while (processed < length) {
        size_t available;
        size_t take;
        chacha20_block(key, nonce, initialCounter + (uint32_t)blockIndex, block);
        available = 64u - blockOffset;
        take = length - processed < available ? length - processed : available;
        for (i = 0; i < take; ++i) output[processed + i] = input[processed + i] ^ block[blockOffset + i];
        processed += take;
        blockOffset = 0;
        ++blockIndex;
    }
    for (i = 0; i < 64; ++i) block[i] = 0;
}

#define SIPROUND(ctx) do { \
    (ctx)->v0 += (ctx)->v1; (ctx)->v1 = rotl64((ctx)->v1, 13); (ctx)->v1 ^= (ctx)->v0; (ctx)->v0 = rotl64((ctx)->v0, 32); \
    (ctx)->v2 += (ctx)->v3; (ctx)->v3 = rotl64((ctx)->v3, 16); (ctx)->v3 ^= (ctx)->v2; \
    (ctx)->v0 += (ctx)->v3; (ctx)->v3 = rotl64((ctx)->v3, 21); (ctx)->v3 ^= (ctx)->v0; \
    (ctx)->v2 += (ctx)->v1; (ctx)->v1 = rotl64((ctx)->v1, 17); (ctx)->v1 ^= (ctx)->v2; (ctx)->v2 = rotl64((ctx)->v2, 32); \
} while (0)

static void siphash_compress(VM_SIPHASH24_CONTEXT* context, uint64_t message) {
    context->v3 ^= message;
    SIPROUND(context);
    SIPROUND(context);
    context->v0 ^= message;
}

void vm_siphash24_init(VM_SIPHASH24_CONTEXT* context, const uint8_t key[16]) {
    uint64_t k0 = load64_le(key);
    uint64_t k1 = load64_le(key + 8);
    context->v0 = 0x736F6D6570736575ULL ^ k0;
    context->v1 = 0x646F72616E646F6DULL ^ k1;
    context->v2 = 0x6C7967656E657261ULL ^ k0;
    context->v3 = 0x7465646279746573ULL ^ k1;
    context->totalLength = 0;
    context->tail = 0;
    context->tailLength = 0;
}

void vm_siphash24_update(VM_SIPHASH24_CONTEXT* context, const uint8_t* data, size_t length) {
    size_t pos = 0;
    context->totalLength += length;
    if (context->tailLength) {
        while (pos < length && context->tailLength < 8) {
            context->tail |= (uint64_t)data[pos++] << (context->tailLength * 8);
            ++context->tailLength;
        }
        if (context->tailLength == 8) {
            siphash_compress(context, context->tail);
            context->tail = 0;
            context->tailLength = 0;
        }
    }
    while (pos + 8 <= length) {
        siphash_compress(context, load64_le(data + pos));
        pos += 8;
    }
    while (pos < length) {
        context->tail |= (uint64_t)data[pos++] << (context->tailLength * 8);
        ++context->tailLength;
    }
}

uint64_t vm_siphash24_final(VM_SIPHASH24_CONTEXT* context) {
    uint64_t finalBlock = context->tail | ((context->totalLength & 0xFFu) << 56);
    uint64_t result;
    siphash_compress(context, finalBlock);
    context->v2 ^= 0xFFu;
    SIPROUND(context);
    SIPROUND(context);
    SIPROUND(context);
    SIPROUND(context);
    result = context->v0 ^ context->v1 ^ context->v2 ^ context->v3;
    context->v0 = context->v1 = context->v2 = context->v3 = 0;
    context->tail = context->totalLength = 0;
    context->tailLength = 0;
    return result;
}

uint64_t vm_siphash24(const uint8_t* data, size_t length, const uint8_t key[16]) {
    VM_SIPHASH24_CONTEXT context;
    vm_siphash24_init(&context, key);
    vm_siphash24_update(&context, data, length);
    return vm_siphash24_final(&context);
}

int vm_constant_time_equal64(uint64_t lhs, uint64_t rhs) {
    uint64_t difference = lhs ^ rhs;
    difference |= difference >> 32;
    difference |= difference >> 16;
    difference |= difference >> 8;
    return (int)(((uint8_t)difference - 1u) >> 7);
}

