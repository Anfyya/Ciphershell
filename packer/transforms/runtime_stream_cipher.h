#ifndef CS_RUNTIME_STREAM_CIPHER_H
#define CS_RUNTIME_STREAM_CIPHER_H

#include <cstdint>

namespace CipherShell {
namespace RuntimeStreamCipher {

inline uint32_t LoadLe32(const uint8_t* value) {
    return static_cast<uint32_t>(value[0]) |
        (static_cast<uint32_t>(value[1]) << 8) |
        (static_cast<uint32_t>(value[2]) << 16) |
        (static_cast<uint32_t>(value[3]) << 24);
}

inline uint32_t RotateRight32(uint32_t value, uint32_t bits) {
    bits &= 31u;
    return (value >> bits) | (value << ((32u - bits) & 31u));
}

// DEPRECATED: Simple repeating XOR with no feedback. Trivially broken by
// known-plaintext attacks.  All callers migrated to ApplyRolling.
inline void ApplyLegacyXor(
    uint8_t* data,
    uint32_t size,
    const uint8_t key[32])
{
    for (uint32_t i = 0; i < size; i++) data[i] ^= key[i & 31u];
}

inline void ApplyRolling(
    uint8_t* data,
    uint32_t size,
    const uint8_t key[32],
    bool encrypting)
{
    uint32_t state = LoadLe32(key);
    if (state == 0) state = 0x0C5C5E11u;
    for (uint32_t i = 0; i < size; i++) {
        const uint8_t input = data[i];
        const uint8_t mask = static_cast<uint8_t>(state) ^ key[i & 31u];
        data[i] = static_cast<uint8_t>(input ^ mask);
        const uint8_t feedback = encrypting ? data[i] : input;
        state = RotateRight32(state, 8) ^ static_cast<uint32_t>(feedback);
    }
}

} // namespace RuntimeStreamCipher
} // namespace CipherShell

#endif // CS_RUNTIME_STREAM_CIPHER_H
