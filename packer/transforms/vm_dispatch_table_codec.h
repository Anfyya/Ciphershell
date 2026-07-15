#ifndef CS_VM_DISPATCH_TABLE_CODEC_H
#define CS_VM_DISPATCH_TABLE_CODEC_H

#include <cstdint>

namespace CipherShell {

enum class VMDispatchTableEncoding : uint8_t {
    XorKeyedTable = 1,
    AddRotateKeyedTable = 2
};

struct VMDispatchTableCodec {
    VMDispatchTableEncoding encoding =
        VMDispatchTableEncoding::XorKeyedTable;
    uint8_t rotate = 1;
    uint16_t reserved = 0;
    uint32_t key = 1;
};

} // namespace CipherShell

#endif // CS_VM_DISPATCH_TABLE_CODEC_H
