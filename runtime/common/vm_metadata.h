#ifndef CS_RUNTIME_VM_METADATA_H
#define CS_RUNTIME_VM_METADATA_H

#include "vm_isa.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VM_METADATA_VERSION 0x00030001u
#define VM_RUNTIME_VERSION  0x00030003u
#define VM_KEY_ENCODING_VERSION 0x00010000u
#define VM_RUNTIME_KEY_SHARE_SIZE 32u
#define VM_ARCH_X86 0x00000086u
#define VM_ARCH_X64 0x00008664u
#define VM_OPCODE_MAP_SIZE 256u
#define VM_REGISTER_MAP_SIZE 32u

enum {
    VM_METADATA_FLAG_AUTHENTICATED = 0x00000001u,
    VM_METADATA_FLAG_BYTECODE_CHACHA20 = 0x00000002u,
    VM_METADATA_FLAG_NATIVE_BODY_DESTROYED = 0x00000004u,
    VM_METADATA_FLAG_CFG_VERIFIED = 0x00000008u,
    VM_METADATA_FLAG_UNWIND_VERIFIED = 0x00000010u,
    VM_METADATA_FLAG_CFG_ENABLED = 0x00000020u
};

enum {
    VM_RECORD_FLAG_X64 = 0x00000001u,
    VM_RECORD_FLAG_NATIVE_BODY_DESTROYED = 0x00000002u,
    VM_RECORD_FLAG_UNWIND_VERIFIED = 0x00000004u,
    VM_RECORD_FLAG_CFG_VERIFIED = 0x00000008u,
    VM_RECORD_FLAG_USES_SIMD = 0x00000010u,
    VM_RECORD_FLAG_USES_AVX = 0x00000020u,
    VM_RECORD_FLAG_USES_X87 = 0x00000040u
};

#pragma pack(push, 1)
typedef struct VM_METADATA_HEADER {
    uint32_t cookie;
    uint32_t headerSize;
    uint32_t totalSize;
    uint32_t metadataVersion;
    uint32_t schemaVersion;
    uint32_t runtimeVersion;
    uint32_t architecture;
    uint32_t flags;
    uint32_t recordCount;
    uint32_t recordSize;
    uint32_t recordOffset;
    uint32_t reverseOpcodeMapOffset;
    uint32_t registerMapOffset;
    uint32_t bytecodeOffset;
    uint32_t bytecodeSize;
    uint32_t runtimeEntryRVA;
    uint32_t runtimeSize;
    uint32_t traceRVA;
    uint32_t imageSize;
    uint32_t guardCFCheckPointerRVA;
    uint32_t guardCFDispatchPointerRVA;
    uint32_t layoutSeed;
    uint32_t keyEncodingVersion;
    uint32_t opcodeMapSize;
    uint32_t registerMapSize;
    uint8_t buildId[16];
    uint8_t encodedMasterKey[32];
    uint64_t metadataTag;
    uint32_t runtimeBaseRVA;
} VM_METADATA_HEADER;

typedef struct VM_FUNCTION_RECORD {
    uint32_t functionRVA;
    uint32_t functionSize;
    uint32_t bytecodeOffset;
    uint32_t bytecodeSize;
    uint32_t trampolineRVA;
    uint32_t trampolineSize;
    uint32_t flags;
    uint32_t returnStackCleanup;
    uint32_t opcodeMapOffset;
    uint32_t registerMapOffset;
    uint8_t nonce[12];
    uint64_t bytecodeTag;
    uint32_t guestStackSize;
} VM_FUNCTION_RECORD;

typedef struct VM_TRACE_STATE {
    uint32_t enterCount;
    uint32_t lastFunctionRVA;
    uint32_t lastOpcode;
    uint32_t lastErrorCode;
    uint32_t lastBytecodeOffset;
    uint32_t lastReturnValueLow;
    uint32_t lastReturnValueHigh;
    uint32_t reserved;
} VM_TRACE_STATE;
#pragma pack(pop)

#ifdef __cplusplus
}
static_assert(sizeof(VM_METADATA_HEADER) == 160, "VM metadata header size mismatch");
static_assert(sizeof(VM_FUNCTION_RECORD) == 64, "VM function record size mismatch");
static_assert(sizeof(VM_TRACE_STATE) == 32, "VM trace state size mismatch");
#endif

#endif // CS_RUNTIME_VM_METADATA_H
