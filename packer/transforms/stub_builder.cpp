#include "stub_builder.h"
#include "loader_import_builder.h"
#include "../pe_parser/pe_emitter.h"
#include "../pe_parser/pe_utils.h"
#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <vector>

namespace CipherShell {
namespace {

constexpr uint32_t kPageNoAccess = 0x01u;
constexpr uint32_t kPageReadOnly = 0x02u;
constexpr uint32_t kPageReadWrite = 0x04u;
constexpr uint32_t kPageExecute = 0x10u;
constexpr uint32_t kPageExecuteRead = 0x20u;
constexpr uint32_t kTaskHeaderSize = 20u;
constexpr uint32_t kTaskSize = 44u;
constexpr uint32_t kLoaderFlagTlsCallback = 0x00000001u;

struct LoaderTask {
    uint32_t rva = 0;
    uint32_t size = 0;
    uint32_t finalProtection = 0;
    std::array<uint8_t, 32> key{};
};

struct Label {
    size_t offset = static_cast<size_t>(-1);
    std::vector<size_t> rel32Fixups;
    std::vector<size_t> rel8Fixups;
};

class CodeBuffer {
public:
    std::vector<uint8_t> bytes;

    void U8(uint8_t value) { bytes.push_back(value); }
    void U16(uint16_t value) { U8(static_cast<uint8_t>(value)); U8(static_cast<uint8_t>(value >> 8)); }
    void U32(uint32_t value) {
        for (unsigned i = 0; i < 4; ++i) U8(static_cast<uint8_t>(value >> (i * 8)));
    }
    void Raw(std::initializer_list<uint8_t> values) { bytes.insert(bytes.end(), values.begin(), values.end()); }
    size_t Size() const { return bytes.size(); }

    void Bind(Label& label) {
        label.offset = bytes.size();
        for (size_t fixup : label.rel32Fixups) PatchRel32(fixup, label.offset);
        for (size_t fixup : label.rel8Fixups) PatchRel8(fixup, label.offset);
        label.rel32Fixups.clear();
        label.rel8Fixups.clear();
    }
    void Rel32(Label& label) {
        const size_t fixup = bytes.size();
        U32(0);
        if (label.offset == static_cast<size_t>(-1)) label.rel32Fixups.push_back(fixup);
        else PatchRel32(fixup, label.offset);
    }
    void Jmp(Label& label) { U8(0xE9); Rel32(label); }
    void Jz(Label& label) { Raw({0x0F, 0x84}); Rel32(label); }
    void Jnz(Label& label) { Raw({0x0F, 0x85}); Rel32(label); }
    void Jb8(Label& label) {
        U8(0x72);
        const size_t fixup = bytes.size();
        U8(0);
        if (label.offset == static_cast<size_t>(-1)) label.rel8Fixups.push_back(fixup);
        else PatchRel8(fixup, label.offset);
    }

    bool Finalize(std::string& error) {
        for (const Label* label : labelsToCheck_) {
            if (label && (!label->rel32Fixups.empty() || !label->rel8Fixups.empty() ||
                    label->offset == static_cast<size_t>(-1))) {
                error = "loader stub contains an unresolved label";
                return false;
            }
        }
        return true;
    }
    void Track(Label& label) { labelsToCheck_.push_back(&label); }

private:
    std::vector<Label*> labelsToCheck_;

    void PatchRel32(size_t position, size_t target) {
        const int64_t delta = static_cast<int64_t>(target) - static_cast<int64_t>(position + 4);
        const int32_t relative = static_cast<int32_t>(delta);
        for (unsigned i = 0; i < 4; ++i) {
            bytes[position + i] = static_cast<uint8_t>(static_cast<uint32_t>(relative) >> (i * 8));
        }
    }
    void PatchRel8(size_t position, size_t target) {
        const int64_t delta = static_cast<int64_t>(target) - static_cast<int64_t>(position + 1);
        bytes[position] = static_cast<uint8_t>(static_cast<int8_t>(delta));
    }
};

uint32_t ProtectionFromCharacteristics(uint32_t characteristics) {
    const bool execute = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    const bool read = (characteristics & IMAGE_SCN_MEM_READ) != 0;
    const bool write = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;
    if (execute && write) return 0; // Long-lived RWX is forbidden.
    if (execute) return read ? kPageExecuteRead : kPageExecute;
    if (write) return kPageReadWrite;
    if (read) return kPageReadOnly;
    return kPageNoAccess;
}

void AppendU32(std::vector<uint8_t>& output, uint32_t value) {
    for (unsigned i = 0; i < 4; ++i) output.push_back(static_cast<uint8_t>(value >> (i * 8)));
}

void AppendLoaderTable(
    std::vector<uint8_t>& code,
    const std::vector<LoaderTask>& tasks,
    uint32_t virtualProtectIatRVA,
    uint32_t flushInstructionCacheIatRVA,
    uint32_t originalEntryPointRVA,
    bool tlsCallback)
{
    AppendU32(code, static_cast<uint32_t>(tasks.size()));
    AppendU32(code, virtualProtectIatRVA);
    AppendU32(code, flushInstructionCacheIatRVA);
    AppendU32(code, originalEntryPointRVA);
    AppendU32(code, tlsCallback ? kLoaderFlagTlsCallback : 0u);
    for (const auto& task : tasks) {
        AppendU32(code, task.rva);
        AppendU32(code, task.size);
        AppendU32(code, task.finalProtection);
        code.insert(code.end(), task.key.begin(), task.key.end());
    }
}

struct X64StubImage {
    std::vector<uint8_t> code;
    std::vector<uint8_t> unwindInfo;
    uint32_t executableSize = 0;
    uint8_t prologSize = 0;
};

std::vector<uint8_t> BuildX64UnwindInfo(uint8_t prologSize) {
    // Prologue: push RBX,RBP,RSI,RDI,R12,R13,R14,R15; sub rsp, 0x68.
    // UNWIND_CODE entries are stored in reverse prologue order.
    struct UnwindCode { uint8_t offset; uint8_t op; uint8_t info; };
    const std::array<UnwindCode, 9> operations = {{
        {prologSize, 2, 12}, // UWOP_ALLOC_SMALL, (0x68 / 8) - 1.
        {12, 0, 15}, {10, 0, 14}, {8, 0, 13}, {6, 0, 12},
        {4, 0, 7}, {3, 0, 6}, {2, 0, 5}, {1, 0, 3}
    }};
    std::vector<uint8_t> info;
    info.push_back(1); // version 1, no flags
    info.push_back(prologSize);
    info.push_back(static_cast<uint8_t>(operations.size()));
    info.push_back(0); // no frame register
    for (const auto& operation : operations) {
        info.push_back(operation.offset);
        info.push_back(static_cast<uint8_t>((operation.info << 4) | operation.op));
    }
    while ((info.size() & 3u) != 0) info.push_back(0);
    return info;
}

X64StubImage BuildX64Stub(
    const std::vector<LoaderTask>& tasks,
    uint32_t virtualProtectIatRVA,
    uint32_t flushInstructionCacheIatRVA,
    uint32_t originalEntryPointRVA,
    bool tlsCallback,
    bool preservePEHeaders,
    std::string& error)
{
    (void)preservePEHeaders; // Headers remain intact for the authenticated VM metadata path.
    CodeBuffer c;
    Label table, loop, decryptLoop, keyNoWrap, rollingStateReady, nextTask, done, fail;
    for (Label* label : {&table, &loop, &decryptLoop, &keyNoWrap, &rollingStateReady, &nextTask, &done, &fail}) c.Track(*label);

    // ABI-correct prologue.  Preserve all x64 non-volatiles and the original
    // DLL/TLS arguments (RCX/RDX/R8) before invoking kernel32 APIs.
    c.U8(0x53); c.U8(0x55); c.U8(0x56); c.U8(0x57);
    c.Raw({0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57});
    c.Raw({0x48,0x83,0xEC,0x68});
    const uint8_t prologSize = static_cast<uint8_t>(c.Size());
    c.Raw({0x48,0x89,0x4C,0x24,0x30});
    c.Raw({0x48,0x89,0x54,0x24,0x38});
    c.Raw({0x4C,0x89,0x44,0x24,0x40});

    // RBX = image base.
    c.Raw({0x65,0x48,0x8B,0x1C,0x25,0x60,0x00,0x00,0x00});
    c.Raw({0x48,0x8B,0x5B,0x10});
    // RSI = table base, RDI = first task, R12D = task count.
    c.Raw({0x48,0x8D,0x35}); c.Rel32(table);
    c.Raw({0x44,0x8B,0x26});
    c.Raw({0x48,0x8D,0x7E,static_cast<uint8_t>(kTaskHeaderSize)});

    c.Bind(loop);
    c.Raw({0x45,0x85,0xE4});
    c.Jz(done);
    // R13 = target, R14D = size, R15D = final protection.
    c.Raw({0x8B,0x07});
    c.Raw({0x4C,0x8D,0x2C,0x03});
    c.Raw({0x44,0x8B,0x77,0x04});
    c.Raw({0x44,0x8B,0x7F,0x08});

    // VirtualProtect(target, size, PAGE_READWRITE, &oldProtect).
    c.Raw({0x4C,0x89,0xE9});
    c.Raw({0x44,0x89,0xF2});
    c.Raw({0x41,0xB8}); c.U32(kPageReadWrite);
    c.Raw({0x4C,0x8D,0x4C,0x24,0x20});
    c.Raw({0x8B,0x46,0x04});
    c.Raw({0x48,0x8B,0x04,0x03});
    c.Raw({0xFF,0xD0,0x85,0xC0});
    c.Jz(fail);

    // Rolling stream decrypt used by SectionEncryptor on x64.
    c.Raw({0x4C,0x89,0xE9});                 // rcx = current byte
    c.Raw({0x44,0x89,0xF2});                 // edx = remaining
    c.Raw({0x4C,0x8D,0x57,0x0C});            // r10 = key
    c.Raw({0x45,0x31,0xC9});                 // r9d = key index
    c.Raw({0x45,0x8B,0x1A});                 // r11d = rolling state
    c.Raw({0x45,0x85,0xDB});                 // test r11d, r11d
    c.Jnz(rollingStateReady);
    c.Raw({0x41,0xBB}); c.U32(0x0C5C5E11u);  // Match RuntimeStreamCipher zero-state fallback.
    c.Bind(rollingStateReady);
    c.Bind(decryptLoop);
    c.Raw({0x85,0xD2});
    c.Jz(nextTask);
    c.Raw({0x44,0x8A,0x01});                 // r8b = ciphertext feedback
    c.Raw({0x43,0x8A,0x04,0x0A});            // al = key[r9]
    c.Raw({0x44,0x30,0xD8});                 // xor al, r11b
    c.Raw({0x30,0x01});                      // xor [rcx], al
    c.Raw({0x41,0xC1,0xCB,0x08});            // ror r11d, 8
    c.Raw({0x45,0x0F,0xB6,0xC0});            // movzx r8d, r8b
    c.Raw({0x45,0x31,0xC3});                 // xor r11d, r8d
    c.Raw({0x48,0xFF,0xC1});                 // inc rcx
    c.Raw({0x41,0xFF,0xC1});                 // inc r9d
    c.Raw({0x41,0x83,0xF9,0x20});
    c.Jb8(keyNoWrap);
    c.Raw({0x45,0x31,0xC9});
    c.Bind(keyNoWrap);
    c.Raw({0xFF,0xCA});
    c.Jmp(decryptLoop);

    c.Bind(nextTask);
    // Restore the original non-RWX protection.
    c.Raw({0x4C,0x89,0xE9});
    c.Raw({0x44,0x89,0xF2});
    c.Raw({0x45,0x89,0xF8});
    c.Raw({0x4C,0x8D,0x4C,0x24,0x20});
    c.Raw({0x8B,0x46,0x04});
    c.Raw({0x48,0x8B,0x04,0x03});
    c.Raw({0xFF,0xD0,0x85,0xC0});
    c.Jz(fail);
    // FlushInstructionCache((HANDLE)-1, target, size).
    c.Raw({0x48,0xC7,0xC1,0xFF,0xFF,0xFF,0xFF});
    c.Raw({0x4C,0x89,0xEA});
    c.Raw({0x45,0x89,0xF0});
    c.Raw({0x8B,0x46,0x08});
    c.Raw({0x48,0x8B,0x04,0x03});
    c.Raw({0xFF,0xD0,0x85,0xC0});
    c.Jz(fail);

    c.Raw({0x48,0x83,0xC7,static_cast<uint8_t>(kTaskSize)});
    c.Raw({0x41,0xFF,0xCC});
    c.Jmp(loop);

    c.Bind(done);
    c.Raw({0x48,0x8B,0x4C,0x24,0x30});
    c.Raw({0x48,0x8B,0x54,0x24,0x38});
    c.Raw({0x4C,0x8B,0x44,0x24,0x40});
    c.Raw({0x48,0x83,0xC4,0x68});
    c.Raw({0x41,0x5F,0x41,0x5E,0x41,0x5D,0x41,0x5C});
    c.U8(0x5F); c.U8(0x5E); c.U8(0x5D); c.U8(0x5B);
    if (tlsCallback) {
        c.U8(0xC3);
    } else {
        c.Raw({0x65,0x48,0x8B,0x04,0x25,0x60,0x00,0x00,0x00});
        c.Raw({0x48,0x8B,0x40,0x10});
        c.Raw({0x48,0x05}); c.U32(originalEntryPointRVA);
        c.Raw({0xFF,0xE0});
    }

    c.Bind(fail);
    c.Raw({0xCC,0x0F,0x0B});
    c.Bind(table);
    const uint32_t executableSize = static_cast<uint32_t>(table.offset);
    AppendLoaderTable(c.bytes, tasks, virtualProtectIatRVA,
        flushInstructionCacheIatRVA, originalEntryPointRVA, tlsCallback);

    if (!c.Finalize(error)) return {};
    X64StubImage image;
    image.code = std::move(c.bytes);
    image.unwindInfo = BuildX64UnwindInfo(prologSize);
    image.executableSize = executableSize;
    image.prologSize = prologSize;
    return image;
}

std::vector<uint8_t> BuildX86Stub(
    const std::vector<LoaderTask>& tasks,
    uint32_t virtualProtectIatRVA,
    uint32_t flushInstructionCacheIatRVA,
    uint32_t originalEntryPointRVA,
    bool tlsCallback,
    bool preservePEHeaders,
    std::string& error)
{
    (void)preservePEHeaders;
    CodeBuffer c;
    Label table, loop, decryptLoop, keyNoWrap, decrypted, done, fail;
    for (Label* label : {&table, &loop, &decryptLoop, &keyNoWrap, &decrypted, &done, &fail}) c.Track(*label);

    c.U8(0x9C); // pushfd
    c.U8(0x60); // pushad
    c.Raw({0x83,0xEC,0x18}); // locals: old,target,size,count,vpIat,flushIat
    // EBX = image base.
    c.Raw({0x64,0xA1}); c.U32(0x30);
    c.Raw({0x8B,0x58,0x08});
    // ESI = table base via call/pop, then task base.
    c.U8(0xE8); c.U32(0);
    const size_t popAddress = c.Size();
    c.U8(0x5E);
    c.Raw({0x81,0xC6});
    const size_t tableDeltaPos = c.Size(); c.U32(0);
    c.Raw({0x8B,0x06,0x89,0x44,0x24,0x0C});
    c.Raw({0x8B,0x46,0x04,0x89,0x44,0x24,0x10});
    c.Raw({0x8B,0x46,0x08,0x89,0x44,0x24,0x14});
    c.Raw({0x83,0xC6,static_cast<uint8_t>(kTaskHeaderSize)});

    c.Bind(loop);
    c.Raw({0x83,0x7C,0x24,0x0C,0x00});
    c.Jz(done);
    c.Raw({0x8B,0x06,0x03,0xC3,0x89,0x44,0x24,0x04});
    c.Raw({0x8B,0x4E,0x04,0x89,0x4C,0x24,0x08});
    // VirtualProtect(target,size,PAGE_READWRITE,&old).
    c.Raw({0x8D,0x14,0x24,0x52});
    c.U8(0x68); c.U32(kPageReadWrite);
    c.U8(0x51); c.U8(0x50);
    c.Raw({0x8B,0x54,0x24,0x20}); // adjusted local + pushed args: vp RVA
    c.Raw({0xFF,0x14,0x13,0x85,0xC0});
    c.Jz(fail);

    // Rolling stream cipher (matches RuntimeStreamCipher::ApplyRolling decrypt).
    // Regs: EAX=state, EBX=mask/temp, ECX=count, EDX=key_index,
    //        EDI=data ptr, EBP=key ptr, ESI=ciphertext feedback.
    c.Raw({0x8B,0x7C,0x24,0x04});          // mov edi, [esp+4]  ; target
    c.Raw({0x8B,0x4C,0x24,0x08});          // mov ecx, [esp+8]  ; size
    c.Raw({0x8D,0x6E,0x0C});              // lea ebp, [esi+0xC]; key ptr
    c.U8(0x53);                            // push ebx           ; save image base
    c.U8(0x56);                            // push esi           ; save task ptr
    c.Raw({0x8B,0x45,0x00});              // mov eax, [ebp]    ; state = *(uint32*)key
    c.Raw({0x85,0xC0});                    // test eax, eax
    c.Jnz(decryptLoop);
    c.U8(0xB8); c.U32(0x0C5C5E11u);      // mov eax, 0x0C5C5E11 (fallback)
    c.Bind(decryptLoop);
    c.Raw({0x31,0xD2});                    // xor edx, edx      ; key index = 0
    c.Bind(keyNoWrap);
    c.Raw({0x85,0xC9});                    // test ecx, ecx
    c.Jz(decrypted);
    c.Raw({0x0F,0xB6,0x37});              // movzx esi, byte [edi] ; esi = ciphertext (feedback)
    c.Raw({0x8A,0x5C,0x15,0x00});         // mov bl, [ebp+edx] ; bl = key[index]
    c.Raw({0x30,0xC3});                    // xor bl, al        ; bl = mask (key[idx]^(u8)state)
    c.Raw({0x30,0x1F});                    // xor [edi], bl     ; decrypt byte
    c.Raw({0xC1,0xC8,0x08});              // ror eax, 8        ; state = ror(state, 8)
    c.Raw({0x31,0xF0});                    // xor eax, esi      ; state ^= (u32)ciphertext
    c.U8(0x47);                            // inc edi
    c.U8(0x49);                            // dec ecx
    c.U8(0x42);                            // inc edx
    c.Raw({0x83,0xFA,0x20});              // cmp edx, 32
    c.Jb8(keyNoWrap);
    c.Raw({0x31,0xD2});                    // xor edx, edx
    c.Jmp(keyNoWrap);

    c.Bind(decrypted);
    c.U8(0x5E);                            // pop esi            ; restore task ptr
    c.U8(0x5B);                            // pop ebx            ; restore image base
    // Restore original protection.
    c.Raw({0x8D,0x04,0x24,0x50});
    c.Raw({0xFF,0x76,0x08});
    c.Raw({0xFF,0x74,0x24,0x10});
    c.Raw({0xFF,0x74,0x24,0x10});
    c.Raw({0x8B,0x54,0x24,0x20});
    c.Raw({0xFF,0x14,0x13,0x85,0xC0});
    c.Jz(fail);
    // FlushInstructionCache(-1,target,size).
    c.Raw({0xFF,0x74,0x24,0x08});
    c.Raw({0xFF,0x74,0x24,0x08});
    c.U8(0x6A); c.U8(0xFF);
    c.Raw({0x8B,0x54,0x24,0x20});
    c.Raw({0xFF,0x14,0x13,0x85,0xC0});
    c.Jz(fail);

    c.Raw({0x83,0xC6,static_cast<uint8_t>(kTaskSize)});
    c.Raw({0xFF,0x4C,0x24,0x0C});
    c.Jmp(loop);

    c.Bind(done);
    c.Raw({0x83,0xC4,0x18,0x61,0x9D});
    if (tlsCallback) {
        c.Raw({0xC2,0x0C,0x00});
    } else {
        c.Raw({0x64,0xA1}); c.U32(0x30);
        c.Raw({0x8B,0x40,0x08,0x05}); c.U32(originalEntryPointRVA);
        c.Raw({0xFF,0xE0});
    }

    c.Bind(fail);
    c.Raw({0xCC,0x0F,0x0B});
    c.Bind(table);
    AppendLoaderTable(c.bytes, tasks, virtualProtectIatRVA,
        flushInstructionCacheIatRVA, originalEntryPointRVA, tlsCallback);
    const int64_t tableDelta = static_cast<int64_t>(table.offset) -
        static_cast<int64_t>(popAddress); // pop ESI receives the call return address.
    const uint32_t delta32 = static_cast<uint32_t>(static_cast<int32_t>(tableDelta));
    for (unsigned i = 0; i < 4; ++i) c.bytes[tableDeltaPos + i] = static_cast<uint8_t>(delta32 >> (i * 8));

    if (!c.Finalize(error)) return {};
    return c.bytes;
}

bool InstallFirstTlsCallback(
    CS_PE_IMAGE* image,
    uint32_t callbackRVA,
    uint32_t& callbackArrayRVA,
    std::string& error)
{
    if (!image || !image->tls.valid || image->tls.directoryRVA == 0) {
        error = "TLS callback installation requires a valid existing TLS directory";
        return false;
    }
    const uint64_t imageBase = PEUtils::ImageBase(image);
    const uint32_t pointerSize = image->is64Bit ? 8u : 4u;
    std::vector<uint8_t> callbacks(
        (image->tls.callbackAddresses.size() + 2u) * pointerSize, 0);

    PEEmitter emitter(image);
    char name[8] = {'.','c','s','t','l','s',0,0};
    auto append = emitter.AppendSection(name, callbacks,
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ);
    if (!append.success) {
        error = "failed to append TLS callback array: " + append.error;
        return false;
    }
    callbackArrayRVA = append.rva;
    uint8_t* emitted = image->rawData + append.rawOffset;
    const uint64_t loaderVA = imageBase + callbackRVA;
    std::memcpy(emitted, &loaderVA, pointerSize);
    for (size_t i = 0; i < image->tls.callbackAddresses.size(); ++i) {
        const uint64_t callbackVA = image->tls.callbackAddresses[i];
        std::memcpy(emitted + (i + 1u) * pointerSize, &callbackVA, pointerSize);
    }

    const uint32_t callbackFieldRVA = image->tls.directoryRVA + static_cast<uint32_t>(
        image->is64Bit ? offsetof(IMAGE_TLS_DIRECTORY64, AddressOfCallBacks)
                       : offsetof(IMAGE_TLS_DIRECTORY32, AddressOfCallBacks));
    const uint64_t callbackArrayVA = imageBase + append.rva;
    std::vector<uint8_t> callbackField(pointerSize, 0);
    std::memcpy(callbackField.data(), &callbackArrayVA, pointerSize);
    if (!emitter.PatchBytes(callbackFieldRVA, callbackField, &error)) return false;

    std::vector<CS_RELOC_ENTRY> relocations;
    relocations.reserve(image->tls.callbackAddresses.size() + 2u);
    const uint16_t type = image->is64Bit ? IMAGE_REL_BASED_DIR64 : IMAGE_REL_BASED_HIGHLOW;
    auto addRelocation = [&](uint32_t rva) {
        CS_RELOC_ENTRY entry{};
        entry.fullRVA = rva;
        entry.pageRVA = rva & ~0xFFFu;
        entry.offset = static_cast<uint16_t>(rva & 0xFFFu);
        entry.type = type;
        relocations.push_back(entry);
    };
    addRelocation(callbackFieldRVA);
    for (size_t i = 0; i <= image->tls.callbackAddresses.size(); ++i) {
        addRelocation(append.rva + static_cast<uint32_t>(i * pointerSize));
    }
    char relocName[8] = {'.','c','s','t','r','l',0,0};
    if (!emitter.RebuildBaseRelocationDirectory(relocations, relocName, nullptr, &error)) return false;

    image->tls.callbacksAddress = callbackArrayVA;
    image->tls.callbackAddresses.insert(image->tls.callbackAddresses.begin(), loaderVA);
    image->tls.callbackCount = static_cast<DWORD>(image->tls.callbackAddresses.size());
    return true;
}

bool AddX64UnwindAndCfg(
    CS_PE_IMAGE* image,
    uint32_t stubRVA,
    uint32_t stubSize,
    const std::vector<uint8_t>& unwindInfo,
    std::string& error)
{
    if (!image || !image->is64Bit || unwindInfo.empty()) return true;
    PEEmitter emitter(image);
    char unwindName[8] = {'.','c','s','u','w','x',0,0};
    auto unwind = emitter.AppendSection(unwindName, unwindInfo,
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ);
    if (!unwind.success) {
        error = "failed to append loader unwind data: " + unwind.error;
        return false;
    }
    CS_RUNTIME_FUNCTION function{};
    function.beginAddress = stubRVA;
    function.endAddress = stubRVA + stubSize;
    function.unwindData = unwind.rva;
    char exceptionName[8] = {'.','c','s','p','d','x',0,0};
    if (!emitter.RebuildExceptionDirectory({function}, exceptionName, nullptr, &error)) return false;
    char cfgName[8] = {'.','c','s','c','f','2',0,0};
    if (!emitter.RebuildGuardCFFunctionTable({stubRVA}, cfgName, nullptr, &error)) return false;
    return true;
}

} // namespace

bool StubBuilder::VerifyNoWritableExecutableSections(
    const CS_PE_IMAGE* image, std::string& error)
{
    if (!image || !image->sections) {
        error = "invalid PE image while verifying W^X";
        return false;
    }
    for (uint32_t i = 0; i < image->numSections; ++i) {
        const uint32_t characteristics = image->sections[i].Characteristics;
        if ((characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 &&
            (characteristics & IMAGE_SCN_MEM_WRITE) != 0) {
            error = "section " + std::to_string(i) + " remains writable and executable";
            return false;
        }
    }
    return true;
}

StubEmbedResult StubBuilder::EmbedStub(
    CS_PE_IMAGE* image,
    const std::vector<CS_ENCRYPTED_SECTION>& encryptedSections,
    uint32_t originalEntryPointRVA,
    bool preservePEHeaders)
{
    StubEmbedResult result{};
    if (!image || !image->isValid || encryptedSections.empty()) {
        result.error = "invalid image or empty loader task list";
        return result;
    }

    std::vector<LoaderTask> tasks;
    tasks.reserve(encryptedSections.size());
    for (const auto& encrypted : encryptedSections) {
        if (encrypted.encryptedSize == 0 || encrypted.originalRVA == 0) continue;
        LoaderTask task{};
        task.rva = encrypted.originalRVA;
        task.size = encrypted.encryptedSize;
        task.finalProtection = ProtectionFromCharacteristics(encrypted.originalCharacteristics);
        if (task.finalProtection == 0) {
            result.error = "input task requests a long-lived writable-executable protection";
            return result;
        }
        std::copy(std::begin(encrypted.sectionKey.key), std::end(encrypted.sectionKey.key),
            task.key.begin());
        tasks.push_back(task);
    }
    if (tasks.empty()) {
        result.error = "loader task list became empty";
        return result;
    }

    LoaderImportBuilder importBuilder;
    char importName[8] = {'.','c','s','l','d','r',0,0};
    const LoaderImportBuildResult imports = importBuilder.Build(image, importName);
    if (!imports.success) {
        result.error = imports.error;
        return result;
    }
    result.virtualProtectIatRVA = imports.virtualProtectIatRVA;
    result.flushInstructionCacheIatRVA = imports.flushInstructionCacheIatRVA;

    const bool useTls = image->tls.valid && image->tls.directoryRVA != 0;
    std::string buildError;
    std::vector<uint8_t> stub;
    std::vector<uint8_t> unwindInfo;
    uint32_t executableSize = 0;
    if (image->is64Bit) {
        X64StubImage built = BuildX64Stub(tasks, imports.virtualProtectIatRVA,
            imports.flushInstructionCacheIatRVA, originalEntryPointRVA,
            useTls, preservePEHeaders, buildError);
        stub = std::move(built.code);
        unwindInfo = std::move(built.unwindInfo);
        executableSize = built.executableSize;
    } else {
        stub = BuildX86Stub(tasks, imports.virtualProtectIatRVA,
            imports.flushInstructionCacheIatRVA, originalEntryPointRVA,
            useTls, preservePEHeaders, buildError);
    }
    if (stub.empty()) {
        result.error = buildError.empty() ? "loader stub generation failed" : buildError;
        return result;
    }

    PEEmitter emitter(image);
    char stubName[8] = {'.','c','s','t','u','b',0,0};
    const auto appended = emitter.AppendSection(stubName, stub,
        IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ);
    if (!appended.success) {
        result.error = "failed to append loader stub: " + appended.error;
        return result;
    }
    result.stubRVA = appended.rva;
    result.stubSize = static_cast<uint32_t>(stub.size());

    if (!AddX64UnwindAndCfg(image, result.stubRVA,
            executableSize ? executableSize : result.stubSize,
            unwindInfo, result.error)) return result;

    if (useTls) {
        if (!InstallFirstTlsCallback(image, result.stubRVA,
                result.tlsCallbackArrayRVA, result.error)) return result;
        result.installedAsTlsCallback = true;
        emitter.SetEntryPoint(originalEntryPointRVA);
    } else {
        emitter.SetEntryPoint(result.stubRVA);
    }

    if (!VerifyNoWritableExecutableSections(image, result.error)) return result;
    result.wxVerified = true;
    result.success = true;
    return result;
}

} // namespace CipherShell
