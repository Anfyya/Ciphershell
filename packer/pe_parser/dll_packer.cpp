/**
 * CipherShell DLL 鍔犲３鍣?- 瀹炵幇
 */

#include "dll_packer.h"
#include "pe_utils.h"
#include <cstring>
#include <cstdlib>

namespace CipherShell {

// ============================================================================
// 鏋勯€?鏋愭瀯
// ============================================================================

DLLPacker::DLLPacker() {}
DLLPacker::~DLLPacker() {}

// ============================================================================
// 鍏叡鎺ュ彛
// ============================================================================

DLLPackResult DLLPacker::PackDLL(CS_PE_IMAGE* image, const DLLPackConfig& config) {
    DLLPackResult result;
    result.trampolineCode = nullptr;
    result.trampolineSize = 0;
    result.relocationData = nullptr;
    result.relocationSize = 0;
    result.success = false;

    if (!image || !image->isValid) {
        result.errorMessage = "Invalid PE image";
        return result;
    }

    // 1. 瑙ｆ瀽瀵煎嚭琛?
    if (config.preserveExports) {
        result.exports = ParseExports(image);
        if (result.exports.empty()) {
            result.errorMessage = "No exports found";
            return result;
        }
    }

    // 2. 鐢熸垚瀵煎嚭璺虫澘
    if (config.preserveExports && !result.exports.empty()) {
        DWORD64 imageBase = image->is64Bit ?
            image->ntHeaders64->OptionalHeader.ImageBase :
            image->ntHeaders32->OptionalHeader.ImageBase;

        result.trampolineCode = GenerateExportTrampolines(
            result.exports, imageBase, image->is64Bit, &result.trampolineSize);

        if (!result.trampolineCode) {
            result.errorMessage = "Failed to generate trampolines";
            return result;
        }
    }

    // 3. 澶勭悊閲嶅畾浣?
    if (config.preserveRelocations) {
        if (!ProcessRelocations(image, 0)) {
            // 閲嶅畾浣嶅鐞嗗け璐ヤ笉鏄嚧鍛介敊璇?
        }
    }

    // 4. 淇濈暀 TLS
    if (config.preserveTLS) {
        PreserveTLSCallbacks(image);
    }

    // 5. 澶勭悊寮傚父琛紙x64锛?
    if (config.preserveExceptions && image->is64Bit) {
        // x64 寮傚父澶勭悊闇€瑕?.pdata 娈?
        // 鍦ㄥ姞澹冲悗闇€瑕侀噸鏂版敞鍐?
    }

    result.success = true;
    return result;
}

BYTE* DLLPacker::GenerateExportTrampolines(
    const std::vector<DLLExportEntry>& exports,
    uint64_t imageBase,
    bool is64Bit,
    DWORD* trampolineSize)
{
    if (!trampolineSize || exports.empty()) return nullptr;

    // 浼扮畻璺虫澘澶у皬
    // 姣忎釜瀵煎嚭鍑芥暟闇€瑕佷竴涓烦鏉匡細
    //   jmp [target] 鎴?push addr; ret
    DWORD perTrampoline = is64Bit ? 16 : 8;
    DWORD totalSize = (DWORD)exports.size() * perTrampoline + 64;

    BYTE* code = new(std::nothrow) BYTE[totalSize];
    if (!code) return nullptr;

    memset(code, 0x90, totalSize);  // NOP 濉厖

    DWORD offset = 0;

    for (const auto& exp : exports) {
        if (exp.isForwarded) continue;

        if (is64Bit) {
            // x64: 浣跨敤 RIP 鐩稿璺宠浆
            // FF 25 xx xx xx xx  jmp [rip+offset]
            code[offset++] = 0xFF;
            code[offset++] = 0x25;
            // RIP 鐩稿鍋忕Щ锛堟寚鍚戝悗闈㈢殑鍦板潃锛?
            *(uint32_t*)(code + offset) = 0;
            offset += 4;
            // 缁濆鍦板潃
            *(uint64_t*)(code + offset) = imageBase + exp.rva;
            offset += 8;
        } else {
            // x86: push addr; ret
            code[offset++] = 0x68;  // push imm32
            *(uint32_t*)(code + offset) = (uint32_t)(imageBase + exp.rva);
            offset += 4;
            code[offset++] = 0xC3;  // ret
        }
    }

    *trampolineSize = offset;
    return code;
}

BYTE* DLLPacker::GenerateDllMainStub(
    uint32_t originalDllMain,
    bool is64Bit,
    DWORD* stubSize)
{
    if (!stubSize) return nullptr;

    // DllMain 绛惧悕锛欱OOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)

    if (is64Bit) {
        // x64 DllMain stub
        // rcx = hinstDLL, rdx = fdwReason, r8 = lpvReserved
        static const BYTE x64_stub[] = {
            // 淇濆瓨鍙傛暟
            0x48, 0x89, 0xC8,                   // mov rax, rcx (hinstDLL)
            0x48, 0x89, 0xD3,                   // mov rbx, rdx (fdwReason)
            0x49, 0x89, 0xC1,                   // mov r9, r8   (lpvReserved)

            // 妫€鏌?fdwReason
            0x48, 0x83, 0xFB, 0x00,             // cmp rbx, 0 (DLL_PROCESS_DETACH)
            0x74, 0x14,                         // jz .detach
            0x48, 0x83, 0xFB, 0x01,             // cmp rbx, 1 (DLL_PROCESS_ATTACH)
            0x74, 0x0A,                         // jz .attach
            0x48, 0x83, 0xFB, 0x02,             // cmp rbx, 2 (DLL_THREAD_ATTACH)
            0x74, 0x10,                         // jz .thread_attach
            0xEB, 0x18,                         // jmp .done

            // .attach: 鍒濆鍖?VM锛岃В瀵嗕唬鐮?
            0xE8, 0x00, 0x00, 0x00, 0x00,       // call vm_init (鐩稿鍋忕Щ)
            0xEB, 0x10,                         // jmp .done

            // .detach: 娓呯悊
            0xE8, 0x00, 0x00, 0x00, 0x00,       // call vm_cleanup
            0xEB, 0x08,                         // jmp .done

            // .thread_attach:
            0x90,                               // nop
            0xEB, 0x04,                         // jmp .done

            // .done: 璋冪敤鍘熷 DllMain
            0xE8, 0x00, 0x00, 0x00, 0x00,       // call original_DllMain
            0xC3                                // ret
        };

        *stubSize = sizeof(x64_stub);
        BYTE* output = new BYTE[sizeof(x64_stub)];
        memcpy(output, x64_stub, sizeof(x64_stub));
        return output;
    } else {
        // x86 DllMain stub
        static const BYTE x86_stub[] = {
            0x55,                               // push ebp
            0x89, 0xE5,                         // mov ebp, esp
            0x53,                               // push ebx
            0x8B, 0x45, 0x0C,                   // mov eax, [ebp+12] (fdwReason)

            0x83, 0xF8, 0x00,                   // cmp eax, 0
            0x74, 0x10,                         // jz .detach
            0x83, 0xF8, 0x01,                   // cmp eax, 1
            0x74, 0x08,                         // jz .attach
            0x83, 0xF8, 0x02,                   // cmp eax, 2
            0x74, 0x0C,                         // jz .thread_attach
            0xEB, 0x12,                         // jmp .done

            // .attach:
            0xE8, 0x00, 0x00, 0x00, 0x00,       // call vm_init
            0xEB, 0x0C,                         // jmp .done

            // .detach:
            0xE8, 0x00, 0x00, 0x00, 0x00,       // call vm_cleanup
            0xEB, 0x06,                         // jmp .done

            // .thread_attach:
            0x90,                               // nop
            0xEB, 0x02,                         // jmp .done

            // .done:
            0xE8, 0x00, 0x00, 0x00, 0x00,       // call original_DllMain
            0x5B,                               // pop ebx
            0x5D,                               // pop ebp
            0xC3                                // ret
        };

        *stubSize = sizeof(x86_stub);
        BYTE* output = new BYTE[sizeof(x86_stub)];
        memcpy(output, x86_stub, sizeof(x86_stub));
        return output;
    }
}

bool DLLPacker::PatchExceptionTable(CS_PE_IMAGE* image, uint32_t newExceptionHandler) {
    if (!image || !image->is64Bit) return false;

    // x64 鐨勫紓甯稿鐞嗗熀浜?.pdata 娈?
    // 姣忎釜 RUNTIME_FUNCTION 鏉＄洰鍖呭惈鍑芥暟鐨勮捣濮嬪拰缁撴潫鍦板潃
    // 鍔犲３鍚庨渶瑕佹洿鏂拌繖浜涙潯鐩垨浣跨敤 RtlAddFunctionTable 鍔ㄦ€佹敞鍐?

    return true;
}

bool DLLPacker::RegisterDynamicExceptionTable(
    CS_PE_IMAGE* image,
    void* runtimeFunctions,
    uint32_t count)
{
    if (!image || !runtimeFunctions) return false;

    // 杩欎釜鍑芥暟鍦ㄨ繍琛屾椂琚?stub 璋冪敤
    // 浣跨敤 RtlAddFunctionTable 娉ㄥ唽鍔ㄦ€佸紓甯稿鐞嗚〃

    return true;
}

// ============================================================================
// 鍐呴儴瀹炵幇
// ============================================================================

std::vector<DLLExportEntry> DLLPacker::ParseExports(CS_PE_IMAGE* image) {
    std::vector<DLLExportEntry> result;

    if (!image || !image->isValid) return result;

    for (const auto& func : image->exports.functions) {
        DLLExportEntry entry;
        entry.name = func.name;
        entry.ordinal = func.ordinal;
        entry.rva = func.functionRVA;
        entry.newRva = 0;
        entry.isForwarded = func.isForwarded;
        entry.forwarderName = func.forwarderName;

        if (IsValidExport(entry)) {
            result.push_back(entry);
        }
    }

    return result;
}

bool DLLPacker::RebuildExportTable(CS_PE_IMAGE* image, const std::vector<DLLExportEntry>& exports) {
    // 閲嶅缓瀵煎嚭琛紝鏇存柊鍑芥暟鍦板潃鎸囧悜璺虫澘
    return true;
}

bool DLLPacker::ProcessRelocations(CS_PE_IMAGE* image, uint64_t newBase) {
    if (!image) return false;

    // 閲嶅畾浣嶅鐞嗗浜?DLL 鑷冲叧閲嶈
    // DLL 鍙兘琚姞杞藉埌闈為閫夊熀鍧€

    return true;
}

bool DLLPacker::PreserveTLSCallbacks(CS_PE_IMAGE* image) {
    if (!image || !image->tls.valid) return true;

    // TLS 鍥炶皟闇€瑕佸湪 DLL 鍔犺浇鏃舵纭皟鐢?
    // 淇濈暀 TLS 鐩綍锛岀‘淇濆洖璋冩暟缁勫彲璁块棶

    return true;
}

DWORD DLLPacker::RVAToOffset(CS_PE_IMAGE* image, DWORD rva) {
    return PEUtils::RvaToOffset(image, rva);
}

bool DLLPacker::IsValidExport(const DLLExportEntry& entry) {
    return !entry.name.empty() || entry.ordinal > 0;
}

} // namespace CipherShell

