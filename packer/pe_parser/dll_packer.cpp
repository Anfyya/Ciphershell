/**
 * CipherShell DLL 加壳器 - 实现
 */

#include "dll_packer.h"
#include "pe_utils.h"
#include <cstring>
#include <cstdlib>

namespace CipherShell {

// ============================================================================
// 构造/析构
// ============================================================================

DLLPacker::DLLPacker() {}
DLLPacker::~DLLPacker() {}

// ============================================================================
// 公共接口
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

    // 1. 解析导出表
    if (config.preserveExports) {
        result.exports = ParseExports(image);
        if (result.exports.empty()) {
            result.errorMessage = "No exports found";
            return result;
        }
    }

    // 2. 生成导出跳板
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

    // 3. 处理重定位
    if (config.preserveRelocations) {
        if (!ProcessRelocations(image, 0)) {
            // 重定位处理失败不是致命错误
        }
    }

    // 4. 保留 TLS
    if (config.preserveTLS) {
        PreserveTLSCallbacks(image);
    }

    // 5. 处理异常表（x64）
    if (config.preserveExceptions && image->is64Bit) {
        // x64 异常处理需要 .pdata 段
        // 在加壳后需要重新注册
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

    // 估算跳板大小
    // 每个导出函数需要一个跳板：
    //   jmp [target] 或 push addr; ret
    DWORD perTrampoline = is64Bit ? 16 : 8;
    DWORD totalSize = (DWORD)exports.size() * perTrampoline + 64;

    BYTE* code = new(std::nothrow) BYTE[totalSize];
    if (!code) return nullptr;

    memset(code, 0x90, totalSize);  // NOP 填充

    DWORD offset = 0;

    for (const auto& exp : exports) {
        if (exp.isForwarded) continue;

        if (is64Bit) {
            // x64: 使用 RIP 相对跳转
            // FF 25 xx xx xx xx  jmp [rip+offset]
            code[offset++] = 0xFF;
            code[offset++] = 0x25;
            // RIP 相对偏移（指向后面的地址）
            *(uint32_t*)(code + offset) = 0;
            offset += 4;
            // 绝对地址
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

    // DllMain 签名：BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)

    if (is64Bit) {
        // x64 DllMain stub
        // rcx = hinstDLL, rdx = fdwReason, r8 = lpvReserved
        static const BYTE x64_stub[] = {
            // 保存参数
            0x48, 0x89, 0xC8,                   // mov rax, rcx (hinstDLL)
            0x48, 0x89, 0xD3,                   // mov rbx, rdx (fdwReason)
            0x49, 0x89, 0xC1,                   // mov r9, r8   (lpvReserved)

            // 检查 fdwReason
            0x48, 0x83, 0xFB, 0x00,             // cmp rbx, 0 (DLL_PROCESS_DETACH)
            0x74, 0x14,                         // jz .detach
            0x48, 0x83, 0xFB, 0x01,             // cmp rbx, 1 (DLL_PROCESS_ATTACH)
            0x74, 0x0A,                         // jz .attach
            0x48, 0x83, 0xFB, 0x02,             // cmp rbx, 2 (DLL_THREAD_ATTACH)
            0x74, 0x10,                         // jz .thread_attach
            0xEB, 0x18,                         // jmp .done

            // .attach: 初始化 VM，解密代码
            0xE8, 0x00, 0x00, 0x00, 0x00,       // call vm_init (相对偏移)
            0xEB, 0x10,                         // jmp .done

            // .detach: 清理
            0xE8, 0x00, 0x00, 0x00, 0x00,       // call vm_cleanup
            0xEB, 0x08,                         // jmp .done

            // .thread_attach:
            0x90,                               // nop
            0xEB, 0x04,                         // jmp .done

            // .done: 调用原始 DllMain
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

    // x64 的异常处理基于 .pdata 段
    // 每个 RUNTIME_FUNCTION 条目包含函数的起始和结束地址
    // 加壳后需要更新这些条目或使用 RtlAddFunctionTable 动态注册

    return true;
}

bool DLLPacker::RegisterDynamicExceptionTable(
    CS_PE_IMAGE* image,
    void* runtimeFunctions,
    uint32_t count)
{
    if (!image || !runtimeFunctions) return false;

    // 这个函数在运行时被 stub 调用
    // 使用 RtlAddFunctionTable 注册动态异常处理表

    return true;
}

// ============================================================================
// 内部实现
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
    // 重建导出表，更新函数地址指向跳板
    return true;
}

bool DLLPacker::ProcessRelocations(CS_PE_IMAGE* image, uint64_t newBase) {
    if (!image) return false;

    // 重定位处理对于 DLL 至关重要
    // DLL 可能被加载到非首选基址

    return true;
}

bool DLLPacker::PreserveTLSCallbacks(CS_PE_IMAGE* image) {
    if (!image || !image->tls.valid) return true;

    // TLS 回调需要在 DLL 加载时正确调用
    // 保留 TLS 目录，确保回调数组可访问

    return true;
}

DWORD DLLPacker::RVAToOffset(CS_PE_IMAGE* image, DWORD rva) {
    return PEUtils::RvaToOffset(image, rva);
}

bool DLLPacker::IsValidExport(const DLLExportEntry& entry) {
    return !entry.name.empty() || entry.ordinal > 0;
}

} // namespace CipherShell

