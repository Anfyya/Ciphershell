#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstring>

#include "vm_abi_unwind_gate.h"
#include "vm_runtime_trace_reader.h"

static int g_relocated_value = 0x13579BDF;

using BinaryFn = int (__cdecl*)(int, int);
using SubFn = VmProtectedSubFunction;

#if defined(_M_IX86)
#pragma comment(linker, "/EXPORT:sub2=_sub2@8")
#define VM_SUB2_EXPORT
#define VM_SUB2_ABI __stdcall
#else
#define VM_SUB2_EXPORT __declspec(dllexport)
#define VM_SUB2_ABI
#endif

extern "C" VM_SUB2_EXPORT int VM_SUB2_ABI sub2(int left, int right);
extern "C" uintptr_t __cdecl CaptureBinaryFunctionFlags(
    SubFn function, int left, int right, int* returnedValue);

constexpr uintptr_t kArithmeticFlagsMask = 0x8D5u;

static bool CheckReturnedFlags() {
    constexpr int left[] = {
        0x12345678,
        0x12345677,
        static_cast<int>(0x92345677u),
    };
    constexpr int right[] = {
        0x12345678,
        0x12345678,
        0x12345678,
    };
    constexpr uintptr_t expected[] = {
        0x044u,
        0x095u,
        0x814u,
    };
    uintptr_t observed[3]{};
    for (size_t index = 0; index < 3; ++index) {
        int returnedValue = 0;
        observed[index] = CaptureBinaryFunctionFlags(
            sub2, left[index], right[index], &returnedValue) &
            kArithmeticFlagsMask;
        if (returnedValue != left[index] - right[index] ||
            observed[index] != expected[index]) {
            std::fprintf(stderr,
                "returned flags mismatch: case=%zu value=0x%08x "
                "actual=0x%llx expected=0x%llx\n",
                index, static_cast<unsigned>(returnedValue),
                static_cast<unsigned long long>(observed[index]),
                static_cast<unsigned long long>(expected[index]));
            return false;
        }
    }
    std::printf("VM_RETURN_FLAGS mask=0x%llx values=0x%llx,0x%llx,0x%llx\n",
        static_cast<unsigned long long>(kArithmeticFlagsMask),
        static_cast<unsigned long long>(observed[0]),
        static_cast<unsigned long long>(observed[1]),
        static_cast<unsigned long long>(observed[2]));
    return true;
}

constexpr uint64_t kDefinedStatusFlags =
    0x0001u | 0x0004u | 0x0010u | 0x0040u | 0x0080u | 0x0800u;
constexpr uint64_t kSubZeroMinusOneFlags =
    0x0001u | 0x0004u | 0x0010u | 0x0080u;

extern "C" __declspec(dllexport) __declspec(noinline) int add(int a, int b) {
    return a + b;
}

extern "C" VM_SUB2_EXPORT __declspec(noinline) int VM_SUB2_ABI sub2(
    int a, int b) {
    return a - b;
}

extern "C" __declspec(dllexport) __declspec(noinline) int max2(int a, int b) {
    return a > b ? a : b;
}

extern "C" __declspec(dllexport) __declspec(noinline) int is_zero(int a) {
    return a == 0 ? 1 : 0;
}

extern "C" __declspec(dllexport) __declspec(noinline) int local1(int a) {
    return a + 3;
}

extern "C" __declspec(dllexport) __declspec(noinline) int* relocated_ptr() {
    return &g_relocated_value;
}

extern "C" __declspec(dllexport) __declspec(noinline) int relocated_read() {
    return g_relocated_value;
}

extern "C" __declspec(dllexport) __declspec(noinline) int relocated_write(int value) {
    const int previous = g_relocated_value;
    g_relocated_value = value;
    return previous;
}

static bool ReadOnDiskPreferredRange(
    uintptr_t& preferredBase,
    size_t& imageSize)
{
    preferredBase = 0;
    imageSize = 0;
    wchar_t path[MAX_PATH]{};
    if (GetModuleFileNameW(nullptr, path, MAX_PATH) == 0) return false;
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    unsigned char headers[4096]{};
    DWORD read = 0;
    const BOOL ok = ReadFile(file, headers, sizeof(headers), &read, nullptr);
    CloseHandle(file);
    if (!ok || read < sizeof(IMAGE_DOS_HEADER)) return false;
    IMAGE_DOS_HEADER dos{};
    std::memcpy(&dos, headers, sizeof(dos));
    if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0) return false;
    const size_t ntOffset = static_cast<size_t>(dos.e_lfanew);
    if (ntOffset > read || sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
            sizeof(WORD) > read - ntOffset) return false;
    DWORD signature = 0;
    std::memcpy(&signature, headers + ntOffset, sizeof(signature));
    if (signature != IMAGE_NT_SIGNATURE) return false;
    const size_t optionalOffset = ntOffset + sizeof(DWORD) +
        sizeof(IMAGE_FILE_HEADER);
    WORD magic = 0;
    std::memcpy(&magic, headers + optionalOffset, sizeof(magic));
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        if (sizeof(IMAGE_OPTIONAL_HEADER64) > read - optionalOffset) return false;
        IMAGE_OPTIONAL_HEADER64 optional{};
        std::memcpy(&optional, headers + optionalOffset, sizeof(optional));
        preferredBase = static_cast<uintptr_t>(optional.ImageBase);
        imageSize = optional.SizeOfImage;
    } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        if (sizeof(IMAGE_OPTIONAL_HEADER32) > read - optionalOffset) return false;
        IMAGE_OPTIONAL_HEADER32 optional{};
        std::memcpy(&optional, headers + optionalOffset, sizeof(optional));
        preferredBase = static_cast<uintptr_t>(optional.ImageBase);
        imageSize = optional.SizeOfImage;
    }
    return preferredBase != 0 && imageSize != 0;
}

int main(int argc, char** argv) {
    const bool expectTrace = argc == 2 &&
        std::strcmp(argv[1], "--expect-trace") == 0;
    if (argc != 1 && !expectTrace) return 1;
    HMODULE module = GetModuleHandleW(nullptr);
    uintptr_t preferredBase = 0;
    size_t imageSize = 0;
    if (!module || !ReadOnDiskPreferredRange(preferredBase, imageSize)) return 2;
    if (reinterpret_cast<uintptr_t>(module) == preferredBase) {
        std::fprintf(stderr,
            "packed EXE did not execute at a relocated base "
            "(actual=0x%llx preferred=0x%llx)\n",
            static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(module)),
            static_cast<unsigned long long>(preferredBase));
        return 3;
    }
    int capturedSubResult = 0;
    const uint64_t capturedSubFlags = CaptureBinaryFunctionFlags(
        &sub2, 0, 1, &capturedSubResult);
    const bool flagsOk = capturedSubResult == -1 &&
        (capturedSubFlags & kDefinedStatusFlags) == kSubZeroMinusOneFlags;
    int* relocated = relocated_ptr();
    MEMORY_BASIC_INFORMATION memory{};
    const int addResult = add(7, 5);
    const int subResult = sub2(7, 5);
    const int maxAbResult = max2(7, 5);
    const int maxBaResult = max2(-3, 9);
    const int zeroTrueResult = is_zero(0);
    const int zeroFalseResult = is_zero(8);
    const int localResult = local1(11);
    const bool returnedFlagsOk = CheckReturnedFlags();
    const bool scalarOk = addResult == 12 && subResult == 2 &&
        maxAbResult == 7 && maxBaResult == 9 &&
        zeroTrueResult == 1 && zeroFalseResult == 0 && localResult == 14 &&
        returnedFlagsOk;
    const bool abiOk = VerifyVmProtectedAbi(
        &sub2, expectTrace, 0x12345678, 0x10203040);
    const bool platformAbiOk = VerifyVmPackedUnwindOrStdcall(
        &sub2, expectTrace);
    const bool pointerOwned = relocated &&
        VirtualQuery(relocated, &memory, sizeof(memory)) == sizeof(memory) &&
        memory.AllocationBase == module;
    const int pointerInitial = relocated ? *relocated : 0;
    const int readInitial = relocated_read();
    const int writeOld1 = relocated_write(0x2468ACE0);
    const int pointerAfterWrite = relocated ? *relocated : 0;
    const int readAfterWrite = relocated_read();
    const int writeOld2 = relocated_write(0x13579BDF);
    const int pointerFinal = relocated ? *relocated : 0;
    const int readFinal = relocated_read();
    const bool relocationOk = pointerOwned &&
        pointerInitial == 0x13579BDF && readInitial == 0x13579BDF &&
        writeOld1 == 0x13579BDF && pointerAfterWrite == 0x2468ACE0 &&
        readAfterWrite == 0x2468ACE0 && writeOld2 == 0x2468ACE0 &&
        pointerFinal == 0x13579BDF && readFinal == 0x13579BDF;
    std::printf(
        "VM_RUNTIME_RESULT add=%d sub=%d max_ab=%d max_ba=%d "
        "zero_true=%d zero_false=%d local=%d ptr_owned=%d "
        "ptr_initial=%d read_initial=%d write_old1=%d ptr_after_write=%d "
        "read_after_write=%d write_old2=%d ptr_final=%d read_final=%d "
        "flags_sub=%d\n",
        addResult, subResult, maxAbResult, maxBaResult, zeroTrueResult,
        zeroFalseResult, localResult, pointerOwned ? 1 : 0, pointerInitial,
        readInitial, writeOld1, pointerAfterWrite, readAfterWrite, writeOld2,
        pointerFinal, readFinal, capturedSubResult);
    const bool traceOk = EmitVmRuntimeTrace(module, expectTrace);
    if (!scalarOk || !relocationOk || !flagsOk || !abiOk ||
        !platformAbiOk || !traceOk) {
        std::fprintf(stderr,
            "packed EXE VM result mismatch "
            "flags=0x%llx expected=0x%llx mask=0x%llx\n",
            static_cast<unsigned long long>(capturedSubFlags),
            static_cast<unsigned long long>(kSubZeroMinusOneFlags),
            static_cast<unsigned long long>(kDefinedStatusFlags));
        return 4;
    }
    std::puts("VM_PACKED_EXE_RUNTIME_PASS");
    return 0;
}
