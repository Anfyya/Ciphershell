#include <windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

#include "vm_abi_unwind_gate.h"
#include "vm_runtime_trace_reader.h"

using BinaryFn = int (__cdecl*)(int, int);
using SubFn = VmProtectedSubFunction;
using UnaryFn = int (__cdecl*)(int);
using NullaryFn = int (__cdecl*)();
using PointerFn = int* (__cdecl*)();

extern "C" uintptr_t __cdecl CaptureBinaryFunctionFlags(
    SubFn function, int left, int right, int* returnedValue);

constexpr uintptr_t kArithmeticFlagsMask = 0x8D5u;
constexpr std::array<int, 3> kFlagsLeft = {
    0x12345678,
    0x12345677,
    static_cast<int>(0x92345677u),
};
constexpr std::array<int, 3> kFlagsRight = {
    0x12345678,
    0x12345678,
    0x12345678,
};
constexpr std::array<uintptr_t, 3> kExpectedFlags = {
    0x044u, // equal: ZF + PF
    0x095u, // borrow to -1: CF + PF + AF + SF
    0x814u, // signed overflow to INT_MAX: OF + PF + AF
};

bool CheckReturnedFlags(SubFn function) {
    if (!function) return false;
    std::array<uintptr_t, kFlagsLeft.size()> observed{};
    for (size_t index = 0; index < kFlagsLeft.size(); ++index) {
        int returnedValue = 0;
        observed[index] = CaptureBinaryFunctionFlags(
            function, kFlagsLeft[index], kFlagsRight[index], &returnedValue) &
            kArithmeticFlagsMask;
        if (returnedValue != kFlagsLeft[index] - kFlagsRight[index] ||
            observed[index] != kExpectedFlags[index]) {
            std::fprintf(stderr,
                "returned flags mismatch: case=%zu value=0x%08x "
                "actual=0x%llx expected=0x%llx\n",
                index, static_cast<unsigned>(returnedValue),
                static_cast<unsigned long long>(observed[index]),
                static_cast<unsigned long long>(kExpectedFlags[index]));
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

bool ReadPreferredImageRange(
    const char* path,
    uintptr_t& preferredBase,
    size_t& imageSize)
{
    preferredBase = 0;
    imageSize = 0;
    HANDLE file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    unsigned char headers[4096]{};
    DWORD read = 0;
    const BOOL ok = ReadFile(file, headers, sizeof(headers), &read, nullptr);
    CloseHandle(file);
    if (!ok || read < sizeof(IMAGE_DOS_HEADER)) return false;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(headers);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0 ||
        static_cast<size_t>(dos->e_lfanew) + sizeof(DWORD) +
            sizeof(IMAGE_FILE_HEADER) + sizeof(WORD) > read) return false;
    const unsigned char* nt = headers + dos->e_lfanew;
    DWORD signature = 0;
    std::memcpy(&signature, nt, sizeof(signature));
    if (signature != IMAGE_NT_SIGNATURE) return false;
    const auto* fileHeader = reinterpret_cast<const IMAGE_FILE_HEADER*>(
        nt + sizeof(DWORD));
    const unsigned char* optional = reinterpret_cast<const unsigned char*>(
        fileHeader + 1);
    const size_t optionalOffset = static_cast<size_t>(
        optional - headers);
    WORD magic = 0;
    std::memcpy(&magic, optional, sizeof(magic));
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
        fileHeader->SizeOfOptionalHeader >= sizeof(IMAGE_OPTIONAL_HEADER64) &&
        optionalOffset <= read &&
        sizeof(IMAGE_OPTIONAL_HEADER64) <= read - optionalOffset) {
        const auto* value = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(optional);
        preferredBase = static_cast<uintptr_t>(value->ImageBase);
        imageSize = value->SizeOfImage;
    } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
               fileHeader->SizeOfOptionalHeader >= sizeof(IMAGE_OPTIONAL_HEADER32) &&
               optionalOffset <= read &&
               sizeof(IMAGE_OPTIONAL_HEADER32) <= read - optionalOffset) {
        const auto* value = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(optional);
        preferredBase = static_cast<uintptr_t>(value->ImageBase);
        imageSize = value->SizeOfImage;
    }
    return preferredBase != 0 && imageSize != 0;
}

int RunExeWithForcedRelocation(const char* path, bool expectTrace) {
    SIZE_T attributeBytes = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attributeBytes);
    if (attributeBytes == 0) {
        std::fprintf(stderr, "could not size process attribute list: %lu\n",
            GetLastError());
        return 3;
    }
    auto* attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attributeBytes));
    if (!attributes ||
        !InitializeProcThreadAttributeList(attributes, 1, 0, &attributeBytes)) {
        std::fprintf(stderr, "could not initialize process attribute list: %lu\n",
            GetLastError());
        if (attributes) HeapFree(GetProcessHeap(), 0, attributes);
        return 3;
    }
    DWORD64 mitigationPolicy =
        PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_ALWAYS_ON_REQ_RELOCS;
    if (!UpdateProcThreadAttribute(attributes, 0,
            PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &mitigationPolicy,
            sizeof(mitigationPolicy), nullptr, nullptr)) {
        std::fprintf(stderr, "could not set force-relocate policy: %lu\n",
            GetLastError());
        DeleteProcThreadAttributeList(attributes);
        HeapFree(GetProcessHeap(), 0, attributes);
        return 3;
    }

    STARTUPINFOEXA startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.lpAttributeList = attributes;
    std::string commandLine = "\"";
    commandLine += path;
    commandLine += "\"";
    if (expectTrace) commandLine += " --expect-trace";
    PROCESS_INFORMATION process{};
    const BOOL created = CreateProcessA(path, commandLine.data(), nullptr, nullptr,
        TRUE, EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr,
        &startup.StartupInfo, &process);
    const DWORD createError = created ? ERROR_SUCCESS : GetLastError();
    DeleteProcThreadAttributeList(attributes);
    HeapFree(GetProcessHeap(), 0, attributes);
    if (!created) {
        std::fprintf(stderr,
            "CreateProcess with force-relocate policy failed: %lu\n", createError);
        return 3;
    }

    const DWORD wait = WaitForSingleObject(process.hProcess, 60000);
    DWORD exitCode = 3;
    if (wait == WAIT_OBJECT_0) {
        if (!GetExitCodeProcess(process.hProcess, &exitCode)) exitCode = 3;
    } else {
        std::fprintf(stderr, "forced-relocation EXE timed out or wait failed: %lu\n",
            wait == WAIT_FAILED ? GetLastError() : ERROR_TIMEOUT);
        TerminateProcess(process.hProcess, 3);
        WaitForSingleObject(process.hProcess, 5000);
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    if (exitCode == 0) std::puts("VM_FORCE_RELOCATE_POLICY_APPLIED");
    return static_cast<int>(exitCode);
}

int main(int argc, char** argv) {
    if (argc == 3 && (std::strcmp(argv[1], "--exe") == 0 ||
                      std::strcmp(argv[1], "--exe-trace") == 0)) {
        return RunExeWithForcedRelocation(
            argv[2], std::strcmp(argv[1], "--exe-trace") == 0);
    }
    bool expectTrace = false;
    const char* dllPath = nullptr;
    if (argc == 2) {
        dllPath = argv[1];
    } else if (argc == 3 && std::strcmp(argv[1], "--expect-trace") == 0) {
        expectTrace = true;
        dllPath = argv[2];
    } else {
        std::fprintf(stderr,
            "usage: vm_similarity_gate_runner [--expect-trace] <dll> | "
            "--exe|--exe-trace <exe>\n");
        return 2;
    }
    uintptr_t preferredBase = 0;
    size_t imageSize = 0;
    if (!ReadPreferredImageRange(dllPath, preferredBase, imageSize)) {
        std::fprintf(stderr, "could not read protected PE preferred image range\n");
        return 3;
    }
    void* reservation = VirtualAlloc(reinterpret_cast<void*>(preferredBase),
        imageSize, MEM_RESERVE, PAGE_NOACCESS);
    if (!reservation) {
        MEMORY_BASIC_INFORMATION preferredMemory{};
        if (VirtualQuery(reinterpret_cast<void*>(preferredBase), &preferredMemory,
                sizeof(preferredMemory)) != sizeof(preferredMemory) ||
            preferredMemory.State == MEM_FREE) {
            std::fprintf(stderr, "could not occupy protected PE preferred base\n");
            return 3;
        }
    }
    HMODULE module = LoadLibraryA(dllPath);
    if (!module) {
        std::fprintf(stderr, "LoadLibrary failed: %lu\n", GetLastError());
        if (reservation) VirtualFree(reservation, 0, MEM_RELEASE);
        return 3;
    }
    if (reservation) VirtualFree(reservation, 0, MEM_RELEASE);
    if (reinterpret_cast<uintptr_t>(module) == preferredBase) {
        std::fprintf(stderr, "protected DLL did not execute at a relocated base\n");
        FreeLibrary(module);
        return 3;
    }
    auto add = reinterpret_cast<BinaryFn>(GetProcAddress(module, "add"));
    auto sub2 = reinterpret_cast<SubFn>(GetProcAddress(module, "sub2"));
    auto max2 = reinterpret_cast<BinaryFn>(GetProcAddress(module, "max2"));
    auto isZero = reinterpret_cast<UnaryFn>(GetProcAddress(module, "is_zero"));
    auto local1 = reinterpret_cast<UnaryFn>(GetProcAddress(module, "local1"));
    auto relocatedPtr = reinterpret_cast<PointerFn>(
        GetProcAddress(module, "relocated_ptr"));
    auto relocatedRead = reinterpret_cast<NullaryFn>(
        GetProcAddress(module, "relocated_read"));
    auto relocatedWrite = reinterpret_cast<UnaryFn>(
        GetProcAddress(module, "relocated_write"));
    if (!add || !sub2 || !max2 || !isZero || !local1 ||
        !relocatedPtr || !relocatedRead || !relocatedWrite) {
        std::fprintf(stderr, "GetProcAddress failed: %lu\n", GetLastError());
        FreeLibrary(module);
        return 4;
    }

    int capturedSubResult = 0;
    const uint64_t capturedSubFlags = CaptureBinaryFunctionFlags(
        sub2, 0, 1, &capturedSubResult);
    const bool flagsOk = capturedSubResult == -1 &&
        (capturedSubFlags & kDefinedStatusFlags) == kSubZeroMinusOneFlags;
    const int addResult = add(7, 5);
    const int subResult = sub2(7, 5);
    const int maxAbResult = max2(7, 5);
    const int maxBaResult = max2(-3, 9);
    const int zeroTrueResult = isZero(0);
    const int zeroFalseResult = isZero(8);
    const int localResult = local1(11);
    const bool returnedFlagsOk = CheckReturnedFlags(sub2);
    const bool scalarOk = addResult == 12 && subResult == 2 &&
        maxAbResult == 7 && maxBaResult == 9 &&
        zeroTrueResult == 1 && zeroFalseResult == 0 && localResult == 14 &&
        returnedFlagsOk;
    const bool abiOk = VerifyVmProtectedAbi(
        sub2, expectTrace, 0x12345678, 0x10203040);
    const bool platformAbiOk = VerifyVmPackedUnwindOrStdcall(
        sub2, expectTrace);
    int* relocated = relocatedPtr();
    MEMORY_BASIC_INFORMATION relocatedMemory{};
    const bool pointerOwned = relocated &&
        VirtualQuery(relocated, &relocatedMemory, sizeof(relocatedMemory)) ==
            sizeof(relocatedMemory) && relocatedMemory.AllocationBase == module;
    const int pointerInitial = relocated ? *relocated : 0;
    const int readInitial = relocatedRead();
    const int writeOld1 = relocatedWrite(0x2468ACE0);
    const int pointerAfterWrite = relocated ? *relocated : 0;
    const int readAfterWrite = relocatedRead();
    const int writeOld2 = relocatedWrite(0x13579BDF);
    const int pointerFinal = relocated ? *relocated : 0;
    const int readFinal = relocatedRead();
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
    FreeLibrary(module);
    if (!scalarOk || !relocationOk || !flagsOk || !abiOk ||
        !platformAbiOk || !traceOk) {
        std::fprintf(stderr,
            "protected VM export result mismatch "
            "flags=0x%llx expected=0x%llx mask=0x%llx\n",
            static_cast<unsigned long long>(capturedSubFlags),
            static_cast<unsigned long long>(kSubZeroMinusOneFlags),
            static_cast<unsigned long long>(kDefinedStatusFlags));
        return 5;
    }
    std::puts("VM_PACKED_RUNTIME_PASS");
    return 0;
}
