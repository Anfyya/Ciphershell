/*
 * CipherShell native differential worker.
 *
 * Isolated, disposable process spawned once per corpus case by the packer's
 * VMNativeDifferentialEvidenceProvider.  It never touches the packer's own
 * state: it reads one request file, runs the target function's original
 * native bytes and this build's synthesized handler chain each in this
 * process's own address space, and writes one response file, then exits.
 * A hang here is the packer's problem to kill via a wait timeout, not this
 * process's; a crash here only takes down this disposable worker.
 *
 * usage: vm_native_differential_worker <request-file> <response-file>
 */

#include "vm_native_differential_protocol.h"
#include "vm_native_differential_worker_harness.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

using namespace CipherShell;

namespace {

bool ReadWholeFile(const char* path, std::vector<uint8_t>& bytes) {
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream) return false;
    const std::streamoff size = stream.tellg();
    if (size < 0) return false;
    bytes.resize(static_cast<size_t>(size));
    stream.seekg(0);
    if (!bytes.empty() && !stream.read(reinterpret_cast<char*>(bytes.data()), size)) {
        return false;
    }
    return true;
}

bool WriteWholeFile(const char* path, const void* data, size_t size) {
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    if (!stream) return false;
    if (size != 0 && !stream.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size))) {
        return false;
    }
    return stream.good();
}

bool RangeInside(size_t total, uint64_t offset, uint64_t size) {
    return offset <= total && size <= total - offset;
}

} // namespace

int main(int argc, char** argv) {
    if (std::getenv("CS_NATIVE_DIFFERENTIAL_DEBUG")) {
        std::fprintf(stderr, "[worker-debug] main: start argc=%d\n", argc);
        std::fflush(stderr);
    }
    if (argc != 3) {
        std::fprintf(stderr, "usage: vm_native_differential_worker <request-file> <response-file>\n");
        return 2;
    }

    std::vector<uint8_t> request;
    if (!ReadWholeFile(argv[1], request) || request.size() < sizeof(VMNativeDifferentialRequestHeader)) {
        std::fprintf(stderr, "vm_native_differential_worker: cannot read request file\n");
        return 3;
    }
    VMNativeDifferentialRequestHeader header{};
    std::memcpy(&header, request.data(), sizeof(header));
    if (header.magic != VM_NATIVE_DIFFERENTIAL_REQUEST_MAGIC ||
        header.version != VM_NATIVE_DIFFERENTIAL_PROTOCOL_VERSION ||
        header.totalFileSize != request.size()) {
        std::fprintf(stderr, "vm_native_differential_worker: malformed request header\n");
        return 4;
    }
    if (!RangeInside(request.size(), header.nativeCodeOffset, header.nativeCodeSize) ||
        !RangeInside(request.size(), header.nativeCodeFixupsOffset,
            static_cast<uint64_t>(header.nativeCodeFixupsCount) *
                sizeof(VMNativeDifferentialCodeFixup)) ||
        !RangeInside(request.size(), header.corpusMemoryOffset, header.memorySize) ||
        !RangeInside(request.size(), header.vmBytecodeOffset, header.vmBytecodeSize) ||
        !RangeInside(request.size(), header.handlerImageOffset, header.handlerImageSize) ||
        !RangeInside(request.size(), header.handlerRelocationsOffset,
            static_cast<uint64_t>(header.handlerRelocationsCount) * sizeof(VMNativeDifferentialRelocation)) ||
        !RangeInside(request.size(), header.handlerUnwindOffset,
            static_cast<uint64_t>(header.handlerUnwindCount) * sizeof(VMNativeDifferentialUnwindEntry))) {
        std::fprintf(stderr, "vm_native_differential_worker: request blob region out of range\n");
        return 5;
    }

    const uint8_t* nativeCode = request.data() + header.nativeCodeOffset;
    const auto* nativeCodeFixups = reinterpret_cast<const VMNativeDifferentialCodeFixup*>(
        request.data() + header.nativeCodeFixupsOffset);
    const uint8_t* corpusMemory = request.data() + header.corpusMemoryOffset;
    const uint8_t* vmBytecode = request.data() + header.vmBytecodeOffset;
    const uint8_t* handlerImage = request.data() + header.handlerImageOffset;
    const auto* handlerRelocations = reinterpret_cast<const VMNativeDifferentialRelocation*>(
        request.data() + header.handlerRelocationsOffset);
    const auto* handlerUnwindEntries = reinterpret_cast<const VMNativeDifferentialUnwindEntry*>(
        request.data() + header.handlerUnwindOffset);

    VMNativeDifferentialWorkerOutcome outcome{};
    std::string error;
    if (!RunNativeDifferentialWorkerCase(header, nativeCode, nativeCodeFixups,
            corpusMemory, vmBytecode,
            handlerImage, handlerRelocations, handlerUnwindEntries, outcome, error)) {
        std::fprintf(stderr, "vm_native_differential_worker: %s\n", error.c_str());
        return 6;
    }

    VMNativeDifferentialResponseBody response{};
    response.nativeExecuted = outcome.nativeExecuted ? 1 : 0;
    response.nativeFaulted = outcome.nativeFaulted ? 1 : 0;
    response.vmExecuted = outcome.vmExecuted ? 1 : 0;
    response.vmFaulted = outcome.vmFaulted ? 1 : 0;
    response.nativeExceptionCode = outcome.nativeExceptionCode;
    response.vmExceptionCode = outcome.vmExceptionCode;
    response.nativeFaultOffset = outcome.nativeFaultOffset;
    response.vmFaultOffset = outcome.vmFaultOffset;
    response.vmCurrentSemantic = outcome.vmCurrentSemantic;
    response.vmCurrentVariant = outcome.vmCurrentVariant;
    response.vmVipOffset = outcome.vmVipOffset;
    response.vmRuntimeError = outcome.vmRuntimeError;
    response.nativeFinalGpr = outcome.nativeFinalGpr;
    response.nativeFinalRflags = outcome.nativeFinalRflags;
    response.vmFinalGpr = outcome.vmFinalGpr;
    response.vmFinalRflags = outcome.vmFinalRflags;
    response.nativeFaultGpr = outcome.nativeFaultGpr;
    response.nativeFaultRflags = outcome.nativeFaultRflags;
    response.vmFaultGpr = outcome.vmFaultGpr;
    response.vmFaultRflags = outcome.vmFaultRflags;
    response.memorySize = header.memorySize;

    std::vector<uint8_t> out;
    out.resize(sizeof(response) + outcome.nativeFinalMemory.size() + outcome.vmFinalMemory.size());
    std::memcpy(out.data(), &response, sizeof(response));
    if (!outcome.nativeFinalMemory.empty()) {
        std::memcpy(out.data() + sizeof(response), outcome.nativeFinalMemory.data(),
            outcome.nativeFinalMemory.size());
    }
    if (!outcome.vmFinalMemory.empty()) {
        std::memcpy(out.data() + sizeof(response) + outcome.nativeFinalMemory.size(),
            outcome.vmFinalMemory.data(), outcome.vmFinalMemory.size());
    }
    if (!WriteWholeFile(argv[2], out.data(), out.size())) {
        std::fprintf(stderr, "vm_native_differential_worker: cannot write response file\n");
        return 7;
    }
    return 0;
}
