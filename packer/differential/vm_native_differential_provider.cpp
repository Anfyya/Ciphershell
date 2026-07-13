#include "vm_native_differential_provider.h"
#include "vm_native_differential_protocol.h"

#include "../vm/vm_schema.h"
#include "../../runtime/common/vm_micro_runtime_abi.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#ifdef _WIN32
#include <Windows.h>
#endif

namespace CipherShell {

namespace {

uint64_t MixIdentityBytes(uint64_t state, const void* data, size_t size) {
    const uint8_t* bytes = static_cast<const uint8_t*>(data);
    for (size_t index = 0; index < size; ++index) {
        state ^= static_cast<uint64_t>(bytes[index]);
        state *= 0x100000001B3ULL;
        state = (state << 13) | (state >> 51);
    }
    return state;
}

template <typename T>
uint64_t MixIdentityValue(uint64_t state, const T& value) {
    return MixIdentityBytes(state, &value, sizeof(value));
}

uint64_t ComputeSemanticDigest(
    VMHandlerArchitecture architecture,
    const std::array<uint8_t, 32>& buildSeed,
    const std::array<uint8_t, VM_HANDLER_TABLE_SIZE>& handlerSemanticToSlot,
    const std::array<uint8_t, VM_HANDLER_TABLE_SIZE>& handlerSlotToSemantic,
    const std::array<uint8_t, VM_HANDLER_TABLE_SIZE>& handlerVariants,
    const VMHandlerOperandCodecConfig& operandCodec,
    uint32_t variantCount)
{
    uint64_t digest = 0x4E41544956454431ULL;
    digest = MixIdentityValue(digest, architecture);
    digest = MixIdentityBytes(digest, buildSeed.data(), buildSeed.size());
    digest = MixIdentityBytes(digest, handlerSemanticToSlot.data(), handlerSemanticToSlot.size());
    digest = MixIdentityBytes(digest, handlerSlotToSemantic.data(), handlerSlotToSemantic.size());
    digest = MixIdentityBytes(digest, handlerVariants.data(), handlerVariants.size());
    digest = MixIdentityValue(digest, operandCodec.opcodeXor);
    digest = MixIdentityValue(digest, operandCodec.opcodeAdd);
    digest = MixIdentityValue(digest, operandCodec.opcodeRotate);
    digest = MixIdentityValue(digest, variantCount);
    return digest == 0 ? 1u : digest;
}

bool BuildContiguousNativeCode(
    const Function& function,
    std::vector<uint8_t>& code,
    std::string& error)
{
    std::vector<const InstructionIR*> ordered;
    for (const auto& block : function.blocks) {
        for (const auto& instruction : block.instructions) ordered.push_back(&instruction);
    }
    if (ordered.empty()) {
        error = "native differential function has no instructions";
        return false;
    }
    std::sort(ordered.begin(), ordered.end(),
        [](const InstructionIR* left, const InstructionIR* right) {
            return left->address < right->address;
        });
    if (ordered.front()->address != function.entryAddress) {
        error = "native differential function's first instruction is not at the entry address";
        return false;
    }
    code.clear();
    code.reserve(function.size);
    uint64_t expected = function.entryAddress;
    for (const auto* instruction : ordered) {
        if (instruction->address != expected) {
            error = "native differential function instructions are not contiguous; a "
                "standalone-callable byte range cannot be reconstructed";
            return false;
        }
        if (instruction->length == 0 || instruction->length > instruction->rawBytes.size()) {
            error = "native differential function instruction has incomplete raw bytes";
            return false;
        }
        code.insert(code.end(), instruction->rawBytes.begin(),
            instruction->rawBytes.begin() + instruction->length);
        expected += instruction->length;
    }
    if (code.size() != function.size) {
        error = "native differential reconstructed code size does not match the function size";
        return false;
    }
    return true;
}

// Appends a differential-only VM_UOP_FLAGS_MATERIALIZE before the terminal
// RET/EXIT so the synthesized handler chain's virtualFlags is fully
// up to date at the comparison point, exactly like a real CPU's RFLAGS
// always is.  Production bytecode never carries this instruction: nothing
// downstream of a returned function is entitled to see pending-but-never-
// consumed flags, so paying for eager materialization there would be pure
// overhead.  Any branch that targeted the original RET is retargeted to the
// inserted instruction so it still falls through into the same RET.
bool BuildDifferentialBytecode(
    const TranslationResult& translation,
    const std::unordered_map<uint8_t, uint8_t>& opcodeMap,
    std::vector<uint8_t>& bytecode,
    std::string& error)
{
    if (translation.instructions.empty() ||
        translation.microOffsets.size() != translation.instructions.size()) {
        error = "native differential translation instruction/offset bookkeeping is incomplete";
        return false;
    }
    const MicroInstruction lastInstruction = translation.instructions.back();
    if (lastInstruction.opcode != VM_UOP_RET && lastInstruction.opcode != VM_UOP_EXIT) {
        error = "native differential translated program does not end with RET/EXIT";
        return false;
    }
    const uint32_t tailOffset = translation.microOffsets.back();

    MicroInstruction materialize{};
    materialize.opcode = VM_UOP_FLAGS_MATERIALIZE;
    materialize.operandCount = 1;
    materialize.operands[0] = VM_FLAG_ARCHITECTURAL_MASK;
    uint32_t materializeSize = 0;
    if (!VMSchema::EncodedSize(materialize, translation.operandCodec, materializeSize, error)) {
        return false;
    }

    std::vector<MicroInstruction> augmented(
        translation.instructions.begin(), translation.instructions.end() - 1);
    for (auto& instruction : augmented) {
        const auto* descriptor = VMSchema::Lookup(instruction.opcode);
        if (!descriptor || !descriptor->branch || descriptor->branchTargetOperand < 0) continue;
        const auto operandIndex = static_cast<uint8_t>(descriptor->branchTargetOperand);
        if (instruction.operands[operandIndex] == tailOffset) {
            instruction.operands[operandIndex] += materializeSize;
        }
    }
    augmented.push_back(materialize);
    augmented.push_back(lastInstruction);

    bytecode.clear();
    for (const auto& instruction : augmented) {
        std::string encodeError;
        if (!VMSchema::Encode(instruction, opcodeMap, translation.operandCodec, bytecode, encodeError)) {
            error = "native differential could not encode augmented bytecode: " + encodeError;
            return false;
        }
    }
    return true;
}

} // namespace

struct VMWindowsNativeDifferentialEvidenceProvider::SharedConfig {
    VMHandlerArchitecture architecture = VMHandlerArchitecture::X64;
    std::array<uint8_t, 32> buildSeed{};
    std::array<uint8_t, VM_HANDLER_TABLE_SIZE> handlerSemanticToSlot{};
    std::array<uint8_t, VM_HANDLER_TABLE_SIZE> handlerSlotToSemantic{};
    std::array<uint8_t, VM_HANDLER_TABLE_SIZE> handlerVariants{};
    VMHandlerOperandCodecConfig operandCodec{};
    uint32_t memorySize = 0;
#ifdef _WIN32
    std::wstring workerExecutablePath;
#endif
};

struct VMWindowsNativeDifferentialEvidenceProvider::Impl {
    bool architectureIsX64 = false;
    uint32_t memorySize = 0;
    uint32_t contextEntryOffset = 0;
    uint32_t preparedFunctionRVA = 0;
    std::vector<uint8_t> handlerImage;
    std::vector<VMNativeDifferentialRelocation> relocations;
    std::vector<VMNativeDifferentialUnwindEntry> unwindEntries;
#ifdef _WIN32
    std::wstring workerExecutablePath;
#endif
};

VMWindowsNativeDifferentialEvidenceProvider::VMWindowsNativeDifferentialEvidenceProvider() = default;
VMWindowsNativeDifferentialEvidenceProvider::~VMWindowsNativeDifferentialEvidenceProvider() = default;

bool VMWindowsNativeDifferentialEvidenceProvider::Initialize(
    VMHandlerArchitecture architecture,
    const std::array<uint8_t, 32>& buildSeed,
    const std::array<uint8_t, VM_HANDLER_TABLE_SIZE>& handlerSemanticToSlot,
    const std::array<uint8_t, VM_HANDLER_TABLE_SIZE>& handlerSlotToSemantic,
    const std::array<uint8_t, VM_HANDLER_TABLE_SIZE>& handlerVariants,
    const VMHandlerOperandCodecConfig& operandCodec,
    uint32_t memorySize,
    std::string& error)
{
#ifndef _WIN32
    (void)architecture; (void)buildSeed; (void)handlerSemanticToSlot;
    (void)handlerSlotToSemantic; (void)handlerVariants; (void)operandCodec; (void)memorySize;
    error = "native differential evidence provider is Windows-only";
    return false;
#else
    if (memorySize < 0x1000u) {
        error = "native differential evidence provider requires a real corpus memory size";
        return false;
    }

    wchar_t selfPath[MAX_PATH];
    const DWORD selfPathLength = GetModuleFileNameW(nullptr, selfPath, MAX_PATH);
    if (selfPathLength == 0 || selfPathLength >= MAX_PATH) {
        error = "native differential evidence provider could not resolve its own module path";
        return false;
    }
    std::wstring workerPath(selfPath, selfPathLength);
    const size_t slash = workerPath.find_last_of(L"\\/");
    workerPath = (slash == std::wstring::npos) ? std::wstring() : workerPath.substr(0, slash + 1);
    workerPath += L"vm_native_differential_worker.exe";
    const DWORD attributes = GetFileAttributesW(workerPath.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY)) {
        error = "isolated same-architecture native differential worker binary is missing "
            "next to the packer executable";
        return false;
    }

    auto config = std::make_unique<SharedConfig>();
    config->architecture = architecture;
    config->buildSeed = buildSeed;
    config->handlerSemanticToSlot = handlerSemanticToSlot;
    config->handlerSlotToSemantic = handlerSlotToSemantic;
    config->handlerVariants = handlerVariants;
    config->operandCodec = operandCodec;
    config->memorySize = memorySize;
    config->workerExecutablePath = workerPath;
    m_config = std::move(config);
    m_impl.reset();
    return true;
#endif
}

bool VMWindowsNativeDifferentialEvidenceProvider::PrepareForFunction(
    uint32_t functionRVA,
    const VM_OPERAND_CODEC& functionOperandCodec,
    std::string& error)
{
#ifndef _WIN32
    (void)functionRVA; (void)functionOperandCodec;
    error = "native differential evidence provider is Windows-only";
    return false;
#else
    if (!m_config) {
        error = "native differential evidence provider was not initialized";
        return false;
    }
    if (functionOperandCodec.functionRva != functionRVA) {
        error = "native differential per-function operand codec does not match its own RVA";
        return false;
    }

    // The decode-plan table is keyed by function RVA exactly like the real
    // shipped image's table (VMRuntimeBuilder::Build), so a handler image
    // synthesized for one function cannot serve a different one; this is
    // re-synthesized once per candidate function; see the class comment.
    VMHandlerFunctionDecodePlans plan{};
    plan.functionRVA = functionRVA;
    plan.codec = functionOperandCodec;
    if (!VMSchema::BuildRuntimeDecodePlans(plan.codec, plan.plans.data(), error)) {
        return false;
    }

    VMHandlerSynthesisConfig config{};
    config.architecture = m_config->architecture;
    config.buildSeed = m_config->buildSeed;
    config.handlerSemanticToSlot = m_config->handlerSemanticToSlot;
    config.handlerSlotToSemantic = m_config->handlerSlotToSemantic;
    config.handlerVariants = m_config->handlerVariants;
    config.operandCodec = m_config->operandCodec;
    config.functionDecodePlans.push_back(std::move(plan));
    config.variantCount = VM_HANDLER_VARIANT_COUNT;
    config.minimumJunkBytesPerHandler = 96;
    // Matches the +16 scratch region the worker reserves past the corpus-
    // verified memorySize bytes; see vm_native_differential_worker_harness.
    config.virtualProtectIatRVA = m_config->memorySize;
    config.flushInstructionCacheIatRVA = m_config->memorySize + 8u;
    config.encryptHandlerBodies = true;
    config.emitCetLandingPads = true;

    VMHandlerSynthesizer synthesizer;
    const VMHandlerSynthesisResult result = synthesizer.Synthesize(config);
    if (!result.success) {
        error = "native differential evidence provider could not synthesize a handler image: " +
            result.error;
        return false;
    }
    std::string validationError;
    if (!VMHandlerSynthesizer::Validate(config, result, validationError)) {
        error = "native differential evidence provider's own handler image failed self-"
            "validation: " + validationError;
        return false;
    }

    auto impl = std::make_unique<Impl>();
    impl->architectureIsX64 = m_config->architecture == VMHandlerArchitecture::X64;
    impl->memorySize = m_config->memorySize;
    impl->workerExecutablePath = m_config->workerExecutablePath;
    impl->contextEntryOffset = result.contextEntryOffset;
    impl->preparedFunctionRVA = functionRVA;
    impl->handlerImage = result.image;
    impl->relocations.reserve(result.relocations.size());
    for (const auto& relocation : result.relocations) {
        impl->relocations.push_back({relocation.offset, relocation.type, relocation.reserved});
    }
    impl->unwindEntries.reserve(result.unwindEntries.size());
    for (const auto& unwind : result.unwindEntries) {
        impl->unwindEntries.push_back({unwind.beginOffset, unwind.endOffset, unwind.unwindOffset});
    }
    m_impl = std::move(impl);
    m_semanticDigest = ComputeSemanticDigest(m_config->architecture, m_config->buildSeed,
        m_config->handlerSemanticToSlot, m_config->handlerSlotToSemantic,
        m_config->handlerVariants, m_config->operandCodec, config.variantCount);
    m_semanticDigest = MixIdentityValue(m_semanticDigest, functionRVA);
    return true;
#endif
}

bool VMWindowsNativeDifferentialEvidenceProvider::ExecuteCase(
    const Function& function,
    const TranslationResult& translation,
    const std::unordered_map<uint8_t, uint8_t>& opcodeMap,
    const std::unordered_map<uint8_t, uint8_t>& registerMap,
    const VMNativeDifferentialCaseRequest& request,
    VMNativeDifferentialCaseEvidence& evidence,
    std::string& error) const
{
    evidence = VMNativeDifferentialCaseEvidence{};
    evidence.corpusIndex = request.corpusIndex;
    evidence.architecture = request.architecture;
    evidence.functionRVA = request.functionRVA;
    evidence.translationIdentity = request.translationIdentity;
    evidence.handlerImageDigest = request.handlerImageDigest;
    evidence.inputIdentity = request.inputIdentity;

#ifndef _WIN32
    error = "native differential evidence provider is Windows-only";
    return false;
#else
    if (!m_impl) {
        error = "native differential evidence provider has no prepared function "
            "(PrepareForFunction was not called)";
        return false;
    }
    if (m_impl->preparedFunctionRVA != request.functionRVA) {
        error = "native differential evidence provider was prepared for a different "
            "function RVA than this request";
        return false;
    }
    const bool wantsX64 = request.architecture == VMNativeDifferentialArchitecture::X64;
    if (wantsX64 != m_impl->architectureIsX64) {
        error = "native differential evidence provider architecture does not match the request";
        return false;
    }
    if (request.initialMemory.size() != m_impl->memorySize) {
        error = "native differential corpus memory size does not match the provider's build";
        return false;
    }

    std::vector<uint8_t> nativeCode;
    if (!BuildContiguousNativeCode(function, nativeCode, error)) {
        return false;
    }
    std::vector<uint8_t> vmBytecode;
    if (!BuildDifferentialBytecode(translation, opcodeMap, vmBytecode, error)) {
        return false;
    }

    std::array<uint8_t, 256> reverseOpcodeMap{};
    reverseOpcodeMap.fill(0xFFu);
    for (const auto& mapping : opcodeMap) reverseOpcodeMap[mapping.second] = mapping.first;
    std::array<uint8_t, 16> familyToVregSlot{};
    for (uint8_t family = 0; family < 16; ++family) {
        familyToVregSlot[family] = registerMap.at(family);
    }

    VMNativeDifferentialRequestHeader header{};
    header.architectureIsX64 = wantsX64 ? 1u : 0u;
    header.timeoutMilliseconds = request.timeoutMilliseconds;
    header.memoryBase = request.memoryBase;
    header.memorySize = m_impl->memorySize;
    header.registerCount = translation.registerCount;
    header.initialGpr = request.initialGpr;
    header.initialRflags = request.initialRflags;
    header.familyToVregSlot = familyToVregSlot;
    header.reverseOpcodeMap = reverseOpcodeMap;
    header.handlerSemanticToSlot = m_config->handlerSemanticToSlot;
    header.operandCodec = translation.operandCodec;
    header.contextEntryOffset = m_impl->contextEntryOffset;

    uint32_t offset = static_cast<uint32_t>(sizeof(VMNativeDifferentialRequestHeader));
    header.nativeCodeOffset = offset; header.nativeCodeSize = static_cast<uint32_t>(nativeCode.size());
    offset += header.nativeCodeSize;
    header.corpusMemoryOffset = offset;
    offset += header.memorySize;
    header.vmBytecodeOffset = offset; header.vmBytecodeSize = static_cast<uint32_t>(vmBytecode.size());
    offset += header.vmBytecodeSize;
    header.handlerImageOffset = offset;
    header.handlerImageSize = static_cast<uint32_t>(m_impl->handlerImage.size());
    offset += header.handlerImageSize;
    header.handlerRelocationsOffset = offset;
    header.handlerRelocationsCount = static_cast<uint32_t>(m_impl->relocations.size());
    offset += header.handlerRelocationsCount * static_cast<uint32_t>(sizeof(VMNativeDifferentialRelocation));
    header.handlerUnwindOffset = offset;
    header.handlerUnwindCount = static_cast<uint32_t>(m_impl->unwindEntries.size());
    offset += header.handlerUnwindCount * static_cast<uint32_t>(sizeof(VMNativeDifferentialUnwindEntry));
    header.totalFileSize = offset;

    std::vector<uint8_t> requestBlob(offset);
    std::memcpy(requestBlob.data(), &header, sizeof(header));
    std::memcpy(requestBlob.data() + header.nativeCodeOffset, nativeCode.data(), nativeCode.size());
    std::memcpy(requestBlob.data() + header.corpusMemoryOffset, request.initialMemory.data(),
        header.memorySize);
    std::memcpy(requestBlob.data() + header.vmBytecodeOffset, vmBytecode.data(), vmBytecode.size());
    std::memcpy(requestBlob.data() + header.handlerImageOffset, m_impl->handlerImage.data(),
        m_impl->handlerImage.size());
    if (!m_impl->relocations.empty()) {
        std::memcpy(requestBlob.data() + header.handlerRelocationsOffset,
            m_impl->relocations.data(),
            m_impl->relocations.size() * sizeof(VMNativeDifferentialRelocation));
    }
    if (!m_impl->unwindEntries.empty()) {
        std::memcpy(requestBlob.data() + header.handlerUnwindOffset,
            m_impl->unwindEntries.data(),
            m_impl->unwindEntries.size() * sizeof(VMNativeDifferentialUnwindEntry));
    }

    wchar_t tempDirectory[MAX_PATH];
    if (GetTempPathW(MAX_PATH, tempDirectory) == 0) {
        error = "native differential evidence provider could not resolve a temp directory";
        return false;
    }
    wchar_t suffix[64];
    swprintf_s(suffix, L"cs_ndiff_%lu_%u", GetCurrentProcessId(), request.corpusIndex);
    const std::wstring requestPath = std::wstring(tempDirectory) + suffix + L"_req.bin";
    const std::wstring responsePath = std::wstring(tempDirectory) + suffix + L"_resp.bin";

    {
        HANDLE file = CreateFileW(requestPath.c_str(), GENERIC_WRITE, 0, nullptr,
            CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, nullptr);
        if (file == INVALID_HANDLE_VALUE) {
            error = "native differential evidence provider could not create the request file";
            return false;
        }
        DWORD written = 0;
        const BOOL ok = WriteFile(file, requestBlob.data(),
            static_cast<DWORD>(requestBlob.size()), &written, nullptr);
        CloseHandle(file);
        if (!ok || written != requestBlob.size()) {
            DeleteFileW(requestPath.c_str());
            error = "native differential evidence provider could not write the request file";
            return false;
        }
    }
    DeleteFileW(responsePath.c_str());

    std::wstring commandLine = L"\"" + m_impl->workerExecutablePath + L"\" \"" +
        requestPath + L"\" \"" + responsePath + L"\"";
    STARTUPINFOW startupInfo{};
    startupInfo.cb = sizeof(startupInfo);
    startupInfo.dwFlags = STARTF_USESTDHANDLES;
    startupInfo.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startupInfo.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    startupInfo.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    PROCESS_INFORMATION processInfo{};
    const BOOL created = CreateProcessW(m_impl->workerExecutablePath.c_str(),
        commandLine.data(), nullptr, nullptr, TRUE,
        0, nullptr, nullptr, &startupInfo, &processInfo);
    if (!created) {
        DeleteFileW(requestPath.c_str());
        error = "native differential evidence provider could not spawn the isolated worker";
        return false;
    }
    CloseHandle(processInfo.hThread);

    evidence.isolatedWorker = true;
    evidence.timeoutEnforced = true;
    const DWORD waitResult = WaitForSingleObject(processInfo.hProcess, request.timeoutMilliseconds);
    if (waitResult == WAIT_TIMEOUT) {
        TerminateProcess(processInfo.hProcess, 1);
        WaitForSingleObject(processInfo.hProcess, INFINITE);
        evidence.timedOut = true;
        CloseHandle(processInfo.hProcess);
        DeleteFileW(requestPath.c_str());
        DeleteFileW(responsePath.c_str());
        return true;
    }
    DWORD exitCode = 1;
    GetExitCodeProcess(processInfo.hProcess, &exitCode);
    CloseHandle(processInfo.hProcess);
    DeleteFileW(requestPath.c_str());
    if (waitResult != WAIT_OBJECT_0 || exitCode != 0) {
        DeleteFileW(responsePath.c_str());
        error = "native differential isolated worker exited abnormally (code " +
            std::to_string(exitCode) + ")";
        return false;
    }

    std::vector<uint8_t> responseBlob;
    {
        HANDLE file = CreateFileW(responsePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) {
            error = "native differential evidence provider could not open the response file";
            return false;
        }
        LARGE_INTEGER size{};
        if (!GetFileSizeEx(file, &size) || size.QuadPart < 0) {
            CloseHandle(file);
            error = "native differential evidence provider could not size the response file";
            return false;
        }
        responseBlob.resize(static_cast<size_t>(size.QuadPart));
        DWORD readBytes = 0;
        const BOOL ok = responseBlob.empty() ||
            ReadFile(file, responseBlob.data(), static_cast<DWORD>(responseBlob.size()),
                &readBytes, nullptr);
        CloseHandle(file);
        DeleteFileW(responsePath.c_str());
        if (!ok || readBytes != responseBlob.size()) {
            error = "native differential evidence provider could not read the response file";
            return false;
        }
    }
    if (responseBlob.size() < sizeof(VMNativeDifferentialResponseBody)) {
        error = "native differential response file is truncated";
        return false;
    }
    VMNativeDifferentialResponseBody response{};
    std::memcpy(&response, responseBlob.data(), sizeof(response));
    if (response.magic != VM_NATIVE_DIFFERENTIAL_RESPONSE_MAGIC ||
        response.version != VM_NATIVE_DIFFERENTIAL_PROTOCOL_VERSION ||
        response.memorySize != m_impl->memorySize ||
        responseBlob.size() != sizeof(response) + 2u * static_cast<size_t>(response.memorySize)) {
        error = "native differential response file is malformed";
        return false;
    }

    if (std::getenv("CS_NATIVE_DIFFERENTIAL_DEBUG")) {
        std::fprintf(stderr,
            "[ndiff-debug] nativeExecuted=%u nativeFaulted=%u nativeExceptionCode=0x%08X "
            "nativeFaultOffset=0x%llX vmExecuted=%u vmFaulted=%u vmExceptionCode=0x%08X "
            "vmFaultOffset=0x%llX vmRuntimeError=%u vmSemantic=%u vmVariant=%u vmVipOffset=0x%llX\n",
            response.nativeExecuted, response.nativeFaulted, response.nativeExceptionCode,
            static_cast<unsigned long long>(response.nativeFaultOffset),
            response.vmExecuted, response.vmFaulted, response.vmExceptionCode,
            static_cast<unsigned long long>(response.vmFaultOffset),
            response.vmRuntimeError, response.vmCurrentSemantic, response.vmCurrentVariant,
            static_cast<unsigned long long>(response.vmVipOffset));
    }
    evidence.nativeCpuExecuted = response.nativeExecuted != 0;
    evidence.synthesizedHandlersExecuted = response.vmExecuted != 0;
    evidence.nativeFaulted = response.nativeFaulted != 0;
    evidence.nativeExceptionCode = response.nativeExceptionCode;
    evidence.vmFaulted = response.vmFaulted != 0 || response.vmRuntimeError != 0;
    // Divide faults reach here through two different mechanisms, and both
    // must map to VMMicroFault::DivideError:
    //   1. response.vmRuntimeError == VM_MICRO_ERR_DIVIDE: some failure paths
    //      set this VM_MICRO_ERR_* context code directly.
    //   2. response.vmExceptionCode is a real STATUS_INTEGER_DIVIDE_BY_ZERO /
    //      STATUS_INTEGER_OVERFLOW: the handler-tail divideFailure trampoline
    //      (see EmitX64Failure/EmitX86Failure's rotation in
    //      vm_handler_semantic_codegen.cpp) deliberately executes a real
    //      `div`-by-zero instead of writing a soft error code, so a debugger
    //      attached to the packed binary sees a real #DE rather than a
    //      distinguishable "VM said no" signal. The worker's SEH wrapper
    //      catches that as a generic VM_MICRO_ERR_HANDLER_BUG, which would
    //      otherwise misclassify a correctly-detected divide fault as an
    //      unrelated crash.  Anything else collapses to the previous generic
    //      fault bucket rather than silently misreporting a real cause.
    constexpr uint32_t kDivideByZeroExceptionCode = 0xC0000094u;
    constexpr uint32_t kIntegerOverflowExceptionCode = 0xC0000095u;
    if (!evidence.vmFaulted) {
        evidence.vmFault = VMMicroFault::None;
    } else if (response.vmRuntimeError == VM_MICRO_ERR_DIVIDE ||
               response.vmExceptionCode == kDivideByZeroExceptionCode ||
               response.vmExceptionCode == kIntegerOverflowExceptionCode) {
        evidence.vmFault = VMMicroFault::DivideError;
    } else {
        evidence.vmFault = VMMicroFault::UnsupportedSemantic;
    }
    evidence.nativeInstructionCount = function.blocks.empty() ? 0 :
        [&function]() {
            uint64_t count = 0;
            for (const auto& block : function.blocks) count += block.instructions.size();
            return count;
        }();
    evidence.handlerInstructionCount = translation.microOpCount;

    if (!evidence.nativeFaulted) {
        for (uint8_t family = 0; family < 16; ++family) {
            evidence.nativeState.gpr[family] = response.nativeFinalGpr[family];
        }
        evidence.nativeState.rflags = response.nativeFinalRflags;
        evidence.nativeState.validRflagsMask = VM_FLAG_ARCHITECTURAL_MASK;
        evidence.nativeState.memory.assign(
            responseBlob.begin() + sizeof(response),
            responseBlob.begin() + sizeof(response) + response.memorySize);
    }
    if (!evidence.vmFaulted) {
        for (uint8_t family = 0; family < 16; ++family) {
            evidence.vmState.gpr[family] = response.vmFinalGpr[family];
        }
        evidence.vmState.rflags = response.vmFinalRflags;
        evidence.vmState.validRflagsMask = VM_FLAG_ARCHITECTURAL_MASK;
        evidence.vmState.memory.assign(
            responseBlob.begin() + sizeof(response) + response.memorySize,
            responseBlob.begin() + sizeof(response) + 2u * static_cast<size_t>(response.memorySize));
    }
    return true;
#endif
}

} // namespace CipherShell
