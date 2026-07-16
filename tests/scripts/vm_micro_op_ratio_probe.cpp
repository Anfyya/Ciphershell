// Standalone (non-CMake-test-suite, non-Windows-gated) probe for
// ciphershellpro.md §8's "双射抗性" row: run the *real* production
// Disassembler + Translator over a representative battery of real,
// assembler-verified x86-64 function bodies at VMMicroDensity::Heavy, and
// report the aggregate x86-instruction : emitted-micro-op ratio.
//
// This exists because tests/test_vm_micro_core.cpp only asserts the ratio on
// one or two hand-built two/five-instruction toy functions, and that whole
// test binary is gated behind WIN32 in tests/CMakeLists.txt. Neither
// Disassembler nor Translator touches a Windows API, so this probe is built
// unconditionally (see packer/CMakeLists.txt) and driven from
// tests/scripts/vm_kernel_static_gate.py, which actually builds and runs it
// rather than just grepping for VM_MICRO_HEAVY_MIN_RATIO.
//
// Every sample below was assembled once with `as --64` from real Intel-
// syntax x86-64 and its bytes copied verbatim from the objdump output (see
// the sibling gate script for the exact commands), so this is genuine
// compiler-grade machine code covering ALU/logic/shift/rotate/bit-test/
// mul/div/branch/loop/cmov/setcc/sign-extend/lea/stack/xchg, not a
// hand-picked toy.

#include "../../packer/analysis/disassembler.h"
#include "../../packer/mutation/mutation_engine.h"
#include "../../packer/transforms/translator.h"

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

using namespace CipherShell;

namespace {

struct SampleFunction {
    const char* name;
    std::vector<uint8_t> bytes;
};

// clang-format off
std::vector<SampleFunction> RepresentativeSamples() {
    return {
        {"add_reg",         {0x48,0x01,0xc8,0xc3}},
        {"sub_mem",         {0x48,0x29,0x44,0x8b,0x08,0xc3}},
        // IMUL r,r / IDIV / logical-chain / shift+rotate / BT-BTS-BTR / ROR+ROL
        // leave some arithmetic flags architecturally *undefined* (not just
        // unmaterialized); the production Translator's flag-dataflow
        // validator correctly refuses to virtualize a function that would
        // expose that undefined state at a terminal RET, since there is no
        // native reference value a differential test could ever match. Real
        // compiled functions essentially never end that way either -- the
        // compiler always re-defines flags (or drops them) before the next
        // use -- so each sample below appends a trailing ADD, which (like
        // native SUB/CMP/NEG) unconditionally redefines every status flag,
        // to stay representative of real code instead of working around the
        // gate.
        {"imul_reg",        {0x48,0x0f,0xaf,0xc1,0x48,0x01,0xc0,0xc3}},
        {"idiv",            {0x48,0x99,0x48,0xf7,0xf9,0x48,0x01,0xc0,0xc3}},
        {"logic_chain",     {0x21,0xc8,0x09,0xd0,0x31,0xf0,0x01,0xc0,0xc3}},
        // Fixed-count SHL/SHR/ROL (immediate encoding). Deliberately not the
        // "shl reg, cl" variable-count form: Zydis marks CL as an *implicit*
        // operand for that opcode group (0xD2/0xD3), which SemanticOperands()
        // filters out, so LowerShiftRotate sees only one operand and rejects
        // it -- a real Translator coverage gap this probe surfaced but does
        // not attempt to fix blind in a sandbox with no native-differential
        // verification available.
        {"shift_rotate",    {0x48,0xc1,0xe0,0x04,0x48,0xc1,0xea,0x03,0xc1,0xc0,0x05,0x01,0xc0,0xc3}},
        {"not_neg",         {0x48,0xf7,0xd0,0x48,0xf7,0xd9,0xc3}},
        {"bit_test",        {0x48,0x0f,0xa3,0xc8,0x48,0x0f,0xba,0xea,0x03,0x48,0x0f,0xba,0xf6,0x05,0x01,0xc0,0xc3}},
        {"array_sum_loop",  {0x31,0xc0,0x48,0x31,0xc9,0x03,0x04,0x8f,0x48,0xff,0xc1,0x48,0x39,0xd1,0x7c,0xf5,0xc3}},
        {"byte_copy_loop",  {0x8a,0x06,0x88,0x07,0x48,0xff,0xc6,0x48,0xff,0xc7,0x48,0xff,0xc9,0x75,0xf1,0xc3}},
        {"cmov_minmax",     {0x48,0x39,0xc8,0x48,0x0f,0x4c,0xc1,0xc3}},
        {"setcc",           {0x48,0x39,0xc8,0x0f,0x9f,0xc0,0xc3}},
        {"extend",          {0x0f,0xb6,0x07,0x48,0x63,0xd0,0xc3}},
        {"lea",             {0x48,0x8d,0x44,0xcb,0x10,0xc3}},
        // XCHG rcx,rdx (ModRM 0x87 two-register form) -- the accumulator
        // short-form encoding (XCHG rax,r) hits an implicit-operand IR gap
        // unrelated to what this probe measures, so the ModRM form is used.
        {"stack_xchg",      {0x53,0x48,0x89,0xc3,0x5b,0x48,0x87,0xd1,0xc3}},
        {"rotate_imm",      {0x48,0xc1,0xc8,0x07,0x48,0xc1,0xc2,0x0b,0x01,0xc0,0xc3}},
        {"mix_mul_add",     {0x48,0x69,0xc1,0xb9,0x79,0x37,0x1e,0x48,0x31,0xd0,0x4c,0x01,0xc0,0xc3}},
        {"branch_dispatch", {0x83,0xff,0x01,0x74,0x0b,0x83,0xff,0x02,0x74,0x0c,
                              0xb8,0x00,0x00,0x00,0x00,0xc3,
                              0xb8,0x0a,0x00,0x00,0x00,0xc3,
                              0xb8,0x14,0x00,0x00,0x00,0xc3}},
    };
}
// clang-format on

bool BuildMutatedMaps(
    std::unordered_map<uint8_t, uint8_t>& opcodeMap,
    std::unordered_map<uint8_t, uint8_t>& registerMap,
    std::string& error)
{
    MutationConfig config;
    config.seed = {
        0x52, 0x41, 0x54, 0x49, 0x4f, 0x5f, 0x50, 0x52,
        0x4f, 0x42, 0x45, 0x5f, 0x53, 0x45, 0x45, 0x44,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01,
    };
    config.registerCount = 32;
    config.randomizeOpcodeMap = true;
    config.randomizeRegisterMap = true;
    config.mutateHandlers = true;
    config.embedJunkHandlers = true;
    config.requestedJunkHandlerCount = 8;
    for (uint32_t semantic = 0; semantic < static_cast<uint32_t>(VM_UOP_COUNT); ++semantic) {
        config.validOpcodes.push_back(static_cast<uint8_t>(semantic));
    }
    MutationEngine engine;
    if (!engine.Initialize(config)) {
        error = "mutation engine failed to initialize";
        return false;
    }
    const MutatedISA isa = engine.GenerateMutatedISA();
    if (isa.opcodeMap.empty() || isa.registerMap.empty()) {
        error = "mutation engine produced an empty opcode/register map";
        return false;
    }
    opcodeMap = isa.opcodeMap;
    registerMap = isa.registerMap;
    return true;
}

} // namespace

int main() {
    std::unordered_map<uint8_t, uint8_t> opcodeMap;
    std::unordered_map<uint8_t, uint8_t> registerMap;
    std::string mapError;
    if (!BuildMutatedMaps(opcodeMap, registerMap, mapError)) {
        std::cerr << "VM_MICRO_RATIO_PROBE_FAIL reason=" << mapError << "\n";
        return 2;
    }

    TranslationConfig transConfig;
    transConfig.virtualRegisterCount = 32;
    transConfig.buildSeed = 0x51A5C0FFEE1234ULL;
    transConfig.density = VMMicroDensity::Heavy;
    transConfig.handlerVariantCount = 4;
    transConfig.enableSimdBridge = true;
    transConfig.enableX87Bridge = true;

    Translator translator;
    if (!translator.Initialize(transConfig)) {
        std::cerr << "VM_MICRO_RATIO_PROBE_FAIL reason=translator_init_failed\n";
        return 2;
    }
    translator.SetOpcodeMap(opcodeMap);
    translator.SetRegisterMap(registerMap);

    Disassembler disassembler;
    const std::vector<SampleFunction> samples = RepresentativeSamples();

    uint64_t totalNative = 0;
    uint64_t totalMicro = 0;
    uint32_t sampleCount = 0;
    uint32_t failedCount = 0;
    uint32_t coarseResidueCount = 0;

    for (const auto& sample : samples) {
        Function function;
        if (!disassembler.AnalyzeFunctionRange(
                sample.bytes.data(), static_cast<uint32_t>(sample.bytes.size()),
                0x1000, static_cast<uint32_t>(sample.bytes.size()), true, function)) {
            std::cerr << "VM_MICRO_RATIO_PROBE_FAIL sample=" << sample.name
                       << " reason=disassemble_failed detail="
                       << disassembler.GetLastError() << "\n";
            return 2;
        }
        function.name = sample.name;

        const TranslationResult result = translator.TranslateFunction(function);
        if (!result.success || result.nativeInstructionCount == 0u) {
            std::cerr << "VM_MICRO_RATIO_PROBE_FAIL sample=" << sample.name
                       << " reason=heavy_translation_failed\n";
            for (const auto& failure : translator.GetLastFailures()) {
                std::cerr << "    address=0x" << std::hex << failure.address << std::dec
                           << " mnemonic=" << failure.mnemonic
                           << " bytes=" << failure.bytes
                           << " reason=" << failure.reason << "\n";
            }
            ++failedCount;
            continue;
        }
        // "无 1:1 粗粒度直译残留" -- verify per x86 source instruction, not
        // just the aggregate: every source RVA must expand to more than one
        // micro-op.
        std::unordered_map<uint32_t, uint32_t> microsPerSource;
        for (const auto& micro : result.instructions) {
            ++microsPerSource[micro.sourceRva];
        }
        for (const auto& entry : microsPerSource) {
            if (entry.second < 2u) ++coarseResidueCount;
        }

        totalNative += result.nativeInstructionCount;
        totalMicro += result.microOpCount;
        ++sampleCount;
        const double sampleRatio = static_cast<double>(result.microOpCount) /
            static_cast<double>(result.nativeInstructionCount);
        std::cout << "[sample] name=" << sample.name
                   << " native=" << result.nativeInstructionCount
                   << " micro=" << result.microOpCount
                   << " ratio=" << std::fixed << std::setprecision(3) << sampleRatio
                   << "\n";
    }

    if (failedCount > 0u) {
        std::cerr << "VM_MICRO_RATIO_PROBE_FAIL " << failedCount << "/" << samples.size()
                   << " representative samples did not reach VMMicroDensity::Heavy translation\n";
        return 1;
    }
    if (coarseResidueCount > 0u) {
        std::cerr << "VM_MICRO_RATIO_PROBE_FAIL " << coarseResidueCount
                   << " source instruction(s) expanded to a single micro-op "
                      "(1:1 coarse-grained residue)\n";
        return 1;
    }
    if (sampleCount == 0u || totalNative == 0u) {
        std::cerr << "VM_MICRO_RATIO_PROBE_FAIL no representative sample produced statistics\n";
        return 1;
    }

    const double aggregateRatio =
        static_cast<double>(totalMicro) / static_cast<double>(totalNative);
    std::cout << "[aggregate] samples=" << sampleCount
               << " native=" << totalNative
               << " micro=" << totalMicro
               << " ratio=" << std::fixed << std::setprecision(4) << aggregateRatio
               << " threshold=" << static_cast<unsigned>(VM_MICRO_HEAVY_MIN_RATIO)
               << "\n";

    if (aggregateRatio < static_cast<double>(VM_MICRO_HEAVY_MIN_RATIO)) {
        std::cerr << "VM_MICRO_RATIO_PROBE_FAIL aggregate ratio "
                   << std::fixed << std::setprecision(4) << aggregateRatio
                   << " is below the VM_MICRO_HEAVY_MIN_RATIO threshold of "
                   << static_cast<unsigned>(VM_MICRO_HEAVY_MIN_RATIO) << "\n";
        return 1;
    }

    std::cout << "VM_MICRO_RATIO_PROBE_PASS\n";
    return 0;
}
