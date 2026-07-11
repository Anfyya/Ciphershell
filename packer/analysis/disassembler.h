#ifndef CS_DISASSEMBLER_H
#define CS_DISASSEMBLER_H

#include "instruction_ir.h"
#include <cstdint>
#include <string>
#include <vector>

namespace CipherShell {

struct DisasmConfig {
    bool linearSweep = false;
    bool recursiveDescent = true;
    bool followCalls = false;
    bool detectFunctions = true;
    uint32_t maxInstructions = 100000;
    uint64_t startAddress = 0;
    uint64_t endAddress = 0;
};

class Disassembler {
public:
    Disassembler();
    ~Disassembler();

    bool Initialize(bool is64Bit, uint64_t imageBase = 0);

    std::vector<InstructionIR> Disassemble(
        const uint8_t* code,
        uint32_t size,
        uint64_t baseAddress);

    std::vector<BasicBlock> BuildBasicBlocks(
        const std::vector<InstructionIR>& instructions);

    std::vector<Function> DetectFunctions(
        const std::vector<BasicBlock>& blocks,
        const uint8_t* codeData,
        uint32_t codeSize);

    std::string FormatInstruction(const InstructionIR& instr) const;

    std::vector<Function> AnalyzeCode(
        const uint8_t* code,
        uint32_t size,
        uint64_t baseAddress,
        bool is64Bit);

    bool AnalyzeFunctionRange(
        const uint8_t* code,
        uint32_t availableSize,
        uint64_t functionRVA,
        uint32_t trustedSize,
        bool is64Bit,
        Function& function);

    const std::string& GetLastError() const;
    bool HasError() const;

    bool MeasureInstructionSpan(
        const uint8_t* code,
        uint32_t availableSize,
        uint64_t baseAddress,
        uint32_t minimumSize,
        uint32_t& span);

private:
    bool DecodeInstruction(
        const uint8_t* code,
        uint32_t size,
        uint64_t address,
        InstructionIR& instr);

    void SetError(uint64_t address, const std::string& reason);

    bool m_initialized;
    bool m_is64Bit;
    uint64_t m_imageBase;
    std::string m_lastError;
};

} // namespace CipherShell

#endif // CS_DISASSEMBLER_H
