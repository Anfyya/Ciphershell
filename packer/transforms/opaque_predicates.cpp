/**
 * CipherShell 不透明谓词 - 实现
 */

#include "opaque_predicates.h"
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <cmath>
#include <random>

namespace CipherShell {

// ============================================================================
// 构造/析构
// ============================================================================

OpaquePredicateGenerator::OpaquePredicateGenerator() 
    : m_nextId(1)
    , m_rng(std::random_device{}())
{
    srand((unsigned int)time(nullptr));
}

OpaquePredicateGenerator::~OpaquePredicateGenerator() {}

// ============================================================================
// 公共接口
// ============================================================================

OpaquePredicate OpaquePredicateGenerator::Generate(OpaquePredicateType type, bool expectedResult) {
    switch (type) {
        case OpaquePredicateType::AlwaysTrue:
            return GenerateAlwaysTrue();
        case OpaquePredicateType::AlwaysFalse:
            return GenerateAlwaysFalse();
        case OpaquePredicateType::MathIdentity:
            return GenerateMathPredicate(expectedResult);
        case OpaquePredicateType::PointerAlias:
            return GeneratePointerAliasPredicate(expectedResult);
        case OpaquePredicateType::FloatPrecision:
            return GenerateFloatPrecisionPredicate(expectedResult);
        case OpaquePredicateType::IntegerOverflow:
            return GenerateIntegerOverflowPredicate(expectedResult);
        case OpaquePredicateType::BitManipulation:
            return GenerateBitManipulationPredicate(expectedResult);
        case OpaquePredicateType::ModularArith:
            return GenerateModularArithPredicate(expectedResult);
        case OpaquePredicateType::StackAlignment:
            return GenerateStackAlignmentPredicate(expectedResult);
        case OpaquePredicateType::DataDependent:
        case OpaquePredicateType::RandomlyTrue:
            return GenerateDataDependentPredicate(expectedResult);
        default:
            return GenerateMathPredicate(expectedResult);
    }
}

OpaquePredicate OpaquePredicateGenerator::GenerateAlwaysTrue() {
    OpaquePredicate pred;
    pred.type = OpaquePredicateType::AlwaysTrue;
    pred.id = m_nextId++;
    pred.expectedResult = true;
    pred.description = "Always true predicate";
    pred.code = nullptr;
    pred.codeSize = 0;
    pred.operand1 = 0;
    pred.operand2 = 0;
    pred.magicValue = 0;
    return pred;
}

OpaquePredicate OpaquePredicateGenerator::GenerateAlwaysFalse() {
    OpaquePredicate pred;
    pred.type = OpaquePredicateType::AlwaysFalse;
    pred.id = m_nextId++;
    pred.expectedResult = false;
    pred.description = "Always false predicate";
    pred.code = nullptr;
    pred.codeSize = 0;
    pred.operand1 = 0;
    pred.operand2 = 0;
    pred.magicValue = 0;
    return pred;
}

OpaquePredicate OpaquePredicateGenerator::GenerateMathPredicate(bool expectedResult) {
    OpaquePredicate pred;
    pred.type = OpaquePredicateType::MathIdentity;
    pred.id = m_nextId++;
    pred.expectedResult = expectedResult;
    
    // 选择一个数学恒等式
    uint32_t choice = rand() % 4;
    
    switch (choice) {
        case 0:
            // x^2 mod 4 ∈ {0, 1}（永远为真）
            pred.operand1 = rand() % 1000;
            pred.magicValue = (pred.operand1 * pred.operand1) % 4;
            pred.description = "x^2 mod 4 ∈ {0, 1}";
            pred.expectedResult = true;  // 这个永远为真
            break;
            
        case 1:
            // x * (x + 1) 是偶数（永远为真）
            pred.operand1 = rand() % 1000;
            pred.magicValue = pred.operand1 * (pred.operand1 + 1);
            pred.description = "x * (x + 1) is even";
            pred.expectedResult = true;
            break;
            
        case 2:
            // x^3 - x 能被 6 整除（对于 x >= 1，永远为真）
            pred.operand1 = rand() % 100 + 1;
            pred.magicValue = pred.operand1 * pred.operand1 * pred.operand1 - pred.operand1;
            pred.description = "x^3 - x divisible by 6";
            pred.expectedResult = true;
            break;
            
        case 3:
            // 选择一个完全平方数
            pred.operand1 = rand() % 100;
            pred.magicValue = pred.operand1 * pred.operand1;
            pred.description = "Is perfect square check";
            pred.expectedResult = expectedResult;
            break;
    }
    
    return pred;
}

OpaquePredicate OpaquePredicateGenerator::GeneratePointerAliasPredicate(bool expectedResult) {
    OpaquePredicate pred;
    pred.type = OpaquePredicateType::PointerAlias;
    pred.id = m_nextId++;
    pred.expectedResult = expectedResult;
    pred.description = "Pointer alias predicate";
    
    // 两个指向同一地址的指针
    pred.operand1 = GenerateRandomValue();
    pred.operand2 = pred.operand1;  // 同一地址
    pred.magicValue = 0;
    
    return pred;
}

OpaquePredicate OpaquePredicateGenerator::GenerateFloatPrecisionPredicate(bool expectedResult) {
    OpaquePredicate pred;
    pred.type = OpaquePredicateType::FloatPrecision;
    pred.id = m_nextId++;
    pred.expectedResult = expectedResult;
    pred.description = "Float precision predicate";
    
    // IEEE 754 浮点精度限制
    pred.operand1 = 0x3F800000;  // 1.0f
    pred.operand2 = 0x3F800001;  // 1.0f + epsilon
    pred.magicValue = 0;
    
    return pred;
}

OpaquePredicate OpaquePredicateGenerator::GenerateIntegerOverflowPredicate(bool expectedResult) {
    OpaquePredicate pred;
    pred.type = OpaquePredicateType::IntegerOverflow;
    pred.id = m_nextId++;
    pred.expectedResult = expectedResult;
    pred.code = nullptr;
    pred.codeSize = 0;

    // 对任意 unsigned x: x + (~x) == 0xFFFFFFFF（恒真）
    pred.operand1 = GenerateRandomValue();
    pred.operand2 = ~pred.operand1;
    pred.magicValue = 0xFFFFFFFF;
    pred.description = "x + ~x == 0xFFFFFFFF";
    return pred;
}

OpaquePredicate OpaquePredicateGenerator::GenerateBitManipulationPredicate(bool expectedResult) {
    OpaquePredicate pred;
    pred.type = OpaquePredicateType::BitManipulation;
    pred.id = m_nextId++;
    pred.expectedResult = expectedResult;
    pred.code = nullptr;
    pred.codeSize = 0;

    uint32_t choice = rand() % 3;
    switch (choice) {
        case 0:
            // x ^ x == 0（恒真）
            pred.operand1 = GenerateRandomValue();
            pred.magicValue = 0;
            pred.description = "x XOR x == 0";
            break;
        case 1:
            // x | ~x == 0xFFFFFFFF（恒真）
            pred.operand1 = GenerateRandomValue();
            pred.magicValue = 0xFFFFFFFF;
            pred.description = "x OR ~x == 0xFFFFFFFF";
            break;
        case 2:
            // (x & y) | (x & ~y) == x（恒真）
            pred.operand1 = GenerateRandomValue();
            pred.operand2 = GenerateRandomValue();
            pred.magicValue = pred.operand1;
            pred.description = "(x&y)|(x&~y) == x";
            break;
    }
    return pred;
}

OpaquePredicate OpaquePredicateGenerator::GenerateModularArithPredicate(bool expectedResult) {
    OpaquePredicate pred;
    pred.type = OpaquePredicateType::ModularArith;
    pred.id = m_nextId++;
    pred.expectedResult = expectedResult;
    pred.code = nullptr;
    pred.codeSize = 0;

    uint32_t choice = rand() % 2;
    switch (choice) {
        case 0:
            // 费马小定理：a^(p-1) ≡ 1 (mod p) 当 p 为素数且 gcd(a,p)=1
            // 用小素数验证
            pred.operand1 = 2 + rand() % 10;  // a
            pred.operand2 = 7;   // p=7, 素数
            pred.magicValue = 1; // 期望结果
            pred.description = "Fermat's little theorem: a^(p-1) mod p == 1";
            break;
        case 1:
            // 对任意 n: (n^2 + n) mod 2 == 0（恒真）
            pred.operand1 = GenerateRandomValue() & 0xFFFF;  // 避免溢出
            pred.operand2 = 2;
            pred.magicValue = 0;
            pred.description = "(n^2 + n) mod 2 == 0";
            break;
    }
    return pred;
}

OpaquePredicate OpaquePredicateGenerator::GenerateStackAlignmentPredicate(bool expectedResult) {
    OpaquePredicate pred;
    pred.type = OpaquePredicateType::StackAlignment;
    pred.id = m_nextId++;
    pred.expectedResult = expectedResult;
    pred.code = nullptr;
    pred.codeSize = 0;

    // x64 ABI 保证函数调用时 RSP 是 16 字节对齐的（call 后 RSP%16==8）
    // x86 上 ESP 至少 4 字节对齐
    pred.operand1 = 0;
    pred.operand2 = 0;
    pred.magicValue = 0;
    pred.description = "Stack pointer alignment check (ABI guaranteed)";
    return pred;
}

OpaquePredicate OpaquePredicateGenerator::GenerateDataDependentPredicate(bool expectedResult) {
    OpaquePredicate pred;
    pred.type = OpaquePredicateType::DataDependent;
    pred.id = m_nextId++;
    pred.expectedResult = expectedResult;
    pred.code = nullptr;
    pred.codeSize = 0;

    // 运行时读取 PEB 中已知位置的值做判断
    // 例如 PEB.OSMajorVersion >= 6 (Vista+)，在目标系统上恒真
    pred.operand1 = 6;   // 最低 OS 主版本号
    pred.operand2 = 0;
    pred.magicValue = 0;
    pred.description = "Data dependent: OS major version >= 6";
    return pred;
}

BYTE* OpaquePredicateGenerator::GenerateConditionalJump(
    const OpaquePredicate& predicate,
    uint64_t targetAddress,
    bool is64Bit,
    DWORD* codeSize)
{
    if (!codeSize) return nullptr;

    // 根据谓词类型选择检查代码生成器
    std::vector<uint8_t> checkCode;
    switch (predicate.type) {
        case OpaquePredicateType::BitManipulation:
        case OpaquePredicateType::IntegerOverflow:
            checkCode = GenerateBitCheckCode(predicate, is64Bit);
            break;
        case OpaquePredicateType::ModularArith:
            checkCode = GenerateModularCheckCode(predicate, is64Bit);
            break;
        case OpaquePredicateType::StackAlignment:
            checkCode = GenerateStackAlignCheckCode(predicate, is64Bit);
            break;
        default:
            // 默认用位检查
            checkCode = GenerateBitCheckCode(predicate, is64Bit);
            break;
    }

    // 追加条件跳转 (jz/jnz rel32)
    // jz  = 0F 84 rel32  (如果 expectedResult 为 true 则跳)
    // jnz = 0F 85 rel32  (如果 expectedResult 为 false 则跳)
    checkCode.push_back(0x0F);
    checkCode.push_back(predicate.expectedResult ? 0x84 : 0x85);
    // rel32 占位 (需要链接时修补)
    for (int i = 0; i < 4; i++) checkCode.push_back(0x00);

    DWORD totalSize = (DWORD)checkCode.size();
    BYTE* result = new(std::nothrow) BYTE[totalSize];
    if (!result) { *codeSize = 0; return nullptr; }
    memcpy(result, checkCode.data(), totalSize);
    *codeSize = totalSize;
    return result;
}

std::vector<OpaquePredicate> OpaquePredicateGenerator::GenerateBatch(uint32_t count, float trueRatio) {
    std::vector<OpaquePredicate> predicates;

    // 使用全部可用谓词类型（跳过 AlwaysTrue/AlwaysFalse/COUNT）
    const OpaquePredicateType validTypes[] = {
        OpaquePredicateType::RandomlyTrue,
        OpaquePredicateType::DataDependent,
        OpaquePredicateType::PointerAlias,
        OpaquePredicateType::MathIdentity,
        OpaquePredicateType::FloatPrecision,
        OpaquePredicateType::IntegerOverflow,
        OpaquePredicateType::BitManipulation,
        OpaquePredicateType::ModularArith,
        OpaquePredicateType::StackAlignment,
    };
    const uint32_t numTypes = sizeof(validTypes) / sizeof(validTypes[0]);

    for (uint32_t i = 0; i < count; i++) {
        OpaquePredicateType type = validTypes[i % numTypes];
        bool expectedResult = (m_rng() % 2) == 0;

        OpaquePredicate pred;
        switch (type) {
            case OpaquePredicateType::RandomlyTrue:
                pred = GenerateRandomlyTruePredicate(expectedResult);
                break;
            case OpaquePredicateType::DataDependent:
                pred = GenerateDataDependentPredicate(expectedResult);
                break;
            case OpaquePredicateType::PointerAlias:
                pred = GeneratePointerAliasPredicate(expectedResult);
                break;
            case OpaquePredicateType::MathIdentity:
                pred = GenerateMathIdentityPredicate(expectedResult);
                break;
            case OpaquePredicateType::FloatPrecision:
                pred = GenerateFloatPrecisionPredicate(expectedResult);
                break;
            case OpaquePredicateType::IntegerOverflow:
                pred = GenerateIntegerOverflowPredicate(expectedResult);
                break;
            case OpaquePredicateType::BitManipulation:
                pred = GenerateBitManipulationPredicate(expectedResult);
                break;
            case OpaquePredicateType::ModularArith:
                pred = GenerateModularArithPredicate(expectedResult);
                break;
            case OpaquePredicateType::StackAlignment:
                pred = GenerateStackAlignmentPredicate(expectedResult);
                break;
            default:
                pred = GenerateMathIdentityPredicate(expectedResult);
                break;
        }
        predicates.push_back(pred);
    }

    return predicates;
}

// ============================================================================
// 代码生成辅助 — 位检查
// ============================================================================

std::vector<uint8_t> OpaquePredicateGenerator::GenerateBitCheckCode(
    const OpaquePredicate& pred, bool is64Bit) {
    std::vector<uint8_t> code;

    // push eax; mov eax, val; bt eax, bit_pos; pop eax
    code.push_back(0x50);  // push eax
    // mov eax, imm32
    code.push_back(0xB8);
    uint32_t val = pred.operand1 ? pred.operand1 : 0xAAAAAAAA;
    code.push_back(val & 0xFF);
    code.push_back((val >> 8) & 0xFF);
    code.push_back((val >> 16) & 0xFF);
    code.push_back((val >> 24) & 0xFF);
    // bt eax, imm8
    code.push_back(0x0F);
    code.push_back(0xBA);
    code.push_back(0xE0);  // bt eax, imm8
    uint8_t bitPos = (pred.operand2 & 31);
    code.push_back(bitPos);
    code.push_back(0x58);  // pop eax

    return code;
}

// ============================================================================
// 代码生成辅助 — 模运算检查
// ============================================================================

std::vector<uint8_t> OpaquePredicateGenerator::GenerateModularCheckCode(
    const OpaquePredicate& pred, bool is64Bit) {
    std::vector<uint8_t> code;

    // push eax; push edx; mov eax, a; xor edx, edx; mov ecx, n; div ecx;
    // test edx, edx; pop edx; pop eax
    code.push_back(0x50);  // push eax
    code.push_back(0x52);  // push edx
    code.push_back(0x51);  // push ecx

    // mov eax, imm32 (a+b)
    code.push_back(0xB8);
    uint32_t a = pred.operand1 ? pred.operand1 : 7;
    uint32_t b = pred.operand2 ? pred.operand2 : 3;
    uint32_t sum = a + b;
    code.push_back(sum & 0xFF);
    code.push_back((sum >> 8) & 0xFF);
    code.push_back((sum >> 16) & 0xFF);
    code.push_back((sum >> 24) & 0xFF);

    // xor edx, edx
    code.push_back(0x31);
    code.push_back(0xD2);

    // mov ecx, n
    code.push_back(0xB9);
    uint32_t n = pred.magicValue ? pred.magicValue : 5;
    if (n == 0) n = 1;  // avoid div by zero
    code.push_back(n & 0xFF);
    code.push_back((n >> 8) & 0xFF);
    code.push_back((n >> 16) & 0xFF);
    code.push_back((n >> 24) & 0xFF);

    // div ecx
    code.push_back(0xF7);
    code.push_back(0xF1);

    // test edx, edx (remainder check)
    code.push_back(0x85);
    code.push_back(0xD2);

    code.push_back(0x59);  // pop ecx
    code.push_back(0x5A);  // pop edx
    code.push_back(0x58);  // pop eax

    return code;
}

// ============================================================================
// 代码生成辅助 — 栈对齐检查
// ============================================================================

std::vector<uint8_t> OpaquePredicateGenerator::GenerateStackAlignCheckCode(
    const OpaquePredicate& pred, bool is64Bit) {
    std::vector<uint8_t> code;

    // push eax; mov eax, esp; and eax, alignment_mask; test eax, eax; pop eax
    code.push_back(0x50);  // push eax

    // mov eax, esp
    code.push_back(0x89);
    code.push_back(0xE0);

    // and eax, imm32 (alignment mask, e.g., 0xF for 16-byte alignment)
    code.push_back(0x25);
    uint32_t mask = is64Bit ? 0xF : 0x3;  // 16-byte on x64, 4-byte on x86
    code.push_back(mask & 0xFF);
    code.push_back((mask >> 8) & 0xFF);
    code.push_back((mask >> 16) & 0xFF);
    code.push_back((mask >> 24) & 0xFF);

    // test eax, eax
    code.push_back(0x85);
    code.push_back(0xC0);

    code.push_back(0x58);  // pop eax

    return code;
}

// ============================================================================
// 数学辅助
// ============================================================================

uint32_t OpaquePredicateGenerator::GenerateRandomValue() {
    return m_rng();
}

bool OpaquePredicateGenerator::IsPerfectSquare(uint32_t n) {
    if (n == 0) return true;
    uint32_t root = (uint32_t)sqrt((double)n);
    return root * root == n;
}

bool OpaquePredicateGenerator::IsPrime(uint32_t n) {
    if (n < 2) return false;
    if (n < 4) return true;
    if (n % 2 == 0 || n % 3 == 0) return false;
    for (uint32_t i = 5; i * i <= n; i += 6) {
        if (n % i == 0 || n % (i + 2) == 0) return false;
    }
    return true;
}


OpaquePredicate OpaquePredicateGenerator::GenerateRandomlyTruePredicate(bool expectedResult) {
    // 随机为真：基于数据依赖
    return GenerateDataDependentPredicate(expectedResult);
}

OpaquePredicate OpaquePredicateGenerator::GenerateMathIdentityPredicate(bool expectedResult) {
    // 数学恒等式：委托给 GenerateMathPredicate
    return GenerateMathPredicate(expectedResult);
}

} // namespace CipherShell
