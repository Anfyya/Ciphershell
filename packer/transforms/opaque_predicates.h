/**
 * CipherShell 不透明谓词
 * 插入条件判断，其结果在编译时已知但静态分析无法证明
 */

#ifndef CS_OPAQUE_PREDICATES_H
#define CS_OPAQUE_PREDICATES_H

#include <cstdint>
#include <vector>
#include <random>
#include <string>
#ifdef _WIN32
#include <windows.h>
#else
#include "windows_compat.h"
#endif

namespace CipherShell {

// ============================================================================
// 不透明谓词类型
// ============================================================================

enum class OpaquePredicateType : uint32_t {
    AlwaysTrue          = 0,    // 恒真
    AlwaysFalse         = 1,    // 恒假
    RandomlyTrue        = 2,    // 随机真（但实际恒真）
    DataDependent       = 3,    // 数据依赖
    PointerAlias        = 4,    // 指针别名
    MathIdentity        = 5,    // 数学恒等式
    FloatPrecision      = 6,    // 浮点精度
    IntegerOverflow     = 7,    // 整数溢出
    BitManipulation     = 8,    // 位操作恒等式
    ModularArith        = 9,    // 模运算恒等式
    StackAlignment      = 10,   // 栈对齐检查（ESP/RSP 恒 16 字节对齐）
    TimestampParity     = 11,   // 时间戳奇偶性（恒不可预测但可构造恒真）
    StringHash          = 12,   // 字符串哈希预计算
    COUNT               = 13
};

// ============================================================================
// 不透明谓词描述
// ============================================================================

struct OpaquePredicate {
    OpaquePredicateType type;           // 类型
    uint32_t            id;             // 唯一 ID
    std::string         description;    // 描述
    bool                expectedResult; // 预期结果（真/假）
    
    // 生成的代码
    BYTE*               code;           // 条件判断代码
    DWORD               codeSize;       // 代码大小
    
    // 操作数
    uint32_t            operand1;       // 操作数 1
    uint32_t            operand2;       // 操作数 2
    uint32_t            magicValue;     // 魔术值
};

// ============================================================================
// 不透明谓词生成器类
// ============================================================================

class OpaquePredicateGenerator {
public:
    OpaquePredicateGenerator();
    ~OpaquePredicateGenerator();

    /**
     * 生成随机不透明谓词
     * @param type 谓词类型
     * @param expectedResult 预期结果
     * @return 不透明谓词描述
     */
    OpaquePredicate Generate(OpaquePredicateType type, bool expectedResult);

    /**
     * 生成恒真谓词
     * @return 不透明谓词
     */
    OpaquePredicate GenerateAlwaysTrue();

    /**
     * 生成恒假谓词
     * @return 不透明谓词
     */
    OpaquePredicate GenerateAlwaysFalse();

    /**
     * 生成数论谓词
     * 基于数学恒等式，如 x^2 mod 4 ∈ {0, 1}
     * @param expectedResult 预期结果
     * @return 不透明谓词
     */
    OpaquePredicate GenerateMathPredicate(bool expectedResult);

    /**
     * 生成指针别名谓词
     * @param expectedResult 预期结果
     * @return 不透明谓词
     */
    OpaquePredicate GeneratePointerAliasPredicate(bool expectedResult);

    /**
     * 生成浮点精度谓词
     * @param expectedResult 预期结果
     * @return 不透明谓词
     */
    OpaquePredicate GenerateFloatPrecisionPredicate(bool expectedResult);

    /**
     * 生成整数溢出谓词
     * 基于整数溢出行为的不透明谓词
     */
    OpaquePredicate GenerateIntegerOverflowPredicate(bool expectedResult);

    /**
     * 生成位操作谓词
     * 如 x & (x-1) == 0 判断2的幂, x ^ x == 0 等
     */
    OpaquePredicate GenerateBitManipulationPredicate(bool expectedResult);

    /**
     * 生成模运算谓词
     * 如 (a+b) mod n == ((a mod n) + (b mod n)) mod n
     */
    OpaquePredicate GenerateModularArithPredicate(bool expectedResult);

    /**
     * 生成栈对齐谓词
     * 利用 ABI 保证的栈对齐特性
     */
    OpaquePredicate GenerateStackAlignmentPredicate(bool expectedResult);

    /**
     * 生成数据依赖谓词
     */
    OpaquePredicate GenerateDataDependentPredicate(bool expectedResult);

    // 代码生成辅助
    std::vector<uint8_t> GenerateBitCheckCode(const OpaquePredicate& pred, bool is64Bit);
    std::vector<uint8_t> GenerateModularCheckCode(const OpaquePredicate& pred, bool is64Bit);
    std::vector<uint8_t> GenerateStackAlignCheckCode(const OpaquePredicate& pred, bool is64Bit);

    // 数学辅助
    uint32_t GenerateRandomValue();
    bool IsPerfectSquare(uint32_t n);
    bool IsPrime(uint32_t n);

    // 成员变量
    // 生成随机为真谓词
    OpaquePredicate GenerateRandomlyTruePredicate(bool expectedResult);

    // 生成数学恒等式谓词
    OpaquePredicate GenerateMathIdentityPredicate(bool expectedResult);

    // 生成条件跳转代码
    BYTE* GenerateConditionalJump(const OpaquePredicate& predicate, uint64_t targetAddress, bool is64Bit, DWORD* jumpSize);

    // 批量生成
    std::vector<OpaquePredicate> GenerateBatch(uint32_t count, float trueRatio);

    uint32_t m_nextId;
    std::mt19937 m_rng;
};

} // namespace CipherShell

#endif // CS_OPAQUE_PREDICATES_H
