/**
 * CipherShell LLVM Pass - 指令替换
 * 将简单指令替换为语义等价的复杂指令序列
 */

#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Constants.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace CipherShell {

// ============================================================================
// 指令替换规则
// ============================================================================

// add x, y → sub x, (sub 0, y)
static bool replaceAdd(BinaryOperator& BO) {
    if (BO.getOpcode() != Instruction::Add) return false;

    IRBuilder<> Builder(&BO);
    Value* op1 = BO.getOperand(0);
    Value* op2 = BO.getOperand(1);

    // add x, y → sub x, (sub 0, y)
    Value* negY = Builder.CreateSub(
        ConstantInt::get(op2->getType(), 0), op2, "neg_y");
    Value* result = Builder.CreateSub(op1, negY, "add_as_sub");

    BO.replaceAllUsesWith(result);
    BO.eraseFromParent();

    return true;
}

// sub x, y → add x, (sub 0, y)
static bool replaceSub(BinaryOperator& BO) {
    if (BO.getOpcode() != Instruction::Sub) return false;

    IRBuilder<> Builder(&BO);
    Value* op1 = BO.getOperand(0);
    Value* op2 = BO.getOperand(1);

    // sub x, y → add x, (sub 0, y)
    Value* negY = Builder.CreateSub(
        ConstantInt::get(op2->getType(), 0), op2, "neg_y");
    Value* result = Builder.CreateAdd(op1, negY, "sub_as_add");

    BO.replaceAllUsesWith(result);
    BO.eraseFromParent();

    return true;
}

// and x, y → not(or(not x, not y))
static bool replaceAnd(BinaryOperator& BO) {
    if (BO.getOpcode() != Instruction::And) return false;

    IRBuilder<> Builder(&BO);
    Value* op1 = BO.getOperand(0);
    Value* op2 = BO.getOperand(1);

    Value* not1 = Builder.CreateNot(op1, "not_x");
    Value* not2 = Builder.CreateNot(op2, "not_y");
    Value* orVal = Builder.CreateOr(not1, not2, "or_not");
    Value* result = Builder.CreateNot(orVal, "and_as_nor");

    BO.replaceAllUsesWith(result);
    BO.eraseFromParent();

    return true;
}

// or x, y → not(and(not x, not y))
static bool replaceOr(BinaryOperator& BO) {
    if (BO.getOpcode() != Instruction::Or) return false;

    IRBuilder<> Builder(&BO);
    Value* op1 = BO.getOperand(0);
    Value* op2 = BO.getOperand(1);

    Value* not1 = Builder.CreateNot(op1, "not_x");
    Value* not2 = Builder.CreateNot(op2, "not_y");
    Value* andVal = Builder.CreateAnd(not1, not2, "and_not");
    Value* result = Builder.CreateNot(andVal, "or_as_nand");

    BO.replaceAllUsesWith(result);
    BO.eraseFromParent();

    return true;
}

// shl x, 1 → add x, x
static bool replaceShl1(BinaryOperator& BO) {
    if (BO.getOpcode() != Instruction::Shl) return false;

    ConstantInt* CI = dyn_cast<ConstantInt>(BO.getOperand(1));
    if (!CI || CI->getZExtValue() != 1) return false;

    IRBuilder<> Builder(&BO);
    Value* op = BO.getOperand(0);

    Value* result = Builder.CreateAdd(op, op, "shl1_as_add");
    BO.replaceAllUsesWith(result);
    BO.eraseFromParent();

    return true;
}

// ============================================================================
// 主替换函数
// ============================================================================

bool runInstrSubstitution(Function& F) {
    bool changed = false;

    // 遍历所有基本块
    for (BasicBlock& BB : F) {
        // 遍历所有指令（需要安全迭代）
        for (auto it = BB.begin(); it != BB.end(); ) {
            Instruction& I = *it++;

            // 二元运算
            if (BinaryOperator* BO = dyn_cast<BinaryOperator>(&I)) {
                switch (BO->getOpcode()) {
                    case Instruction::Add:
                        changed |= replaceAdd(*BO);
                        break;
                    case Instruction::Sub:
                        changed |= replaceSub(*BO);
                        break;
                    case Instruction::And:
                        changed |= replaceAnd(*BO);
                        break;
                    case Instruction::Or:
                        changed |= replaceOr(*BO);
                        break;
                    case Instruction::Shl:
                        changed |= replaceShl1(*BO);
                        break;
                    default:
                        break;
                }
            }
        }
    }

    if (changed) {
        errs() << "[CipherShell] Substituted instructions in " << F.getName() << "\n";
    }

    return changed;
}

} // namespace CipherShell
