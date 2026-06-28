/**
 * CipherShell LLVM Pass - 虚假控制流注入
 * 插入由不透明谓词守护的假分支路径
 */

#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Constants.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace CipherShell {

// ============================================================================
// 不透明谓词生成
// ============================================================================

// 生成恒真谓词: (x * x) % 4 != 2
static Value* createAlwaysTruePredicate(IRBuilder<>& Builder, Function& F) {
    // 获取一个随机变量 x
    AllocaInst* xVar = Builder.CreateAlloca(
        Type::getInt32Ty(F.getContext()), nullptr, "opaque_x");
    Builder.CreateStore(
        ConstantInt::get(Type::getInt32Ty(F.getContext()), 42),
        xVar);
    Value* x = Builder.CreateLoad(Type::getInt32Ty(F.getContext()), xVar);

    // x * x
    Value* x2 = Builder.CreateMul(x, x);

    // (x * x) % 4
    Value* mod4 = Builder.CreateAnd(x2, ConstantInt::get(Type::getInt32Ty(F.getContext()), 3));

    // (x * x) % 4 != 2
    Value* pred = Builder.CreateICmpNE(mod4,
        ConstantInt::get(Type::getInt32Ty(F.getContext()), 2));

    return pred;
}

// ============================================================================
// 虚假控制流注入
// ============================================================================

bool runBogusFlow(Function& F) {
    // 跳过小函数
    if (F.size() < 2) return false;

    LLVMContext& Ctx = F.getContext();
    int injectedCount = 0;

    // 收集基本块（避免在迭代时修改）
    std::vector<BasicBlock*> blocks;
    for (BasicBlock& BB : F) {
        blocks.push_back(&BB);
    }

    for (BasicBlock* BB : blocks) {
        // 跳过入口块
        if (BB == &F.getEntryBlock()) continue;

        // 跳过太小的块
        if (BB->size() < 2) continue;

        // 只对部分块注入（50%概率）
        static std::random_device rd;
        static std::mt19937 gen(rd());
        static std::uniform_int_distribution<int> dis(0, 1);
        if (dis(gen) == 0) continue;

        // 创建假分支块
        BasicBlock* bogusBB = BasicBlock::Create(Ctx, "bogus", &F);

        // 在假块中添加无害代码
        IRBuilder<> bogusBuilder(bogusBB);
        // 添加一些看起来有意义的代码
        Value* dummy = bogusBuilder.CreateAdd(
            ConstantInt::get(Type::getInt32Ty(Ctx), 0),
            ConstantInt::get(Type::getInt32Ty(Ctx), 0),
            "bogus_add");
        bogusBuilder.CreateBr(BB->getSingleSuccessor() ? BB->getSingleSuccessor() : BB);

        // 在原始块开头插入不透明谓词分支
        Instruction* firstInst = &BB->front();
        IRBuilder<> builder(firstInst);

        Value* pred = createAlwaysTruePredicate(builder, F);

        // 条件分支：永远跳转到原始代码，假分支永远不会执行
        builder.CreateCondBr(pred, BB, bogusBB);

        // 移除原始块的第一个指令（现在在分支之后）
        // 注意：这里简化处理

        injectedCount++;
    }

    if (injectedCount > 0) {
        errs() << "[CipherShell] Injected " << injectedCount
               << " bogus blocks into " << F.getName() << "\n";
    }

    return injectedCount > 0;
}

} // namespace CipherShell
