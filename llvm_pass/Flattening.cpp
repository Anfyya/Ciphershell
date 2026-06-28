/**
 * CipherShell LLVM Pass - 控制流平坦化
 * 将函数的基本块重组为 switch-case 分发结构
 */

#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Constants.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Support/raw_ostream.h"

#include <vector>
#include <random>
#include <algorithm>

using namespace llvm;

namespace CipherShell {

// ============================================================================
// 辅助函数
// ============================================================================

static uint32_t generateRandomState() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<uint32_t> dis(1, 0xFFFFFFFF);
    return dis(gen);
}

// ============================================================================
// 控制流平坦化实现
// ============================================================================

bool runFlattening(Function& F) {
    // 跳过小函数
    if (F.size() < 3) return false;

    // 收集所有基本块（跳过入口块）
    std::vector<BasicBlock*> blocks;
    for (BasicBlock& BB : F) {
        if (&BB == &F.getEntryBlock()) continue;
        blocks.push_back(&BB);
    }

    if (blocks.empty()) return false;

    // 为每个块分配随机 state ID
    std::map<BasicBlock*, uint32_t> stateMap;
    for (BasicBlock* BB : blocks) {
        stateMap[BB] = generateRandomState();
    }

    // 获取入口块
    BasicBlock& entryBB = F.getEntryBlock();

    // 创建 dispatcher 基本块
    LLVMContext& Ctx = F.getContext();
    BasicBlock* dispatcherBB = BasicBlock::Create(Ctx, "dispatcher", &F);

    // 创建状态变量 alloca（在入口块开头）
    IRBuilder<> entryBuilder(&*entryBB.getFirstInsertionPt());
    AllocaInst* stateVar = entryBuilder.CreateAlloca(
        Type::getInt32Ty(Ctx), nullptr, "state");

    // 初始化状态变量
    entryBuilder.CreateStore(
        ConstantInt::get(Type::getInt32Ty(Ctx), stateMap[blocks[0]]),
        stateVar);

    // 跳转到 dispatcher
    entryBB.getTerminator()->eraseFromParent();
    IRBuilder<> entryTermBuilder(&entryBB);
    entryTermBuilder.CreateBr(dispatcherBB);

    // 构建 dispatcher: switch(load(stateVar))
    IRBuilder<> dispatcherBuilder(dispatcherBB);
    LoadInst* stateLoad = dispatcherBuilder.CreateLoad(
        Type::getInt32Ty(Ctx), stateVar, "state_val");

    // 创建 default 分支（回到 dispatcher）
    BasicBlock* defaultBB = BasicBlock::Create(Ctx, "default", &F);
    IRBuilder<> defaultBuilder(defaultBB);
    defaultBuilder.CreateBr(dispatcherBB);

    SwitchInst* switchInst = dispatcherBuilder.CreateSwitch(stateLoad, defaultBB);

    // 为每个基本块创建 case 分支
    for (BasicBlock* BB : blocks) {
        uint32_t stateId = stateMap[BB];

        // 创建一个包装块
        BasicBlock* wrapperBB = BasicBlock::Create(
            Ctx, "case_" + Twine::utohexstr(stateId), &F);

        // 将原始块的内容移动到包装块
        // 注意：这里简化处理，实际需要更复杂的代码移动

        // 添加 case 到 switch
        switchInst->addCase(
            ConstantInt::get(Type::getInt32Ty(Ctx), stateId),
            wrapperBB);

        // 在包装块末尾，更新状态变量并跳转回 dispatcher
        // 需要根据原始块的后继确定下一个状态
        IRBuilder<> wrapperBuilder(wrapperBB);

        // 复制原始块的指令（简化：直接跳转到原始块）
        wrapperBuilder.CreateBr(BB);

        // 在原始块末尾，更新状态变量
        TerminatorInst* term = BB->getTerminator();
        if (term) {
            // 如果是条件分支
            if (BranchInst* br = dyn_cast<BranchInst>(term)) {
                if (br->isConditional()) {
                    // 条件分支：根据条件设置不同的状态
                    BasicBlock* trueBB = br->getSuccessor(0);
                    BasicBlock* falseBB = br->getSuccessor(1);

                    uint32_t trueState = stateMap.count(trueBB) ?
                        stateMap[trueBB] : generateRandomState();
                    uint32_t falseState = stateMap.count(falseBB) ?
                        stateMap[falseBB] : generateRandomState();

                    IRBuilder<> termBuilder(term);
                    Value* cond = br->getCondition();

                    // 选择下一个状态
                    Value* nextState = termBuilder.CreateSelect(cond,
                        ConstantInt::get(Type::getInt32Ty(Ctx), trueState),
                        ConstantInt::get(Type::getInt32Ty(Ctx), falseState));

                    term->eraseFromParent();
                    termBuilder.CreateStore(nextState, stateVar);
                    termBuilder.CreateBr(dispatcherBB);
                } else {
                    // 无条件分支
                    BasicBlock* succBB = br->getSuccessor(0);
                    uint32_t nextState = stateMap.count(succBB) ?
                        stateMap[succBB] : generateRandomState();

                    term->eraseFromParent();
                    IRBuilder<> termBuilder(BB);
                    termBuilder.CreateStore(
                        ConstantInt::get(Type::getInt32Ty(Ctx), nextState),
                        stateVar);
                    termBuilder.CreateBr(dispatcherBB);
                }
            }
        }
    }

    errs() << "[CipherShell] Flattened function: " << F.getName()
           << " (" << blocks.size() << " blocks)\n";

    return true;
}

} // namespace CipherShell
