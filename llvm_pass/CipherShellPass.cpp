/**
 * CipherShell LLVM Pass - 主入口
 * 在编译阶段注入代码保护变换
 *
 * 使用方法：
 *   clang -Xclang -load -Xclang libCipherShellPass.so -c input.cpp -o output.o
 *   opt -load-pass-plugin=libCipherShellPass.so -passes="ciphershell" input.bc -o output.bc
 */

#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace CipherShell {

// ============================================================================
// 前向声明
// ============================================================================

bool runFlattening(Function& F);
bool runBogusFlow(Function& F);
bool runInstrSubstitution(Function& F);
bool runStringEncryption(Module& M);

// ============================================================================
// CipherShell Module Pass
// ============================================================================

struct CipherShellModulePass : public PassInfoMixin<CipherShellModulePass> {
    PreservedAnalyses run(Module& M, ModuleAnalysisManager& AM) {
        errs() << "[CipherShell] Processing module: " << M.getName() << "\n";

        bool changed = false;

        // 字符串加密（模块级）
        changed |= runStringEncryption(M);

        // 对每个函数应用变换
        for (Function& F : M) {
            if (F.isDeclaration()) continue;
            if (F.getName().startswith("__cs_")) continue;  // 跳过 CipherShell 内部函数

            errs() << "[CipherShell] Processing function: " << F.getName() << "\n";

            // 控制流平坦化
            changed |= runFlattening(F);

            // 虚假控制流注入
            changed |= runBogusFlow(F);

            // 指令替换
            changed |= runInstrSubstitution(F);
        }

        return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }

    static bool isRequired() { return true; }
};

// ============================================================================
// CipherShell Function Pass
// ============================================================================

struct CipherShellFunctionPass : public PassInfoMixin<CipherShellFunctionPass> {
    PreservedAnalyses run(Function& F, FunctionAnalysisManager& AM) {
        if (F.isDeclaration()) return PreservedAnalyses::all();

        bool changed = false;

        // 控制流平坦化
        changed |= runFlattening(F);

        // 指令替换
        changed |= runInstrSubstitution(F);

        return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }
};

} // namespace CipherShell

// ============================================================================
// Pass 注册（新版 Pass Manager）
// ============================================================================

extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK llvmGetPassPluginInfo() {
    return {
        LLVM_PLUGIN_API_VERSION,
        "CipherShell",
        LLVM_VERSION_STRING,
        [](PassBuilder& PB) {
            // 注册 Module Pass
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager& MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "ciphershell") {
                        MPM.addPass(CipherShell::CipherShellModulePass());
                        return true;
                    }
                    return false;
                }
            );

            // 注册 Function Pass
            PB.registerPipelineParsingCallback(
                [](StringRef Name, FunctionPassManager& FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "ciphershell-func") {
                        FPM.addPass(CipherShell::CipherShellFunctionPass());
                        return true;
                    }
                    return false;
                }
            );

            // 注册优化等级回调
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager& MPM, OptimizationLevel Level) {
                    if (Level != OptimizationLevel::O0) {
                        MPM.addPass(CipherShell::CipherShellModulePass());
                    }
                }
            );
        }
    };
}
