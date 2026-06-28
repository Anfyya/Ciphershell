/**
 * CipherShell LLVM Pass - 字符串加密
 * 编译期加密字符串字面量，运行期解密
 */

#include "llvm/Pass.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/raw_ostream.h"

#include <vector>
#include <random>

using namespace llvm;

namespace CipherShell {

// ============================================================================
// 字符串加密
// ============================================================================

static uint8_t generateRandomKey() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<int> dis(1, 255);
    return (uint8_t)dis(gen);
}

static std::vector<uint8_t> encryptString(const std::string& str, uint8_t key) {
    std::vector<uint8_t> encrypted;
    for (char c : str) {
        encrypted.push_back((uint8_t)c ^ key);
    }
    encrypted.push_back(0 ^ key);  // null terminator
    return encrypted;
}

// ============================================================================
// 字符串加密 Pass
// ============================================================================

bool runStringEncryption(Module& M) {
    LLVMContext& Ctx = M.getContext();
    bool changed = false;

    // 收集需要加密的全局字符串
    std::vector<GlobalVariable*> stringGlobals;

    for (GlobalVariable& GV : M.globals()) {
        if (!GV.hasInitializer()) continue;

        // 检查是否是字符串常量
        ConstantDataArray* CDA = dyn_cast<ConstantDataArray>(GV.getInitializer());
        if (!CDA) continue;
        if (!CDA->isString()) continue;

        // 跳过空字符串
        StringRef str = CDA->getAsString();
        if (str.empty()) continue;

        // 跳过太短的字符串
        if (str.size() < 3) continue;

        stringGlobals.push_back(&GV);
    }

    if (stringGlobals.empty()) return false;

    // 生成解密函数
    // void __cs_decrypt_string(uint8_t* data, size_t len, uint8_t key)
    FunctionType* decryptFuncType = FunctionType::get(
        Type::getVoidTy(Ctx),
        {PointerType::get(Type::getInt8Ty(Ctx), 0),
         Type::getInt64Ty(Ctx),
         Type::getInt8Ty(Ctx)},
        false);

    FunctionCallee decryptFunc = M.getOrInsertFunction(
        "__cs_decrypt_string", decryptFuncType);

    // 对每个字符串进行加密
    for (GlobalVariable* GV : stringGlobals) {
        ConstantDataArray* CDA = cast<ConstantDataArray>(GV->getInitializer());
        StringRef str = CDA->getAsString();

        // 生成随机密钥
        uint8_t key = generateRandomKey();

        // 加密字符串
        std::vector<uint8_t> encrypted = encryptString(str.str(), key);

        // 创建新的常量
        Constant* encryptedConst = ConstantDataArray::get(Ctx, encrypted);

        // 替换全局变量的初始化器
        GV->setInitializer(encryptedConst);
        GV->setConstant(false);  // 需要修改，所以不能是 const

        // 在 main 函数开头插入解密调用
        Function* mainFunc = M.getFunction("main");
        if (mainFunc && !mainFunc->isDeclaration()) {
            IRBuilder<> Builder(&*mainFunc->getEntryBlock().getFirstInsertionPt());

            // 计算字符串长度
            Value* strPtr = Builder.CreatePointerCast(GV,
                PointerType::get(Type::getInt8Ty(Ctx), 0));
            Value* len = ConstantInt::get(Type::getInt64Ty(Ctx), str.size() + 1);
            Value* keyVal = ConstantInt::get(Type::getInt8Ty(Ctx), key);

            // 调用解密函数
            Builder.CreateCall(decryptFunc, {strPtr, len, keyVal});
        }

        changed = true;
    }

    if (changed) {
        errs() << "[CipherShell] Encrypted " << stringGlobals.size()
               << " string(s)\n";
    }

    return changed;
}

} // namespace CipherShell
