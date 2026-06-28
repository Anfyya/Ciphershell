# CipherShell LLVM Pass CMakeLists.txt
# 源码级保护 LLVM Pass

cmake_minimum_required(VERSION 3.20)

# 查找 LLVM
find_package(LLVM REQUIRED CONFIG)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

# 包含 LLVM 头文件
include_directories(${LLVM_INCLUDE_DIRS})
separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND ${LLVM_DEFINITIONS})
add_definitions(${LLVM_DEFINITIONS_LIST})

# 添加 Pass 库
add_library(CipherShellPass SHARED
    CipherShellPass.cpp
    Flattening.cpp
    BogusFlow.cpp
    InstrSubstitution.cpp
    StringEncryption.cpp
)

# 链接 LLVM 库
target_link_libraries(CipherShellPass PRIVATE
    LLVMCore
    LLVMSupport
    LLVMAnalysis
    LLVMTransformUtils
    LLVMInstCombine
)

# 设置输出名称
set_target_properties(CipherShellPass PROPERTIES
    OUTPUT_NAME "CipherShellPass"
    PREFIX "lib"
)

# 安装规则
install(TARGETS CipherShellPass
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)
