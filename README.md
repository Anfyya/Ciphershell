# CipherShell

**自研高强度代码保护壳**

## 项目概述

CipherShell 是一款自研的 Windows 可执行文件保护系统，定位为**高强度加密壳 / 代码保护器（Protector）**。

### 核心特性

- **零特征重叠**：与市面所有已知壳在二进制特征、VM 架构、section 命名、stub 签名上完全不同
- **最大化反逆向**：多层嵌套保护架构，使静态分析和动态调试均极度困难
- **可控的保护粒度**：用户自选函数级 / 基本块级 / 指令级保护，以及保护强度等级
- **双模式输入**：支持导入编译后的 PE 文件（EXE/DLL），以及可选的源码级保护

## 保护等级

| 等级 | 名称 | 包含的保护措施 | 典型性能开销 | 适用场景 |
|------|------|---------------|-------------|---------|
| L1 | **Guard** | Section 加密 + 字符串加密 + 导入表混淆 + 基础反调试 | ~1.05x | 性能敏感的主循环 |
| L2 | **Shield** | L1 + 控制流平坦化 + 常量拆分 | ~2-3x | 一般业务逻辑 |
| L3 | **Armor** | L2 + 虚假控制流注入 + 不透明谓词 + 混合变异 | ~5-8x | 重要逻辑 |
| L4 | **Fortress** | L3 + 单层代码虚拟化（VM）+ Handler 变异 | ~15-30x | 核心算法、授权验证 |
| L5 | **Citadel** | L4 + 多层嵌套 VM + 全维度变异 + Nanomite + 完整性互锁 | ~50-100x+ | 最高价值代码 |

## 构建说明

### 环境要求

- Windows 10/11
- Visual Studio 2022 (MSVC)
- CMake 3.20+
- NASM 2.16+

### 构建步骤

```bash
# 克隆项目
git clone https://github.com/yourusername/CipherShell.git
cd CipherShell

# 创建构建目录
mkdir build
cd build

# 生成项目文件
cmake .. -G "Visual Studio 17 2022" -A x64

# 编译
cmake --build . --config Release
```

### 使用方法

```bash
# 基本用法
ciphershell input.exe -o protected.exe

# 指定保护等级
ciphershell input.exe -o protected.exe -l 3

# 使用配置文件
ciphershell input.exe -o protected.exe -c config.toml

# 显示详细信息
ciphershell input.exe -o protected.exe -v
```

## 项目结构

```
CipherShell/
├── CMakeLists.txt
├── README.md
├── ciphershell.md                    # 设计文档
│
├── packer/                          # 加壳器主程序
│   ├── main.cpp                     # 入口 + CLI 解析
│   ├── pe_parser/                   # PE 解析器
│   ├── transforms/                  # 变换引擎
│   └── signature/                   # 签名消除
│
├── stub/                            # 运行时 Stub
│   ├── stage0/                      # 初始解密器
│   ├── stage1/                      # 运行时引擎
│   └── vm/                          # Mirage VM 引擎
│
├── third_party/                     # 第三方库
│   └── chacha20.h                   # ChaCha20 加密实现
│
└── tests/                           # 测试
    ├── test_pe_parser.cpp           # PE 解析器测试
    ├── test_vm_correctness.cpp      # VM 正确性测试
    └── samples/                     # 测试样本
```

## 技术架构

### 模块组成

1. **PE 解析器**：自研 PE 解析器，支持 PE32/PE32+，完整解析所有 Data Directory
2. **Section 加密器**：使用 ChaCha20 流密码加密代码段和数据段
3. **导入表混淆**：API Hash 化 + 假导入表 + 延迟导入干扰
4. **重定位修复器**：处理重定位表，支持多种重定位类型
5. **Stub 生成器**：生成运行时解密/加载代码
6. **VM 引擎 (Mirage)**：混合架构虚拟机，支持栈+寄存器模式

### 反调试技术

- 时序检测（RDTSC、QPC）
- 状态检测（PEB、硬件断点）
- 完整性检测（代码段 CRC、API 入口点扫描）
- 隐式响应（密钥投毒、延迟炸弹）

## 开发路线图

- [x] Phase 1: 基础框架
  - [x] PE Parser
  - [x] PE Rebuilder
  - [x] Section 加密
  - [x] Stub Stage0
  - [x] API Hash Resolve
  - [x] 导入表重建
  - [x] 重定位修复

- [ ] Phase 2: 反调试 + 字符串/导入混淆
  - [ ] 字符串加密
  - [ ] 完整的导入表混淆
  - [ ] 反调试检测矩阵
  - [ ] 隐式响应机制

- [ ] Phase 3: 控制流混淆
  - [ ] Zydis 反汇编引擎集成
  - [ ] CFG 构建器
  - [ ] 控制流平坦化
  - [ ] 不透明谓词库
  - [ ] 虚假控制流注入

- [ ] Phase 4: VM 引擎 Mirage
  - [ ] VM 上下文结构
  - [ ] Dispatcher（三种模式）
  - [ ] Handler 集（约 60 个）
  - [ ] EFLAGS 模拟
  - [ ] x86→bytecode 转译器

- [ ] Phase 5: 高级特性 + DLL 支持
  - [ ] VM 嵌套
  - [ ] Nanomite 技术
  - [ ] DLL 加壳支持
  - [ ] 热点分析

## 许可证

本项目仅供学习和研究使用，请勿用于非法用途。

## 致谢

- Zydis - x86/x64 反汇编引擎
- toml++ - TOML 解析库
- ChaCha20 - 流密码算法
