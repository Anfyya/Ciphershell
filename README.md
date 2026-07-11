# CipherShell

CipherShell 是面向 Windows PE32/PE32+ 的代码保护器。项目使用 Zydis 作为唯一正式 x86/x64 解码后端，自有统一指令 IR、CFG、x86/x64 → VM bytecode Translator、随机化 VM ISA、认证加密 metadata/bytecode、x86/x64 runtime、trampoline、native/SIMD/x87 bridge 和 PE 重建链路。

> 当前仓库仍处于开发和静态验证阶段。编译通过不等同于所有目标程序均已完成运行验证；不支持或无法证明安全的函数会 fail-closed，而不是静默降级为 native 或 NOP。

## 构建环境

- Windows 10/11
- Visual Studio 2022，安装“使用 C++ 的桌面开发”与 Windows 10/11 SDK
- CMake 3.20+
- NASM 2.16+
- Git（需要递归获取 Zydis/Zycore 子模块）

## 克隆

```powershell
git clone --recursive https://github.com/Anfyya/Ciphershell.git
cd Ciphershell
```

已经普通克隆但缺少第三方子模块时：

```powershell
git submodule update --init --recursive
```

Zydis 固定为 `v4.1.0` 对应提交 `569320ad3c4856da13b9dbf1f0d9e20bda63870e`，其 Zycore 子模块由 Zydis 自己固定。

## 使用 VS2022/MSVC 编译

CMake 负责生成和维护 VS2022 工程，真正执行编译的仍是 Visual Studio 2022 自带的 MSVC。

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

也可以直接运行仓库根目录的 `build_win.bat`。脚本会从自身位置构建，
自动发现 VS2022/CMake，并将日志写入 `build/build_Release.log`；不再依赖
任何开发者机器的固定盘符。若 NASM 不在 `PATH`，可先设置
`CS_NASM_EXECUTABLE` 为 `nasm.exe` 的完整路径。

测试目标默认参与编译，但依据本仓库的验证边界，运行测试可执行文件和
加壳样本仍由使用者在隔离环境中手动完成。历史 `decryptor` 只保留为显式
诊断目标，默认不构建；它没有生产恢复密钥契约，也不会再复制输入文件并
误报“解密完成”。如需审查该诊断目标，可配置
`-DCS_BUILD_LEGACY_DECRYPTOR=ON`。

生成的解决方案位于 `build/CipherShell.sln`，也可以直接用 VS2022 打开。构建系统会从当前 CMake/VS2022 generator 自动发现 MSVC 与 Windows SDK，不依赖开发者机器上的固定绝对路径。

## 基本用法

```powershell
.\build\bin\Release\ciphershell.exe input.exe -o protected.exe -c config\default.toml -v
```

配置以模块化开关为准；`--level` 仅是快捷 preset，不是核心架构。主要配置位于：

- `config/default.toml`
- `config/full_example.toml`

## 关键架构

```text
PE32 / PE32+
  → Zydis 解码
  → CipherShell Instruction/Operand IR
  → 函数发现与 CFG
  → VM Translator
  → 随机 opcode/register/handler 入口布局
  → 认证加密 metadata + bytecode
  → x86/x64 runtime + trampoline + bridge
  → PEEmitter / PERebuilder
  → 最终 PE 重新解析与静态复验
```

当前 VM 链路包含：

- Zydis 唯一生产解码路径，无手写 ModRM/SIB/REX fallback
- x86/x64 函数发现，包含 `.pdata`、OEP、exports、TLS、明确 RVA 与 direct-call roots
- 随机构建种子、opcode/register permutation、handler slot/variant 变异与不可达 junk handler
- 认证 metadata、按函数派生的 bytecode 密钥与完整性标签
- x86/x64 runtime、CALL/RET、guest stack；Translator 只允许能静态证明属于当前 VM 控制流的直接 VM CALL，external native / import / indirect register / indirect memory CALL 一律翻译失败
- SIMD/x87 严格指令桥与 x64 unwind/CFG 静态链接检查
- final output 重新解析后复验 metadata、bytecode、trampoline、patch、imports、unwind、CFG 与 W^X

## Fail-closed 模块

以下模块当前不具备完整生产语义闭环，默认关闭，且 protection level / preset 不会隐式开启。
用户显式开启时，`CapabilityChecker` 会在任何 PE 内容、section、header、入口点、导入表或文件偏移被修改之前以 fatal issue 拒绝，输出状态只能是 `rejected` / `skipped` / `disabled`，绝不出现 `applied` 或 `partial`：

- **section encryption** —— 未认证算法 + 可恢复密钥，无生产闭环
- **startup string encryption** —— 未认证算法 + 可恢复密钥，无生产闭环
- **import protection** —— 仅追加假导入并保留真实 IAT，未改写 callsite
- **CFG flattening** —— 缺少 RIP-relative/CALL 重定位、ABI、unwind、CFG 修复，无法保持原函数语义
- **bogus flow** —— 无法证明原函数语义保持

`control_flow` 总开关与 `flattening` / `bogus` 子开关必须一致：总开关开启但无子功能（no-op）、或子功能开启却绕过总开关，均被 fatal 拒绝。

## 目录

```text
Ciphershell/
├── CMakeLists.txt
├── ciphershell.md                 # 详细设计文档
├── config/                        # 模块化配置
├── packer/                        # PE 分析、变换、VM 生成与主程序
├── runtime/                       # x86/x64 VM runtime 源码
├── stub/                          # 启动与辅助 stub
├── third_party/zydis/             # 固定版本 Git submodule
├── tests/                         # 测试源码与静态分析脚本
└── tools/                         # 辅助工具源码
```

## 验证边界

项目维护过程默认只进行：

- CMake configure
- Release 编译
- `git diff --check`
- 静态反汇编和 PE 结构检查

加壳产物的实际运行由使用者在隔离测试环境中完成。任何静态检查未通过的 VM/loader 链路都不得标记为 `applied`。

## 使用范围

仅用于合法的软件保护、研究和学习。不得用于隐藏恶意代码、规避安全检测或侵犯他人软件权益。
