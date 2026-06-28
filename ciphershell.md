# CipherShell — 自研高强度代码保护壳 设计书

> **项目代号**：CipherShell  
> **版本**：v0.1 Draft  
> **作者**：安方怡（yjln / Anfyya）  
> **日期**：2026-06-27  
> **状态**：设计阶段

---

## 一、项目概述

### 1.1 项目目标

CipherShell 是一款自研的 Windows 可执行文件保护系统，定位为**高强度加密壳 / 代码保护器（Protector）**。核心设计哲学：

- **零特征重叠**：与市面所有已知壳（VMProtect、Themida/WinLicense、Obsidium、ASPack、UPX、PELock、Enigma 等）在二进制特征、VM 架构、section 命名、stub 签名上完全不同
- **最大化反逆向**：多层嵌套保护架构，使静态分析（IDA Pro、Ghidra、Binary Ninja）和动态调试（x64dbg、WinDbg、Frida）均极度困难
- **可控的保护粒度**：用户自选函数级 / 基本块级 / 指令级保护，以及保护强度等级，在安全性与运行时性能之间自由权衡
- **双模式输入**：支持导入编译后的 PE 文件（EXE/DLL，**必须实现**），以及可选的源码级保护（编译器插件/预处理方式）

### 1.2 与现有产品的差异化策略

| 维度 | VMProtect | Themida | CipherShell（本项目） |
|------|-----------|---------|----------------------|
| VM 架构 | 基于栈的 VM，handler 模式相对固定 | RISC 风格 VM，FISH/TIGER 虚拟机 | 混合架构 VM（栈+寄存器），每次生成完全不同的 ISA |
| 特征签名 | `.vmp0`/`.vmp1` section，已被大量签名库收录 | 固定 stub 入口模式，Oreans watermark | 无固定 section 名、无固定入口模式、无 watermark，所有元数据随机化 |
| 反调试 | 成熟但模式已被广泛研究和绕过 | 强但 anti-anti-debug 工具链完善 | 基于不可预测时序 + 密钥派生的隐式检测，无显式 API 调用可 hook |
| 代码变异 | Handler 多态但结构可识别 | 代码变形强度高 | 多维变异（opcode 编码 + handler AST 级变形 + 执行语义等价替换） |
| 性能控制 | 有限的粒度选择 | 粗粒度选择 | 五级保护等级 + 函数级精确标注 + 自动热点分析建议 |

### 1.3 支持目标

- **输入格式**：PE32 (x86)、PE32+ (x64) 的 EXE 和 DLL；可选 C/C++ 源码（通过 LLVM Pass 或预处理器）
- **操作系统**：Windows 7 SP1 ~ Windows 11（含最新版本）
- **开发语言**：Packer 端使用 C++ (C++17)；Stub/VM 引擎使用 C (无 CRT) + NASM 汇编
- **构建工具链**：MSVC (x86/x64) + NASM + CMake

---

## 二、总体架构

### 2.1 系统架构全景

```
┌─────────────────────────────────────────────────────────────────────┐
│                        CipherShell Protector                        │
│                                                                     │
│  ┌───────────┐   ┌──────────────┐   ┌──────────────┐              │
│  │ 输入层     │──→│ 分析层        │──→│ 保护层        │              │
│  │           │   │              │   │              │              │
│  │ PE Parser │   │ 反汇编引擎    │   │ 代码虚拟化    │              │
│  │ COFF 解析 │   │ CFG 构建器    │   │ 控制流混淆    │              │
│  │ 源码接口   │   │ 数据流分析    │   │ 变异引擎      │              │
│  │ 配置解析   │   │ 热点标注      │   │ 数据加密      │              │
│  └───────────┘   └──────────────┘   │ 反调试注入    │              │
│                                     └──────┬───────┘              │
│                                            │                      │
│                                     ┌──────▼───────┐              │
│                                     │ 输出层        │              │
│                                     │              │              │
│                                     │ PE 重建器    │              │
│                                     │ Stub 链接器  │              │
│                                     │ 签名消除器   │              │
│                                     └──────────────┘              │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.2 数据流

```
                 ┌──────────────────────────────────┐
                 │        输入阶段                    │
                 │  原始 PE ──→ PE Parser             │
                 │  保护配置 ──→ Config Parser         │
                 │  [可选] 源码 ──→ LLVM Pass         │
                 └──────────────┬───────────────────┘
                                │
                 ┌──────────────▼───────────────────┐
                 │        分析阶段                    │
                 │  反汇编 ──→ 指令流                 │
                 │  CFG 构建 ──→ 基本块图             │
                 │  标记目标函数/区域                  │
                 │  分析导入表/重定位表/资源            │
                 └──────────────┬───────────────────┘
                                │
                 ┌──────────────▼───────────────────┐
                 │        变换阶段（按保护等级）       │
                 │                                   │
                 │  L1: 代码段 XOR 加密              │
                 │  L2: + 控制流平坦化               │
                 │  L3: + 虚假控制流注入             │
                 │  L4: + 代码虚拟化 (VM)            │
                 │  L5: + 多层嵌套 VM + 全变异       │
                 │                                   │
                 │  各等级均叠加：                     │
                 │    反调试逻辑注入                   │
                 │    导入表混淆                      │
                 │    字符串加密                      │
                 │    数据段加密                      │
                 └──────────────┬───────────────────┘
                                │
                 ┌──────────────▼───────────────────┐
                 │        输出阶段                    │
                 │  Stub 生成（变异后）               │
                 │  Section 布局（随机化）             │
                 │  PE 头重建 + 校验                  │
                 │  特征消除 + 最终写出               │
                 └──────────────────────────────────┘
```

---

## 三、模块详细设计

### 3.1 输入层

#### 3.1.1 PE 解析器（PE Parser）

自研 PE 解析器，不依赖第三方库（避免引入可被识别的解析特征）。

**功能清单**：

- 解析 DOS Header、NT Headers（x86/x64 双模式）
- 解析所有 Section Headers，保留原始属性
- 完整解析 Data Directory 的全部 16 项：
  - 导入表（Import Table / IAT / ILT）
  - 导出表（Export Table）
  - 重定位表（Base Relocation Table）
  - 资源表（Resource Table）
  - TLS 表（Thread Local Storage）
  - 异常处理表（Exception Directory，x64 必需）
  - 调试目录（Debug Directory）—— 解析后删除
  - 延迟导入表（Delay Import）
  - CLR Header（检测 .NET 程序并拒绝/提示）
  - Load Config（SEH/CFG/RF Guard 信息）
  - Bound Import（解析后丢弃）
- 验证 PE 完整性：checksum、overlay 数据、签名（Authenticode）
- Rich Header 解析与可选删除（消除编译器指纹）

**数据结构**：

```c
typedef struct _CS_PE_IMAGE {
    // 原始文件
    BYTE*                   rawData;
    DWORD                   rawSize;
    
    // 解析后的头
    PIMAGE_DOS_HEADER       dosHeader;
    PIMAGE_NT_HEADERS64     ntHeaders;      // 统一用64位结构，x86时做适配
    PIMAGE_SECTION_HEADER   sections;
    WORD                    numSections;
    BOOL                    is64Bit;
    
    // 解析后的目录
    CS_IMPORT_TABLE         imports;         // 解析后的导入表
    CS_EXPORT_TABLE         exports;         // 解析后的导出表
    CS_RELOC_TABLE          relocs;          // 解析后的重定位表
    CS_RESOURCE_TREE        resources;       // 解析后的资源树
    CS_TLS_INFO             tls;             // TLS回调信息
    CS_EXCEPTION_TABLE      exceptions;      // x64异常处理
    CS_LOAD_CONFIG          loadConfig;      // CFG/RF Guard信息
    
    // 元数据
    BOOL                    hasOverlay;
    DWORD                   overlayOffset;
    BOOL                    hasSignature;
    BOOL                    hasRichHeader;
    BOOL                    isDotNet;
} CS_PE_IMAGE;
```

#### 3.1.2 保护配置系统

使用 TOML 格式的配置文件定义保护策略（选择 TOML 而非 JSON/YAML，因为可读性好且解析库轻量）。

```toml
# CipherShell 保护配置示例

[global]
protection_level = 3              # 全局默认保护等级 1-5
strip_debug_info = true           # 删除所有调试信息
strip_rich_header = true          # 删除 Rich Header（编译器指纹）
strip_timestamps = true           # 时间戳归零
randomize_section_names = true    # Section 名称随机化
anti_debug_mode = "implicit"      # "explicit" | "implicit" | "hybrid"
string_encryption = true          # 全局字符串加密
import_obfuscation = true         # 导入表混淆
resource_encryption = false       # 资源加密（可能影响兼容性）

[vm]
register_count = 24               # 虚拟寄存器数量（16-64）
stack_size = 0x20000              # 虚拟栈大小
opcode_width = "variable"         # "fixed_8" | "fixed_16" | "variable"
handler_mutation = true           # Handler 代码变异
bytecode_encryption = "rolling"   # "none" | "xor" | "rolling" | "aes_ctr"
embed_junk_handlers = true        # 嵌入无意义的假 handler 干扰分析

[anti_debug]
timing_checks = true              # 时序检测
hardware_bp_detection = true      # 硬件断点检测
software_bp_detection = true      # INT3 / 0xCC 扫描
memory_integrity = true           # 代码完整性校验
debugger_window_scan = false      # 扫描调试器窗口类名（可选，易被绕过）
parent_process_check = true       # 父进程检测
thread_hiding = true              # NtSetInformationThread HideFromDebugger
kernel_debugger_check = true      # 内核调试器检测

[anti_dump]
erase_pe_header = true            # 运行时擦除 PE 头
section_permission_guard = true   # 动态权限管理
nanomite_patches = true           # INT3 Nanomite 技术

[performance]
auto_hotspot_analysis = true      # 自动分析热点函数并降低其保护等级
max_vm_overhead_ratio = 15.0      # VM 执行最大允许倍率（超过则自动降级）

# 函数级精确控制
[[function_overrides]]
pattern = "main"                  # 函数名匹配（支持通配符）
level = 5                         # 覆盖为最高保护

[[function_overrides]]
pattern = "render_*"              # 渲染相关函数
level = 1                         # 性能敏感，仅做基础加密

[[function_overrides]]
pattern = "license_check*"        # 授权验证函数
level = 5                         # 最高保护
vm_nesting = 2                    # 双层 VM 嵌套

[[function_overrides]]
pattern = "crypto_*"              # 已有加密函数
level = 2                         # 避免过度保护影响性能
```

#### 3.1.3 源码模式接口（可选实现）

通过 LLVM Pass 在编译阶段注入保护。本质是 **IR 级别的控制流混淆**，在编译器生成机器码之前完成变换。

**实现方式**：编写自定义 LLVM Pass（ModulePass / FunctionPass），在 `opt` 阶段插入。

**支持的 IR 级变换**：

- **控制流平坦化（Control Flow Flattening）**：将所有基本块重组为 switch-case 分发结构
- **虚假控制流（Bogus Control Flow）**：插入永不触发的分支路径 + 不透明谓词
- **指令替换（Instruction Substitution）**：`add` → 等价的 `sub + not` 组合等
- **常量拆分（Constant Unfolding）**：立即数拆分为多步运算
- **字符串加密**：编译期加密字符串字面量，运行期解密
- **函数调用间接化**：直接 call 替换为函数指针表间接调用

**与二进制模式的关系**：源码模式产出的目标文件（.obj / .o）可以正常链接为 PE，然后再经过二进制模式的 VM 保护。两层保护可叠加。

```
源码 ──→ [LLVM Pass: CFG混淆 + 指令替换] ──→ .obj ──→ 链接 ──→ EXE ──→ [CipherShell 二进制保护] ──→ 最终 EXE
```

> **注**：源码模式实现优先级低于二进制模式。若自动化实现存在困难，可仅提供 LLVM Pass 源码模板和集成指南，由用户手动配置编译流程。

---

### 3.2 分析层

#### 3.2.1 反汇编引擎

集成 **Zydis**（选择理由：纯 C、无依赖、维护活跃、x86/x64 全支持、许可证友好 MIT）。

**功能**：

- 线性扫描（Linear Sweep）+ 递归下降（Recursive Descent）双模式反汇编
- 完整解码每条指令的操作数类型、寻址模式、前缀
- 识别函数边界（通过 prologue/epilogue 模式 + 交叉引用分析）
- 标记所有分支目标地址，构建跳转关系图

#### 3.2.2 控制流图构建器（CFG Builder）

```c
typedef struct _CS_BASIC_BLOCK {
    DWORD                   id;              // 基本块唯一ID
    DWORD64                 startRVA;        // 起始地址
    DWORD64                 endRVA;          // 结束地址（含末尾指令）
    CS_INSTRUCTION*         instructions;    // 指令列表
    DWORD                   instrCount;
    
    // 控制流边
    struct _CS_BASIC_BLOCK** successors;     // 后继块
    DWORD                   numSuccessors;
    struct _CS_BASIC_BLOCK** predecessors;   // 前驱块
    DWORD                   numPredecessors;
    
    // 分析标记
    BOOL                    isLoopHeader;    // 是否为循环头
    BOOL                    isHotspot;       // 性能热点
    DWORD                   protectionLevel; // 分配的保护等级
    DWORD                   dominatorTreeId; // 支配树节点ID
} CS_BASIC_BLOCK;

typedef struct _CS_FUNCTION {
    DWORD64                 entryRVA;
    char                    name[256];       // 如有符号信息
    CS_BASIC_BLOCK**        blocks;
    DWORD                   blockCount;
    CS_FUNCTION_FLAGS       flags;           // 叶子函数、递归、使用SEH等
    DWORD                   assignedLevel;   // 保护等级
} CS_FUNCTION;
```

**CFG 构建流程**：

1. 从入口点和导出函数开始递归下降反汇编
2. 在每个分支指令处切割基本块
3. 建立后继/前驱关系
4. 计算支配树（Dominator Tree），用于后续混淆变换的安全性验证
5. 识别循环结构（通过回边检测），标记性能敏感区域
6. 根据配置文件的 `function_overrides` 分配每个函数的保护等级

#### 3.2.3 数据流分析

- **活跃变量分析（Liveness Analysis）**：确定每个基本块入口/出口处哪些寄存器是活跃的，用于安全插入垃圾代码（只能使用死寄存器）
- **常量传播分析**：识别可优化的常量表达式，为常量拆分提供目标
- **栈帧分析**：识别函数的栈帧布局（局部变量、参数），确保虚拟化后栈行为一致

---

### 3.3 保护层 — 核心变换引擎

#### 3.3.1 保护等级定义

| 等级 | 名称 | 包含的保护措施 | 典型性能开销 | 适用场景 |
|------|------|---------------|-------------|---------|
| L1 | **Guard** | Section 加密 + 字符串加密 + 导入表混淆 + 基础反调试 | ~1.05x | 性能敏感的主循环 |
| L2 | **Shield** | L1 + 控制流平坦化 + 常量拆分 | ~2-3x | 一般业务逻辑 |
| L3 | **Armor** | L2 + 虚假控制流注入 + 不透明谓词 + 混合变异 | ~5-8x | 重要逻辑 |
| L4 | **Fortress** | L3 + 单层代码虚拟化（VM）+ Handler 变异 | ~15-30x | 核心算法、授权验证 |
| L5 | **Citadel** | L4 + 多层嵌套 VM + 全维度变异 + Nanomite + 完整性互锁 | ~50-100x+ | 最高价值代码 |

> 用户可为整个程序设置默认等级，并对特定函数覆盖。保护器会自动分析调用频率，对热点路径上的函数给出降级建议（需用户确认）。

#### 3.3.2 L1 — 基础加密保护

**Section 加密**：

```
加密流程：
  1. 遍历所有代码段（.text 及其他含可执行代码的 section）
  2. 使用 ChaCha20 流密码加密（密钥嵌入 stub，每次加壳随机生成）
  3. 标记 section 为不可执行（去除 IMAGE_SCN_MEM_EXECUTE）
  4. Stub 运行时解密 → 恢复可执行权限 → 跳转执行

密钥管理：
  - 256-bit 随机密钥，嵌入 stub 中，自身也被白盒加密保护
  - 密钥的存储位置在 stub 代码中通过代码混淆隐藏
  - 解密完成后密钥从内存中擦除（SecureZeroMemory）
```

**字符串加密**：

```
1. 扫描所有 section 中的可打印字符串引用
2. 将字符串数据替换为加密版本
3. 在引用处插入解密 thunk：
   原始：  push offset aHelloWorld    ; "Hello World"
   加壳后：call decrypt_string_0x1A3  ; 解密并返回指针
           push eax
4. 每个字符串使用不同的加密密钥（从主密钥派生）
5. 解密后的字符串存储在动态分配的内存中，用完即擦除（可选）
```

**导入表混淆**：

```
策略A — API Hash 化：
  1. 清空原始 IAT，只保留 kernel32!LoadLibraryA 和 kernel32!GetProcAddress
  2. 其余所有 API 调用改为：运行时通过 DLL 名 hash + 函数名 hash 动态 resolve
  3. Hash 算法自定义（非标准 CRC32/djb2，避免被通用工具识别）

策略B — 导入表重建伪装：
  1. 生成一组看起来合理但无关的假导入项（干扰静态分析判断程序行为）
  2. 真正的 API 调用通过隐藏的 hash resolve 完成
  3. 假导入项中的函数实际被调用（调用后立即丢弃返回值），避免被 loader 优化掉

策略C — 混合模式（默认）：
  结合 A 和 B，真实 API 用 hash resolve，同时保留一组无关的假导入表
```

#### 3.3.3 L2 — 控制流混淆

**控制流平坦化（Control Flow Flattening）**：

将函数的正常控制流结构（if-else、for、while）拍平为一个由 dispatcher 驱动的状态机。

```
原始 CFG：                       平坦化后：
                                
  ┌──→ [BB1] ──→ [BB2]           ┌─────────────┐
  │      │         │              │ Dispatcher   │◄──────────────┐
  │      ▼         ▼              │ switch(state)│               │
  │    [BB3] ──→ [BB4]           └──┬──┬──┬──┬──┘               │
  │      │                          │  │  │  │                   │
  └──────┘                          ▼  ▼  ▼  ▼                  │
                                [BB1][BB2][BB3][BB4]             │
                                  │    │    │    │               │
                                  └────┴────┴────┴──→ state = next
                                                       └────────┘
```

```c
// 平坦化变换伪代码
void flatten_function(CS_FUNCTION* func) {
    // 1. 为每个基本块分配一个随机 state ID（非顺序）
    for (BB : func->blocks) {
        BB->stateId = generate_random_state_id();
    }
    
    // 2. 创建 dispatcher 基本块
    //    switch (state_var) {
    //        case 0x7A3F: goto BB1;
    //        case 0x1D92: goto BB2;
    //        ...
    //    }
    
    // 3. 在每个基本块末尾，将原始的跳转替换为 state_var = next_state_id
    //    对于条件分支：state_var = cond ? stateA : stateB
    
    // 4. state_var 自身可以做加密：
    //    实际存储的是 state_var ^ rolling_key
    //    dispatcher 中做 switch((state_var ^ rolling_key) & mask)
    //    增加 pattern matching 难度
}
```

**不透明谓词（Opaque Predicates）**：

插入条件判断，其结果在编译时已知（恒真/恒假），但静态分析工具无法轻易证明。

```c
// 基于数论的不透明谓词
// 对任意整数 x：x^2 mod 4 ∈ {0, 1}，永远不等于 2 或 3
BOOL opaque_always_true(int x) {
    return ((x * x) % 4 != 2);  // 恒真，但 IDA 无法证明
}

// 基于指针别名的不透明谓词
// 两个指向同一地址的指针，解引用必然相等
// 但静态分析的别名分析往往不够精确
BOOL opaque_alias(int* p, int* q) {
    // p 和 q 实际指向同一地址（由加壳器保证）
    return (*p == *q);  // 恒真
}

// 基于浮点精度的不透明谓词
BOOL opaque_float() {
    volatile double x = 1.0;
    return (x + 1e-15 != x);  // 在IEEE 754下恒真
}
```

**常量拆分**：

```c
// 原始
mov eax, 0xDEADBEEF

// 拆分后（每次加壳生成不同的拆分方案）
mov eax, 0x9E2D5A81
xor eax, 0x40806B6E     // 0x9E2D5A81 ^ 0x40806B6E == 0xDEADBEEF
add eax, 0x12345678
sub eax, 0x12345678      // 无效操作对，增加噪音
ror eax, 0               // 更多噪音
```

#### 3.3.4 L3 — 高级混淆

**虚假控制流注入（Bogus Control Flow）**：

在真实基本块前后插入由不透明谓词守护的假路径。假路径中包含看起来合理但永远不会执行的代码（从程序其他位置复制并变异的代码片段），大幅增加 Ghidra/IDA 的反编译输出噪音。

```
原始：                  注入后：
                       
 [BB_real]             [opaque_check] ──真──→ [BB_real]
                            │ 假（永不触发）
                            ▼
                       [BB_bogus_1] ──→ [BB_bogus_2] ──→ [opaque_loop_back]
                                                               │
                                                               ▼
                                                          [BB_real] (再次)
```

**代码复制与分裂（Code Duplication / Splitting）**：

- 将一个基本块复制为多个语义等价但代码不同的副本
- 通过不透明谓词随机选择执行哪个副本
- 每个副本使用不同的寄存器分配和指令选择
- 效果：同一段逻辑在反汇编中出现多次，无法确定哪个是"真的"

#### 3.3.5 L4 — 代码虚拟化（VM 核心）

##### 3.3.5.1 VM 架构设计 — "Mirage Engine"

CipherShell 的 VM 引擎代号为 **Mirage**。区别于 VMProtect 的纯栈式 VM 和 Themida 的纯寄存器式 VM，Mirage 采用**混合架构**：

```
Mirage VM 架构：

  ┌──────────────────────────────────────────────┐
  │              Virtual CPU                      │
  │                                              │
  │  ┌──────────────┐  ┌──────────────────────┐  │
  │  │ 虚拟寄存器组  │  │ 虚拟栈               │  │
  │  │ vR0 - vR23   │  │ [         ...       ] │  │
  │  │ （数量可配置） │  │ ← vSP               │  │
  │  └──────────────┘  └──────────────────────┘  │
  │                                              │
  │  ┌──────────────┐  ┌──────────────────────┐  │
  │  │ 虚拟 Flags   │  │ 上下文保存区          │  │
  │  │ vZF/vSF/vCF  │  │ 真实寄存器快照        │  │
  │  │ vOF/vPF      │  │ 真实 EFLAGS 快照      │  │
  │  └──────────────┘  └──────────────────────┘  │
  │                                              │
  │  ┌──────────────────────────────────────────┐ │
  │  │ Bytecode Stream                          │ │
  │  │ [enc_opcode][operands...][enc_opcode]... │ │
  │  │       ↑ vIP                              │ │
  │  └──────────────────────────────────────────┘ │
  │                                              │
  │  ┌──────────────────────────────────────────┐ │
  │  │ Handler Dispatch Table                   │ │
  │  │ [handler_0][handler_1]...[handler_N]     │ │
  │  │ + [junk_handler_0]...[junk_handler_M]    │ │
  │  └──────────────────────────────────────────┘ │
  └──────────────────────────────────────────────┘
```

**关键设计决策**：

| 决策项 | 选择 | 理由 |
|--------|------|------|
| 架构风格 | 混合（栈+寄存器） | 增加分析复杂度：分析者无法套用纯栈或纯寄存器 VM 的已有分析框架 |
| 寄存器数量 | 可配置 16-64 | 更多虚拟寄存器 = 更多映射可能性 = 更难追踪 |
| Opcode 编码 | 变长指令 | 固定长度更容易被模式匹配；变长配合加密后完全无法静态切割 |
| Dispatch 方式 | 间接跳转表 + 计算跳转混合 | 纯跳转表容易被识别；混合后部分 handler 通过计算地址跳转 |
| Bytecode 加密 | 滚动密钥流 + 密文反馈 | 单条指令被修改 → 后续所有指令解密失败 → 防 patch |

##### 3.3.5.2 ISA（指令集）设计

Mirage 的指令集不固定——每次加壳时通过变异引擎重新生成。以下是**基础模板**，实际生成时 opcode 编号、编码格式、操作数顺序全部随机化。

```
指令集模板（约 60 条核心指令）：

── 数据传送 ──
VM_MOV_RR       vReg ← vReg
VM_MOV_RC       vReg ← Const
VM_MOV_RM       vReg ← [vReg + Offset]      ; 内存读
VM_MOV_MR       [vReg + Offset] ← vReg      ; 内存写
VM_MOV_RM8/16   部分宽度的内存读
VM_MOV_MR8/16   部分宽度的内存写
VM_LEA          vReg ← vReg + vReg * Scale + Offset

── 栈操作 ──
VM_PUSH_R       push vReg
VM_PUSH_C       push Const
VM_POP_R        pop → vReg
VM_PUSH_FLAGS   push vFlags
VM_POP_FLAGS    pop → vFlags

── 算术 ──
VM_ADD_RR       vReg += vReg
VM_ADD_RC       vReg += Const
VM_SUB_RR       vReg -= vReg
VM_MUL_RR       vReg *= vReg
VM_IMUL         有符号乘法
VM_DIV          无符号除法
VM_IDIV         有符号除法
VM_NEG          vReg = -vReg
VM_INC          vReg++
VM_DEC          vReg--

── 逻辑 / 位操作 ──
VM_AND_RR       vReg &= vReg
VM_OR_RR        vReg |= vReg
VM_XOR_RR       vReg ^= vReg
VM_NOT          vReg = ~vReg
VM_SHL          vReg <<= N
VM_SHR          vReg >>= N (逻辑右移)
VM_SAR          vReg >>= N (算术右移)
VM_ROL / VM_ROR 循环移位
VM_BT / VM_BTS / VM_BTR  位测试与设置

── 比较 / 测试 ──
VM_CMP_RR       比较并设置 vFlags
VM_CMP_RC       
VM_TEST_RR      按位与测试

── 控制流 ──
VM_JMP          无条件跳转（bytecode 内偏移）
VM_JZ / VM_JNZ  条件跳转（基于 vFlags）
VM_JA / VM_JB / VM_JG / VM_JL / ...  全套条件跳转
VM_CALL_VM      VM 内部函数调用（push return offset, jmp）
VM_RET_VM       VM 内部返回

── 与外部世界交互 ──
VM_CALL_NATIVE  调用真实 API（通过 hash resolve）
VM_VMENTER      从 native 进入 VM（保存 CPU 状态）
VM_VMEXIT       从 VM 退出到 native（恢复 CPU 状态）
VM_SYSCALL      可选：直接 syscall 绕过 API hook（高级）

── 特殊 ──
VM_NOP          空操作（但解密密钥仍然滚动）
VM_ANTI_DEBUG   内联反调试检查
VM_CRC_CHECK    内联完整性校验
VM_RDTSC        读时间戳（用于 timing 检测）
```

##### 3.3.5.3 x86/x64 → Mirage Bytecode 转译器

**转译策略**：

```
策略1 — 直接映射（大部分指令）：
  x86 mov eax, ebx  →  VM_MOV_RR vR[map(eax)], vR[map(ebx)]
  
策略2 — 展开（复杂指令拆为多条 VM 指令）：
  x86 rep movsb  →  VM 循环序列：
    VM_CMP_RC vR[map(ecx)], 0
    VM_JZ end
    VM_MOV_RM8 vTmp, [vR[map(esi)]]
    VM_MOV_MR8 [vR[map(edi)]], vTmp
    VM_INC vR[map(esi)]
    VM_INC vR[map(edi)]
    VM_DEC vR[map(ecx)]
    VM_JMP loop_start
    
策略3 — VMEXIT 回退（极少数难以模拟的指令）：
  x86 cpuid       →  VM_VMEXIT → 执行原始 cpuid → VM_VMENTER
  x86 fpu 指令    →  VM_VMEXIT → 执行 → VM_VMENTER
  x86 SSE/AVX    →  VM_VMEXIT → 执行 → VM_VMENTER
  
  VMEXIT/VMENTER 对的存在也增加了分析难度（上下文切换点）
```

**EFLAGS 精确模拟**——这是 VM 正确性的最大挑战：

```c
// 每条算术/逻辑指令都需要精确模拟受影响的 flags
typedef struct _VM_FLAGS {
    BYTE CF;  // Carry
    BYTE ZF;  // Zero
    BYTE SF;  // Sign
    BYTE OF;  // Overflow
    BYTE PF;  // Parity
    BYTE AF;  // Auxiliary (BCD 运算需要，可降低优先级)
} VM_FLAGS;

// ADD 的 flags 计算
void compute_add_flags(VM_FLAGS* f, uint64_t a, uint64_t b, uint64_t result, int bitwidth) {
    uint64_t signMask = 1ULL << (bitwidth - 1);
    
    f->ZF = (result & ((1ULL << bitwidth) - 1)) == 0;
    f->SF = (result & signMask) != 0;
    f->CF = (result < a);  // 无符号溢出
    f->OF = ((a ^ b ^ signMask) & (a ^ result) & signMask) != 0;  // 有符号溢出
    f->PF = compute_parity(result & 0xFF);
    f->AF = ((a ^ b ^ result) & 0x10) != 0;
}
```

##### 3.3.5.4 Dispatcher 实现

**多种 Dispatch 模式随机混合**：

```c
// 模式A：跳转表 Dispatch（最常见，也最容易被识别）
void dispatch_table(VM_CONTEXT* ctx) {
    while (1) {
        BYTE opcode = decrypt_next_opcode(ctx);
        ctx->handlerTable[opcode](ctx);
    }
}

// 模式B：计算跳转 Dispatch（handler 地址通过计算得出）
void dispatch_computed(VM_CONTEXT* ctx) {
    while (1) {
        BYTE opcode = decrypt_next_opcode(ctx);
        // 地址 = base + opcode * stride + offset_table[opcode]
        // 每次加壳 base/stride/offset_table 都不同
        uintptr_t target = ctx->dispatchBase 
                         + opcode * ctx->dispatchStride 
                         + ctx->dispatchOffsets[opcode];
        ((VM_HANDLER)target)(ctx);
    }
}

// 模式C：Threaded Dispatch（每个 handler 末尾直接跳转到下一个）
// 无集中的 dispatch 循环，分析者无法找到单一的"调度器"
void handler_add_threaded(VM_CONTEXT* ctx) {
    // ... 执行 ADD 操作 ...
    
    // 末尾直接解码下一条并跳转
    BYTE nextOp = decrypt_next_opcode(ctx);
    goto *ctx->handlerTable[nextOp];  // computed goto (GCC extension)
    // MSVC 下用内联汇编实现等效
}

// 实际使用：混合三种模式
// 一部分 handler 用跳转表到达，一部分用计算跳转，一部分用 threaded
// 混合比例每次加壳随机
```

#### 3.3.6 L5 — 多层嵌套 VM + 全维度变异

**嵌套 VM**：将部分 VM handler 的实现本身也虚拟化——用另一套不同 ISA 的 VM 来执行。

```
外层 VM (ISA-A)
  ├── handler_add:      由 ISA-A 的 bytecode 实现
  ├── handler_xor:      由 ISA-A 的 bytecode 实现
  ├── handler_cmp:      ★ 由内层 VM (ISA-B) 的 bytecode 实现
  │                         ├── ISA-B handler_sub
  │                         ├── ISA-B handler_and
  │                         └── ISA-B handler_flags
  ├── handler_call_api: ★ 由内层 VM (ISA-C) 的 bytecode 实现
  │                         └── ...
  └── handler_mov:      由 ISA-A 的 bytecode 实现
  
每层 VM 的 ISA 完全不同（不同的 opcode 编码、不同的寄存器数量、不同的 dispatch 方式）
```

**全维度变异清单**：

1. **Opcode 编码随机化**：每次加壳生成新的 opcode ↔ handler 映射
2. **Opcode 宽度变异**：部分指令用 8-bit opcode，部分用 12-bit 或 16-bit
3. **寄存器映射随机化**：x86 寄存器到虚拟寄存器的映射每次不同
4. **Handler 代码 AST 变形**：同一语义的 handler 生成结构不同的机器码
   - 指令选择变异（`add` ↔ `sub+neg`、`xor` ↔ `not+and+or` 等）
   - 寄存器分配变异（handler 内部使用不同的物理寄存器）
   - 垃圾代码插入（在 handler 间插入无意义但看起来有意义的指令序列）
   - 指令调度变异（无数据依赖的指令重排序）
5. **Dispatch 方式混合**：跳转表 / 计算跳转 / threaded dispatch 随机混合
6. **虚拟栈布局变异**：栈增长方向、对齐方式、栈帧结构每次不同
7. **Bytecode 编码变异**：操作数编码方式（大端/小端、变长/定长、offset 编码方式）每次不同
8. **Handler 顺序和位置随机化**：handler 在内存中的排列顺序随机，不相邻
9. **假 Handler 注入**：插入大量永远不会被调度到的假 handler，增加分析噪音

---

### 3.4 反调试与反分析系统

#### 3.4.1 设计哲学

**核心原则：隐式检测，隐式响应。**

传统壳的反调试（如直接调用 `IsDebuggerPresent`、`NtQueryInformationProcess`）容易被 hook/patch 绕过。CipherShell 采用不同策略：

- **不调用可被 hook 的 API**（或仅作为诱饵）
- **检测结果不直接触发退出**，而是悄悄破坏解密密钥或虚拟机状态
- **检测逻辑分散嵌入 VM handler 中**，无法被集中 patch

#### 3.4.2 反调试技术矩阵

```
┌─────────────────────────────────────────────────────────────────────┐
│                        反调试技术分类                                │
│                                                                     │
│  ┌─────────────────────┐  ┌──────────────────────┐                 │
│  │ 时序检测（Timing）    │  │ 状态检测（State）     │                 │
│  │                     │  │                      │                 │
│  │ • RDTSC 差值检测     │  │ • PEB.BeingDebugged  │                 │
│  │ • QPC 差值检测       │  │   (直接读PEB，不调API)│                 │
│  │ • GetTickCount64    │  │ • PEB.NtGlobalFlag   │                 │
│  │ • Thread cycle计数   │  │ • Heap flags         │                 │
│  │ • 多点时序交叉验证   │  │ • DR0-DR7 硬件断点    │                 │
│  └─────────────────────┘  │ • KUSER_SHARED_DATA  │                 │
│                           │   .KdDebuggerEnabled │                 │
│  ┌─────────────────────┐  └──────────────────────┘                 │
│  │ 完整性检测           │                                           │
│  │ (Integrity)         │  ┌──────────────────────┐                 │
│  │                     │  │ 环境检测              │                 │
│  │ • 代码段CRC校验      │  │ (Environment)        │                 │
│  │ • Handler代码校验    │  │                      │                 │
│  │ • API入口点INT3扫描  │  │ • 父进程名检测        │                 │
│  │ • 关键函数头部校验    │  │ • 已加载模块扫描      │                 │
│  │   (检测inline hook) │  │   (检测注入的DLL)     │                 │
│  │ • 重定位完整性       │  │ • 窗口类名/标题扫描   │                 │
│  └─────────────────────┘  │ • VM/沙箱检测         │                 │
│                           │ • 远程调试器端口扫描   │                 │
│  ┌─────────────────────┐  └──────────────────────┘                 │
│  │ 主动对抗             │                                           │
│  │ (Active)            │                                           │
│  │                     │                                           │
│  │ • NtSetInformation  │                                           │
│  │   Thread 隐藏线程   │                                           │
│  │ • 异常处理链验证     │                                           │
│  │ • 自修改代码触发     │                                           │
│  │   单步异常           │                                           │
│  │ • 心跳线程互相监控   │                                           │
│  └─────────────────────┘                                           │
└─────────────────────────────────────────────────────────────────────┘
```

#### 3.4.3 隐式响应机制

```c
// 检测到调试时，不做任何明显操作
// 而是"投毒"——污染 VM 的解密密钥

void anti_debug_response_poison(VM_CONTEXT* ctx, DWORD detectionId) {
    // 每种检测方式用不同的异或值污染密钥
    // 这样逆向者需要同时绕过所有检测才能正常运行
    ctx->decryptKey ^= detectionId;
    
    // 污染后：
    // - 后续 bytecode 解密出错 → 错误的 opcode → 错误的 handler
    // - 程序不会立即崩溃，而是在之后某个不确定的时间点产生错误行为
    // - 逆向者很难定位"到底是哪里出了问题"
}

// 进阶：延迟炸弹
// 污染不立即生效，而是在N条指令后才开始影响
void anti_debug_response_delayed(VM_CONTEXT* ctx, DWORD detectionId) {
    ctx->poisonCountdown = rand() % 1000 + 500;  // 500-1500条指令后生效
    ctx->pendingPoison = detectionId;
}

// 在 dispatcher 中：
void dispatcher_tick(VM_CONTEXT* ctx) {
    if (ctx->poisonCountdown > 0) {
        ctx->poisonCountdown--;
        if (ctx->poisonCountdown == 0) {
            ctx->decryptKey ^= ctx->pendingPoison;
        }
    }
    // ... 正常 dispatch
}
```

#### 3.4.4 反 Dump 保护

```
技术组合：

1. PE 头擦除
   - Stub 完成初始化后，用 VirtualProtect 将 PE 头区域设为 PAGE_NOACCESS
   - 然后用随机数据覆写 DOS Header + NT Headers
   - dump 工具（如 Scylla）无法重建 PE

2. Section 权限动态管理
   - 代码段平时设为 PAGE_NOACCESS
   - 只在即将执行时临时解密 + 设为 PAGE_EXECUTE_READ
   - 执行完毕后立即重新加密 + 恢复 PAGE_NOACCESS
   - 任何时刻 dump 都无法获得完整的解密代码

3. Nanomite 技术
   - 将原始代码中的条件跳转替换为 INT3 (0xCC)
   - 注册 VEH/SEH 异常处理器
   - 异常处理器中根据上下文（寄存器值、触发地址）决定跳转目标
   - dump 后的代码无法执行（缺少异常处理器的跳转逻辑）

4. Guard Pages
   - 在关键数据结构周围设置 PAGE_GUARD 页
   - 正常执行通过异常处理器透明处理
   - 调试器/dump 工具触发 guard 时行为异常

5. API 重定向
   - 关键 API 不通过 IAT 调用，而是复制 API 前几条指令到自有内存中执行
   - 即使重建 IAT 也无法恢复完整的 API 调用关系
```

#### 3.4.5 反虚拟机/沙箱检测

```
检测目标：VMware, VirtualBox, Hyper-V, QEMU, Sandboxie, Windows Sandbox, 
          ANY.RUN, VirusTotal, Cuckoo Sandbox

检测手段（可选启用，某些场景下目标程序确实需要在 VM 中运行）：

1. CPUID 指令检测虚拟化特征位
2. 特定 I/O 端口检测 (VMware backdoor: port 0x5658)
3. 注册表键检测 (HKLM\SOFTWARE\VMware, VBox...)
4. MAC 地址前缀检测 (00:0C:29 VMware, 08:00:27 VBox)
5. 设备驱动扫描 (vmhgfs.sys, VBoxGuest.sys)
6. 进程列表扫描 (vmtoolsd.exe, VBoxService.exe)
7. 文件系统特征 (%SystemRoot%\system32\drivers\vm*.sys)
8. 时序异常检测（VM 中的指令执行时间与裸机有细微差异）
9. 内存容量 / 磁盘大小检测（沙箱通常资源较少）
10. 最近文件 / 桌面文件数量检测（沙箱通常为空）
```

---

### 3.5 反静态分析系统

#### 3.5.1 反 IDA Pro / Ghidra 策略

```
1. 破坏线性扫描反汇编：
   - 在代码流中插入精心构造的垃圾字节
   - 利用 IDA 的线性扫描假设：在跳转目标前插入不完整的指令前缀
   - 效果：IDA 的自动分析会将代码错误地对齐，产出大量错误反汇编

2. 反递归下降：
   - 使用间接跳转（计算地址后 jmp reg）替代直接跳转
   - 交叉引用（xref）被切断 → IDA 无法自动发现目标基本块
   - 函数被识别为更小的碎片，CFG 严重不完整

3. 反反编译器（Hex-Rays / Ghidra Decompiler）：
   - 构造反编译器无法合并的控制流结构（不可归约图）
   - 插入大量别名指针操作，污染类型推断
   - 使用位操作替代算术运算，反编译器输出变得不可读
   
4. 反签名扫描：
   - 所有代码经过变异引擎处理，无固定字节序列
   - Section 名称随机（不使用 .vmp / .themida / .packed 等已知名称）
   - PE 时间戳、Checksum 随机化
   - 清除所有调试目录、Rich Header
   - 不在代码中嵌入任何版本字符串或水印
```

#### 3.5.2 零特征保证

**消除所有已知壳特征的检查清单**：

| 特征类别 | 已知壳的特征 | CipherShell 的处理 |
|---------|------------|-------------------|
| Section 名称 | `.vmp0`/`.vmp1` (VMP), `.themida` (Themida), `UPX0`/`UPX1` (UPX) | 随机 8 字节名称，每次加壳不同 |
| 入口点模式 | VMP: `push reg / call` 序列; Themida: 特定 stub 模式 | 入口点代码完全变异，无固定模式 |
| PE 元数据 | Rich Header、特定 linker 版本、时间戳 | 全部删除或随机化 |
| 导入表 | VMP: 极少导入; Themida: 特定 DLL 列表 | 生成合理的假导入表，模拟正常程序 |
| 资源 | Themida: 嵌入特定资源 | 不嵌入任何自有资源 |
| 字符串 | 壳引擎的错误消息、版本号 | 所有 stub 字符串加密，无明文 |
| 代码模式 | VMP dispatcher 的 `fetch-decode-dispatch` 循环 | Dispatch 方式随机化，无固定循环结构 |
| 内存布局 | VMP: 特定的 section 权限组合 | 权限组合模拟正常编译器输出 |

---

### 3.6 Stub 生成与 PE 重建

#### 3.6.1 Stub 架构

Stub 是嵌入到输出 PE 中的运行时引擎，负责解密、反调试和 VM 执行。

```
Stub 组成：

┌────────────────────────────────────┐
│ Stage 0: 初始解密器                 │
│ - 最小的代码，解密 Stage 1           │
│ - 自身经过重度变异                   │
│ - 使用 PEB 遍历获取 API，无导入依赖  │
├────────────────────────────────────┤
│ Stage 1: 运行时引擎                 │
│ - 反调试初始化                      │
│ - 解密代码段 / 数据段               │
│ - 修复导入表（hash resolve）        │
│ - 处理重定位                        │
│ - 初始化 VM 引擎                    │
│ - 启动心跳监控线程                   │
├────────────────────────────────────┤
│ Stage 2: VM 引擎（Mirage）          │
│ - Dispatcher                       │
│ - Handler 集合                     │
│ - Bytecode 流                      │
├────────────────────────────────────┤
│ Stage 3: 数据区                     │
│ - 加密后的原始 section 数据          │
│ - 加密后的 bytecode                 │
│ - Handler 跳转表                   │
│ - 反调试校验值                      │
│ - API hash 表                      │
└────────────────────────────────────┘
```

#### 3.6.2 PE 重建器

```
输出 PE 的 Section 布局（随机化示例）：

Section 0: [随机名]  - 加密后的原始 .text
Section 1: [随机名]  - 加密后的原始 .rdata
Section 2: [随机名]  - 加密后的原始 .data
Section 3: .rsrc      - 资源段（保持名称以兼容 Windows loader）
Section 4: [随机名]  - Stub Stage 0
Section 5: [随机名]  - 加密后的 Stub Stage 1 + Stage 2
Section 6: [随机名]  - 加密后的 bytecode + 数据区
Section 7: .reloc     - 重定位段（如果是 DLL 则必须保留）

注意：
- Section 的顺序也是随机的（但 .rsrc 和 .reloc 需遵守 Windows loader 约束）
- 每个 section 的 VirtualSize 和 SizeOfRawData 添加随机 padding
- Section 属性设置模拟正常编译器输出（不全设 RWX）
```

#### 3.6.3 DLL 加壳特殊处理

DLL 加壳比 EXE 复杂，需要额外注意：

```
1. 入口点：DLL 的入口点是 DllMain，接收 DLL_PROCESS_ATTACH 等通知
   - Stub 需要在 DLL_PROCESS_ATTACH 时完成初始化
   - 需要正确处理 DLL_THREAD_ATTACH/DETACH
   - 需要在 DLL_PROCESS_DETACH 时清理

2. 导出表：DLL 的导出函数必须保持可调用
   - 导出函数地址指向 VM 入口 trampoline
   - 每个导出函数有独立的 VMENTER 跳板

3. 重定位：DLL 可能被加载到非首选基址
   - 必须保留和正确处理重定位表
   - VM 内部的地址引用也需要重定位支持

4. TLS：某些 DLL 使用 TLS 回调
   - 需要保留 TLS 目录
   - 可以利用 TLS 回调作为额外的初始化/反调试点

5. 异常处理（x64）：x64 DLL 的 SEH 基于 .pdata
   - 需要生成正确的 RUNTIME_FUNCTION 条目
   - 或使用 RtlAddFunctionTable 动态注册
```

---

### 3.7 签名消除引擎

专门负责确保输出文件不会触发任何已知的壳检测签名。

```
检测规避手段：

1. Anti-PEiD / Detect-It-Easy：
   - 这些工具依赖入口点字节模式匹配
   - 入口点代码完全变异，每次不同
   - 导入表结构模拟正常程序

2. Anti-YARA：
   - 不存在任何跨样本一致的字节序列（signature）
   - 所有字符串加密
   - 代码变异消除固定 pattern

3. Anti-Heuristic：
   - Section 权限不全设 RWX（分阶段修改权限）
   - 入口点位于代码段合理位置（不在最后一个 section）
   - PE 头各字段值在合理范围内
   - 导入表包含合理的函数集（不为空，也不只有 LoadLibrary）

4. 自测试流程：
   - 加壳完成后自动用 DIE (Detect It Easy) 签名库扫描
   - 如果匹配到任何已知壳签名 → 重新变异并再次生成
   - 循环直到零匹配
```

---

## 四、性能控制策略

### 4.1 性能开销模型

```
各保护措施的开销估算：

基础加密 (L1)：
  ├── Section 解密：一次性开销，程序启动时 ~10-50ms（取决于代码段大小）
  ├── 字符串解密：每次使用 ~1μs（可缓存）
  ├── API hash resolve：首次调用 ~5μs，后续缓存命中 ~0
  └── 总运行时开销：约 1.02-1.05x

控制流混淆 (L2)：
  ├── 平坦化 dispatcher：每个基本块 +1 次间接跳转 + 状态更新
  ├── 不透明谓词：每个谓词 ~2-5 条指令
  └── 总运行时开销：约 2-3x

高级混淆 (L3)：
  ├── 虚假控制流：增加代码体积但不影响执行路径（分支预测器可学习）
  ├── 代码分裂：增加 I-Cache 压力
  └── 总运行时开销：约 5-8x

VM 保护 (L4)：
  ├── Fetch-Decode-Dispatch 循环开销
  ├── 间接跳转导致分支预测失败
  ├── Bytecode 解密开销
  ├── EFLAGS 模拟开销
  └── 总运行时开销：约 15-30x

嵌套 VM (L5)：
  ├── 多层 dispatch 叠加
  └── 总运行时开销：约 50-100x+
```

### 4.2 自动热点建议

```
流程：
1. 对输入 PE 进行静态分析
2. 识别循环结构（回边计数估算）
3. 估算每个函数的调用频率（通过调用图入度分析）
4. 对高频函数（循环体内、高入度）建议降低保护等级
5. 生成建议报告，用户确认后应用

示例输出：
  ⚠ 函数 render_frame (0x00401000) 位于主循环内，估算调用频率极高
    建议保护等级：L1 (当前配置: L4)
    预估性能改善：~20x
    
  ⚠ 函数 process_input (0x00402000) 每帧调用
    建议保护等级：L2 (当前配置: L4)
    
  ✓ 函数 validate_license (0x00405000) 仅启动时调用一次
    当前 L5 保护等级适合，无需调整
```

### 4.3 运行时动态降级（高级，可选）

```
概念：根据运行时性能监控动态调整保护强度

实现：
- 在 VM dispatcher 中嵌入轻量级性能计数器
- 如果检测到 VM 执行耗时超过阈值（如配置的 max_vm_overhead_ratio）
- 动态将部分 bytecode "JIT 编译" 回 native 代码执行
- 但 JIT 编译后的代码仍然经过基础混淆

风险：
- JIT 代码是可分析的 native 代码，降低了保护强度
- 需要权衡：如果对性能不敏感，建议关闭此特性
```

---

## 五、构建与工具链

### 5.1 项目结构

```
CipherShell/
├── CMakeLists.txt
├── README.md
├── docs/
│   └── design.md                    ← 本文档
│
├── packer/                          # 加壳器主程序
│   ├── main.cpp                     # 入口 + CLI 解析
│   ├── pe_parser/                   # PE 解析器
│   │   ├── pe_parser.h
│   │   ├── pe_parser.cpp
│   │   ├── pe_rebuilder.h
│   │   └── pe_rebuilder.cpp
│   ├── analysis/                    # 分析引擎
│   │   ├── disassembler.h           # Zydis 封装
│   │   ├── cfg_builder.h            # CFG 构建器
│   │   ├── data_flow.h              # 数据流分析
│   │   └── hotspot_analyzer.h       # 热点分析
│   ├── transforms/                  # 变换引擎
│   │   ├── section_encryptor.h      # Section 加密 (L1)
│   │   ├── string_encryptor.h       # 字符串加密 (L1)
│   │   ├── import_obfuscator.h      # 导入表混淆 (L1)
│   │   ├── cfg_flattener.h          # 控制流平坦化 (L2)
│   │   ├── opaque_predicates.h      # 不透明谓词 (L2/L3)
│   │   ├── bogus_flow.h             # 虚假控制流 (L3)
│   │   ├── translator.h             # x86→VM 转译器 (L4)
│   │   └── vm_nester.h              # VM 嵌套 (L5)
│   ├── mutation/                    # 变异引擎
│   │   ├── opcode_randomizer.h
│   │   ├── handler_mutator.h
│   │   ├── junk_generator.h
│   │   └── register_shuffler.h
│   ├── config/                      # 配置解析
│   │   └── config_parser.h
│   └── signature/                   # 签名消除
│       └── signature_eliminator.h
│
├── stub/                            # 运行时 Stub
│   ├── stage0/                      # 初始解密器
│   │   ├── stage0.asm               # NASM 汇编
│   │   └── stage0_template.h        # 编译后的 shellcode 模板
│   ├── stage1/                      # 运行时引擎
│   │   ├── runtime.c                # 无 CRT 的 C 代码
│   │   ├── anti_debug.c
│   │   ├── import_resolver.c
│   │   ├── reloc_fixer.c
│   │   └── peb_utils.asm
│   └── vm/                          # Mirage VM 引擎
│       ├── dispatcher.c
│       ├── handlers/
│       │   ├── handler_alu.c        # 算术逻辑 handlers
│       │   ├── handler_mem.c        # 内存操作 handlers
│       │   ├── handler_flow.c       # 控制流 handlers
│       │   ├── handler_api.c        # API 调用 handlers
│       │   └── handler_special.c    # 特殊 handlers
│       ├── vm_context.h
│       └── flags_emu.c              # EFLAGS 模拟
│
├── llvm_pass/                       # 可选：源码保护 LLVM Pass
│   ├── CMakeLists.txt
│   ├── CipherShellPass.cpp
│   ├── Flattening.cpp
│   ├── BogusFlow.cpp
│   ├── InstrSubstitution.cpp
│   └── StringEncryption.cpp
│
├── third_party/                     # 第三方库
│   ├── zydis/                       # 反汇编引擎
│   ├── toml++/                      # TOML 解析
│   └── chacha20/                    # 加密库（精简实现）
│
└── tests/                           # 测试
    ├── test_pe_parser.cpp
    ├── test_vm_correctness.cpp       # VM 正确性测试（关键！）
    ├── test_transforms.cpp
    ├── test_antidebug.cpp
    ├── samples/                      # 测试用 PE 样本
    │   ├── hello_world.exe
    │   ├── gui_app.exe
    │   ├── test_dll.dll
    │   └── cpp_complex.exe
    └── scripts/
        ├── verify_no_signature.py    # 自动签名检测验证
        └── benchmark.py              # 性能基准测试
```

### 5.2 Stub 编译要求

```
Stub 编译约束（MSVC 示例）：

cl /c /O1 /GS- /Zl /nologo
   /DWIN32_LEAN_AND_MEAN
   /D_NO_CRT
   runtime.c

link /NODEFAULTLIB
     /ENTRY:StubEntry
     /SUBSYSTEM:CONSOLE
     /SECTION:.text,ERW
     /MERGE:.rdata=.text
     /MERGE:.data=.text
     stub.obj

含义：
  /GS-              禁用 stack cookie（依赖 CRT）
  /Zl               不嵌入默认库名
  /NODEFAULTLIB      不链接任何默认库
  /ENTRY:StubEntry   自定义入口点
  /MERGE             合并 section，减小体积
  
NASM 编译：
  nasm -f win32 stage0.asm -o stage0.obj     (x86)
  nasm -f win64 stage0.asm -o stage0.obj     (x64)
```

### 5.3 依赖清单

| 依赖 | 版本 | 用途 | 许可证 |
|------|------|------|--------|
| Zydis | ≥4.0 | x86/x64 反汇编 | MIT |
| toml++ | ≥3.0 | 配置文件解析 | MIT |
| 自研 ChaCha20 | — | 对称加密（精简实现，不依赖 OpenSSL） | — |
| NASM | ≥2.16 | 汇编器 | BSD-2 |
| CMake | ≥3.20 | 构建系统 | BSD-3 |
| LLVM | ≥15.0 | 可选：源码保护 Pass | Apache-2.0 |

---

## 六、开发路线图

### Phase 1 — 基础框架（预计 4-6 周）

```
里程碑：能对简单 EXE 进行 L1 保护并正确运行

任务：
  □ 实现 PE Parser（完整解析所有 Data Directory）
  □ 实现 PE Rebuilder（能无损重建未修改的 PE）
  □ 实现 Section 加密 + 对应的 Stub 解密
  □ 实现 PEB 遍历获取 kernel32 基址（x86 + x64）
  □ 实现基础 API hash resolve（LoadLibrary + GetProcAddress）
  □ 实现导入表重建
  □ 实现重定位修复
  □ 端到端测试：加壳 hello_world.exe → 正常运行

验收标准：
  - 加壳后的 EXE 功能完全正常
  - DIE / PEiD 不识别为任何已知壳
  - IDA 中原始代码段显示为加密数据
```

### Phase 2 — 反调试 + 字符串/导入混淆（预计 3-4 周）

```
里程碑：L1 保护完整实装

任务：
  □ 实现字符串扫描与加密
  □ 实现导入表混淆（Strategy C: 混合模式）
  □ 实现反调试检测矩阵（至少 8 种检测手段）
  □ 实现隐式响应（密钥投毒）
  □ 实现 PE 头擦除
  □ 实现 Rich Header / Debug Directory 清除
  □ 配置文件系统（TOML）

验收标准：
  - x64dbg 附加后程序行为异常（但不立即退出）
  - 字符串窗口 (IDA Shift+F12) 无法看到原始字符串
  - 导入表不反映真实 API 依赖
```

### Phase 3 — 控制流混淆（预计 4-5 周）

```
里程碑：L2/L3 保护实装

任务：
  □ 集成 Zydis 反汇编引擎
  □ 实现 CFG 构建器
  □ 实现控制流平坦化
  □ 实现不透明谓词库（至少 10 种不同类型）
  □ 实现虚假控制流注入
  □ 实现常量拆分
  □ 实现垃圾代码生成器（基于活跃变量分析）
  □ 函数级保护等级标注

验收标准：
  - IDA 反编译器输出严重膨胀，可读性极差
  - 控制流图极度复杂化
  - 功能正确性不受影响
```

### Phase 4 — VM 引擎 Mirage（预计 8-12 周）— 核心

```
里程碑：L4 保护实装

任务：
  □ 设计并实现 VM 上下文结构
  □ 实现 Dispatcher（三种模式）
  □ 实现完整的 Handler 集（约 60 个）
  □ 实现精确的 EFLAGS 模拟
  □ 实现 x86→bytecode 转译器（覆盖常用指令子集）
  □ 实现 VMENTER/VMEXIT 上下文切换
  □ 实现 bytecode 滚动加密
  □ 实现变异引擎（opcode随机化 + 寄存器映射随机化 + handler变异）
  □ 大量正确性测试（算术、逻辑、分支、循环、函数调用、异常处理）

验收标准：
  - 虚拟化后的函数计算结果与原始完全一致
  - 同一程序两次加壳产出完全不同的二进制
  - x64dbg 中 VM dispatcher 难以追踪
  - 无已知壳签名匹配
```

### Phase 5 — 高级特性 + DLL 支持（预计 4-6 周）

```
里程碑：L5 保护 + DLL 加壳 + 性能控制

任务：
  □ 实现 VM 嵌套（双层不同 ISA）
  □ 实现 Nanomite 技术
  □ 实现完整 DLL 加壳（导出表保持、重定位、TLS）
  □ 实现 x64 异常处理兼容（.pdata / RtlAddFunctionTable）
  □ 实现热点分析与自动建议
  □ 实现性能 benchmark 框架
  □ 假 Handler 注入
  □ Handler 内联反调试检查

验收标准：
  - DLL 加壳后可被正常 LoadLibrary 加载
  - 导出函数可被正常调用
  - L5 保护下 IDA + x64dbg 组合分析极度困难
```

### Phase 6 — 源码模式 + 打磨（预计 4-6 周，可选）

```
里程碑：LLVM Pass 实装 + GUI + 文档

任务：
  □ 实现 LLVM Pass: 控制流平坦化
  □ 实现 LLVM Pass: 虚假控制流
  □ 实现 LLVM Pass: 指令替换
  □ 实现 LLVM Pass: 字符串加密
  □ 编写集成指南（如何在 CMake 项目中使用）
  □ 可选：简单的 GUI 前端（Qt / ImGui）
  □ 完善文档和使用手册

验收标准：
  - LLVM Pass 能在 clang 编译流程中正常工作
  - 源码保护 + 二进制保护可叠加使用
```

---

## 七、测试策略

### 7.1 正确性测试（最高优先级）

```
测试用例矩阵：

1. 基础功能测试
   - Hello World (console)
   - MessageBox (GUI)
   - 文件 I/O 操作
   - 网络操作 (Winsock)
   - 多线程程序
   - C++ 异常处理
   - SEH 异常处理
   - TLS 使用
   - DLL 加载 (LoadLibrary)
   - DLL 被加载 (导出函数调用)

2. 编译器覆盖
   - MSVC Debug/Release (x86/x64)
   - MinGW GCC (x86/x64)
   - Clang/LLVM (x86/x64)
   - 不同优化等级 (/Od, /O1, /O2, /Ox)

3. 保护等级覆盖
   - 每个测试用例 × 每个保护等级 (L1-L5) = 完整矩阵

4. VM 正确性专项
   - 整数算术溢出边界
   - EFLAGS 精确性 (CMC, STC 等边缘指令)
   - 64位操作 (x64 模式)
   - 调用约定正确性 (stdcall, cdecl, fastcall, x64 ABI)
   - 栈平衡验证
```

### 7.2 安全性测试

```
1. 签名扫描
   - DIE (Detect It Easy) 全签名库扫描
   - YARA 规则匹配（收集 VMP/Themida/已知壳的公开 YARA 规则）
   - 自动化：加壳后自动扫描，匹配到任何签名则 CI 失败

2. 反调试验证
   - x64dbg 附加测试
   - WinDbg 附加测试
   - Frida 注入测试
   - Cheat Engine 附加测试
   - Process Monitor 行为观察

3. 反 dump 验证
   - Scylla dump 尝试
   - Process Dump 工具测试
   - 验证 dump 后的文件不可运行

4. 变异唯一性验证
   - 同一输入加壳 100 次
   - 验证 100 个输出两两之间无共同字节序列 > 16 字节
```

### 7.3 性能基准测试

```
基准测试程序：
  - CPU 密集型：矩阵乘法、排序算法、加密运算
  - I/O 密集型：文件读写、网络通信
  - 混合型：游戏引擎核心循环模拟

测量指标：
  - 启动时间增加量
  - 运行时 CPU 开销倍率
  - 内存占用增加量
  - 代码体积膨胀比

输出格式：
  保护等级 | 启动延迟 | CPU 开销 | 内存增加 | 体积膨胀
  L1       | +12ms    | 1.03x   | +2MB    | 1.1x
  L2       | +15ms    | 2.5x    | +5MB    | 2.3x
  L3       | +18ms    | 6.1x    | +12MB   | 4.7x
  L4       | +25ms    | 22x     | +20MB   | 3.2x
  L5       | +40ms    | 75x     | +35MB   | 5.1x
```

---

## 八、风险与缓解

| 风险 | 影响 | 可能性 | 缓解措施 |
|------|------|--------|---------|
| EFLAGS 模拟不精确 | 虚拟化后程序逻辑错误 | 高 | 编写大量边界测试；VMEXIT 回退机制兜底 |
| x64 支持复杂度 | x64 的 ABI 和异常处理更复杂 | 中 | 先做 x86 版本，x64 作为 Phase 4+ |
| Windows 版本兼容性 | 反调试技术依赖未文档化结构 | 中 | 运行时检测 OS 版本，动态选择兼容的技术 |
| 杀毒软件误报 | 加壳行为本身可能触发启发式检测 | 高 | 签名消除引擎 + 导入表伪装 + 行为模拟正常程序 |
| 大型程序加壳后不稳定 | 复杂的 PE 结构（MFC、Qt 等）可能有特殊依赖 | 中 | 渐进式保护 + 充分的回归测试套件 |
| 开发周期过长 | VM 引擎工程量巨大 | 高 | 严格按 Phase 推进，每个 Phase 有可交付成果 |

---

## 九、术语表

| 术语 | 含义 |
|------|------|
| OEP | Original Entry Point，原始程序入口点 |
| IAT | Import Address Table，导入地址表 |
| RVA | Relative Virtual Address，相对虚拟地址 |
| CFG | Control Flow Graph，控制流图 |
| Stub | 嵌入加壳后 PE 中的运行时解密/加载代码 |
| Handler | VM 中执行单条虚拟指令的函数 |
| Dispatcher | VM 的指令分发循环 |
| Bytecode | 自定义虚拟指令的二进制编码 |
| Opaque Predicate | 不透明谓词，编译时已知结果但静态分析难以证明的条件 |
| Nanomite | 用 INT3 替换条件跳转，通过异常处理器实现跳转逻辑的技术 |
| VMEXIT/VMENTER | VM 执行与 Native 执行之间的切换点 |
| Threaded Dispatch | Handler 末尾直接跳转到下一个 Handler 的分发方式，无集中调度器 |
| Rolling Key | 滚动密钥，每次解密操作后密钥自身发生变化 |
| Junk Code | 语义上无意义的代码，插入以增加分析难度 |

---

## 十、参考文献与资源

1. Microsoft PE/COFF Specification — PE 格式权威文档
2. 《加密与解密》（第四版）— 看雪论坛经典，壳技术系统讲解
3. Zydis Documentation — 反汇编引擎 API
4. "An Abstract Interpretation-Based Framework for Control Flow Flattening" — 平坦化的学术基础
5. "Opaque Predicates: Past, Present, and Future" — 不透明谓词综述
6. Tigress C Obfuscator — 学术级代码虚拟化参考
7. 看雪论坛 VMP 分析系列 — 逆向视角的 VM 保护分析
8. LLVM Developer Documentation — LLVM Pass 开发指南

---

> **文档状态**：初版草案，后续随实现推进持续更新。
