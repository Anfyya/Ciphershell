# CipherShell — Windows x86/x64 生产级代码保护系统设计书

> **项目代号**：CipherShell  
> **文档版本**：v1.0 Production Architecture Baseline  
> **更新日期**：2026-07-10  
> **目标平台**：Windows PE32 / PE32+，EXE / DLL  
> **实现语言**：C++17、C、x86/x64 汇编  
> **构建工具**：CMake、MSVC、NASM  
> **文档状态**：最终生产架构约束，不是 MVP、原型或临时路线图

---

## 0. 不可变更的工程原则

本节是 CipherShell 的最高优先级约束。后续实现、重构、AI 编码提示词和代码审查都必须遵守。

1. **不做 MVP**：不以“先能运行”为理由引入最终必然废弃的架构。
2. **不做最小可运行实例**：可以限制某个功能的合法适用范围，但不能用假的 runtime、空 handler、NOP 替代、静默跳过或原生逻辑回退来伪造功能完成。
3. **不分阶段交付临时架构**：所有新增模块必须直接接入最终生产数据流。
4. **不保留双轨生产路径**：正式构建中只能存在一套解码器、一套 IR、一套 PE 修改模型和一套功能状态判定。
5. **不使用 fallback 掩盖错误**：Zydis 解码失败、Translator 不支持、runtime 缺失、静态链接不完整时必须 fail-closed。
6. **不承诺“以后再替换”**：确认最终应使用的组件必须直接采用。例如 x86/x64 指令解码最终使用 Zydis，就不得继续扩展手写 ModRM/SIB/REX 解码器。
7. **功能必须真实闭环**：一个功能只有在配置、分析、变换、PE 写入、runtime 支持、静态验证和状态报告全部闭环后才能标记 `applied`。
8. **保护等级不是架构核心**：L1-L5 仅作为配置预设。所有保护功能必须可以独立启用、关闭、调节强度和设置作用范围。
9. **不运行产物的开发约束**：编码 AI 只负责代码、配置、编译和静态检查；原始 EXE、加壳 EXE 和测试 EXE 的运行验证由用户手动完成。
10. **不以编译通过代替功能完成**：编译通过是必要条件，不是功能正确性的证明。

---

## 1. 项目定位

CipherShell 是面向合法软件保护场景的 Windows 原生代码保护系统，目标是对 PE32/PE32+ 程序提供函数级代码虚拟化、数据保护、导入保护、控制流变换、完整性验证和可审计的失败策略。

### 1.1 核心目标

- 支持 Windows x86 与 x64 的 EXE、DLL。
- 对指定函数实施真正的 native → trampoline → VM runtime → bytecode → native return 执行闭环。
- 每次构建随机化 VM opcode、虚拟寄存器映射、metadata cookie、section 名称和可变布局。
- 保护功能独立配置，不以等级硬编码决定功能开关。
- 对不支持的输入明确拒绝，不产生“看似加壳成功、实际仍执行 native”的文件。
- 对 PE 修改进行统一建模，避免多个模块互相覆盖 Header、Section 或 Data Directory。
- 保留完整静态诊断，使用户能够定位 Translator、metadata、trampoline、runtime 或 PE 重建错误。

### 1.2 非目标

- 不保护 .NET IL；检测到 CLR Header 时明确拒绝或交由独立产品线。
- 不以内核驱动作为基础依赖。
- 不依赖云端服务才能完成加壳。
- 不通过恶意行为、持久化或系统破坏实现保护。
- 不将反调试、反虚拟机当作 VM 正确性的替代品。

---

## 2. 最终总体架构

```text
输入 PE + 保护配置
        │
        ▼
┌──────────────────────────────┐
│ PE Platform Layer            │
│ Parser / Image Model         │
│ Directory Model / Validation │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ Zydis Decode Layer           │
│ x86/x64 machine instruction  │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ CipherShell Unified IR       │
│ Instruction / Operand / CFG  │
│ Function / Data-flow         │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ Protection Planner           │
│ BuildContext / Capability    │
│ Scope / FailurePolicy        │
└──────────────┬───────────────┘
               │
       ┌───────┴───────────────────────────┐
       ▼                                   ▼
┌──────────────────────┐        ┌────────────────────────┐
│ VM Protection        │        │ Non-VM Protections     │
│ Translator           │        │ Strings / Imports      │
│ Bytecode / Metadata  │        │ Sections / CFG / CFI   │
│ Runtime / Trampoline │        │ Integrity              │
└───────────┬──────────┘        └────────────┬───────────┘
            └──────────────┬─────────────────┘
                           ▼
┌──────────────────────────────┐
│ PEEmitter                    │
│ Append / Patch / Fill        │
│ Directory & Header Updates   │
└──────────────┬───────────────┘
               ▼
┌──────────────────────────────┐
│ Static Verifiers             │
│ VM / PE / CFG / Directory    │
└──────────────┬───────────────┘
               ▼
┌──────────────────────────────┐
│ PERebuilder                  │
│ Serialization Only           │
└──────────────┬───────────────┘
               ▼
         输出受保护 PE
```

### 2.1 单一数据流原则

正式构建必须始终经过同一数据流：

```text
Zydis → Unified IR → CFG → Translator → VM Bytecode → Metadata
       → Runtime/Trampoline → PEEmitter → Static Verification → PERebuilder
```

不得出现以下生产路径：

- Zydis 失败后退回自研 decoder。
- Translator 失败后保留原函数继续标记 VM applied。
- runtime 不完整时仍写出 VM record。
- PEEmitter 修改后由 PERebuilder 重新猜测布局。
- 不支持指令转 NOP。
- 配置字段未被解析但不报错。

---

## 3. ProtectionBuildContext 与配置决策

所有模块共享一个不可变的构建上下文。模块不得各自生成互不一致的 opcode map、register map、密钥或 section 名称。

```cpp
struct ProtectionBuildContext {
    uint64_t buildSeed;
    TargetArchitecture architecture;   // X86 / X64
    TargetImageKind imageKind;          // EXE / DLL

    VMOptions vm;
    StringProtectionOptions strings;
    ImportProtectionOptions imports;
    SectionProtectionOptions sections;
    ControlFlowOptions controlFlow;
    IntegrityOptions integrity;

    ScopePolicy scope;
    FailurePolicy failurePolicy;

    OpcodeMap opcodeMap;
    ReverseOpcodeMap reverseOpcodeMap;
    RegisterMap registerMap;
    VMMetadataLayout metadataLayout;
    RuntimeLayout runtimeLayout;
    BuildKeys keys;
    GeneratedSectionNames sectionNames;
};
```

### 3.1 配置优先级

```text
命令行显式参数
    > TOML 模块化配置
    > --level 预设展开结果
    > 内置安全默认值
```

`--level` 只能转换为模块化配置，不得在主流程中作为 `if (level >= 4)` 的核心功能判断。

### 3.2 功能状态

每个模块只能输出以下状态之一：

- `applied`：完整闭环并通过静态验证。
- `partial`：仅用于明确存在的非关键子能力；不得用于 VM 主链闭环。
- `skipped`：配置关闭、作用域为空或由用户策略明确跳过。
- `failed`：请求启用但无法安全完成。

标准输出格式：

```text
FEATURE_STATUS name=vm status=applied reason=static_link_verified
FEATURE_STATUS name=import_protection status=failed reason=runtime_resolver_missing
```

---

## 4. PE 平台层

### 4.1 PEParser

PEParser 负责将原始文件解析为统一内存模型，至少覆盖：

- DOS Header、NT Headers、Optional Header。
- x86/x64 Section Table。
- Import、Delay Import、Export。
- Base Relocation。
- Resource。
- TLS。
- x64 Exception Directory / `.pdata` / unwind 信息。
- Load Config、CFG Guard、SafeSEH。
- Debug Directory、Rich Header。
- Security Directory / Authenticode 范围。
- Overlay。
- CLR Header 检测。

解析器必须执行严格边界检查，所有 RVA、raw offset、size 运算使用防溢出逻辑。

### 4.2 PEEmitter

PEEmitter 是所有内存 PE 修改的唯一入口，负责：

- `AppendSection`
- `PatchBytes`
- `FillBytes`
- Header 扩容与 raw data 搬移
- `NumberOfSections`
- `SizeOfImage`
- `SizeOfHeaders`
- Section `VirtualAddress / VirtualSize / PointerToRawData / SizeOfRawData`
- Data Directory 更新
- Overlay 位移更新
- x64 unwind/exception 表更新
- CFG Guard 兼容更新
- Base relocation 更新
- TLS / import / export 相关目录写入

禁止保护模块直接通过裸指针随意改 Header。

### 4.3 PERebuilder

PERebuilder 只负责序列化已经由 PEEmitter 确定的最终内存映像，不得：

- 重新排列 section。
- 重新猜测 RVA/raw offset。
- 覆盖 PEEmitter 已写入的数据。
- 忽略新增 runtime、metadata 或 trampoline section。

### 4.4 输出验证

写出前必须验证：

- Section 无 raw/virtual 重叠。
- 所有 Data Directory 范围合法。
- EntryPoint 落在可执行 section。
- runtime/trampoline 落在可执行 section。
- metadata 落在可读且默认不可写 section；仅 debug trace 需要时按配置提供可写数据区。
- x64 `.pdata` 与 unwind 信息与新增可执行区域一致。
- CFG Guard 目标表在启用时包含新增合法间接调用目标。
- DLL 的导出、TLS、初始化顺序与 loader 语义保持一致。

---

## 5. 正式指令解码与统一 IR

### 5.1 Zydis 是唯一生产解码器

CipherShell 正式生产路径必须使用固定版本、固定 tag/commit 的 Zydis。依赖应内置于 `third_party` 或由固定 commit 的 CMake FetchContent 获取，不要求用户安装全局库。

Zydis 负责：

- x86/x64 指令长度与 mnemonic。
- legacy prefix、REX、ModRM、SIB。
- register、immediate、memory operand。
- operand width 与访问类型。
- RIP-relative 与 relative branch/call。
- instruction category。
- flags read/write 元数据。

Zydis 不负责：

- 函数边界最终判定。
- CFG 策略。
- VM 语义翻译。
- native bridge。
- PE 修改。

生产代码中必须删除或禁止：

- `DecodeModRMInstr`
- `DecodedModRM`
- 手写 REX/ModRM/SIB 解析
- 通过 `instr.bytes[0]` 推断语义
- Zydis 失败后使用 legacy decoder

### 5.2 统一 IR

```cpp
enum class OperandType {
    None,
    Register,
    Immediate,
    Memory,
    Pointer
};

enum class OperandAction {
    None,
    Read,
    Write,
    ReadWrite
};

struct MemoryOperandIR {
    RegisterId segment;
    RegisterId base;
    RegisterId index;
    uint8_t scale;
    int64_t displacement;
    uint16_t width;
    bool hasBase;
    bool hasIndex;
    bool hasDisplacement;
    bool isRipRelative;
    uint64_t resolvedVA;
    uint32_t resolvedRVA;
};

struct OperandIR {
    OperandType type;
    OperandAction action;
    uint16_t width;
    RegisterId reg;
    uint64_t immediate;
    bool immediateSigned;
    bool immediateRelative;
    MemoryOperandIR memory;
};

struct InstructionIR {
    uint64_t address;
    uint32_t rva;
    uint8_t length;
    std::array<uint8_t, 15> rawBytes;
    InstructionMnemonic mnemonic;
    InstructionCategory category;
    MachineMode machineMode;
    uint16_t operandWidth;
    uint16_t stackWidth;
    std::vector<OperandIR> operands;

    BranchKind branchKind;
    bool hasBranchTarget;
    uint64_t branchTargetVA;
    uint32_t branchTargetRVA;

    uint64_t flagsRead;
    uint64_t flagsWritten;
};
```

IR 不得保存指向 Zydis 临时对象的指针。

### 5.3 部分寄存器语义

必须区分 AL/AH/AX/EAX/RAX、R8B/R8W/R8D/R8 等不同宽度。

- 写 EAX/R8D 等 32 位 GPR：高 32 位清零。
- 写 AX/AL：只修改相应低位。
- AH/BH/CH/DH：若 runtime 未实现高 8 位语义，必须拒绝函数。
- 不得将所有同族寄存器粗暴映射成完整 64 位写入。

### 5.4 CFGBuilder

CFGBuilder 只使用 IR 提供的 category、branch kind 和绝对 branch target，不再自行解析 rel8/rel32。

必须验证：

- target 位于合法可执行 section。
- target 是指令边界。
- 函数内与函数外跳转明确分类。
- indirect branch/call 不猜测目标。
- basic block 不重叠。
- 所有可达路径有明确终止或后继。

---

## 6. CapabilityChecker 与失败策略

CapabilityChecker 在任何破坏性修改前检查：

- PE 架构和类型。
- CFG Guard / CET / SafeSEH / unwind 要求。
- DLL 特殊约束。
- 目标函数是否完整可解码。
- 当前 runtime 是否覆盖所有目标指令和 operand 形式。
- import resolver、on-demand string runtime 等依赖是否闭环。

标准失败原因示例：

```text
zydis_decode_failed
unsupported_instruction_mnemonic
unsupported_operand_form
partial_register_write_not_supported
high_8bit_register_not_supported
memory_arithmetic_not_supported
native_call_bridge_not_supported
import_call_bridge_not_supported
indirect_call_not_supported
vm_native_stack_mapping_not_supported
branch_target_outside_function
branch_target_not_instruction_boundary
runtime_resolver_missing
unwind_rewrite_required
cfg_guard_rewrite_required
```

任何错误必须包含：

- function RVA
- instruction RVA
- mnemonic
- operand summary
- raw bytes
- reason

---

## 7. Mirage VM 最终架构

### 7.1 目标执行闭环

```text
原函数调用
  → patched entry
  → trampoline
  → VM runtime entry
  → 定位 metadata
  → 根据 functionRVA 查 VMFunctionRecord
  → 解密 bytecode
  → reverse opcode map
  → handler dispatch
  → 执行 VM 指令
  → 恢复寄存器、RFLAGS、栈与返回值
  → 返回原调用者
```

只要其中任一环缺失，VM 不得标记 `applied`。

### 7.2 VM 上下文

最终 VMContext 至少包含：

```cpp
struct VMContext {
    uint64_t vmRegs[64];
    uint64_t vmIP;
    uint64_t vmSP;

    uint8_t ZF;
    uint8_t SF;
    uint8_t CF;
    uint8_t OF;
    uint8_t PF;
    uint8_t AF;

    NativeRegisterSnapshot native;
    uint64_t savedRflags;
    uint64_t imageBase;
    uint64_t metadataVA;

    const uint8_t* bytecode;
    uint32_t bytecodeSize;
    const uint8_t* reverseOpcodeMap;
    const uint8_t* registerMap;

    VMTraceState* trace;
};
```

### 7.3 ISA

正式 ISA 必须覆盖 Windows 编译器常见标量代码，而不是只覆盖演示函数。

#### 数据传送

- MOV RR / RC / RM / MR
- LEA
- MOVZX / MOVSX / MOVSXD
- XCHG
- 部分寄存器读写语义

#### 算术与逻辑

- ADD、ADC、SUB、SBB
- AND、OR、XOR、NOT、NEG
- INC、DEC
- SHL、SHR、SAR、ROL、ROR
- MUL、IMUL、DIV、IDIV
- CMP、TEST

#### 控制流

- JMP
- 全套 JCC，包括 PF 相关条件
- CMOVcc
- SETcc
- VM 内部 CALL/RET
- native bridge CALL
- import thunk bridge
- indirect call/branch 的受控策略

#### 栈与调用约定

- PUSH / POP
- Windows x64 shadow space
- 16-byte stack alignment
- 参数寄存器 RCX/RDX/R8/R9
- x86 cdecl/stdcall/fastcall/thiscall
- non-volatile register 规则

#### SIMD 与浮点

最终生产架构必须定义 SSE2、SSE4、AVX/AVX2 与 x87 的处理策略。可以采用专用 VM handler 或严格的 native bridge，但不得使用隐式 native fallback。所有 bridge 都必须是正式、可验证、可配置的组件。

### 7.4 BytecodeInstr

```cpp
struct BytecodeInstr {
    uint8_t opcode;

    uint8_t dst;
    uint8_t src;
    uint8_t extra;
    uint16_t operandWidth;

    uint64_t immediate;

    uint8_t memBase;
    uint8_t memIndex;
    uint8_t memScale;
    int64_t memDisp;
    uint16_t memWidth;
    MemoryKind memoryKind;

    uint32_t branchTargetOffset;
};
```

编码格式必须由统一 schema 描述，Translator、Emitter、runtime decoder 和静态 verifier 共用同一份定义，禁止四处复制长度常量。

### 7.5 Translator

Translator 只消费统一 IR，不解析原始 opcode 字节。

核心规则：

```text
MOV reg,reg → VM_MOV_RR
MOV reg,imm → VM_MOV_RC
MOV reg,mem → VM_MOV_RM
MOV mem,reg → VM_MOV_MR
LEA reg,mem → VM_LEA
ADD reg,reg → VM_ADD_RR
ADD reg,imm → VM_ADD_RC
CMP reg,mem → 对应正式 memory handler
TEST reg,imm → VM_TEST_RC
JCC target → VM bytecode instruction boundary offset
```

不支持的语义必须拒绝，不得：

- 转 NOP。
- 删除指令。
- 保留原 native 指令并继续标记 VM applied。
- 把 CALL 粗暴映射为 VM_CALL_VM。

### 7.6 Flags

必须按 operand width 精确计算：

- ZF、SF、CF、OF、PF、AF。
- ADD/SUB/CMP 的进位与溢出。
- TEST/AND/OR/XOR 清 CF/OF。
- INC/DEC 不修改 CF。
- SHL/SHR/SAR 的边界计数语义。
- 32 位结果零扩展与 flags 计算使用 32 位宽度。

JCC 条件映射必须严格区分：

```text
JA  = !CF && !ZF
JAE = !CF
JB  = CF
JBE = CF || ZF
JG  = !ZF && SF == OF
JGE = SF == OF
JL  = SF != OF
JLE = ZF || SF != OF
```

### 7.7 Metadata

Metadata 使用版本化格式，所有 offset/size 必须边界验证。

当前基础布局：

| Offset | 字段 |
|---:|---|
| 0x00 | cookie |
| 0x04 | encoded record count |
| 0x08 | encoded record table offset |
| 0x0C | encoded reverse opcode map offset |
| 0x10 | encoded register map offset |
| 0x14 | encoded bytecode offset |
| 0x18 | encoded bytecode total size |
| 0x1C | encoded runtime entry RVA |
| 0x20 | encoded runtime version |
| 0x24 | encoded runtime flags |
| 0x28 | enter_count |
| 0x2C | last_function_rva |
| 0x30 | last_opcode |
| 0x34 | last_error_code |
| 0x38 | last_bytecode_offset |
| 0x3C | last_ret_value_low32 |
| 0x40 | reserved trace 0 |
| 0x44 | reserved trace 1 |

正式生产版必须进一步增加：

- metadata total size
- header checksum/MAC
- record size/version
- opcode schema version
- bytecode authentication tag
- architecture marker
- build identifier

### 7.8 Trace 与 runtime 错误

Debug/test 配置可启用无 CRT trace slot，不写文件日志。

至少支持：

```text
VM_ERR_METADATA_INVALID
VM_ERR_RECORD_NOT_FOUND
VM_ERR_BYTECODE_RANGE
VM_ERR_OPCODE_UNSUPPORTED
VM_ERR_REGISTER_MAP_INVALID
VM_ERR_MEMORY_ADDR_INVALID
VM_ERR_HANDLER_BUG
VM_ERR_RET_WITHOUT_CONTEXT
VM_ERR_STACK_ALIGNMENT
VM_ERR_NATIVE_BRIDGE
VM_ERR_UNWIND
```

调试模式失败路径写入错误码后触发 `int3; ud2`，不得静默返回。

### 7.9 Runtime 生成

runtime 必须是正式位置无关代码，不能依赖 packer 进程地址、CRT 或未解析外部符号。

推荐最终结构：

- 独立 runtime 源码/汇编模块。
- 编译为可提取、可重定位的 code/data blob。
- 明确 relocation/fixup 表。
- 由 VMRuntimeBuilder 按最终 section RVA 应用 fixup。
- runtime 与 metadata version 双向校验。
- x86 与 x64 分别实现，不用大量条件字节拼接共享一份脆弱 emitter。

手写机器码 emitter 只能作为 runtime 生成基础设施，不得通过散落的魔法字节承担全部解释器维护。最终应有汇编源或结构化 assembler backend，使 handler 能被审查和验证。

### 7.10 TrampolinePatcher

#### x86

- 近跳 `E9 rel32`。
- 必须覆盖完整指令边界。
- 被覆盖的额外字节按策略填充。

#### x64

按顺序选择：

1. `E9 rel32`，目标位于 ±2GB。
2. 原函数附近 relay thunk，再由 relay 绝对跳转。
3. 足够覆盖长度时使用正式 absolute jump sequence。

Patcher 必须：

- 使用 Zydis 计算可覆盖的完整指令长度。
- 不切断指令。
- 记录 patch kind、function RVA、trampoline RVA、覆盖长度。
- 验证写入后的跳转目标。
- 处理 x64 unwind 与 CFG Guard。
- 按配置销毁或加密 native body，避免原始逻辑仍可直接执行。

### 7.11 Native Bridge

Native bridge 是正式 VM 子系统，不是 fallback。

必须处理：

- Windows x64 调用约定。
- x86 多种调用约定。
- 参数寄存器与 stack args。
- shadow space 与 16-byte 对齐。
- 返回值 RAX/XMM0。
- volatile/non-volatile GPR、XMM。
- import thunk 与直接 native target。
- 异常传播与 unwind。
- bridge 白名单与 capability check。

---

## 8. VM 随机化与变异

每次构建由 BuildContext 统一生成：

- opcode map 与 reverse map。
- native register → VM register map。
- metadata cookie 与派生密钥。
- bytecode operand encoding。
- handler 排列。
- section 名称。
- runtime layout。

最终变异能力包括：

- handler 指令选择变异。
- handler 内部寄存器分配变异。
- dispatcher 结构变异。
- bytecode schema 变异。
- authenticated bytecode encryption。
- 假 handler 与不可达 metadata 噪声。

所有变异必须保持统一 schema，可由 packer 侧 verifier 解码验证，不能靠随机字节堆叠。

---

## 9. 非 VM 保护模块

### 9.1 字符串保护

必须支持两种明确模式：

#### startup

程序初始化时统一解密。兼容性较好，但明文生命周期长。

#### on_demand

- 改写字符串引用点。
- 每个字符串独立或派生密钥。
- 调用 decrypt thunk 后返回临时缓冲区。
- 可配置用后清零与缓存策略。
- 支持 ANSI、UTF-16、只读数据与资源字符串。

如果 on-demand 引用点重写未闭环，配置请求必须失败，不能自动降级为 startup。

### 9.2 导入保护

完整导入保护必须包含：

- 必需 loader API 的 bootstrap 策略。
- DLL/API 名称哈希。
- runtime resolver。
- resolver cache。
- IAT/thunk/callsite 重写。
- delay import 处理。
- forwarded export 处理。
- API-set schema 处理。
- x86/x64 调用兼容。
- 真正写入 PE 的可选 fake imports。

只有修改导入表而没有 runtime resolver/callsite rewrite 时不得标记 `applied`。

### 9.3 Section 加密

- 每个目标 section 独立密钥。
- authenticated encryption 或至少完整性校验。
- loader/runtime 解密顺序明确。
- TLS、OEP、DLL 初始化顺序兼容。
- 解密后权限恢复遵守 W^X 策略。
- 不与 VM runtime/metadata section 冲突。

### 9.4 控制流变换

控制流平坦化、bogus flow、不透明谓词均必须基于 IR/CFG 操作，不能直接在原始字节上随意插入。

必须维护：

- branch relocation。
- block boundary。
- flags 与寄存器活跃性。
- x64 unwind。
- CFG Guard。
- exception edge。

“生成了假块对象”不等于已应用；只有真实写入输出 PE 且通过 CFG/PE 验证才可计数。

### 9.5 完整性保护

完整性保护应作为独立功能：

- runtime/metadata/bytecode MAC。
- 关键 native thunk 校验。
- 可配置校验时机。
- 失败策略明确。

不得让完整性模块掩盖 VM 执行错误。

### 9.6 反调试与反分析

反调试是独立可配置模块，不能作为基础运行依赖。设计原则：

- 不破坏合法用户环境。
- 不影响 VM 正确性诊断。
- debug/test build 默认关闭或使用明显错误码。
- 不在 VM 核心未闭环时优先开发。
- 所有检测与响应必须可独立关闭、调强度、指定范围。

---

## 10. 模块化 TOML 配置

```toml
[global]
seed = 0
verbose = true
strip_debug_info = true
strip_rich_header = true
randomize_section_names = true

[section_encryption]
enabled = false
strength = 70
target_sections = [".text", ".rdata"]

[string_encryption]
enabled = false
strength = 80
mode = "on_demand"
ascii = true
utf16 = true
resources = false
clear_after_use = true

[import_protection]
enabled = false
strength = 80
api_hash = true
fake_imports = true
hide_real_imports = true

[control_flow.flattening]
# 独立本地 CFG 档：真实块体由编码状态分发器调度，不依赖 VM。
# 显式目标无法完成重定位/unwind/入口修补时整个构建 fail-closed。
enabled = false
strength = 70

[control_flow.bogus_flow]
enabled = false
strength = 60

[vm]
enabled = true
strength = 90
target_functions = []
target_rvas = [0x1234]
register_count = 32
opcode_randomization = true
handler_mutation = true
bytecode_encryption = true
native_body_policy = "destroy"

[integrity]
enabled = true
strength = 80
protect_metadata = true
protect_bytecode = true

[scope]
target_functions = []
target_rvas = []
target_sections = []
protect_exports = false

[failure_policy]
on_decode_failure = "fail_build"
on_unsupported_instruction = "reject_function"
on_vm_runtime_missing = "fail_build"
on_native_bridge_missing = "reject_function"
on_import_runtime_missing = "fail_build"
on_on_demand_string_runtime_missing = "fail_build"
on_cfg_guard_rewrite_required = "fail_build"
on_unwind_rewrite_required = "fail_build"
```

旧字段如 `[import_obfuscation]`、`[global] import_obfuscation` 可以在迁移窗口内给出明确 deprecation error/warning，但正式默认配置、示例和文档必须只使用新 schema。

---

## 11. 静态验证体系

### 11.1 VM bytecode verifier

对每个 record：

- reverse opcode map 解码。
- opcode 是否在 runtime schema 中。
- 指令长度是否越界。
- register id 是否合法。
- operand width 是否合法。
- memory base/index/scale/disp 是否可表达。
- branch target 是否位于 record 内且为指令边界。
- 所有可达控制流是否终止于 RET/VMEXIT/受控 bridge。
- 不存在从未定义 handler 进入的路径。
- bytecode authentication 信息匹配。

### 11.2 VM static link checker

必须验证：

- runtime `executionReady=true`。
- runtime section/metadata section/bytecode 均存在。
- runtime entry 已回填 metadata。
- record 与 trampoline 一一对应。
- function patch 已验证。
- opcode/register map 非空且版本匹配。
- native body policy 已落实。
- x64 unwind/CFG 要求已满足。

### 11.3 PE verifier

- 输出 PE 可重新解析。
- Section 与 Directory 全部合法。
- PEEmitter 写入结果未被 Rebuilder 覆盖。
- runtime、trampoline、metadata、resolver、string thunk 均位于正确权限 section。
- DLL/EXE loader 语义一致。

---

## 12. 构建、依赖与工程结构

### 12.1 推荐结构

```text
CipherShell/
├─ CMakeLists.txt
├─ cmake/
│  ├─ dependencies.cmake
│  └─ toolchains/
├─ third_party/
│  ├─ zydis/
│  └─ manifest.json
├─ packer/
│  ├─ main.cpp
│  ├─ pe_parser/
│  │  ├─ pe_parser.*
│  │  ├─ pe_emitter.*
│  │  └─ pe_rebuilder.*
│  ├─ analysis/
│  │  ├─ zydis_decoder.*
│  │  ├─ instruction_ir.*
│  │  ├─ function_discovery.*
│  │  ├─ cfg_builder.*
│  │  └─ dataflow.*
│  ├─ config/
│  │  ├─ config_parser.*
│  │  ├─ protection_build_context.*
│  │  └─ capability_checker.*
│  ├─ vm/
│  │  ├─ vm_schema.*
│  │  ├─ translator.*
│  │  ├─ vm_section_emitter.*
│  │  ├─ vm_runtime_builder.*
│  │  ├─ trampoline_patcher.*
│  │  ├─ native_bridge_builder.*
│  │  └─ vm_verifier.*
│  └─ transforms/
│     ├─ string_protection.*
│     ├─ import_protection.*
│     ├─ section_encryption.*
│     ├─ cfg_flattening.*
│     └─ integrity.*
├─ runtime/
│  ├─ x86/
│  ├─ x64/
│  ├─ bridge/
│  └─ common/
├─ config/
│  ├─ default.toml
│  ├─ full_example.toml
│  └─ vm_test.toml
├─ tests/
│  ├─ compile/
│  ├─ samples/
│  ├─ static/
│  └─ manual/
└─ docs/
   ├─ cipher-shell-design.md
   ├─ metadata-format.md
   ├─ vm-isa.md
   └─ manual-runtime-test.md
```

### 12.2 依赖要求

| 依赖 | 用途 | 要求 |
|---|---|---|
| Zydis | 唯一 x86/x64 指令解码器 | 固定版本/commit，静态链接，不依赖系统安装 |
| CMake | 构建 | 支持全新 build tree 配置 |
| MSVC | Windows x86/x64 构建 | 明确最低工具集版本 |
| NASM/ML64 | runtime/bridge 汇编 | 构建脚本自动检测 |
| TOML parser | 配置 | 固定版本，统一 schema |
| 密码学实现 | 数据/bytecode 保护 | 经过审查的实现，不自创密码算法 |

### 12.3 标准构建命令

```powershell
cd <CipherShell 仓库目录>
cmake -S . -B build
cmake --build build --config Release
git diff --check
```

Windows 开发环境也可直接运行仓库根目录的 `build_win.bat`；脚本必须以
自身目录为源码根目录，不得绑定开发者机器的固定盘符。

编码 AI 不运行任何生成 exe。

---

## 13. 验证与验收策略

### 13.1 AI/编码侧允许执行

- CMake configure。
- Release/Debug 编译。
- 静态库级检查。
- PE 静态解析。
- 生成测试样本源码、配置与命令。
- `git diff --check`。

### 13.2 AI/编码侧禁止执行

- 原始 EXE。
- 加壳 EXE。
- 测试 EXE。
- 任何受保护产物。

### 13.3 用户手动运行验证

最终功能验收由用户执行，至少覆盖：

- x64 / x86。
- EXE / DLL。
- Debug-like / optimized 编译结果。
- GPR、部分寄存器、memory、flags、JCC。
- CALL/native bridge/import bridge。
- stack alignment 与 shadow space。
- exceptions/unwind。
- CFG Guard / ASLR / DEP。
- section encryption、string on-demand、import resolver。

运行成功后不能只看“程序没崩”，还要验证：

- 目标函数确实进入 VM。
- enter_count 增加。
- last_opcode 更新。
- 返回值与原程序一致。
- native body 已按策略破坏。
- 未发生静默 native fallback。

---

## 14. 当前代码状态基线（2026-07-10）

本节记录当前实现事实，避免把设计目标误认为已完成能力。

### 14.1 已存在的能力

- PE 解析与基础重建框架。
- ProtectionBuildContext、CapabilityChecker 雏形。
- VM metadata、record、reverse opcode map、register map。
- x64 runtime interpreter emitter。
- trampoline 与函数入口 patch。
- x64 rel32/absolute 跳转策略的基础实现。
- VM trace slot 与 runtime error code。
- bytecode 静态 decoder/verifier。
- 基础 VM handler：MOV、LEA、ADD、SUB、AND、OR、XOR、CMP、TEST、JMP、常用 JCC、RET。
- memory load/store 的基础 operand 描述。
- 不支持 CALL/PUSH/POP 时 fail-closed。
- 编译通过与静态检查流程。

### 14.2 当前尚未达到最终架构的部分

- 正式生产解码路径仍有手写 ModRM/SIB/REX 解析；必须一次性替换为 Zydis + Unified IR。
- runtime 仍以大量手写机器码 emitter 维护，尚未达到可审查的独立汇编/runtime blob 结构。
- CALL/native bridge/import bridge 未闭环。
- VM stack、PUSH/POP、shadow space 未闭环。
- 部分寄存器、高 8 位寄存器、完整 PF/AF 语义未闭环。
- memory arithmetic 尚未完整覆盖。
- SSE/AVX/x87、CMOV/SETcc、异常/unwind 未闭环。
- x86 runtime 与 x86 trampoline 尚未达到与 x64 对等能力。
- import protection 仍缺 runtime resolver/callsite rewrite 完整闭环。
- on-demand string protection 尚未闭环。
- PEEmitter/PERebuilder 仍需完成所有 Directory 的统一边界。
- 配置与 CLI 仍存在等级导向和旧字段遗留。
- 未由用户完成运行时验证。

以上未完成项不得通过 `partial`、native fallback、NOP 或文案描述伪装为已完成。

---

## 15. 最终完成判定矩阵

CipherShell 只有同时满足以下条件，才可称为生产级完成：

### 解码与分析

- Zydis 是唯一正式解码器。
- 生产目录无手写 ModRM/SIB/REX parser。
- Unified IR 覆盖 operand action、width、部分寄存器、RIP-relative、branch target。
- CFG 和 Translator 不通过 raw opcode 猜语义。

### VM

- x86/x64 runtime 完整。
- 常见 GPR、memory、flags、JCC、stack、CALL、bridge、部分寄存器完整。
- SSE/AVX/x87 有正式 handler 或正式 bridge。
- runtime、metadata、bytecode 有版本与完整性验证。
- trampoline、unwind、CFG Guard 全部闭环。
- 原 native body 按策略处理。

### PE

- EXE/DLL、x86/x64 均支持。
- Import/Export/TLS/Reloc/Exception/LoadConfig/CFG/Security/Overlay 正确。
- PEEmitter 是唯一修改入口。
- PERebuilder 只序列化。

### 非 VM 保护

- on-demand string 引用点改写闭环。
- import resolver/callsite rewrite 闭环。
- section encryption 与 loader 顺序闭环。
- CFG 变换真实写入且通过验证。
- integrity 独立可配置。

### 配置与报告

- 所有功能独立 enable/strength/scope/failure_policy。
- L1-L5 只作为 preset。
- 旧字段从默认配置与示例删除。
- `applied` 必须由 verifier 决定。

### 验证

- 全新 build tree configure/build 通过。
- 静态 verifiers 全部通过。
- 用户完成运行验证，行为与原程序一致。
- 不存在 NOP 替代、静默跳过、native fallback 或假 applied。

---

## 16. 风险与强制缓解措施

| 风险 | 影响 | 强制措施 |
|---|---|---|
| 手写 x86/x64 decoder 误解码 | VM 语义错误且难定位 | 生产路径仅使用 Zydis，失败即拒绝 |
| runtime 魔法字节难维护 | 编译通过但运行错误 | 独立汇编/runtime blob、fixup 表、版本化 |
| flags/width 错误 | 条件分支与返回值错误 | operand-width-aware handler 与 verifier |
| x64 unwind/CFG 未更新 | 运行崩溃或系统阻止 | PEEmitter 统一重写并由 CapabilityChecker 阻止遗漏 |
| native bridge 不完整 | CALL 后栈或寄存器损坏 | 正式 ABI bridge，不允许隐式 fallback |
| Rebuilder 覆盖 Emitter 修改 | 输出 PE 缺失 section/patch | Rebuilder serialization-only，前后结构比对 |
| 配置字段漂移 | 用户以为功能已启用 | 单一 schema、unknown key error、旧字段弃用 |
| 功能状态虚报 | 无法判断保护是否真实 | `applied` 仅由静态 verifier 生成 |
| 随机变异破坏语义 | 构建不稳定 | 共享 schema、可重放 seed、静态解码验证 |

---

## 17. 术语

- **IR**：CipherShell 自己的指令/操作数中间表示。
- **VM Bytecode**：由 native 指令转换出的 Mirage 指令流。
- **VM Runtime**：嵌入目标 PE、负责执行 bytecode 的位置无关代码。
- **Trampoline**：原函数入口与 VM runtime 之间的桥接代码。
- **Native Bridge**：VM 调用未虚拟化 native 函数或 API 的正式 ABI 适配层。
- **PEEmitter**：唯一允许修改内存 PE 结构的模块。
- **PERebuilder**：将最终内存映像写出为文件的序列化模块。
- **CapabilityChecker**：在修改前判断功能能否安全闭环。
- **fail-closed**：无法保证正确时明确失败，不输出伪成功文件。
- **preset**：一组模块化配置的快捷展开，不是独立架构等级。

---

## 18. 文档维护规则

- 每次架构变更必须更新本文档和对应格式文档。
- 代码实现与本文不一致时，先判断是代码缺陷还是设计需要修订，不能用临时代码事实反向合理化错误架构。
- `codex_change.log` 记录代码变化；本文记录最终架构与当前实现差距。
- 任何新增功能必须同步补充：配置 schema、CapabilityChecker、状态报告、静态 verifier、手动验证说明。
- 不允许以“先实现简化版、以后再替换”为文档路线。

---

**结论**：CipherShell 的核心竞争力应集中在自研 VM 语义、runtime、bytecode、随机化、bridge、PE 正确性与验证体系；标准 x86/x64 指令解码由 Zydis 负责。所有模块直接按照最终生产架构实现，不保留临时双轨、fallback 或伪成功路径。
