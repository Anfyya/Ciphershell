# Zydis Encoder 语义内核试点评估

日期：2026-07-19
范围：`packer/transforms/vm_handler_semantic_codegen.cpp`，仅迁移
`VM_UOP_AND`、`VM_UOP_OR`、`VM_UOP_XOR`，不迁移移位/旋转、CFG、
CALL_HOST、BRIDGE_EXTENDED 或 unwind 生成逻辑。

## 结论

这条路线可行，且值得继续推广到“显式 GPR 操作数、无 ABI/故障/隐式寄存器
约束”的普通 ALU 语义。试点已经证明：

1. vendored Zydis 4.1.0 Encoder 能编码当前所有实际生成出来的 x86/x64
   handler 指令，包括 CFG 分支、CALL_HOST、BRIDGE_EXTENDED 以及 x64 unwind
   funclet 内的 prolog/epilog 指令；未发现指令语义层面的编码缺口。
2. AND/OR/XOR 的生产机器码已改由 `ZydisEncoderRequest` 生成，并在 x86 与
   x64 上分别得到 3 套和 4 套由 build seed 选择的真实寄存器操作数序列。
3. 两种架构的 handler 合成/执行门禁、静态门禁、隔离原生 CPU 差分和正式
   per-build similarity gate 全部通过。

Encoder 降低的是 REX/ModRM/opcode 选择风险，不会自动解决寄存器活跃性、
隐式寄存器、FLAGS、Win32/Win64 ABI、故障边界或 `.pdata` 一致性。因此不能把
“所有 `c.Raw` 机械替换”作为推广方法。

## 构建与接入

Zydis 的 `ZYDIS_FEATURE_ENCODER` 上游默认值为 `ON`，`ciphershell_packer` 原本
已经链接 `Zydis`。试点把这个生产依赖在根 `CMakeLists.txt` 中显式固定为
`ON`，避免外部 cache 把 Encoder 关闭后到链接阶段才失败。

生产辅助层只允许 legacy encoding，并统一完成：

- `ZydisEncoderRequest` 的 machine mode、mnemonic 和 operands 初始化；
- GPR32/GPR64 编号到 `ZydisRegister` 的转换；
- MOV、XCHG、二元寄存器、二元立即数和一元指令的编码；
- Encoder 失败时写入 `CodeBuffer` 的 fail-closed 错误，而不是回退到手写字节。

## 全指令形式覆盖审计

永久测试 `TestZydisEncoderCoversGeneratedInstructionForms` 使用两个独立 seed、
全部 4 个 K 变体和两种架构，遍历每个成功生成的语义 kernel。每条指令都执行：

1. Zydis 完整解码；
2. `ZydisEncoderDecodedInstructionToEncoderRequest`；
3. `ZydisEncoderEncodeInstruction`；
4. 再解码，并比较 mnemonic、寄存器、有效地址和立即数语义。

实测覆盖如下：

| 架构 | kernel | 指令 | CFG/CALL/JMP | unwind funclet 内 | CALL_HOST | BRIDGE_EXTENDED |
|---|---:|---:|---:|---:|---:|---:|
| x86 | 456 | 78,009 | 6,512 | 0 | 4,428 | 1,712 |
| x64 | 456 | 78,936 | 7,072 | 5,480 | 4,608 | 2,344 |

没有指令被 Decoder→Request→Encoder 路径拒绝。

### 明确边界

- `.pdata`、`RUNTIME_FUNCTION`、`UNWIND_INFO` 是 PE 元数据，不是 x86 指令，
  Zydis Encoder 不生成它们。Encoder 能覆盖与这些记录绑定的 prolog/epilog
  指令，但 `RecordX64StackFunclet`、范围计算和 unwind metadata 仍必须由项目
  维护并由现有 ABI/unwind 门禁验证。
- Encoder 能表达 near/short branch 和 call 的相对立即数，但不了解
  `CodeBuffer::Label`。符号标签绑定和 rel32 fixup 仍由 `CodeBuffer` 负责。
- `ZydisEncoderRequest` 表达指令语义，不保证保留同一 mnemonic 的特定物理
  opcode 变体。当前 API 没有“强制使用 accumulator 之外的 81 /group”或
  “强制使用 90+rd 的 XCHG 短形式”的选择字段。这不是语义覆盖缺口，但如果
  某处把具体字节长度写进 unwind/prolog 契约，就不能直接迁移。

## 三语义试点设计

选择 AND、OR、XOR 的原因是它们属于纯 ALU，完全不涉及 CFG 分发、栈展开、
native call、故障或隐式硬件寄存器。当前静态门禁已经把 54 个可适用语义全部
标为真实双策略，因此不存在“尚未标记 real_strategy_variant”的候选；试点保留
三者已有的两套业务恒等变换，只替换物理指令编码和寄存器分配。

安全寄存器池：

- x64：`RAX, RDX, R8, R11`。R9 是 width mask，R10 是 lazy-flags auxiliary，
  R15 是 context；RSP 与所有 nonvolatile GPR 均排除。
- x86：`EAX, EDX, ECX`。EBX/ESI/EDI 是 direct-threaded ABI 状态，均排除。

build seed 对语义专属 seed byte 和 K variant 做轮转，前三个位置分别作为
value/source/scratch。若 value 不在入口 RAX/EAX，先复制原 source，再用
不改 FLAGS 的 XCHG 完成并行重命名；计算结束后把结果移回 RAX/EAX。生成结果
发布的 `registerAssignment` 就是内核实际使用的计划，独立重发射验证也使用
同一计划。

永久测试遍历每个语义的 16 个 seed byte，实测：

| 架构 | 每个语义的不同 assignment | 固定 core strategy 下寄存器签名是否变化 |
|---|---:|---|
| x86 | 3 | 是 |
| x64 | 4 | 是 |

测试从反汇编后的寄存器 operands 构造签名，因此这个结论不依赖 seed-keyed
立即数变化，证明变化确实落在 REX/ModRM 的寄存器字段中。

## 迁移前后字节对比

对相同固定寄存器请求，常用寄存器指令与原手写编码逐字节一致：

| 指令 | 旧编码 | Zydis 输出 |
|---|---|---|
| `mov r8,rdx` | `49 89 D0` | `49 89 D0` |
| `and rax,rdx` | `48 21 D0` | `48 21 D0` |
| `or rax,rdx` | `48 09 D0` | `48 09 D0` |
| `xor rax,rdx` | `48 31 D0` | `48 31 D0` |
| `not rax` | `48 F7 D0` | `48 F7 D0` |
| `neg rax` | `48 F7 D8` | `48 F7 D8` |

完整 core 并非总能逐字节相同。零 seed、K=0 的 x64 AND 旧 core 为：

```text
49 89 D0 49 81 E0 90 9A 00 73 48 81 F0 90 9A 00 73 48 21 D0 4C 31 C0
```

迁移后为：

```text
49 89 D0 49 81 E0 90 9A 00 73 48 35 90 9A 00 73 48 21 D0 4C 31 C0
```

差异是 Zydis 为 `xor rax,imm32` 选择了等价且更短的 accumulator opcode
`48 35`，而旧 helper 固定输出 `48 81 /6`。同一配置下 AND 从 23 字节变为
22 字节；XOR 因 accumulator 和 imm8 规范化从 45 字节变为 35 字节。
项目没有为保住旧字节而回退到手写 ModRM，也没有插入填充绕过这个差异。

因此字节 A/B 的实际结论是：寄存器—寄存器迁移逐字节相同；完整语义 core
存在已解释的规范化差异，不能仅靠 byte equality 判定。后续以解码语义、
独立重发射、真实执行和隔离差分闭环确认无回归。

## 正确性验证

### 构建与静态/合成门禁

- x64 Release `ciphershell_packer`：通过 `/W4 /WX`。
- Win32 Release `ciphershell_packer`：通过 `/W4 /WX`。
- `test_vm_handler_synthesis`：x64、Win32 可执行文件均通过，包括主机真实
  handler 执行、双策略、#DE、CALL_HOST、BRIDGE_EXTENDED 和 unwind 相关检查。
- `vm_kernel_static_gate.py`：通过，真实双策略覆盖保持 `54/54`。

### 隔离原生 CPU 差分

`TestZydisAluPilotNativeDifferential` 构造：

```asm
and eax, ecx
or  eax, edx
xor eax, ecx
ret
```

它先通过软件 IR preflight，再复用 `packer/differential/` 的隔离 worker。
x64 与 x86 各使用 4 个独立 provider build seed，每个 seed 32 个 corpus，合计
256 个真实 CPU 对比样本，全部通过。随后两种架构的完整 native differential
测试套件也全部通过。

## 多样性效果

确定性 handler 合成指标的迁移前后变化：

| 指标 | x86 迁移前 | x86 迁移后 | x64 迁移前 | x64 迁移后 |
|---|---:|---:|---:|---:|
| business_without_codec | 0.409203 | 0.408657 | 0.462825 | 0.462747 |
| core_variant | 0.276391 | 0.273444 | 0.334314 | 0.333107 |
| max core-variant pair | 0.714286 | 0.714286 | 0.517241 | 0.483516 |

三语义只占全部业务核的一小部分，因此 aggregate 改善按预期较小；x64 原本由
AND K=1 贡献的最差 core-variant pair 已不再是全局最差点。

正式 `vm_per_build_similarity_gate` 的迁移后实测：

| 架构/容器 | business_core | core_variant | codec | encrypted_handlers |
|---|---:|---:|---:|---:|
| x64 EXE | 0.2751 | 0.1794 | 0.1163 | 0.0001 |
| x64 DLL | 0.2763 | 0.1285 | 0.1408 | 0.0001 |
| x86 EXE | 0.2546 | 0.0904 | 0.0231 | 0.0001 |
| x86 DLL | 0.2711 | 0.1019 | 0.0634 | 0.0001 |

所有 business_core 值均低于 `0.32`，正式门禁在两种架构均输出
`VM_PER_BUILD_SIMILARITY_GATE_PASS`。这证明试点没有造成 per-build 回退，且
寄存器字段确实提供了额外变化；不能把三语义的结果外推成大规模迁移后的线性
改善，推广后仍需重新采样和校准，而不能放宽阈值。

## 与手写方式的实际对比

### 开发效率

Zydis 路线更高。新增寄存器只改变 operand，不再逐条推导 REX.R/REX.B、ModRM
reg/rm、opcode direction 和高寄存器位。一次通用辅助层可复用于多个语义。
代价是需要显式处理 Encoder 的规范化输出和错误传播。

### 正确性风险

位编码风险显著降低：试点没有新增任何 REX/ModRM 位运算，所有候选寄存器都由
同一请求路径编码。风险没有归零：寄存器活跃性、并行 move、隐式 operands、
FLAGS、ABI 与 unwind 仍属于 CipherShell。永久的全指令重编码审计和隔离差分
应当成为后续迁移的前置条件。

### per-build 多样性

手写固定字节不能让寄存器位随 seed 变化；试点在固定业务 strategy 下已经得到
3/4 套真实寄存器签名。与只改立即数相比，这些变化会进入 REX/ModRM 和周边
move/xchg 序列，能移动 value-codec 排除立即数后的 4-gram。小范围试点的聚合
收益有限，但机制有效。

## 推广建议

### 普通显式操作数语义

建议推广。下一批优先选择 ADD、SUB、NOT、NEG、MUL 的显式寄存器部分，以及
简单 load/store 地址形式；每批保持 3–6 个语义，并要求：

1. 从活跃性契约导出安全寄存器池，而不是共享一个全局池；
2. Encoder 请求 fail-closed，禁止静默回退到手写字节；
3. 保存固定寄存器的旧/新字节对比，记录 Encoder 规范化；
4. 运行全矩阵重编码、两架构 handler 合成、隔离差分和正式 per-build gate。

### x86 `VM_UOP_UMUL_WIDE` K=1

建议作为高优先级、独立批次处理，而不是混进普通 ALU 批量迁移。Zydis 能表达
`MUL/IMUL r/m32`，但 EDX:EAX 是硬件隐式输入/输出，Encoder 本身不能随机化它们。
改善 K=1 需要把显式 divisor 放入 seed 选择的安全寄存器或地址形式，同时证明
EDX:EAX、lazy-flags latch 和 #DE/高半结果没有隐藏依赖。至少应增加按每个 K、
多个 seed 的 x86 隔离差分和 core-pair 专项指标后再合入。

### CALL_HOST 与 BRIDGE_EXTENDED

不建议现在整体迁移。覆盖审计证明 Encoder 能表达其中每一条指令，但这两个语义
的主要风险不是 ModRM，而是 Win64/Win32 ABI、shadow space、XSAVE/FXSAVE、
间接调用、异常边界、stack funclet 范围与 `.pdata` 的共同一致性。可先迁移不在
prolog/epilog 且不影响 unwind offset 的叶子指令片段；整体推广前应让“指令序列
+ stack effect + unwind record”来自同一份 typed IR，并继续运行真实 ABI/unwind
runner。仅用 Zydis Encoder 不能承担这部分正确性责任。

## 推广批次 1：显式 ALU 与简单内存（2026-07-19）

### 范围与结论

第一批推广迁移了 6 个语义：`ADD`、`SUB`、`NOT`、`NEG`、`LOAD`、
`STORE`。`MUL` 留给后续普通批次；x86 `UMUL_WIDE K=1` 仍按独立批次处理。
`CALL_HOST`、`BRIDGE_EXTENDED`、CFG 分发和 unwind 代码没有迁移。

这批验证通过。生产路径中的显式寄存器、立即数、`LEA` 和简单
`MOV/MOVZX [base+disp32]` 均由 `ZydisEncoderRequest` 生成；任意请求失败都写入
`CodeBuffer` 的编码错误并使 kernel 生成失败，没有手写字节回退。

### 按语义导出的活跃性契约

这批没有扩大或复用全局寄存器池。`registerAssignment[0..2]` 分别按各语义
实际的数据流解释，候选来自该语义进入 core 时的活跃性状态：

| 语义 | x64 安全池/计划 | x86 安全池/计划 | 排除依据 |
|---|---|---|---|
| ADD/SUB | RAX, RDX, R8, R11 轮转 | EAX, EDX, ECX 轮转 | R9 保留 width mask，R10 保留 lazy-flags auxiliary；x86 EBX/ESI/EDI 保留 direct-threaded ABI 状态 |
| NOT/NEG | RAX, RCX, RDX, R10, R11 轮转 | EAX, ECX, EDX 轮转 | x64 R8 保留原操作数、R9 保留 mask；x86 原操作数已写入 latch，只有 caller-volatile GPR 可用 |
| LOAD/STORE | RAX, RCX, R8, R10 轮转为 address/value/temp | `(EBX,ECX,ESI)` 与 `(ESI,EBX,ECX)` 两个角色计划 | x64 RDX 是 STORE 源、R11 被 width dispatch 使用；x86 只在这个原本已使用 EBX/ESI 的内存 core 内采用两套已证明安全的地址计划，EDX 始终保留 STORE 源 |

16 个语义专属 seed-byte 样本在固定 business strategy 下得到的真实结果为：

| 语义 | x86 assignment 数 | x64 assignment 数 |
|---|---:|---:|
| ADD/SUB | 3 | 4 |
| NOT/NEG | 3 | 5 |
| LOAD/STORE | 2 | 4 |

测试从 Zydis 反汇编后的显式寄存器和内存 base/index 构造签名，因而这些变化确实
进入 ModRM/REX，而不是仅由 seed-keyed 立即数造成。

### 迁移中发现的两个边界

1. 原 `EmitKeyedAddSubCore` 不是 ADD/SUB 私有函数，还被 `BRANCH`、
   `BRANCH_IF`、`CALL_VM`、`RET` 和 `BRIDGE_EXTENDED` 共用。直接替换该函数会
   越界改变 CFG/桥接路径，并在组合执行中形成 direct-threaded 循环，虽然孤立
   ADD/SUB 冒烟仍能通过。最终保留原函数给 CFG/桥接语义，新建
   `EmitZydisKeyedAddSubCore` 只由 ADD/SUB 调用。这也是后续迁移必须先审计
   helper 调用图、不能只按函数名判断归属的实证。
2. `ZydisRegisterEncode(ZYDIS_REGCLASS_GPR8, id)` 的 id 不是通用物理 GPR 编号：
   GPR8 类在 AL..BL 后还排列 AH..BH，随后才是 SPL..DIL 与 R8B..R15B。
   未转换时物理 R10 的 byte operand 会被编码成 SIL。辅助层现在仅在 x64
   byte operand 上把物理编号 4..15 映射到 GPR8 id 8..19；x86 的 byte value
   契约只允许 EAX/ECX/EDX/EBX。全宽度内存执行矩阵捕获并验证了这个修复。

这两个问题都不是 REX/ModRM 位运算错误：Encoder 正确编码了收到的请求，错误在
请求的语义所有权和寄存器编号域。结论是 Encoder 显著缩小了正确性风险面，但不能
代替活跃性契约、调用图审计和真实执行验证。

### 固定寄存器的迁移前后字节

以下使用相同寄存器及相同 `disp32=0x11223344`。寄存器/寄存器、unary 和简单
地址形式逐字节一致；立即数形式由 Encoder 规范化为 accumulator 短 opcode：

| 指令 | 旧手写/helper | Zydis Encoder |
|---|---|---|
| `add rax,rdx` | `48 01 D0` | `48 01 D0` |
| `sub rax,rdx` | `48 29 D0` | `48 29 D0` |
| `not rax` | `48 F7 D0` | `48 F7 D0` |
| `neg rax` | `48 F7 D8` | `48 F7 D8` |
| `lea rcx,[rax+11223344h]` | `48 8D 88 44 33 22 11` | `48 8D 88 44 33 22 11` |
| `movzx rax,byte ptr [rcx+11223344h]` | `48 0F B6 81 44 33 22 11` | `48 0F B6 81 44 33 22 11` |
| `mov byte ptr [rcx+11223344h],dl` | `88 91 44 33 22 11` | `88 91 44 33 22 11` |
| `add rax,11223344h` | `48 81 C0 44 33 22 11` | `48 05 44 33 22 11` |
| `sub rax,11223344h` | `48 81 E8 44 33 22 11` | `48 2D 44 33 22 11` |

因此迁移判据与试点一致：固定寄存器的基本指令语义和字节先对齐；完整 core 允许
存在已解释的等价规范化，并继续由重编码、handler 执行和隔离差分闭环验证。

### 验证结果

- 全矩阵 Decoder→Request→Encoder→Decoder：x86 456 个 kernel、78,065 条指令；
  x64 456 个 kernel、79,010 条指令。CFG、CALL_HOST、BRIDGE_EXTENDED 和 x64
  funclet 覆盖仍在，所有重编码操作数语义一致。
- Release handler 合成与真实执行：x64 和 Win32 均通过全宽度双策略数据/内存、
  算术、flags、控制流、CALL_HOST、BRIDGE_EXTENDED 与故障矩阵。
- 隔离原生 CPU 差分：构造
  `LOAD→ADD→SUB→NOT→NEG→STORE→LOAD` 链；x64 与 x86 各 4 个独立 provider
  seed、每 seed 32 个 corpus，共 256 个新增真实 CPU 样本，全部通过。
- 静态门禁：真实双策略覆盖保持 `54/54`。
- 正式 per-build similarity gate（真实 DLL 与 EXE、独立 seed）全部通过：

| 架构/容器 | business_core | core_variant | codec | encrypted_handlers |
|---|---:|---:|---:|---:|
| x64 EXE | 0.2779 | 0.1853 | 0.1319 | 0.0001 |
| x64 DLL | 0.2859 | 0.1992 | 0.1202 | 0.0001 |
| x86 EXE | 0.2579 | 0.1008 | 0.0000 | 0.0001 |
| x86 DLL | 0.2661 | 0.0761 | 0.0051 | 0.0001 |

所有 `business_core` 均低于 0.32，并输出
`VM_PER_BUILD_SIMILARITY_GATE_PASS`。本机完整门禁实测耗时 x64 375.4 秒、
Win32 458.6 秒，超过原 CTest 外层 300 秒限制；测试属性已提高到 900 秒，避免
外层先于脚本自身的逐 case deadline 终止并遗留占用输出 PE 的 runner。

### 实际评估与后续顺序

- 开发效率：对显式寄存器和简单 `[base+disp32]` 明显优于手算字节；新增候选
  寄存器只改 operand/契约。必须额外花时间审计 helper 调用图和编号域。
- 正确性风险：REX/ModRM/opcode direction 风险转移给 Zydis；剩余主要风险是
  活跃性、隐式操作数、FLAGS、ABI、故障边界及 shared helper 所有权。本批两处
  问题都由全矩阵和组合执行捕获，没有以静默回退掩盖。
- per-build 多样性：6 个语义在固定策略下得到 2–5 套真实寄存器签名，正式聚合
  门禁没有退化。范围仍小，不能据此线性外推全量收益。

建议继续推广普通显式操作数语义，但保持每批 3–6 个并执行同一闭环。下一步把
x86 `UMUL_WIDE K=1` 单独处理：只随机化显式 multiplier 的寄存器/地址形式，明确
保留硬件隐式 EDX:EAX。`CALL_HOST` 与 `BRIDGE_EXTENDED` 继续不迁移。

## 同批 Linux PE 兼容常量修复

`pe_emitter.cpp` 使用标准值为 `0x0040` 的
`IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE`，而非 Windows 构建使用的
`compat/windows_compat.h` 原先只定义了 `GUARD_CF`。审计后补齐同一标准常量族：

| 常量 | 值 |
|---|---:|
| `HIGH_ENTROPY_VA` | `0x0020` |
| `DYNAMIC_BASE` | `0x0040` |
| `FORCE_INTEGRITY` | `0x0080` |
| `NX_COMPAT` | `0x0100` |
| `NO_ISOLATION` | `0x0200` |
| `NO_SEH` | `0x0400` |
| `NO_BIND` | `0x0800` |
| `APPCONTAINER` | `0x1000` |
| `WDM_DRIVER` | `0x2000` |
| `GUARD_CF` | `0x4000` |
| `TERMINAL_SERVER_AWARE` | `0x8000` |

这样 Linux 兼容头不再只为当前单个引用打补丁，后续 PE emitter 使用同族标志也
不会再次因缺失宏而失败。

本机没有安装可用的 WSL 发行版，也没有 Docker/Podman；现有 `build_linux` 还是
指向 `/usr/bin/c++` 的 Unix Makefiles，不能在当前 Windows 主机执行。仓库当前
CI 只有静态门禁及 Win32/x64 构建，同样没有 Linux 编译 job。因此本批完成的是
常量族审计和两套 Windows 构建验证，尚未取得真正的非 Windows 编译证据；后续需
在 Linux 环境复验，或给 CI 增加 Linux build job。这个限制不计作已验证结果。

## 独立批次 2：x86 `UMUL_WIDE K=1` 显式乘数（2026-07-19）

### 范围与设计

本批只处理已知最差单点 x86 `VM_UOP_UMUL_WIDE K=1`，没有混入普通 ALU
迁移。x64 `UMUL_WIDE`、普通 `MUL`、`CALL_HOST`、`BRIDGE_EXTENDED`、CFG
分发及 unwind 序列均未改动。K=0 保持原来的 `F7 E1`（`mul ecx`）逐字节不变，
作为控制臂；K=1 的显式乘数由固定 ESI 扩展为四个 seed 选择的操作数计划：

| 计划 | `registerAssignment` | 主乘法显式操作数 |
|---|---|---|
| 0 | `{ESI,ECX,EBX,EDX}` | `mul esi` |
| 1 | `{EDX,ECX,EBX,ESI}` | `mul edx` |
| 2 | `{ESI,ECX,EBX,0(memory marker)}` | `mul dword ptr [esi-addressKey]` |
| 3 | `{EDX,ECX,EBX,0(memory marker)}` | `mul dword ptr [edx-addressKey]` |

这些不是全局共享池。它们直接来自 K=1 core 的活跃性契约：EDI 在整个 handler
中保持 context；EAX 是硬件隐式 multiplicand；ECX 保存 `b+key`；EBX 保存用于
校正的 `a`；EDX:EAX 是 `MUL` 的隐式输出。EDX 只在执行主乘法之前作为显式源或
地址 base，x86 会先读取源/计算有效地址，再写入 EDX:EAX；之后旧 EDX 不再活跃。

内存计划先令 base 指向
`EDI + CtxMutationScratch + 4 + addressKey`，再通过 `[base-addressKey]` 访问真正的
`CtxMutationScratch+4`。`CtxMutationScratch+0` 仍单独保存 keyed-add carry，因此
两个 scratch word 不冲突。寄存器计划及地址计划的所有 `MOV/LEA/MUL r/m32`
均通过 `ZydisEncoderRequest` 生成；请求失败沿现有 `CodeBuffer` 错误路径使 kernel
生成失败，不存在退回固定手写字节的分支。

### 固定操作数的迁移前后字节

固定为原 ESI 寄存器场景时，迁移前后的字节完全一致：

| 指令/序列 | 旧手写字节 | Zydis Encoder |
|---|---|---|
| `mov esi,ecx` | `89 CE` | `89 CE` |
| `mul esi` | `F7 E6` | `F7 E6` |
| 合并序列 | `89 CE F7 E6` | `89 CE F7 E6` |

其余三套计划提供真实 ModRM/address-form 变化：直接 EDX 形式为
`89 CA F7 E2`；令 `A=CtxMutationScratch+4+addressKey`、`D=-addressKey`，ESI
内存形式为 `8D B7 <A32> 89 8E <D32> F7 A6 <D32>`，EDX 内存形式为
`8D 97 <A32> 89 8A <D32> F7 A2 <D32>`。`<A32>/<D32>` 均为小端 disp32。
这既保留了固定 ESI 请求的旧/新 byte equality，也证明新增变化实际进入 ModRM
和地址位移，而不是只改无关立即数。

### 验证结果

- Release 构建：Win32 与 x64 的 `test_vm_handler_synthesis`、
  `test_vm_native_differential` 均编译并通过。
- 全矩阵 Decoder→Request→Encoder→Decoder：x86 456 个 kernel、78,071 条指令；
  x64 456 个 kernel、79,010 条指令。CFG、CALL_HOST、BRIDGE_EXTENDED 与 x64
  funclet 仍在覆盖矩阵中，操作数重编码一致。
- handler 合成/执行：Win32 与 x64 的数据、内存、算术、flags、控制流、ABI、
  故障及宽乘除矩阵全部通过。专项解码测试枚举出 4 套 assignment 和 4 个不同的
  `MUL` operand signature（register ESI/EDX、memory base ESI/EDX）。
- x86 隔离原生 CPU 差分：K=0 使用 provider seed 1、4；K=1 使用覆盖四套计划的
  seed 2、3、7、19；每 seed 32 个 corpus，共 192 个新增真实 CPU 样本全部通过。
- 静态门禁：真实双策略覆盖保持 `54/54`。
- 正式 per-build similarity gate（独立真实 EXE/DLL 与 build seed）全部通过：

| 架构/容器 | business_core | core_variant | codec | encrypted_handlers |
|---|---:|---:|---:|---:|
| x64 EXE | 0.2718 | 0.1575 | 0.1131 | 0.0001 |
| x64 DLL | 0.2856 | 0.1867 | 0.1235 | 0.0001 |
| x86 EXE | 0.2520 | 0.0784 | 0.0226 | 0.0001 |
| x86 DLL | 0.2682 | 0.0868 | 0.0634 | 0.0001 |

两架构均输出 `VM_PER_BUILD_SIMILARITY_GATE_PASS`。本次直接运行正式脚本并使用
独立 workdir，耗时 x64 396.6 秒、Win32 473.2 秒；900 秒 CTest 上限有足够余量。

### 效果与推广结论

专项 deterministic core-pair 指标中，x86 `UMUL_WIDE K=1` 从迁移前的
`0.714286` 降到 `0.500000`，绝对下降 `0.214286`、相对下降 30%。当前 x86
最差 pair 转为本批刻意保持不变的 `UMUL_WIDE K=0`，值为 `0.702128`；K=1 另有
`<0.55` 的专项回归上限，不能再被全局 `<0.75` 上限掩盖。

- 开发效率：一旦活跃性契约确定，寄存器和内存两类显式源只需构造 operand，
  无需分别维护四套 ModRM 字节。该批真正耗时的部分是隐式 EDX:EAX 数据流审计，
  不是编码本身。
- 正确性风险：Zydis 接管了 MOV/LEA/MUL 的 opcode、ModRM 与位移编码，但不能
  接管硬件隐式操作数和 scratch 生命周期。四计划真实执行、按 K 的隔离差分和
  全矩阵验证仍是必要条件；本批没有发现未解释的隐藏寄存器依赖。
- per-build 多样性：固定 `89 CE F7 E6` 已变为两种寄存器形式和两种地址形式，
  K=1 专项相似度得到明显下降，正式聚合门禁也没有退化。这比仅改变 keyed
  immediate 更直接地改变 business core 的寄存器/地址字节。

结论是 Zydis 路线值得继续用于普通显式操作数和简单地址形式；下一普通批次可处理
尚未迁移的 `MUL` 等 3–6 个语义，并保持同一验证闭环。`UMUL_WIDE K=0` 若要继续
降低当前最差 pair，应作为新的独立设计审计，而不是复用 K=1 方案硬改。
`CALL_HOST` 与 `BRIDGE_EXTENDED` 仍不建议整体迁移：其主要风险在 ABI、故障边界
和 unwind 元数据一致性，Encoder 本身不能降低这些风险。

## 推广批次 3A：`MUL` 显式操作数（2026-07-19）

### 设计与活跃性契约

本批只迁移普通截断乘法 `VM_UOP_MUL`，不包含宽乘法。两种业务 K 的约束不同，
因此不再让它们共享一个无角色的全局寄存器池：

| 架构/K | seed 选择的角色 | 明确保留/排除 |
|---|---|---|
| x64 K=0 two-operand IMUL | value/source/correction 在 RAX、RDX、R8、R11 中轮转 | R9 保留 width mask，R10 保留 lazy-flags auxiliary，RCX/R15 与非易失寄存器不参与 |
| x64 K=1 one-operand MUL | 显式 multiplier 在 RDX/R8/R11/RCX 中选择；correction 仅用可跨 MUL 存活的 R8/R11/RCX | RDX:RAX 始终是硬件隐式 pair，correction 禁止分配到二者 |
| x86 K=0 two-operand IMUL | value/source/correction 在 EAX、EDX、EBX、ECX 中轮转 | EDI 保留 context，ESI 不参与；EBX 是旧 MUL core 已使用并验证过的 correction 角色 |
| x86 K=1 one-operand MUL | multiplier 在 EDX/ECX/EBX 中选择，correction 在另一个 ECX/EBX 中选择 | EDX:EAX 保持隐式 pair，ESI/EDI 不参与 |

非固定角色的 a/b 从进入 core 前已落盘的 `CtxLastAlu` 重载，避免靠交叉 `MOV/XCHG`
猜测旧寄存器值。K=1 只随机化显式 multiplier 与跨 `MUL` 存活的 correction；
Encoder 不承担、也没有试图随机化硬件隐式 RDX:RAX/EDX:EAX。所有 MOV、IMUL、
MUL、ADD、SUB 请求均走 `ZydisEncoderRequest`；失败写入 `CodeBuffer` 编码错误并
使 kernel fail-closed，没有手写回退。

### 固定寄存器字节对比

固定为旧角色时，显式寄存器指令逐字节一致：

| 指令 | 旧 helper/手写 | Zydis Encoder |
|---|---|---|
| `imul r8,rdx` | `4C 0F AF C2` | `4C 0F AF C2` |
| `imul rax,rdx` | `48 0F AF C2` | `48 0F AF C2` |
| `mul rdx` | `48 F7 E2` | `48 F7 E2` |
| `sub rax,r8` | `4C 29 C0` | `4C 29 C0` |
| `imul ebx,edx` | `0F AF DA` | `0F AF DA` |
| `imul eax,edx` | `0F AF C2` | `0F AF C2` |
| `mul edx` | `F7 E2` | `F7 E2` |
| `sub eax,ebx` | `29 D8` | `29 D8` |

立即数 ADD/MOV 允许 Encoder 选择等价短形式，例如 accumulator ADD 可从
`81 C0 <imm32>` 规范化为 `05 <imm32>`；这不作为 byte-equality 失败，而由完整
重编码和真实执行闭环确认。

### 当前验证状态

- 本地完整静态门禁（含比例探针）：`54/54`，通过。
- handler register-signature 测试已扩展到 MUL：每个 K 在固定业务策略下至少取
  两套 assignment；完整枚举要求 x64/x86 均覆盖 4 套计划。
- 隔离原生差分已扩展为每个 K 两个不同 provider plan、每 seed 32 个 corpus；
  Win32/x64 的实际执行、全矩阵重编码与正式 per-build gate 由本批提交后的 CI
  核实，结果将在本节后续更新。
