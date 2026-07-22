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
- 原先用 two-operand IMUL 作为 fixture 是错误的：translator 明确把该形式降为
  `SMUL_WIDE`，不会产生 `VM_UOP_MUL`。修正后的 fixture 使用生产真实入口
  `lea rax/eax,[rax/eax+rcx/ecx*4]`，并在确定性地址范围内选择 EmitAddress 的
  MUL lowering arm，防止测试静默绕开目标语义。
- 修正后 x64 与 Win32 隔离原生差分均通过：每个 K 两个不同 provider plan、每
  seed 32 个 corpus；negative control 用原生 ADD 对比 VM scaled-LEA MUL，均能
  检出分歧。正式全套 ctest 与 per-build gate 仍由最终提交后的 CI 核实。

## 独立批次 3B：x86 `UMUL_WIDE K=0` 显式乘数（2026-07-19）

### 与 K=1 分离的设计

K=0 没有复用 K=1 的“seed-split base + 负位移”地址方案。两者只共享硬件不可变
约束：EAX 是隐式 multiplicand，EDX:EAX 是 `MUL` 的隐式结果。K=0 进入主乘法前
的活跃性契约是：EBX 保存原始 a，ECX 保存 `(b + key)`，EDI 始终是 context；
keyed-add carry 使用 `CtxMutationScratch+0`。据此单独导出四套计划：

| 计划 | 显式 multiplier | 迁移后序列 | 活跃性依据 |
|---|---|---|---|
| 0（固定基线） | ECX | `mul ecx` | 直接消费现有 `(b+key)`，不增加临时寄存器 |
| 1 | EDX | `mov edx,ecx; mul edx` | EDX 在主 `MUL` 前可覆盖，本来就会被隐式写回 |
| 2 | ESI | `mov esi,ecx; mul esi` | ESI 的旧值在该 core 内不再活跃，主乘法后用于保存 low half |
| 3 | `[EDI+CtxMutationScratch+4]` | store ECX 后 `mul dword ptr [...]` | EDI 保持 context；`+4` 与 carry 的 `+0` 槽分离 |

前三个 assignment 角色保持互异，validator 继续按该语义的局部契约只允许
ECX/EDX/EBX/ESI，加上 memory-plan marker；没有引入全局共享寄存器池。K=1 的
ESI/EDX 寄存器源与 seed-split 地址源实现、计划表和专项上限均保持原样。

四种主乘数的 MOV/store/MUL 都由 `ZydisEncoderRequest` 生成；Encoder 拒绝任一
请求都会写入 `CodeBuffer` 编码错误并让 kernel 生成失败，不存在回退到
`c.Raw(...)` 的分支。后半段校正乘法仍是本批未迁移的固定隐式操作数序列。

### 固定寄存器字节对比

固定基线保持迁移前后的精确字节一致，其余三套是 seed 可选的新 operand 形式：

| 指令/形式 | 迁移前/预期 | Zydis Encoder |
|---|---|---|
| `mul ecx` | `F7 E1` | `F7 E1` |
| `mov edx,ecx; mul edx` | `89 CA F7 E2` | `89 CA F7 E2` |
| `mov esi,ecx; mul esi` | `89 CE F7 E6` | `89 CE F7 E6` |
| `mov [edi+disp32],ecx; mul dword ptr [edi+disp32]` | `89 8F <disp32> F7 A7 <disp32>` | `89 8F <disp32> F7 A7 <disp32>` |

### 当前验证状态

- 本地完整静态门禁（含比例探针）：`54/54`，通过。
- handler 合成测试现按 K 分别要求 4 套 assignment 和 4 个真实解码 operand
  signature；K=0 期望 ECX/EDX/ESI 三种 register signature 与 EDI memory
  signature，K=1 保持原四种 signature。
- x86 隔离差分的 provider seed 选择已从“K=0 两个、K=1 四个”提升为两个 K
  各覆盖四套计划；实测 K=0 seed 1/4/5/22、K=1 seed 2/3/7/19，每个 seed
  32 个真实 CPU corpus，共 256 个样本全部通过。
- deterministic gate 新增 K=0 专项 `<0.65` 上限，替代迁移前 `0.702128` 最差
  单点的无专项约束状态。本地定点执行实测为 `0.583333`，绝对下降 `0.118795`、
  相对下降约 16.9%；K=1 保持 `0.500000`。正式 per-build similarity gate 仍由
  最终提交后的 CI 核实。

## 推广批次 3C：`BSWAP`、`ZERO_EXTEND`、`SIGN_EXTEND`（2026-07-19）

### 范围与活跃性契约

本批只迁移三个算术语义的显式寄存器指令。`BSWAP` 的本地 width 分支和 invalid
路径保持原控制结构；扩展语义仍固定使用 CL 作为硬件 shift count。没有触碰 VM
CFG 分发、unwind funclet、native 调用桥接或故障语义，`CALL_HOST` 与
`BRIDGE_EXTENDED` 继续排除。

| 语义/架构 | seed 选择的角色与安全池 | 明确保留/排除 |
|---|---|---|
| BSWAP x64 | value/transform/key/spare 在 RAX、RCX、RDX、R10 中轮转 | R8 保留原值，R9 保留 width mask，R11 专用于 width dispatch，R15 为 context |
| BSWAP x86 | value/transform/spare 在 EAX、EDX、EBX 中轮转 | ECX 专用于 width dispatch，EDI 为 context，ESI 不参与 |
| ZERO/SIGN_EXTEND x64 | value/mask/count/sign 在 RAX、R10、RDX、R11 中轮转 | RCX 固定提供 CL，R8 保留原值，R9 保留 destination mask，R15 为 context |
| ZERO/SIGN_EXTEND x86 | value/mask/count-or-sign 在 EAX、EBX、EDX 中轮转 | ECX 固定提供 CL，EDI 为 context；count 写入 CL 后同一角色才可复用为 sign scratch |

扩展语义在任何可能把 RAX/EAX 分配为 count scratch 的计划中，都会先把输入复制到
seed 选中的 value 寄存器，再生成 count；因此不会用 count 计算覆盖尚未搬走的输入。
每条 MOV、XOR、ROL/ROR、BSWAP、SUB、SHL/SHR/SAR、AND 指令都通过
`ZydisEncoderRequest` 构造。请求失败沿统一 `CodeBuffer::FailEncoding` 路径让
kernel fail-closed，不回退手写 ModRM/REX。

### 固定寄存器字节对比

将角色固定为迁移前使用的寄存器时，下列代表性显式指令逐字节一致：

| 指令 | 迁移前 | Zydis Encoder |
|---|---|---|
| `xor al,imm8` | `34 <imm8>` | `34 <imm8>` |
| `rol ax,8` | `66 C1 C0 08` | `66 C1 C0 08` |
| `bswap eax` | `0F C8` | `0F C8` |
| `bswap rax` | `48 0F C8` | `48 0F C8` |
| `mov edx,eax; bswap edx; mov eax,edx` | `89 C2 0F CA 89 D0` | `89 C2 0F CA 89 D0` |
| `mov edx,8; sub edx,ecx; shl edx,3; mov ecx,edx` | `BA 08 00 00 00 29 CA C1 E2 03 89 D1` | 相同 |
| `shl rax,cl; mov rcx,rdx; shr rax,cl` | `48 D3 E0 48 89 D1 48 D3 E8` | 相同 |
| `mov ebx,-1; shr ebx,cl; and eax,ebx` | `BB FF FF FF FF D3 EB 21 D8` | 相同 |

非固定计划由 Encoder 自动改变 REX/ModRM，例如 value 轮转到 R10/R11 或 EBX/EDX；
代码不再自己拼位域。x64 的 64-bit key/sign immediate 仍允许 Encoder 在合法的
sign-extended imm32 与 imm64 形式间选择，语义等价性由重编码和执行测试闭环约束。

首轮 CI 还暴露了一个 Encoder API 边界：legacy ALU/MOV 的 8/16/32-bit immediate
在 Zydis 匹配阶段按 signed field 判断能否装入目标编码。直接把 `0xCD15` 作为正的
`uint64_t` 提交给 16-bit XOR，会被判断为需要更宽 immediate 并 fail-closed；这不是
机器码语义错误，而是 request 数值表示不完整。统一 helper 现先按目标位宽保留低位
并符号扩展，再提交请求；生成的低 8/16/32 位字节不变。错误信息同时补充 mnemonic、
status 和 operand 摘要，今后 Encoder 拒绝不再只返回无法定位的泛化文本。

### 当前验证状态

- 首轮远端 CI 如预期 fail-closed，定位到上述 immediate request 表示问题；修正后
  本地 x64-host `test_vm_handler_synthesis` 定点执行完整通过，其中 pack-time
  x86/x64 handler 合成、全矩阵重编码和 13 个迁移语义 register-signature 均通过。
- x64 与 Win32 `test_vm_native_differential` 定点执行均完整通过。BSWAP 每架构
  4 个 provider seed，ZERO/SIGN_EXTEND 每架构 5 个 provider seed，每 seed
  32 个 corpus；所有目标计划的真实 CPU 对照均成功。
- 本地完整静态门禁（含比例探针）：`54/54`，通过。
- register-signature 枚举从 10 个迁移语义扩展为 13 个；每个新语义要求同一业务
  K 下至少两个不同 assignment 和两个不同真实解码 signature，并校验实际发布的
  value/mask/count/sign 角色出现在 core 字节中。
- 隔离原生差分会按 fixture 中的实际 handler variant 自动选择 provider seed，
  对 BSWAP 以及 ZERO/SIGN_EXTEND 的每个 K 各覆盖至少两个不同 assignment，每
  seed 32 个 corpus。上述本地运行是为定位首轮 CI 失败的定点可执行文件运行，
  不是完整 CTest/per-build 的替代；正式全套 ctest 与 per-build similarity gate
  由最终修复提交后的 CI 核实。

### 本轮评估与继续推广边界

- 开发效率：新增 sized register/immediate helper 后，8/16/32/64 位 XOR、rotate、
  BSWAP 和 shift 不再分别拼 prefix/REX/ModRM；三个语义共用同一套 request 规则。
  immediate 的 signed-field 约束只需在 helper 修正一次，所有后续语义自动继承。
- 正确性风险：Encoder 把位域编码错误变成可诊断的 fail-closed 失败，但不能替代
  活跃性审计。本批真正需要人工证明的是 RAX 输入搬运必须早于 count scratch 覆盖，
  以及 RCX/CL、R8/R9、context 的跨 core 生命周期；两架构真实差分没有发现隐藏
  寄存器依赖。
- per-build 多样性：BSWAP 和扩展语义分别得到 x64 四套、x86 三套 assignment；
  x86 `UMUL_WIDE K=0` 专项 pair 从 `0.702128` 降至 `0.583333`，已低于新设
  `<0.65` 上限。最终聚合效果以正式 per-build CI 数值为准。

结论仍是值得按 3–6 个简单显式操作数语义的小批次继续推广，前提是每个语义单独
导出活跃性契约并保留真实 CPU 差分。隐式硬件 pair 应继续只随机化显式源，不能把
Encoder 当成活跃性分配器。`CALL_HOST` 与 `BRIDGE_EXTENDED` 本轮未迁移，后续也不应
按普通 ALU 模板批量处理；其 ABI、unwind、故障边界风险需要独立设计和独立批次。

### 最终 CI 闭环

修复提交 `25a4c10` 对应 GitHub Actions run `29689692551` 最终为 `success`：
`static-gate`、`build-and-test (x64)`、`build-and-test (Win32)` 三个 job 全部通过。
两个架构 job 都完成完整 Release 构建和全部 CTest，因此本轮要求的全矩阵重编码、
两架构 handler 合成、隔离原生差分与正式 per-build similarity gate 均已由 CI
核实通过。首轮三个功能提交的红灯均被该修复提交取代，根因是上述 immediate request
表示和无效 IMUL fixture，不是用手写字节回退绕过 Encoder。

## 推广批次 4：`SHL`、`SHR`、`SAR`、`ROL`、`ROR`、`ROT`（2026-07-20）

### 范围与局部活跃性契约

本批迁移 6 个简单语义。`SHL/SHR/SAR/ROL/ROR` 的值搬运、key share、按 CL
移位/循环、低宽度归一化以及计数掩码均改由 `ZydisEncoderRequest` 生成；`ROT`
的三值循环改由 Encoder 生成 MOV/XCHG/XOR。CFG width dispatch 和 handler 输入/输出
边界保持不变，`CALL_HOST`、`BRIDGE_EXTENDED` 仍未迁移。

寄存器分配没有使用全局共享池，而是由每个语义进入 core 时的活跃性直接导出：

| 语义/架构 | seed 选择的角色与安全池 | 保留/排除 |
|---|---|---|
| 五个移位 x64 | value/key-accumulator/key-share/spare 在 RAX、R8、R11、R12、R13 中轮转 | RCX/RDX 固定为 count 路径；R9 保留 width mask；R10 保留 lazy-flags auxiliary；R15 保留 context；R14 因既有隔离实测失败继续排除 |
| 五个移位 x86 | value/key-accumulator/key-share 在 EAX、EBX、EDX 中轮转 | ECX/CL 固定为 count；EDI 保留 context；ESI 不进入本批契约；使用 EDX 前必须先发布 CL |
| ROT x64 | RAX/RDX/R8 保持三个栈值边界，R10 保持原临时角色；seed 在两种等价 cycle choreography 间选择 | 不增加新的物理寄存器；RCX/R9/R11/R15 与非易失寄存器不参与 |
| ROT x86 | EAX/EDX/ECX 保持三个输入，EBX 保持第三输出；seed 在两种等价 choreography 间选择 | 不引入 ESI；EDI 保持 context |

x86 `SHL/SHR` 有一个顺序约束：固定基线 `{value=EAX,acc=EBX,share=EDX}`
保留旧顺序，先完成 keyed value 处理再执行 `mov cl,dl`；当 seed 把 value 或
accumulator 分配到 EDX 时，先发布 CL 再覆盖 EDX。该顺序由局部契约决定，不靠
Encoder 猜测活跃性。

所有新指令都沿用统一的 `EmitZydisInstruction` fail-closed 路径。Encoder 请求失败会
记录 mnemonic、status 和 operand 摘要并使 kernel 生成失败；不存在静默回退到
`c.Raw(...)` 的分支。保留的 `c.Raw` 只属于未迁移的 width dispatch、跳转和 invalid
故障路径，不用于本批显式寄存器指令。

### 固定寄存器场景的迁移前后字节

将 assignment 固定为旧实现使用的寄存器时，代表性显式指令和完整 ROT 基线逐字节
一致：

| 指令/序列 | 迁移前 | Zydis Encoder |
|---|---|---|
| `mov rcx,rdx` | `48 89 D1` | `48 89 D1` |
| `xor rax,r8` | `4C 31 C0` | `4C 31 C0` |
| `shl r8,cl` | `49 D3 E0` | `49 D3 E0` |
| `sar r8,cl` | `49 D3 F8` | `49 D3 F8` |
| `rol ebx,cl` | `D3 C3` | `D3 C3` |
| `xor eax,edx` | `31 D0` | `31 D0` |
| x64 ROT MOV cycle | `49 89 C2 48 89 D0 4C 89 C2 4D 89 D0` | 相同 |
| x64 ROT XCHG cycle | `48 92 49 87 D0` | 相同 |
| x86 ROT MOV cycle | `89 C3 89 D0 89 CA` | 相同 |
| x86 ROT XCHG cycle + output | `92 87 CA 89 CB` | 相同 |

非固定计划由 Encoder 自动改变 REX/ModRM。五个移位的 16-seed 枚举实测 x86 每个
语义得到 3 套 assignment、x64 每个得到 5 套；ROT 两架构各得到 2 套。永久测试还
要求同一 business strategy 下至少出现两种真实解码 register signature，并校验发布
的 value/accumulator/share 角色确实出现在 core 指令中。

### 本地验证结果与限制

- 完整静态门禁（含比例探针）通过，真实双策略覆盖保持 `54/54`。
- Release x64 与 Win32 的 `test_vm_handler_synthesis`、
  `test_vm_native_differential` 均编译并定点执行通过。
- 全矩阵 Decoder→Request→Encoder→Decoder 覆盖通过：x86 456 个 kernel、78,235
  条指令；x64 456 个 kernel、79,236 条指令。CFG、funclet、CALL_HOST 和
  BRIDGE_EXTENDED 仍在覆盖矩阵中，迁移没有改变其边界。
- 隔离原生 CPU 差分继续覆盖 SHL/SHR 的 count=0/1/>1、5/6-bit count mask、8/16-bit
  full-width 边界和负控制；新增 provider-seed 选择要求 SHL/SHR 每个 K 至少执行两套
  assignment。SAR/ROL/ROR 所在组合也从只为 BSWAP 选 seed 扩展为对四个迁移语义
  分别要求每个 K 至少两套 assignment。
- ROT 没有一条可由 translator 一对一产生的原生 CPU 指令：它是 VM value-stack 的
  三元素循环，而 ROL/ROR 才是硬件 bit rotate。因此 ROT 由 host-arch direct-threaded
  handler 全矩阵/双策略执行和 register-signature 测试验证，不把 ROL/ROR 差分冒充为
  ROT 的隔离原生证据。
- 本批第一版只随机化 scratch 时，x64 固定种子聚合 `core_variant` 为 `0.364725`，超过
  本地 `<0.35` 回归线；把已经落盘的 value 也纳入同一局部安全池后降到 `0.344195`。
  最终本地 x86 为 `0.260252`。这是定点合成门禁，不替代正式独立 EXE/DLL per-build
  similarity gate；正式数值仍由最终提交后的 CI 核实。

### 评估

- 开发效率：五个带 1/2/4/8-byte 编码的语义共用 sized operand 请求，不再分别拼接
  operand-size prefix、REX 和 ModRM；新增计划只修改角色契约，不修改编码公式。
- 正确性风险：Encoder 消除了此前手写 REX/ModRM 位运算的责任，但活跃性和指令顺序
  仍必须人工证明。本批实际发现并固定了 x86 EDX 在 CL 发布前不可覆盖的依赖，说明
  fail-closed Encoder 与局部契约缺一不可。
- per-build 多样性：五个移位从固定 value 加手工 scratch 选择扩展到两架构 3/5 套
  value+scratch assignment；ROT 在不扩大寄存器集合的情况下获得两套结构字节序列。
  x64 定点聚合指标的实际回落证明 value 角色变化比只改 keyed immediate 或只换两个
  scratch 更有效。

结论：该路线适合继续按 3–6 个普通显式操作数语义的小批次推进，并继续要求每批局部
活跃性契约、每 K 多 seed 差分和正式 gate。`CALL_HOST` 与 `BRIDGE_EXTENDED` 仍不应
混入普通 ALU 批次；其 ABI、unwind 和故障边界需要独立设计。

### 最终 CI 闭环

代码提交 `9bbfe54` 对应 GitHub Actions run `29697464581` 最终为 `success`：
`static-gate`、`build-and-test (x64)`、`build-and-test (Win32)` 三个 job 全部通过。
两个架构 job 均完成完整 Release 构建和全部 CTest，因此本批的全矩阵重编码、两架构
handler 合成、扩展后的多 seed 隔离差分和正式独立 EXE/DLL per-build similarity gate
均已由最终代码提交的 CI 核实通过。

## 推广批次 5：`ADD_CARRY`、`SUB_BORROW`、`BIT_TEST`、`BIT_SET`、`BIT_RESET`（2026-07-20）

### 范围与局部活跃性契约

本批迁移五个普通显式寄存器语义。carry/borrow core 的值搬运、key correction、
ADD/SUB 和立即数修正，以及 bit core 的 index 掩码、old-bit 提取、BT/BTS/BTR、
SETB 和结果合成都改由 `ZydisEncoderRequest` 生成。handler 边界、width dispatch、
lazy-flags latch 和 context load/store 保持原结构；CFG 分发、栈展开、native bridge、
故障处理均未进入本批。`CALL_HOST` 与 `BRIDGE_EXTENDED` 继续不迁移。

安全寄存器池由两个 core 各自的活跃性契约导出，没有使用全局共享池：

| 语义/架构 | seed 选择的角色与安全池 | 保留/排除 |
|---|---|---|
| carry/borrow x64 | result、b-work、carry/borrow、spare 在 RAX、RDX、R8、RCX 中按三套已审计计划轮转 | R10/R11 保留原始 a/b 供 latch 使用；R9 保留 width mask；R15 保留 context |
| carry/borrow x86 | result、b-work、carry/borrow、spare 在 EAX、EDX、ECX、EBX 中按三套计划轮转 | 原始值已由 `X86BeginLatch` 落盘；EDI 保留 context；EBX 的旧 width 值进入 core 时已死亡 |
| bit family x64 | value/result、index、auxiliary、spare 在 RAX/R8、RDX/R11、R10 和剩余局部角色中按四套计划选择 | R10 必须最终发布 old bit；R9 保留 width mask；R15 保留 context；已落盘的 R11 原始 b 可作为替代 index |
| bit family x86 | value/result、index、auxiliary、spare 在 EAX/EBX、ECX/ESI、EDX 和剩余局部角色中按四套计划选择 | EDX 必须最终发布 old bit；EDI 保留 context；原始值已经落盘，EBX/ESI 仅在本 core 生命周期内复用 |

carry core 会先保护仍需读取的 source/carry，再覆盖 seed 选择的 result；bit core 则在任何
可能覆盖 EAX/ECX 的计划中先搬走 value/index。该顺序属于活跃性契约，不由 Encoder
推断。所有新请求继续经过统一的 `EmitZydisInstruction` fail-closed 路径；任何请求失败
都会写入带 mnemonic、status 和 operand 摘要的编码错误并终止 kernel 生成，不存在
回退到手写字节的分支。

### 固定寄存器场景的迁移前后字节

将角色固定为旧实现的寄存器时，代表性的寄存器形式保持逐字节一致：

| 指令 | 迁移前 | Zydis Encoder |
|---|---|---|
| `add rax,rdx` | `48 01 D0` | `48 01 D0` |
| `add rax,r8` | `4C 01 C0` | `4C 01 C0` |
| `sub rax,rdx` | `48 29 D0` | `48 29 D0` |
| `add eax,edx` | `01 D0` | `01 D0` |
| `add eax,ecx` | `01 C8` | `01 C8` |
| `sub eax,edx` | `29 D0` | `29 D0` |
| `bt rax,rdx` | `48 0F A3 D0` | `48 0F A3 D0` |
| `bts rax,rdx` | `48 0F AB D0` | `48 0F AB D0` |
| `btr rax,rdx` | `48 0F B3 D0` | `48 0F B3 D0` |
| `setb r10b` | `41 0F 92 C2` | `41 0F 92 C2` |
| `bt eax,ecx` | `0F A3 C8` | `0F A3 C8` |
| `setb dl` | `0F 92 C2` | `0F 92 C2` |

固定 x64 bit-mask 基线继续使用 32-bit `mov eax,1`，保留旧字节
`B8 01 00 00 00`，避免无意义地扩大为 64-bit immediate。与此前批次相同，accumulator
立即数 ADD/SUB 允许 Encoder 在 `81 /0|/5 <imm32>` 和 `05/2D <imm32>` 等等价合法
形式间规范化；这类预期差异由完整重编码和真实执行闭环验证，不作为寄存器形式的
byte-equality 失败。

### 本地验证结果与限制

- 完整静态门禁（含比例探针）通过，真实双策略覆盖保持 `54/54`。
- Release x64 与 Win32 的 `test_vm_handler_synthesis`、
  `test_vm_native_differential` 均编译并定点执行通过。
- 最终 x64-host 全矩阵 Decoder→Request→Encoder→Decoder 覆盖通过：x86 456 个
  kernel、78,290 条指令；x64 456 个 kernel、79,261 条指令。CFG、funclet、
  CALL_HOST 和 BRIDGE_EXTENDED 继续在覆盖矩阵内，但本批没有改变其边界。
- register-signature 枚举从 19 个迁移语义扩展到 24 个；carry/borrow 在两架构均得到
  3 套 assignment，三个 bit 语义在两架构均得到 4 套 assignment。测试同时要求局部
  temp 角色真实出现在解码后的 core 指令中。
- signature 测试原先直接比较 Zydis 的窄寄存器 ID，导致 `R10B` 被误认为不是物理
  R10。本批把解码操作数统一归一化到 largest enclosing register 后再取 ID；这修复的
  是测试证据本身，不是放宽生产寄存器契约。
- 隔离原生 CPU 差分会为每个 bit 语义动态挑选覆盖四套 assignment 的 provider seed，
  每个 seed 执行 32 个 corpus，并保留 ADD 对 BIT_SET 的负控制。carry/borrow 所在
  ADC/SBB 组合也按语义、按 K 动态选择至少两套 assignment；两架构全部通过。
- 最终本地定点合成指标为 x86 `core_variant=0.258477`、x64
  `core_variant=0.342660`，均通过当前回归线。正式完整 CTest 与独立 EXE/DLL
  per-build similarity gate 仍只以最终提交后的 CI 为准，本地不冒充 Windows-only
  CI 结论。

### 评估与后续边界

- 开发效率：ADC/SBB 与 BT/BTS/BTR 的 REX、ModRM、窄寄存器 SETB 编码由同一套
  operand request 生成；增加一套安全 assignment 只改角色计划，不再复制位域公式。
- 正确性风险：Encoder 消除了扩展寄存器和 byte-register REX 拼接的人工责任；人工
  审计集中在 source 保护、old-bit auxiliary 和 latch 生命周期。本批两架构多 seed
  真实 CPU 差分未发现隐藏依赖，测试中的 R10B 归一化问题也能被明确诊断而非静默绕过。
- per-build 多样性：carry/borrow 获得三套 result/source/carry 编排，bit family 获得
  四套 value/index/auxiliary 编排；变化直接进入业务 core 的 REX/ModRM，而不是只改变
  keyed immediate。当前聚合定点指标没有退化，正式效果等待 CI gate 核实。

结论：该路线对剩余简单显式操作数语义仍值得按 3–6 个小批次推进。每批必须继续独立
导出活跃性契约、保留固定角色字节证据和多 seed 隔离差分。`CALL_HOST`、
`BRIDGE_EXTENDED` 继续留待独立的 ABI/unwind/故障边界设计，不能混入普通 ALU 批次。

### 最终 CI 闭环

代码提交 `e5692f0` 对应 GitHub Actions run `29698611515` 最终为 `success`：
`static-gate`、`build-and-test (x64)`、`build-and-test (Win32)` 三个 job 全部通过。
两个架构 job 均完成完整 Release 构建与全部 CTest，因此全矩阵重编码、两架构 handler
合成、扩展后的多 seed 隔离原生差分和正式独立 EXE/DLL per-build similarity gate
均已由最终代码提交的 CI 核实通过。该 run 从 `18:22:50Z` 到 `18:28:55Z`，实际耗时
365 秒；后续代码 push 将以此作为首次查询前的等待时长。

## 推广批次 6：`LOAD_TEMP`、`STORE_TEMP`、`DUP`、`DROP`（2026-07-20）

### 范围与局部活跃性契约

本批迁移四个简单数据/值栈语义。临时槽的 scaled-index LEA、地址 key 修正和
load/store，DUP 的 keyed copy，以及 DROP 的已释放物理槽清零都改由
`ZydisEncoderRequest` 生成。值栈深度检查、push/pop、value codec、range/stack
failure 跳转保持原结构；没有触碰 CFG 分发、unwind、native bridge 或故障语义。
`CALL_HOST` 与 `BRIDGE_EXTENDED` 继续不迁移。

`SWAP` 没有混入本批：它虽然也是简单值栈操作，但当前 translator 没有一条生产原生
指令会一对一发出该语义，隔离差分证据会弱于本批四个都有的生产入口。它应和其他
缺少 translator 入口的值栈语义单独评估，而不是为了凑批量降低验证标准。

本批继续按 core 导出安全寄存器计划，不复用全局共享池：

| 语义/架构 | seed 选择的角色与安全池 | 保留/边界约束 |
|---|---|---|
| LOAD/STORE_TEMP x64 | result/value、address、index、spare 按四套计划使用 RAX/RDX/RCX/R8/R10/R11 的已审计子集 | R10 是入口 slot index，RAX 是 LOAD 结果/STORE 输入边界，R15 是 context；非易失寄存器不参与 |
| LOAD/STORE_TEMP x86 | result/value、address、index 只在 EAX/ECX/EDX 中按三套计划轮转 | EDI 是 context；STORE 的既有 post-core 高 dword 清零仍要求 ECX 为原 slot index，搬到 EDX 的计划必须在返回前恢复 ECX |
| DUP x64 | source/destination 在 RAX/RDX/R8/R10 中轮转，共四套计划 | RAX 是弹出输入，RAX/RDX 是 PushTwo 输出边界；RCX 由 PushTwo 重载，R15 是 context |
| DUP x86 | source/destination 在 EAX/EDX/ECX 中轮转，共三套计划 | EAX 是输入，EAX/EDX 是输出；EBX/ESI/EDI 不参与 |
| DROP x64 | address 在 R10/R11/R8/RDX 中选择，zero 使用与 address 不冲突的死亡寄存器，共四套计划 | RCX 保持递减后的 slot index，R15 是 context，弹出的 RAX 值已死亡 |
| DROP x86 | address/index/zero 只在 EAX/ECX/EDX 中按三套计划选择 | value codec 可能复用 ECX，因此 core 先从 `CtxValueDepth` 重载权威 index；EDI 是 context |

为表达临时槽和值栈槽的八字节步长，通用 `ZydisMemoryOperand`/`EmitZydisLea`
增加显式 scale 参数；未传 scale 的既有调用仍保持默认 1。所有新指令继续沿统一
fail-closed 路径：Encoder 拒绝请求即使 kernel 生成失败，不回退到 `c.Raw(...)`。

### 固定寄存器场景的迁移前后字节

固定为旧实现角色时，代表性 scaled-index、复制和清零形式逐字节一致：

| 指令/序列 | 迁移前 | Zydis Encoder |
|---|---|---|
| `lea r11,[r15+r10*8+disp32]` | `4F 8D 9C D7 <disp32>` | 相同 |
| `mov rax,[r11+disp32]` | `49 8B 83 <disp32>` | 相同 |
| `mov [r11+disp32],rax` | `49 89 83 <disp32>` | 相同 |
| `lea edx,[edi+ecx*8+disp32]` | `8D 94 CF <disp32>` | 相同 |
| `mov eax,[edx+disp32]` | `8B 82 <disp32>` | 相同 |
| `mov [edx+disp32],eax` | `89 82 <disp32>` | 相同 |
| DUP MOV：`mov rdx,rax` / `mov edx,eax` | `48 89 C2` / `89 C2` | 相同 |
| DUP LEA：`lea rdx,[rax]` / `lea edx,[eax]` | `48 8D 10` / `8D 10` | 相同 |
| DROP x64 address + zero/store | `4D 8D 94 CF <disp32> 31 C0 49 89 82 <disp32>` | 相同 |
| DROP x86 address + zero/store | `8D 94 CF <disp32> 31 C0 89 82 <disp32> 89 82 <disp32>` | 相同 |

x86 temp slot 仍按 8-byte VM 槽寻址，但本架构 core 只 load/store 低 4 字节；
`STORE_TEMP` 随后的高 4 字节清零保持原位置和原语义，没有被错误合并为单次 8-byte
访问。非固定计划由 Encoder 自动改变 REX、ModRM、SIB 和必要的边界 MOV。

### 本地验证结果与限制

- 完整静态门禁（含比例探针）通过，真实双策略覆盖保持 `54/54`。
- Release x64 与 Win32 的 `test_vm_handler_synthesis`、
  `test_vm_native_differential` 均编译并定点执行通过。
- 全矩阵 Decoder→Request→Encoder→Decoder 覆盖通过：x86 456 个 kernel、78,327
  条指令；x64 456 个 kernel、79,287 条指令。迁移语义 register-signature 总数从
  24 个扩展到 28 个；本批每个语义均实测 x86 3 套、x64 4 套 assignment，并要求
  同一 K 下至少两套真实解码 signature。
- 隔离差分使用生产 NOP + scaled-LEA fixture：Light NOP lowering 发出
  STORE_TEMP/LOAD_TEMP/DROP，scaled LEA 的确定性地址 lowering 发出 DUP。测试在有界
  RVA 范围内寻找确实包含四个语义的生产 TranslationResult，不手工伪造 VM IR。
  provider seed 再动态覆盖每个语义、每个 K 至少两套 assignment：x64 5 个 seed、
  x86 8 个 seed，每 seed 32 个 corpus，全部通过。
- data/stack 全宽度双策略 host-arch handler 矩阵继续覆盖 temp round-trip、DUP、DROP
  和其后续 stack depth/slot 状态。x86 的替代 index 计划同时由该矩阵和隔离差分证明
  ECX 恢复正确。
- 最终本地定点 `core_variant` 从上一批的 x86 `0.258477`、x64 `0.342660`
  进一步降到 x86 `0.255818`、x64 `0.341153`。正式完整 CTest 与独立 EXE/DLL
  per-build similarity gate 仍以最终代码提交后的 CI 为准。

### 评估与后续边界

- 开发效率：新增 scale 参数后，base+index*8+disp 的 REX/SIB/ModRM 组合只由一个
  Encoder request 表达；x64/x86 temp 和 DROP 不再分别维护四套地址位域公式。
- 正确性风险：Encoder 接管了 SIB scale、扩展寄存器和内存操作数编码，但无法推断
  x86 STORE_TEMP 的 ECX post-core 依赖。本批通过局部契约显式恢复 ECX，并由两架构
  真实执行闭环验证，说明地址编码安全和生命周期安全仍需分别证明。
- per-build 多样性：四个语义均把 seed 变化直接放进业务 core 的 register/SIB 字节；
  x86 获得三套、x64 获得四套真实 assignment，聚合定点指标小幅继续下降。

结论：Zydis 路线同样适合简单值栈与 context 地址形式，但应优先选择存在生产
translator 入口、能构造隔离原生差分证据的语义。`SWAP` 等无直接入口语义需要明确
记录证据限制；`CALL_HOST`、`BRIDGE_EXTENDED` 仍不能混入普通批次。

### 最终 CI 闭环

代码提交 `52a52f3` 对应 GitHub Actions run `29700145717` 最终为 `success`：
`static-gate`、`build-and-test (x64)`、`build-and-test (Win32)` 三个 job 全部通过。
两个架构 job 均完成完整 Release 构建与全部 CTest，因此全矩阵重编码、两架构 handler
合成、生产 translator fixture 的多 seed 隔离差分和正式独立 EXE/DLL per-build
similarity gate 均已由最终代码提交的 CI 核实通过。该 run 从 `19:12:05Z` 到
`19:18:15Z`，实际耗时 370 秒；后续会触发同一 CI 的代码 push 以此作为首次查询前
的等待时长。纯文档 `[skip ci]` push 不等待，也不查询不存在的新 run。

## 推广批次 7：`PUSH_FLAGS`、`PUSH_IMAGE_BASE`、`PUSH_IP`、`PUSH_VREG`、`PUSH_IMM`（2026-07-20）

### 范围与结论

本批迁移五个简单值/上下文语义：`PUSH_FLAGS`、`PUSH_IMAGE_BASE` 的 keyed 上下文
地址加载，`PUSH_IP` 的 vip/bytecodeBegin 差值计算，`PUSH_VREG`/`PUSH_IMM` 的
按位提取或掩码组合。CFG 分发、栈深度检查、宽度校验、`CtxMutationScratch`
预备等外层结构未改动；`CALL_HOST`、`BRIDGE_EXTENDED` 继续不迁移。

`POP_VREG` 在本批**评估后未迁移**：它的两种业务 K 在两种架构上都把
value、CL 计数、地址 scratch、writeAll 标志、宽度 mask、vreg 索引、取反后的
mask 临时值同时占满了全部可用易失寄存器，活跃性分析找不到任何安全寄存器池
（详见下表）。项目仍实现并本地验证了一版寄存器无多样性的 Zydis 重编码，但
它在正式 per-build 差分 gate 中把 x64 EXE 上 `core_variant` 单点 Dice 相似度
推到 `0.72`（Win32 EXE `0.69`），超过 `tests/scripts/vm_per_build_similarity_gate.py`
中不可放宽的 `0.65` 硬上限 `MAX_PAIR_CEILINGS["core_variant"]`——因为它的字节
差异只能来自很短的 keyed 立即数，不会进入 REX/ModRM 寄存器位。这是一次真实、
可复现的正式 gate 回归，不是编造的限制；已将 `POP_VREG` 保持在原手写实现，
问题和后续方向记录在下方，不带着这个已知失败提交。`SWAP`、`SMUL_WIDE`、
`IDIV_WIDE`、`UDIV_WIDE`、`INT3`、`PUSH_CONDITION` 留给后续批次。

### 按语义/架构导出的活跃性契约

没有复用全局寄存器池；每个语义的安全池都从进入 core 时刻实际被加载/清空的
寄存器直接读出：

| 语义/架构 | seed 选择的角色与安全池 | 保留/排除依据 |
|---|---|---|
| PUSH_FLAGS/PUSH_IMAGE_BASE x64 | address 在 R8、R9、R10、R11 中轮转 | `X64CallFlagMaterializer` 是一次真实间接调用，按 Win64 ABI 清空全部易失寄存器；PUSH_IMAGE_BASE 是函数体的第一条指令，同样只有 R15/context 有意义；RAX 是 PushOne 边界 |
| PUSH_FLAGS/PUSH_IMAGE_BASE x86 | address 在 ECX、EDX 中轮转 | 同一调用/零前导逻辑限制在易失的 ECX/EDX；EBX/ESI/EDI 未在该语义原实现中被证明安全，继续排除 |
| PUSH_IP x64 | value、source 在 RAX、RDX、RCX、R8、R9、R10、R11 中轮转（RDX 紧跟 RAX 排列，便于 seed=0 复现旧固定字节） | core 前只加载 RAX=vip、RDX=bytecodeBegin，RCX/R8/R9/R10/R11 全部死亡；两个角色互不相同时用 MOV 搬入/搬出，一种循环依赖情形（value=RDX 且 source=RAX）改用 XCHG，见下文踩坑记录 |
| PUSH_IP x86 | value、source 在 EAX、EDX、ECX 中轮转 | 同一推理限制在 EAX/ECX/EDX |
| PUSH_VREG x64 | scratch 在 RDX、R8、R9、R10 中轮转 | RAX 是 value 边界，RCX 提供架构 CL；R10（vreg 索引）在被索引读取消费后死亡，R11（宽度）留到 core 之后才被读取，R9 在 core 之后才被无条件覆写写入宽度 mask，三者在 core 内部都是安全 scratch |
| PUSH_VREG x86 | scratch 固定为 EDX，无 seed 多样性 | EAX 是 value，ECX 是 CL；EDX 曾经保存 vreg 索引，但已在 core 前被复制进 ECX 并死亡，是唯一被证明安全的 scratch；EBX/ESI 未被原实现使用，不新增 |
| PUSH_IMM x64 | scratch 在 RCX、R10、R11 中轮转 | RAX 是 value，R9 是 core 内部直接读取的宽度 mask；R11（已验证宽度）和 RCX（`X64MaskForWidthInR11` 内部用完即弃的计数）在 core 运行时都已死亡 |
| PUSH_IMM x86 | scratch 在 ECX、EDX 中轮转 | RAX 是 value；x86 的宽度 mask 存在 `CtxMutationScratch` 内存而非寄存器，ECX（宽度字节已被 `X86BuildMaskInScratch` 消费）与 EDX（全程未加载）都是安全 scratch |
| POP_VREG（两种架构） | 无安全池，继续使用原手写固定寄存器 | 见上文范围说明；本节末尾附完整逐寄存器占用表 |

POP_VREG 的完整占用证据（两种 K 合并，同一时刻在架构内互斥或先后复用，
没有空闲寄存器）：

| 架构 | 同时占用的寄存器 | 各自角色 |
|---|---|---|
| x64 | RAX, RCX, RDX, R8, R9, R10, R11 | value、CL 计数、地址/合并 scratch、writeAll 标志、宽度 mask、vreg 索引（LEA 的 scaled index）、取反 mask 临时值（R9 在 K=1 与地址 scratch 共用 R9 前先把 mask 复制到 R11） |
| x86 | EAX, ECX, EDX, EBX, ESI | value、CL 计数（core 内部重新加载）、vreg 索引（LEA 的 scaled index，全程存活）、writeAll 标志/取反 mask scratch、地址/合并 scratch |

`EmitZydisPushVregCore`/`EmitZydisPushImmCore` 的 scratch 池只有单一角色，
不需要搬入/搬出；`EmitZydisContextLoadCore`（PUSH_FLAGS/PUSH_IMAGE_BASE）
的 address 角色同理只是一个纯 scratch LEA 目的寄存器。只有 `PUSH_IP` 需要
在 value/source 两个角色和固定的 RAX/RDX 加载边界之间做真正的搬入/搬出，
这也是本批唯一实现踩坑的地方。

### 迁移中发现的一个正确性坑：PUSH_IP 的循环依赖搬运

`EmitKeyedCopyCore`（DUP）确立的“非固定角色先 MOV 搬入,计算后再 MOV 搬出”
模式在 PUSH_IP 上第一版实现直接套用时出现了真实 bug：当 `value` 恰好等于
`source` 的固定边界寄存器（RDX/EDX，物理编号 2）且 `source` 恰好等于
`value` 的固定边界寄存器（RAX/EAX，物理编号 0）时，两个角色的目标寄存器
正好互换——这是一个二元置换环，不能用两条顺序 MOV 表达：先搬 `value` 会在
`source` 读取之前覆盖 RDX 原值，先搬 `source` 会在 `value` 读取之前覆盖 RAX
原值。永久测试 `TestHostContextEntryExecution` 在 Win32 上（该架构的三元素
池 `{EAX,EDX,ECX}` 更容易撞上这个组合）实际执行合成 handler 时立即捕获：
`vreg[10]` 期望的 `PUSH_IP` 结果变成了 `0`。x64 六元素池此前不包含寄存器 2，
从未触发这一分支，因此同一个 bug 在 x64 上完全不可见——这正是"两种架构都要
真实执行验证,不能只信任其中一种"的一次实证。修复方法是检测这一具体环并改用
一条保留标志位的 `XCHG`；同时把 RDX/EDX 紧跟在 RAX/EAX 后面排入寄存器池，
使 seed 的自然起始位置就能精确复现旧固定寄存器的逐字节实现，也让 x64 池扩大到
包含全部 7 个此前证明空闲的寄存器（原来遗漏了 RDX 本身）。

### 固定寄存器场景的迁移前后字节

将角色固定为旧实现使用的寄存器时，代表性指令逐字节一致；累加立即数允许
Encoder 规范化为 accumulator 短形式（与前几批一致，不算失败）：

| 指令/序列 | 迁移前 | Zydis Encoder |
|---|---|---|
| `lea r10,[r15+disp32]`（PUSH_FLAGS/PUSH_IMAGE_BASE x64，address=R10） | `4D 8D 97 <disp32>` | 相同 |
| `mov rax,[r10+disp32]` | `49 8B 82 <disp32>` | 相同 |
| `lea edx,[edi+disp32]`（x86，address=EDX） | `8D 97 <disp32>` | 相同 |
| `mov eax,[edx+disp32]` | `8B 82 <disp32>` | 相同 |
| PUSH_IP x64（value=RAX,source=RDX）：`add rax,imm32` | `48 81 C0 <imm32>` | `48 05 <imm32>` |
| `sub rax,rdx` | `48 29 D0` | 相同 |
| `sub rax,imm32` | `48 81 E8 <imm32>` | `48 2D <imm32>` |
| PUSH_IP x64 K=1：`neg rdx` / `add rax,rdx` | `48 F7 DA` / `48 01 D0` | 相同 |
| PUSH_IP x86（value=EAX,source=EDX）：`add eax,imm32` | `81 C0 <imm32>` | `05 <imm32>` |
| `sub eax,edx` | `29 D0` | 相同 |
| PUSH_VREG x64（scratch=R10）：`xor rax,imm32` | `48 81 F0 <imm32>` | `48 35 <imm32>` |
| `shr rax,cl` | `48 D3 E8` | 相同 |
| K=1：`xor r10d,r10d` / `shrd rax,r10,cl` | `45 31 D2` / `4C 0F AD D0` | 相同 |
| PUSH_VREG x86（scratch=EDX，唯一计划）：`shr eax,cl` | `D3 E8` | 相同 |
| `shr edx,cl` / `xor eax,edx` | `D3 EA` / `31 D0` | 相同 |
| PUSH_IMM x64（scratch=R10）：`and rax,r9` | `4C 21 C8` | 相同 |
| `and r10,r9` | `4D 21 CA` | 相同 |
| PUSH_IMM x86（scratch=EDX）：`and eax,[edi+CtxMutationScratch]` | `23 87 <disp32>` | 相同 |

### 本地验证结果与限制

- 完整静态门禁（含比例探针）通过，真实双策略覆盖保持 `54/54`。
- Release x64 与 Win32 的 `ciphershell_packer` 均以 `/W4 /WX` 编译通过。
- `test_vm_handler_synthesis` 新增专用测试
  `TestZydisPushPopFamilyRegisterDiversity`：按语义/架构分别给出最小
  assignment 数（PUSH_FLAGS/PUSH_IMAGE_BASE 两种架构各 2/4，PUSH_IP 3/7，
  PUSH_VREG 1/4，PUSH_IMM 2/3），实测结果与预期一致或更高；PUSH_VREG x86
  按活动性证据只有一个真实计划，测试据实只要求生成/校验成功，不假装存在
  多样性。
- x64 与 Win32 的 `test_vm_handler_synthesis` 全量执行（含
  `TestHostContextEntryExecution` 真实合成 handler 执行）通过；上一版本
  暴露的 PUSH_IP 循环依赖 bug 已在本地 Win32 执行中复现并修复。
- x64 `ctest`（14/14）与 Win32 `ctest`（13/14，唯一例外见下）全部通过，
  包括正式 `vm_per_build_similarity_gate`：

| 架构/容器 | business_core | core_variant | codec | encrypted_handlers |
|---|---:|---:|---:|---:|
| x64 EXE | 0.2671 | 0.1329 | 0.1572 | 0.0001 |
| x64 DLL | 0.2751 | 0.1270 | 0.1558 | 0.0001 |
| Win32 EXE | 0.2529 | 0.0828 | 0.0231 | 0.0001 |
| Win32 DLL | 0.2789 | 0.1099 | 0.0451 | 0.0001 |

  全部低于对应硬上限（`business_core<0.55`、`core_variant<0.65`、
  `codec<0.30`、`encrypted_handlers<0.15`）与常规回归阈值，输出
  `VM_PER_BUILD_SIMILARITY_GATE_PASS`。
- 本地定点 handler 合成相似度（非正式 gate，仅供趋势参考）：x86
  `core_variant=0.254705`、x64 `core_variant=0.336519`，较上一批（x86
  `0.255818`、x64 `0.341153`）继续小幅下降。
- 唯一未通过项：Win32 `vm_native_differential` 在本机命中 CMakeLists.txt
  中该测试固定的 `TIMEOUT 120` 秒属性（该属性与 `ctest --timeout` 命令行值
  无关，显式设置会覆盖命令行默认值）。直接运行同一可执行文件（不经过
  ctest 的进程调度开销）稳定在约 146～150 秒完成，退出码 `0`，日志中没有
  任何 `FAIL`。本机在本次会话中经历了长时间连续的 x64/Win32 全量编译和多轮
  ctest，怀疑是本机瞬时负载/杀毒软件扫描新生成可执行文件导致的本地余量问题，
  不是本批代码引入的功能回归——本批修改的五个语义都不在该测试实际打印的
  受测语义列表中（SHL/SHR/ADC/SBB/BSWAP/ZERO_EXTEND/SIGN_EXTEND/ROT/BIT_*/
  DIV/INT3 等），且 x64 侧同一测试在本机稳定于 100 秒左右通过。这一结论按
  用户红线不能替代 CI 的最终判定，正式确认交给 Windows CI runner。

### 评估

- 开发效率：五个语义共用同一套 `EmitZydis*Core` 辅助层（context 地址、
  keyed shift/mask、边界搬入搬出），比逐条手算 REX/ModRM 明显更快；真正
  耗时的部分是逐寄存器活跃性证明和 POP_VREG 的放弃判断，不是编码本身。
- 正确性风险：Encoder 消除了 REX/ModRM 拼接风险，但没有消除“角色搬运顺序”
  这一新的风险面——PUSH_IP 的循环依赖 bug证明了这一点，也证明了双架构真实
  执行门禁是必要而非可选的验证层。POP_VREG 的判断同样证明了 Encoder 不能
  替代对活跃性和正式 per-build gate 的独立核实：一个语义即使成功迁移、
  本地功能测试全绿，仍可能在真实统计门禁下退化。
- per-build 多样性：四个有真实寄存器池的语义分别获得 x86 2～3 套、x64
  4～7 套 assignment；正式 gate 的四个架构/容器组合全部低于硬上限，且
  `core_variant` 较上一批继续下降。

结论：该路线仍适合继续按 3–6 个语义的小批次推进，但本批新增了两条方法论
证据——(1) 搬入/搬出模式在角色与固定边界寄存器发生循环置换时必须显式处理，
不能假设两条独立 MOV 总是安全；(2) 迁移到 Encoder 且本地功能测试全绿，不
代表自动通过正式 per-build 相似度门禁,寄存器多样性太小的语义仍可能让某个
单点 K 组合越过硬上限,必须实测而不能仅凭“已迁移到 Encoder”就假定通过。
`POP_VREG` 留给未来一个独立批次,方向是设计不依赖寄存器选择的等价指令序列
（例如用不同的 AND/OR 与异或合成恒等式重排 core 内部指令顺序），而不是再次
尝试寻找并不存在的空闲寄存器。`SWAP`、`SMUL_WIDE`、`UDIV_WIDE`、`IDIV_WIDE`、
`INT3`、`PUSH_CONDITION`、`FLAGS_*` 家族与控制流语义均未进入本批。

### 最终 CI 闭环

代码提交 `027ee53` 对应 GitHub Actions run `29706361374` 最终为 `success`：
`static-gate`、`build-and-test (x64)`、`build-and-test (Win32)` 三个 job 全部通过。
两个架构 job 均完成完整 Release 构建与全部 CTest（包括本机曾经历瞬时 120 秒
ctest 属性余量问题的 Win32 `vm_native_differential`——CI 环境没有本机当时的
并发编译负载，稳定通过），因此全矩阵重编码、两架构 handler 合成、隔离/host-arch
差分与正式独立 EXE/DLL per-build similarity gate 均已由最终代码提交的 CI
核实通过。该 run 从 `22:33:24Z` 到 `22:39:25Z`，实际耗时 361 秒；后续会触发
同一 CI 的代码 push 以此作为首次查询前的等待时长。纯文档 `[skip ci]` push
不等待，也不查询不存在的新 run。

## 推广批次 8：`SWAP`、`SMUL_WIDE`、`UDIV_WIDE`、`IDIV_WIDE`、`INT3`（2026-07-20）

### 范围与结论

本批迁移五个语义。`SWAP` 的两值交换改由 `ZydisEncoderRequest` 生成，采用与
`PUSH_IP` 相同的"从固定边界寄存器搬入/搬出到 seed 选定角色"模式。
`SMUL_WIDE`/`UDIV_WIDE`/`IDIV_WIDE` 复用独立批次 2（x86 `UMUL_WIDE` K=1）确立
的方法：只随机化显式乘数/除数的寄存器形式或地址形式，`RDX:RAX`/`EDX:EAX`
硬件隐式 pair 保持不变。`INT3` 是零操作数指令，没有寄存器可随机化，只把编码
迁移到 Encoder。`POP_VREG` 仍留待未来独立批次（见批次 7 的结论，本批未重新
尝试）。`PUSH_CONDITION`、`FLAGS_*` 家族与控制流语义均未进入本批。

### 按语义/架构导出的活跃性契约

| 语义/架构 | seed 选择的角色与安全池 | 保留/排除依据 |
|---|---|---|
| SWAP x64 | a、b 在 RAX、RDX、RCX、R8、R9、R10、R11 中轮转 | `X64RequireAndPop(count=2)` 把两值弹入 RAX/RDX，RCX（索引 scratch）用后即死；R8/R9/R10/R11 全程未被触碰 |
| SWAP x86 | a、b 在 EAX、EDX、ECX 中轮转 | 同一推理限制在易失的 EAX/ECX/EDX；EBX/ESI 未被原实现证明安全，不新增 |
| SMUL_WIDE/UDIV_WIDE/IDIV_WIDE x64 | 显式乘数/除数在寄存器直接形式（R9）与经 seed-split 地址的内存形式（R10 为 K=0、R11 为 K=1）之间选择 | R9 已由外层 `EmitX64WideMultiply`/`EmitX64WideDivide` 准备好显式值，core 结束后立即被无条件覆写，可安全复用；R10/R11 分别是该语义原有的 K=0/K=1 地址寄存器，两者在两个 K 下都已证明空闲，K 到地址寄存器的绑定保持不变 |
| SMUL_WIDE/UDIV_WIDE/IDIV_WIDE x86 | 同一寄存器直接（ECX）与内存（EBX 为 K=0、ESI 为 K=1）二选一 | ECX 同理已备好显式值且用后即死；ESI 已由独立批次 2 在同一 `EmitX86WideMultiply` 包装函数中证明对 `UMUL_WIDE` K=1 安全，此处复用同一活跃性证据 |
| INT3（两种架构） | 无寄存器角色 | 指令零操作数，两个 K 分别是 `INT3`（`CC`）与 `INT imm8`（`CD 03`），寄存器多样性天然不适用 |

寄存器直接形式与内存形式的选择不是每个 K 独立抛硬币：若同一 seed 让 K=0 与
K=1 都落在"寄存器直接"，两者字节会完全相同（`<op> r9` 不含任何寄存器/立即数
差异），违反"双策略必须真实不同"的要求。因此改为让 seed 先选定唯一一个
K 使用寄存器直接形式，另一个 K 强制落在其（K 专属、地址寄存器不同的）内存
形式，两者永远不会同时选中同一种形式。

寄存器直接形式本身也不携带任何随 build 变化的字节（`imul r9` 三个字节固定），
如果两次不同的构建恰好都选中寄存器直接形式，会产生逐字节相同的核心，同样
违反"两次构建同一 (semantic,K) 必须不同"的要求。修复方法是给寄存器直接
形式套上一对自抵消的 keyed XOR（`xor r9,key; xor r9,key`，与
`PUSH_VREG`/`PUSH_IMM` 已经使用的可逆扰动手法一致）：不改变送入硬件宽运算的
真实值，但让该形式也携带真实的 per-build 立即数。

### 迁移中发现的一个正确性坑：SWAP 的搬入/搬出循环依赖

`MoveRegisterPair` 是本批新增的通用二元并行搬运原语，取代了批次 7 中
`EmitZydisKeyedIpCore` 里针对 PUSH_IP 的三分支临时方案。批次 7 的实现只处理了
"搬入"方向（从固定 RAX/RDX 搬进任意角色）里恰好构成置换环的那一种组合；
`SWAP` 需要同一逻辑再反向用一次（把角色的最终值搬回固定 RAX/RDX 供
`PushTwo` 使用），而反向搬运的循环依赖条件与正向并不对称（正向的危险条件是
"目的寄存器 2 号角色恰好是源寄存器 0 号"，反向的危险条件是"源寄存器 0 号角色
恰好是目的寄存器 2 号，且顺序颠倒"）。`MoveRegisterPair` 用一次通用推导覆盖了
全部重叠情形（无重叠、目的等于对应源、四种部分重叠、完全置换环），只在真正
构成环时使用一条 `XCHG`，其余情形用最少的 `MOV`；这一版本已经过手工逐分支
验证（对全部 5 种可能的重叠关系分别证明了指令顺序不会用未读取的数据覆盖
仍需要的数据）。

### 固定寄存器场景的迁移前后字节

将角色固定为旧实现使用的寄存器时，代表性形式的对比如下；累加立即数按前几批
惯例允许 Encoder 规范化为 accumulator 短形式：

| 指令/序列 | 迁移前 | Zydis Encoder |
|---|---|---|
| SWAP x64（a=RAX,b=RDX，K=0）：`xchg rax,rdx` | `48 92` | 相同 |
| SWAP x64 K=1：`xor rax,rdx` / `xor rdx,rax` / `xor rax,rdx` | `48 31 D0` / `48 31 C2` / `48 31 D0` | 相同 |
| SWAP 的 keyed XOR 括号：`xor rax,imm32` | `48 81 F0 <imm32>` | `48 35 <imm32>`（accumulator 规范化） |
| SMUL_WIDE/UDIV_WIDE/IDIV_WIDE x64 内存形式（address=R10，K=0，与迁移前地址寄存器选择一致）：`lea r10,[r15+disp32]` | `4D 8D 97 <disp32>` | 相同 |
| `mov [r10+disp32],r9` | `4D 89 8A <disp32>` | 相同 |
| `imul/div/idiv [r10+disp32]`（`F7 /5`、`/6`、`/7`） | `49 F7 AA/B2/BA <disp32>` | 相同 |
| x86 SMUL_WIDE/IDIV_WIDE 寄存器直接形式的核心操作：`imul ecx` / `idiv ecx` | `F7 E9` / `F7 F9` | 相同（前面新增 keyed XOR 括号，见上） |
| INT3 K=0/K=1：`int3` / `int 3` | `CC` / `CD 03` | 相同 |

x86 `UDIV_WIDE` 的内存形式不再复用旧实现里"K=0 用 slot+0、K=1 用 slot+4"的
额外偏移分离——那个偏移只是防御性写法，不是正确性要求（各 K 是独立编译的
kernel，从不共享运行时状态），x64 的对应实现原本就没有这个偏移。这是一处
已解释的规范化差异，不是字节对齐失败。

### 本地验证结果与限制

- 完整静态门禁（含比例探针）通过，真实双策略覆盖保持 `54/54`。
- Release x64 与 Win32 的 `ciphershell_packer` 均以 `/W4 /WX` 编译通过。
- `test_vm_handler_synthesis` 新增 `TestZydisSwapRegisterDiversity`（SWAP，
  x86/x64 分别要求 ≥3/≥7 套 assignment）与
  `TestZydisWideOperandRegisterDiversity`（三个宽运算语义，逐 K 要求寄存器
  直接与内存两种形式都被覆盖到，且内存形式的地址寄存器在同一 K 下保持
  唯一）；两种架构、两台本机可执行文件（x64、Win32）全部通过，包含
  `TestHostContextEntryExecution` 真实合成 handler 执行。
- 隔离原生 CPU 差分覆盖按语义扩展：
  - `SMUL_WIDE` 接入了 `TestRemainingArithmeticFamiliesNativeDifferential`
    已有的动态 provider-seed 覆盖机制（此前该语义的
    `migratedSemanticCount` 为 0，实际未被这套机制覆盖），两种架构均实测
    4 个 provider seed、每 seed 32 个真实 CPU corpus。
  - `UDIV_WIDE`/`IDIV_WIDE` 原来的
    `TestWideDivideNativeDifferentialAndDivideFault` 只用一个固定 provider
    seed（覆盖不到寄存器直接与内存两种形式），本批改为动态选择：每个语义、
    每个 K 独立挑选覆盖两种形式的 2 个 provider seed（共 4 个 seed/语义），
    每 seed 64 个真实 CPU corpus，语料天然混有可整除样本与触发 `#DE` 的
    除零/商溢出样本；两种架构全部通过，未削弱原有的 `#DE` 断言强度。
  - `SWAP` 没有一条可由 translator 一对一产生的原生 CPU 指令（与批次 6 对
    `ROT` 的结论一致），因此和 `ROT` 一样只用 host-arch direct-threaded
    handler 全矩阵/双策略真实执行与寄存器签名解码验证，不构造隔离原生差分、
    也不用其他语义的原生差分冒充证据。
  - `INT3` 的隔离原生差分沿用既有的 `TestInt3NativeDifferentialAndBreakpointFault`
    （两种编码的 `#BP` 故障 EIP/寄存器现场一致性），未受本批影响，继续通过。
- x64 `ctest`（14/14）与 Win32 `ctest`（13/14，唯一例外见下）全部通过，包括
  正式 `vm_per_build_similarity_gate`：

| 架构/容器 | business_core | core_variant | codec | encrypted_handlers |
|---|---:|---:|---:|---:|
| x64 EXE | 0.2724 | 0.1590 | 0.1455 | 0.0001 |
| x64 DLL | 0.2798 | 0.1258 | 0.1822 | 0.0001 |
| Win32 EXE | 0.2579 | 0.1003 | 0.0564 | 0.0001 |
| Win32 DLL | 0.2783 | 0.1005 | 0.0695 | 0.0001 |

  全部低于对应硬上限，输出 `VM_PER_BUILD_SIMILARITY_GATE_PASS`。
- 本地定点 handler 合成相似度（非正式 gate，仅供趋势参考）：x86
  `core_variant=0.253614`、x64 `core_variant=0.33651`；较上一批（x86
  `0.254705`、x64 `0.336519`）相比，x86 继续小幅下降，x64 基本持平。
- 唯一未通过项：Win32 `vm_native_differential` 再次命中 CMakeLists.txt 中
  该测试固定的 `TIMEOUT 120` 秒属性——本批为 `UDIV_WIDE`/`IDIV_WIDE` 新增了
  6 个额外的真实 CPU corpus 批次（原 1 个 provider seed 扩展为 4 个/语义），
  总耗时随之增加，在本机于本次会话经历长时间连续编译/执行后更容易越过这
  个和 build 无关的本地属性余量。直接运行同一可执行文件（不经过 ctest 的
  进程调度开销）稳定在约 112 秒完成，退出码 `0`，日志中没有任何 `FAIL`，
  15 个测试全部输出 `PASS`。这与批次 7 记录的同一类本地余量问题性质相同，
  不是本批代码引入的功能回归，正式确认交给 Windows CI runner。
- 本次会话中还发现一次本机执行环境异常：`test_vm_handler_synthesis.exe`
  在重新编译后一度被本机安全软件/文件系统层持续拒绝执行（"Access is
  denied"/"process cannot access the file"），改名、删除重建、更换执行方式
  （PowerShell `Start-Process`、ctest、bash exec）均未能立即恢复，而同一
  时间新编译的其他体积相近的可执行文件（`test_vm_runtime_integrity.exe`、
  `test_cli_options.exe`）不受影响；等待约 15 分钟后自然恢复，之后的编译/
  执行均正常。这是本机环境的瞬时限制，不代表代码问题，记录在此供后续
  批次参考（如再次出现，应换一个不同名字重新编译或耐心等待，而不是假设
  代码有 bug）。

### 评估

- 开发效率：`MoveRegisterPair` 把批次 7 中专属于 PUSH_IP 的搬入/搬出特判
  推广成了通用原语，两个方向（搬入、搬出）与全部重叠情形只需推导一次；
  三个宽运算语义共用同一个 `EmitZydisWideOperandCore`，寄存器直接与内存
  两种形式的选择只是一个布尔翻转。
- 正确性风险：本批修复的两个问题（SWAP 的反向循环依赖、宽运算寄存器直接
  形式的跨 K/跨 build 字节退化）都不是 REX/ModRM 编码错误，而是"如何在
  Encoder 之上组织多个可选形式"的设计错误。两者都是被现有验证层（真实
  Win32 host-arch 执行、`ValidateBusinessCoreStrategyReemission` 的跨 K 字节
  比较）在本地捕获的，不是留到 CI 才发现，说明这套分层验证确实起作用。
- per-build 多样性：SWAP 获得 x86 3 套、x64 7 套真实 assignment；三个宽运算
  语义在每个 K 下都新增了寄存器直接/内存两种真实可选形式，正式聚合门禁
  的四个组合均未退化。

结论：该路线继续适用于剩余简单显式操作数与零操作数语义。本批额外确认的
方法论结论——(1) 通用双向并行搬运原语应该一次性覆盖全部重叠情形而不是
逐语义特判；(2) 任何"零字节差异"的固定形式（无论是零操作数指令还是寄存器
直接操作）如果被设计成可与另一种形式互换，必须显式证明两个 K 不会同时选中
它，且它自身要么真的不需要 per-build 差异（如 INT3），要么必须额外携带 keyed
扰动——都应写入后续批次的复核清单。`POP_VREG` 继续留给独立批次；
`PUSH_CONDITION`、`FLAGS_*` 家族与控制流语义未进入本批。

## 推广批次 9：`PUSH_CONDITION`（收官第一类，2026-07-20）

### 范围与结论

本批只迁移一个语义，`PUSH_CONDITION`，收官第一类全部 12 个语义（`POP_VREG`
按批次 7 的结论继续保留手写实现，是唯一的已知例外）。`PUSH_CONDITION` 涉及
标志位读取（core 前有一次真实的 flag materializer 调用），按任务要求的分类
规则，即使被列在"第一类"也要按第二类的审查强度处理：本节的活跃性分析、
正确性复核与验证语料都按这一更高标准执行。

`X64EvaluateCondition`/`X86EvaluateCondition`（既有的、本批未触碰的条件分发
基础设施）在 core 运行前已经把分支条件求值为干净的 0 或 1，落在固定的
RAX/EAX 边界；实际持有各分支标志位比较逻辑的正是这套未迁移代码，本批
core 本身只对这个已经求好的布尔值做一次 keyed 恒等变换，不重新读取或计算
任何 flags。这个事实经过两遍独立复核（见下）后被认为是把本语义按"第一类
风险"对待的正当理由，同时仍然执行第二类要求的验证语料覆盖强度。

### 按语义/架构导出的活跃性契约

| 语义/架构 | seed 选择的角色与安全池 | 保留/排除依据 |
|---|---|---|
| PUSH_CONDITION x64 | value 在 RAX、RCX、RDX、R8、R9、R10、R11 中轮转 | `X64CallFlagMaterializer` 是真实间接调用，按 Win64 ABI 清空全部易失寄存器；`X64EvaluateCondition` 自身的 RCX/RDX scratch 在返回后即死；R8/R9/R10/R11 全程未被两者触碰 |
| PUSH_CONDITION x86 | value 在 EAX、ECX、EDX 中轮转 | 同一推理限制在易失的 EAX/ECX/EDX；`X86CallFlagMaterializer`（cdecl 调用）与 `X86EvaluateCondition` 均未触碰 EBX/ESI，不新增 |

这个活跃性契约与 x64 `PUSH_IP`/`SWAP`、x86 默认三寄存器池完全一致，因此代码
没有新增专属的 `DeriveVariantRegisters` 分支——它直接复用已有的通用回退池
（x64 7 元素 stride-2、x86 3 元素 stride-1），两者在这一批之前就已经过其他
语义反复验证，能保证 `registerAssignment[0..2]` 三者互异。

### 迁移中发现的一个正确性坑：CMP 立即数的隐式回绕

`strategy=1` 分支需要发出 `cmp value, 1-key`，其中 `1u - key` 是有意的
`uint32_t` 回绕（`key` 可达 `0x0FFFFFFF`，回绕后是一个高位为 1 的大数，
代表一个负数在 32 位模式下的位模式）。第一版实现直接把这个 `uint32_t` 传给
不做位宽处理的 `EmitZydisBinaryImmediate`，在 x64（8 字节目的操作数）上失败，
报错 "business core strategy re-emission is empty or unresolved"：原始手写
`0x81 /7 imm32` 编码依赖 CPU 把 32 位立即数按目的宽度符号扩展到 64 位，但
`EmitZydisBinaryImmediate` 把这个 `uint32_t` 参数隐式零扩展成 `uint64_t` 交给
Zydis，Zydis 因此认为这是一个正的大数，需要比 32 位更宽的立即数编码，
拒绝了请求。修复方法是显式调用 `ZydisSignExtendImmediateBits(1u - key, 4u)`
先按 32 位位宽做符号扩展，再交给按目的宽度构造请求的
`EmitZydisSizedBinaryImmediate`——这正是批次 3C 已经踩过并修好的同一类坑
（"16 位立即数在 Zydis 匹配阶段按 signed field 判断能否装入目标编码"），
只是这次出现在没有走 sized 版本的调用点上。第二遍复核确认：`key+1u`
（`strategy=0` 分支）不需要这个修复，因为 `CoreAddressKey` 已经把 `key` 限制
在 28 位（最高 `0x10000000`），加 1 后仍是一个符号位为 0 的正数，不会触发
同样的歧义。

### 固定寄存器场景的迁移前后字节

x64（value=RAX，与旧实现固定寄存器一致）：

| 指令/序列 | 迁移前 | Zydis Encoder |
|---|---|---|
| `strategy=0`：`add rax,key` | `48 81 C0 <key>` | `48 05 <key>`（accumulator 规范化） |
| `cmp rax,key+1` | `48 81 F8 <key+1>` | `48 3D <key+1>`（accumulator 规范化） |
| `strategy=1`：`sub rax,key` | `48 81 E8 <key>` | `48 2D <key>`（accumulator 规范化） |
| `sete al` / `movzx eax,al` | `0F 94 C0` / `0F B6 C0` | 相同 |

x86 是本批唯一的行为性变化，而不是纯编码迁移：原实现 `strategy=0` 用
`and eax,1`（`83 E0 01`）、`strategy=1` 用 `test eax,eax; setne al; movzx eax,al`
（`85 C0 0F 95 C0 0F B6 C0`），两者都不含任何随 build 变化的字节。迁移后
x86 与 x64 共用同一个 keyed add/sub+CMP+SETcc 恒等式（`EmitZydisPushConditionCore`
按架构套用相同逻辑，只是操作数宽度不同），因此 x86 也获得了此前完全没有
的 per-build 立即数多样性，不再是这批之前唯一"零字节差异"的固定形式语义。
这一形式变化的正确性已经过两遍独立推导确认（见上），并且已由真实 CPU 执行
（`TestHostContextEntryExecution` 的 `ExecuteFlagsVariantMatrix`）在全部宽度、
两个 K 上验证。

### 本地验证结果与限制

- 完整静态门禁（含比例探针）通过，真实双策略覆盖保持 `54/54`。
- Release x64 与 Win32 的 `ciphershell_packer` 均以 `/W4 /WX` 编译通过。
- `test_vm_handler_synthesis` 新增 `TestZydisPushConditionRegisterDiversity`
  （x86 ≥3、x64 ≥4 套 assignment；实测 x86 3 套、x64 7 套）；两种架构、
  两台本机可执行文件（x64、Win32）全部通过，包含
  `TestHostContextEntryExecution` 的 `ExecuteFlagsVariantMatrix`——该矩阵已经
  覆盖全部宽度（1/2/4/8 字节）、两个 K，并在 `PUSH_CONDITION` 之后紧跟
  `POP_VREG`/`SELECT` 读取其结果，验证下游语义消费的值确实正确，这正是
  任务要求的"覆盖全部宽度和会读写标志位的下游语义组合"标准，而不是只用
  随机语料。
- 隔离原生 CPU 差分：本语义没有独立的隔离原生差分测试（`PUSH_CONDITION`
  的分支条件求值逻辑本身未被本批触碰，且没有一条 translator 会直接产生
  裸的 `PUSH_CONDITION`——它总是伴随控制流分支一起出现），继续依赖上面的
  host-arch 真实执行矩阵作为证据，与批次 6/8 对 `ROT`/`SWAP` 的证据边界
  结论一致，如实记录而不冒充隔离差分。
- x64 `ctest`（14/14）与 Win32 `ctest`（14/14，`vm_native_differential` 因本机
  持续高负载分两次单独运行验证，均通过）全部通过，包括正式
  `vm_per_build_similarity_gate`：

| 架构/容器 | business_core | core_variant | codec | encrypted_handlers |
|---|---:|---:|---:|---:|
| x64 EXE | 0.2778 | 0.1560 | 0.1136 | 0.0001 |
| x64 DLL | 0.2759 | 0.1407 | 0.1451 | 0.0001 |
| Win32 EXE | 0.2568 | 0.1074 | 0.0433 | 0.0001 |
| Win32 DLL | 0.2728 | 0.0843 | 0.0226 | 0.0001 |

  全部低于对应硬上限，输出 `VM_PER_BUILD_SIMILARITY_GATE_PASS`。
- 本地定点 handler 合成相似度（非正式 gate，仅供趋势参考）：x86
  `core_variant=0.253659`、x64 `core_variant=0.335338`，与上一批
  （x86 `0.253614`、x64 `0.33651`）基本持平，符合预期——单个语义、且只有
  一个真实角色，对聚合指标的边际影响很小。

### 评估

- 开发效率：由于活跃性契约与既有的通用回退池完全吻合，这是本项目至今
  唯一一个不需要新增 `DeriveVariantRegisters` 分支的迁移语义，核心工作量
  集中在验证"回退池确实安全"而不是设计新契约。
- 正确性风险：本批发现的坑（`EmitZydisBinaryImmediate` 对回绕立即数的
  隐式零扩展）不是新的错误类别，而是批次 3C 已知问题在一个新调用点上的
  复现，说明"哪个 helper 自带符号扩展、哪个不带"仍然是这条迁移路线里
  容易踩的坑，后续批次凡是使用非 seed-key（例如 `1-key` 这类刻意构造的
  回绕值）作为立即数时，都应默认使用 `EmitZydisSizedBinaryImmediate` 而不是
  裸的 `EmitZydisBinaryImmediate`。x86 一侧的行为统一（复用 x64 恒等式）
  经过两遍复核后判断是安全的等价变换，且已被真实执行验证。
- per-build 多样性：`PUSH_CONDITION` 获得 x86 3 套、x64 7 套真实
  assignment；更重要的是 x86 从此前完全没有 build-seed 相关字节的两个
  固定形式，变成了和 x64 对称的、真正带 per-build 立即数的 keyed 恒等式。

结论：第一类风险较低的 12 个语义中，11 个已完成迁移（`POP_VREG` 按批次 7
的结论继续留给独立批次）。本批额外确认的方法论结论——"零字节差异的固定
形式"不仅可能出现在寄存器直接操作里（批次 8 的 SMUL_WIDE/UDIV_WIDE/
IDIV_WIDE），也可能出现在看起来只是"分支到不同手写字节"的两个 K 分支里
（本批迁移前的 x86 PUSH_CONDITION）；迁移到统一的 keyed 恒等式框架后，这类
语义会自动获得 per-build 多样性，不需要额外的专项处理。接下来按计划进入
第二类：`FLAGS_LAZY`、`FLAGS_MATERIALIZE`、`FLAGS_PACK_AH`、
`FLAGS_UNPACK_AH`、`FLAGS_UPDATE`、`FLAGS_WRITE` 六个标志位管理语义，
要求双倍复核、覆盖全部宽度与下游语义组合、可拆分成两个 3 语义子批。

## 推广批次 10：`FLAGS_MATERIALIZE`、`FLAGS_PACK_AH`、`FLAGS_UNPACK_AH`（2026-07-20）

### 范围、风险边界与结论

本批迁移第二类 flags 家族的第一个三语义子批：
`FLAGS_MATERIALIZE`、`FLAGS_PACK_AH`、`FLAGS_UNPACK_AH`。三者都位于真实
flag-materializer 调用边界：前者准备 requested mask 后立即调用 materializer，
后两者分别实现 `LAHF`/`SAHF` 的 status-bit 打包与合并。它们按 flags/ABI 高风险
语义执行两遍活跃性与边界复核，没有与普通 ALU、控制流或 ABI bridge 混做。

三个 business core 的正式生产路径均只调用 `EmitZydisFlags*Core`，每条目标
指令都通过 `ZydisEncoderRequest` 生成；Encoder 失败写入
`CodeBuffer::FailEncoding` 并使 kernel 生成失败。不存在 Zydis 失败后回退
`c.Raw` 的双轨实现。

本批完成后累计 Zydis business-core 迁移进度为 **42/54**；VM 真 K 双策略
静态覆盖保持 **54/54**。

### 按语义/架构导出的真实活跃性契约

| 语义/架构 | core 入口真实状态 | seed 选择的安全角色池 | 固定边界与排除依据 |
|---|---|---|---|
| FLAGS_MATERIALIZE x64 | handler 第一段代码，只有 R15=context；requested mask 尚未加载 | address 在 R10、RAX、RCX、RDX、R8、R9、R11 中轮转（7 套） | RDX 是 core 结束后的 materializer mask 输出，不是入口 live 值；`mov rdx,[rdx+disp]` 先取有效地址再覆盖 RDX，安全；RSP/nonvolatile 全排除 |
| FLAGS_MATERIALIZE x86 | handler 第一段代码，只有 EDI=context | address 在 ECX、EAX、EDX 中轮转（3 套） | EDX 仅是 post-core mask 输出；EBX/ESI 是 direct-threaded ABI 状态，排除 |
| FLAGS_PACK_AH x64 | 真实 Win64 materializer 调用已清空易失 GPR，随后仅 RDX=virtualFlags | 32 位 work/result 在 RAX、RCX、RDX、R8、R9、R10、R11 中轮转（7 套） | R15=context；最后结果移回 RAX 供 `X64PushOne`；全部运算保持 32 位，和旧 EAX 实现一样零扩展高 32 位 |
| FLAGS_PACK_AH x86 | cdecl materializer 返回后仅 EDX=virtualFlags | work/result 在 EAX、ECX、EDX 中轮转（3 套） | EDI=context，EBX/ESI threaded state；结果移回 EAX 供 `X86PushOne` |
| FLAGS_UNPACK_AH x64 | materializer 返回后包装层只重载 RAX=packed AH、RDX=virtualFlags | packed/flags 相邻角色在 RAX、RDX、RCX、R8、R9、R10、R11 中轮转（7 套） | `MoveRegisterPair` 处理包括 RAX/RDX 对调在内的全部重叠；结果固定回 RDX 存入 context；R15/nonvolatile 排除 |
| FLAGS_UNPACK_AH x86 | 包装层只重载 EAX=packed AH、EDX=virtualFlags | packed/flags 在 EAX、EDX、ECX 中轮转（3 套） | 同一并行搬运推理；EBX/ESI/EDI 排除 |

这里没有共享“全局 scratch pool”：三个语义分别有独立的
`DeriveVariantRegisters` 分支与逐架构注释。永久测试遍历每个语义的 16 个
seed byte，验证发布 assignment 确实出现在解码后的寄存器/内存 operand 中，
并要求固定 K 下的真实 decode signature 发生变化；实测三语义均为 x86 3 套、
x64 7 套，变化进入 ModRM/REX/内存 base 字段，不依赖随机立即数刷相似度。

### 固定旧寄存器计划的代表字节

零 seed、variant 0 固定为旧计划：MATERIALIZE 使用 x64 R10/x86 ECX，
PACK_AH 使用 EAX，UNPACK_AH 使用 RAX:RDX/EAX:EDX。永久回归
`TestZydisFlagsBoundaryFixedRegisterPlans` 同时锁定这些角色并打印实际 core 字节。

| 架构/语义 | 迁移前代表字节 | Zydis 输出 | 结论 |
|---|---|---|---|
| x86 MATERIALIZE K=1 | `8D 8F CB260103 81 C1 D8B11A0D 81 E9 8AA6D309 81 C1 CF0E2001 8B 91 DCCD97F8` | 完全相同 | LEA、三段 keyed 地址修正与最终 mask load 逐字节一致 |
| x64 MATERIALIZE K=1 | `4D 8D 97 52D2A605 49 81 C2 458B2D0B 49 83 EA 3D 49 81 C2 F5ACF301 49 8B 92 750438ED` | 完全相同 | Zydis 对小的 SUB key 合法选择 `83 /5 imm8`；旧 helper 本来也是该形式 |
| x86 PACK_AH K=0 的首个 keyed XOR | `81 F0 94000000` | `35 94000000` | 合法 EAX accumulator short form；旋转、mask、逆旋转、固定 bit1 完全不变 |
| x64 PACK_AH K=0 的首个 keyed XOR（仍是 32 位 EAX） | `81 F0 85000000` | `35 85000000` | 同一 accumulator 规范化；完整新 core 为 `89 D0 35 85000000 C1 C8 1A 25 40350000 C1 C0 1A 35 85000000 83 C8 02` |
| x86 UNPACK_AH K=0 首个 XOR | `81 F0 5D546472` | `35 5D546472` | 仅 EAX accumulator 规范化；EDX key、`~0xD5` mask、OR 与最终 decode 不变 |
| x64 UNPACK_AH K=0 首个 XOR | `48 81 F0 6CF25946` | `48 35 6CF25946` | 同一规范化；完整新 core 为 `48 35 6CF25946 48 81 F2 6CF25946 48 81 E2 2AFFFFFF 25 D5000000 48 09 C2 48 81 F2 6CF25946` |

项目没有为保持旧 `81 /6` 长形式而回退手写字节或插入 NOP。上述差异只改变
合法 opcode 选择，不改变 operand 位宽、flags 位掩码、key 共轭、fault 行为或
context/stack 生命周期；固定计划、Zydis 完整解码、真实 handler 执行和 native
differential 共同验证其语义等价。

### 实现中实际发现并修复的问题

第一版 x64 `FLAGS_UNPACK_AH` 把 `~0xD5 == 0xFFFFFF2A` 直接作为 64 位无符号
立即数交给 `AND r64,imm32` 请求。真实 Zydis Encoder 正确拒绝：该正数无法由
架构唯一可用的 sign-extended imm32 表示。旧手写 `48 81 /4 2AFFFFFF` 的真实
含义是把 `0xFFFFFF2A` 符号扩展为 `0xFFFFFFFFFFFFFF2A`。修复是先调用
`ZydisSignExtendImmediateBits(...,4)`，再构造 64 位目标请求；没有回退
`c.Raw`。修复后 x64/x86 全矩阵、固定重发射和真实 CPU 差分均通过。

验证过程中还确认旧 `vm_native_differential` 在本机 Win32 Release 下即使完全
不运行本批入口也需要 124.4 秒，超过其既有 CTest `TIMEOUT 120`，但直接运行
同一可执行文件自然结束时 15 个旧测试全部 PASS。为避免提高超时或削减本批
覆盖，新矩阵注册为同一可执行文件的独立 hard-gate
`vm_flags_boundary_native_differential`，使用 `--flags-boundary-only` 入口；
旧入口、旧 corpus、旧 timeout 均未修改。

### native differential、host-arch 与 flags/ABI 证据

- production translator 可真实触达三者：`LAHF` 下沉为 `FLAGS_PACK_AH`，
  `SAHF` 下沉为 `FLAGS_UNPACK_AH`，`RET` 强制发出
  `FLAGS_MATERIALIZE(VM_FLAG_ARCHITECTURAL_MASK)`。因此使用真实
  `LAHF; SAHF; RET` 函数，不伪造 differential-only micro-op。
- 新 hard-gate 从 255 个真实候选 provider seed 生成三个目标 handler，按尚未
  覆盖的 semantic/K/assignment 单元做最大覆盖选择。x64 实选 seed
  `1/2/3/7`，Win32 实选 `1/4/6/15`；每 seed 32 个真实 CPU corpus。每个语义
  的两个 K 和不同寄存器 assignment 都被实际执行，x64/Win32 全部通过。
- `LAHF` 验证 SF/ZF/AF/PF/CF 到 AH 的精确布局及固定 bit1；随后的 `SAHF`
  验证只覆盖 status mask、保留 OF 与其他 architectural flags；`RET` 再把所有
  待决 flags materialize 到真实 native 返回 frame。差分逐 GPR/FLAGS 比较，
  不是只检查“无崩溃”。
- 既有 `ExecuteFlagsVariantMatrix` 继续在 host architecture 上覆盖宽度
  1/2/4/8、两个 core strategy、lazy record、preserve mask、PACK/UNPACK、
  UPDATE/WRITE 与下游 PUSH/SELECT/POP 组合；本批没有放宽任何断言。
- x64 三个语义仍发布既有 `kX64FlagCallStackBytes=0x28` stack funclet，调用位置、
  prolog/epilog、`.pdata`/UNWIND_INFO 生成路径均未改；全量 unwind/handler
  合成门禁通过。

### 双架构验证与 per-build similarity

- x64、Win32 全量 Release 构建通过；未安装或下载任何依赖。
- x64 完整 CTest **15/15** 通过：旧 native differential 114.99 秒，新 flags
  hard-gate 5.47 秒，54/54 static gate 与真实 per-build gate 均通过。
- Win32 除上述旧 wrapper 固定 120 秒超时项外 CTest **14/14** 通过；新 flags
  hard-gate 6.75 秒。旧 native differential 直接运行 124.4 秒、退出码 0，
  15 个旧子测试全部 PASS。这里不把它写成 Win32 全量 CTest 15/15。
- 固定种子 handler 合成代理（不是正式 per-build gate）：x86
  `core_variant=0.250882`、x64 `core_variant=0.332414`；最差 pair 分别
  `0.583333`、`0.447059`，均低于既有独立硬上限，阈值未改。
- 正式独立 seed、真实 EXE/DLL 打包执行数据如下：

| 架构/容器 | business_core | core_variant | codec | encrypted_handlers |
|---|---:|---:|---:|---:|
| x64 EXE | 0.2618 | 0.1169 | 0.0799 | 0.0001 |
| x64 DLL | 0.2815 | 0.1613 | 0.1323 | 0.0001 |
| Win32 EXE | 0.2580 | 0.0929 | 0.0226 | 0.0000 |
| Win32 DLL | 0.2728 | 0.1074 | 0.0432 | 0.0001 |

四组均输出 `VM_PER_BUILD_SIMILARITY_GATE_PASS`；business/core/codec/encrypted
聚合阈值与单 pair ceiling 均未改，未删除 corpus、跳过语义或使用 native
fallback。

### 剩余语义与下一批边界

当前剩余 **12/54**：

- flags 高风险：`FLAGS_LAZY`、`FLAGS_UPDATE`、`FLAGS_WRITE`；
- 控制流/上下文：`SELECT`、`BRANCH`、`BRANCH_IF`、`CALL_VM`、`RET`；
- ABI/bridge：`CALL_HOST`、`BRIDGE_EXTENDED`；
- 已有明确阻塞证据：`POP_VREG`（无安全寄存器池且曾触发单 pair similarity
  回归，继续保留原正式实现）；
- 部分架构尚未完成：x64 `UMUL_WIDE` business core。

下一批最多继续处理剩余三个 flags 语义，并保持同样的双倍复核；
`FLAGS_UPDATE/WRITE` 的 mask merge、preserve semantics 与 `FLAGS_LAZY` 的 record
生命周期必须逐字段证明。控制流、CALL_HOST、BRIDGE_EXTENDED、POP_VREG 和 x64
UMUL_WIDE 不与该批混做。本文档只记录本地验证；本批尚未 push，也没有对应的
远端 GitHub Actions 运行，因此不宣称远端 CI 状态。

## 推广批次 11：`FLAGS_LAZY`、`FLAGS_UPDATE`、`FLAGS_WRITE`（2026-07-20）

### 范围、风险边界与结论

本批完成 flags 生命周期第二个三语义子批，不混入控制流、ABI bridge、
`POP_VREG` 或 x64 `UMUL_WIDE`。`FLAGS_LAZY` 的逐字段 record 搬运、
`FLAGS_UPDATE` 的 clear/set/toggle 与 keyed correction、`FLAGS_WRITE` 的
masked merge 均改由正式 `ZydisEncoderRequest` 路径编码；Encoder 失败写入
`CodeBuffer::FailEncoding` 并使 kernel 生成失败，不存在回退 `c.Raw` 的双轨路径。
用于内部 label/fixup 的 `CodeBuffer::Jcc/Jmp` 仍只承担控制边连接，不负责业务
指令编码。

完成后累计 Zydis business-core 迁移进度为 **45/54**；VM 真 K 双策略静态覆盖
保持 **54/54**。

### 每语义、每架构的真实活跃性契约

| 语义/架构 | core 入口实际状态 | seed 选择的角色与安全计划 | 保留/排除依据 |
|---|---|---|---|
| FLAGS_LAZY x64 | 真实 materializer 调用后，校验路径只暂存 operation/width/mask 于 RAX/RCX/RDX/R11；这些值在 core 后全部从 context 重载 | address/value 在 R10、RAX、RCX、RDX、R8、R9、R11 相邻轮转，共 7 套；R10/RAX 为旧固定计划 | R15=context 保留；RSP/nonvolatile 排除；所有候选均在 core 后无条件被覆盖 |
| FLAGS_LAZY x86 | cdecl materializer 与校验后仅 EDI=context 跨 core 存活 | address/value 在 EDX、EAX、ECX 相邻轮转，共 3 套；EDX/EAX 为旧固定计划 | EBX/ESI 未被该语义旧实现证明安全，继续排除 |
| FLAGS_WRITE x64 | wrapper 在 materializer 后精确重载 RAX=old、RCX=mask、RDX=value | old/mask/value 使用固定边界或互不覆盖源值的 R8/R9/R10 高寄存器计划，共 8 套；scratch=R11 | 其余 Win64 volatile 在调用后死亡；高目标不会覆盖仍待搬运的 RAX/RCX/RDX 源；R15/context 与 nonvolatile 排除 |
| FLAGS_WRITE x86 | EAX=old、ECX=mask、EDX=value | 三个逻辑角色在 EAX/ECX/EDX 上采用固定计划和两个三循环，共 3 套；scratch=EBX | 两个三循环由保 flags 的两条 `XCHG` 完成；EBX 是旧 K=0 core 已实际使用的 inverted-mask scratch，因此是该语义局部已证明角色，ESI/EDI 排除 |
| FLAGS_UPDATE x64 | materializer 后 RAX=flags、RCX=mode、RDX=mask；RCX 仅在 keyed dispatch 前存活 | flags/mask 使用 RAX/RDX 或 R8/R9 的 6 套显式安全 pair，scratchA/B=R10/R11 | `MoveRegisterPair` 处理 RAX/RDX 对调；RCX 保持 mode 到分发完成，不被偷作数据 scratch；R15/nonvolatile 排除 |
| FLAGS_UPDATE x86 | EAX=flags、ECX=mode、EDX=mask；分发后 ECX 死亡 | flags/mask/scratchA 在 EAX/EDX/EBX 上 4 套显式计划，scratchB=ECX | EBX 与分发后 ECX 都是旧 core 已使用的同语义局部 scratch；`MoveRegisterPair` 的 swap 使用 `XCHG`，不改变进入 keyed dispatch 的 EFLAGS；ESI/EDI 排除 |

这些是三个独立的 `DeriveVariantRegisters` 分支，不是共享全局 scratch pool。
`TestZydisFlagsLifecycleRegisterDiversity` 对每个 seed 生成并完整解码 core，验证发布
角色确实出现在寄存器/内存 operand 中，并要求固定 K 下的真实 REX/ModRM/SIB
signature 变化。实测 assignment 数为：`FLAGS_LAZY` x64 7 / x86 3，
`FLAGS_WRITE` 8 / 3，`FLAGS_UPDATE` 6 / 4。

### 固定旧寄存器计划的代表性字节

`TestZydisFlagsLifecycleFixedRegisterPlans` 用零 seed、variant 0 锁定旧物理角色并
打印完整 core。逐指令核对结果如下：

| 架构/语义 | 迁移前代表字节 | Zydis 输出 | 结论 |
|---|---|---|---|
| x64 FLAGS_LAZY keyed copy | `4D 8D 97 <disp32> 49 8B 82 <disp32> 4D 8D 97 <disp32> 49 89 82 <disp32>` | 相同 | R10 address、RAX value 的 LEA/load/LEA/store 逐字节一致 |
| x86 FLAGS_LAZY keyed copy | `8D 97 <disp32> 8B 82 <disp32> 8D 97 <disp32> 89 82 <disp32>` | 相同 | EDX/EAX 固定计划逐字节一致 |
| x64 FLAGS_WRITE K=0 首个 XOR | `48 81 F0 4FD97161` | `48 35 4FD97161` | 合法 RAX accumulator short form；其余 mask complement/AND/OR 与最终 decode 等价 |
| x86 FLAGS_WRITE K=0 首个 XOR | `81 F0 5D792F01` | `35 5D792F01` | 合法 EAX accumulator short form；完整新 core 为 `35 5D792F01 81 F2 5D792F01 89 CB F7 D3 21 D8 21 CA 09 D0 35 5D792F01` |
| x64 FLAGS_UPDATE K=0 mode LEA/CMP | `48 8D 89 15000000 48 81 F9 15000000` | `48 8D 49 15 48 83 F9 15` | Zydis 合法选择 disp8/imm8；目标仍是 RCX+0x15 与 modeKey+CLEAR，分支条件和 flags 相同 |
| x86 FLAGS_UPDATE K=1 keyed XOR | `81 F0 1A000000` | `83 F0 1A` | 合法 imm8 sign-extended short form；值为正 0x1A，XOR 位模式完全相同 |

项目没有为保留长 opcode 而插入 NOP 或回退手写编码。短形式只改变合法编码长度，
不改变 operand 宽度、flags、fault、context/stack 生命周期或 label 目标；完整 decode、
host-arch 执行与 native differential 共同证明等价。

### 实现和验证中发现的问题

第一轮 Win32 pack-time 合成在 `FLAGS_WRITE` 上 fail-closed，错误为
`variant register allocation violates its liveness contract`。原因不是生成了危险计划，
而是永久 validator 尚未认识本批逐语义证明的 EBX 局部契约。处理方式是只为
`FLAGS_WRITE/FLAGS_UPDATE` 增加精确的 `x86FlagsMutationContract && reg==3`，没有
放宽其他语义、没有提高阈值；随后 Win32 真 handler 全矩阵通过。该失败验证了
validator 会在发布未知计划时立即阻断，而不是静默接受。

`FLAGS_WRITE` 的 x86 三寄存器轮换还暴露了与批次 7 `PUSH_IP` 相同类别、但为三元
循环的搬运风险：顺序 MOV 会覆盖尚未读取的源。本批没有尝试寻找不存在的第四个
caller-volatile 寄存器，而是将两种合法三循环分别固定为两条 `XCHG`，其既保留三
个输入，又不修改 EFLAGS。host-arch 真 handler 执行覆盖两个 K 和所有发布计划。

### native differential 与 host-arch 证据边界

- `FLAGS_LAZY` 与 `FLAGS_UPDATE` 可由生产 translator 真实触达。新增独立 hard-gate
  `vm_flags_lifecycle_native_differential`，使用真实函数
  `add eax,ecx; clc; stc; cmc; ret`：ADD 产生 lazy record，CLC/STC/CMC 覆盖
  clear/set/toggle，RET materialize 最终可观察 flags。
- provider seed 从实际生成的所有已触达 `(semantic, handlerVariant)` 选择，而不是
  猜 seed byte；每个目标 variant、每个 K 至少覆盖两个不同 assignment。x64 选择
  seed `1/2/5/10`，Win32 选择 `1/2/6/30`，每 seed 32 个真实 CPU corpus，全部通过。
- `FLAGS_WRITE` 没有一对一生产 translator 入口：`POPF/POPFD/POPFQ` 因 privilege、
  trap、RF 语义无法无损虚拟化而明确 fail-closed。因此本批没有伪造 isolated native
  differential。证据来自 host-arch `ExecuteFlagsVariantMatrix` 的真实合成 handler
  执行；矩阵已覆盖全 status mask，并新增仅写 CF 的窄 mask corpus，以验证未选中的
  architectural flags 保留，同时覆盖两个 K、全部宽度和下游 PUSH/POP 读取。

### 双架构验证与 per-build similarity

- Release x64 与 Win32 的目标均重新生成并编译通过，未安装或下载依赖。
- x64 全量 CTest **16/16** 通过：旧完整 native differential 97.56 秒，新 lifecycle
  differential 5.08 秒，正式 per-build gate 289.37 秒。
- Win32 CTest 16 项中 **15 项完成且 14 项通过**，唯一未完成项仍是既有
  `vm_native_differential` 被其固定 `TIMEOUT 120` 在 120.03 秒截断；同一可执行文件
  不经 CTest 直接完整运行 134.7 秒、退出码 0，全部旧子测试 PASS。新增 lifecycle
  differential 6.12 秒、54/54 static gate 和正式 per-build gate 383.61 秒均通过。
  没有修改 timeout 或删减 corpus。
- 固定种子 handler 合成代理：x86 `core_variant=0.243326`、最差 pair `0.583333`；
  x64 `core_variant=0.324319`、最差 pair `0.447059`。既有硬阈值未修改。

| 架构/容器 | business_core | core_variant | codec | encrypted_handlers |
|---|---:|---:|---:|---:|
| x64 EXE | 0.2669 | 0.1387 | 0.1050 | 0.0001 |
| x64 DLL | 0.2768 | 0.1412 | 0.0982 | 0.0001 |
| Win32 EXE | 0.2565 | 0.0921 | 0.0265 | 0.0001 |
| Win32 DLL | 0.2663 | 0.0840 | 0.0441 | 0.0001 |

四组均输出 `VM_PER_BUILD_SIMILARITY_GATE_PASS`；聚合阈值、单 pair ceiling、corpus
与跳过规则均未更改。

### 剩余语义和下一批风险边界

当前剩余 **9/54**：

- 控制流/上下文：`SELECT`、`BRANCH`、`BRANCH_IF`、`CALL_VM`、`RET`；
- ABI/bridge：`CALL_HOST`、`BRIDGE_EXTENDED`；
- 已有明确阻塞证据：`POP_VREG`，继续保留原正式实现；
- 部分架构尚未完成：x64 `UMUL_WIDE` business core。

下一批不得把 `CALL_HOST`/`BRIDGE_EXTENDED` 与普通控制流或 x64 宽乘法混做。
控制流五语义可评估为一个独立高风险批次，但必须逐 edge 验证 VIP/call-stack、
真实 branch target 和 RET materialization；若其规模不适合 3～6 个小批，则优先单独
处理 x64 `UMUL_WIDE`，不为凑数量重试 `POP_VREG`。

## 推广批次 12：`POP_VREG`、`BRANCH`、`BRANCH_IF`、`CALL_VM`、`RET`（2026-07-20）

### 范围、HEAD 核对与结论

本批按指定范围补回批次 7 曾回退的 `POP_VREG`，并迁移四个控制流语义
`BRANCH`、`BRANCH_IF`、`CALL_VM`、`RET`；`CALL_HOST` 与
`BRIDGE_EXTENDED` 明确未动。五个 business core 的目标指令全部走正式
`ZydisEncoderRequest`，Encoder 失败写入 `CodeBuffer::FailEncoding` 并使生成
失败，没有 Zydis 失败后回退 `c.Raw` 的双轨路径。`CodeBuffer::Jcc/Jmp` 仍只负责
POP 的局部 merge edge 和既有 wrapper 的控制边 fixup，不承担业务指令编码。

开工时重新核对 `5711a9f` 发现：该提交的生产源码只新增并接入
`EmitZydisPushConditionCore`；`SELECT` 虽然进入了该批 host-arch 下游执行矩阵，
当前 HEAD 的正式 core 仍调用含 `X64/X86BinaryImmediate32` 与 `c.Raw` 的
`EmitKeyedSelectCore`。因此本批遵守指定范围没有重做 `SELECT`，但进度统计不能把
“已被下游测试覆盖”写成“已迁移到 Zydis”。按当前生产源码逐项计数，本批从
**45/54** 增加五项到 **50/54**；真 K 静态覆盖保持 **54/54**。

### 每语义、每架构的真实活跃性契约

| 语义/架构 | core 入口实际状态 | seed 选择的角色/形式 | 保留与排除依据 |
|---|---|---|---|
| POP_VREG x64 | RAX=已按 width mask 截断的新值；RCX=CL；R8=writeAll；R9=width mask（K1 兼作旧值/address）；R10=vreg index；R11=inverted mask；K0 的 RDX=旧值/address | 无空闲池。K0 固定角色 `{RAX,RDX,R11}`，K1 固定 `{RDX,R9,R11}`；slot 3 只在已存活的 R8/RCX/R10/R9 中选择四种等价 instruction form | R10 在 core 后仍用于最终 vreg store，R15=context；所有易失 GPR 均已有意义，禁止借用所谓全局 scratch |
| POP_VREG x86 | EAX=新值；ECX=CL；EDX=vreg index；EBX=writeAll/inverted mask；ESI=K0 address/旧值或 K1 candidate；EDI=context | 无空闲池。K0 固定 `{EAX,ESI,EBX}`，K1 固定 `{ESI,EAX,EBX}`；slot 3 在 ECX/EDX/EBX/ESI 四个已存活角色中选择形式 | EDX 在 core 后用于最终 store，EBX/ESI 已是该 core 的必要局部角色，不能再发明第四个 scratch |
| BRANCH x64/x86 | RAX/EAX=bytecodeBegin，RDX/EDX=decoded target RVA | x64 value/source 在 `{RAX,RDX,RCX,R8,R9,R10,R11}` 相邻轮转 7 套；x86 在 `{EAX,EDX,ECX}` 轮转 3 套 | x64 R15、x86 EDI 为 context；x86 EBX/ESI 为 threaded ABI state；其余候选在 wrapper 中未承载 live 值 |
| BRANCH_IF x64/x86 | 只有 taken edge 进入 core；真实 materializer 与 condition evaluator 已结束，wrapper 随后重新加载与 BRANCH 相同的 pair | 与 BRANCH 相同，但独立按本语义 seed 派生 | false edge 完全跳过 core；不移动、不重算 flags，也不改变既有 edge label |
| CALL_VM x64/x86 | callDepth 上限检查、递增和 return RVA 保存均已提交；随后 RAX/EAX=bytecodeBegin、RDX/EDX=target RVA | 与 BRANCH 相同；每个语义独立 seed | RCX/ECX 的 depth 临时值已死；core 只计算 target，不触碰 context call stack、fault 或 ABI 状态 |
| RET x64/x86 | 只有非顶层返回 edge 进入 core；depth 已递减，RAX/EAX=return RVA、RDX/EDX=bytecodeBegin | 与 BRANCH 相同；每个语义独立 seed | 顶层 RET 的 halt/cleanup edge 跳过 core；返回栈、unwind 与 stack cleanup 仍全部由旧 wrapper 管理 |

四个控制流语义共用的只是经过上述逐 wrapper 证明后的 target-add Encoder helper，
`DeriveVariantRegisters` 仍以四个明确语义为条件，不会影响同样调用旧
`EmitKeyedAddSubCore` 的 `BRIDGE_EXTENDED`。`MoveRegisterPair` 处理 pair 对调和
重叠，结果再固定回 RAX/EAX；变化真实进入 REX/ModRM，而不是只靠立即数。

### 固定旧寄存器计划的代表字节

永久测试 `TestZydisPopControlFixedRegisterPlans` 使用零 seed/variant 0，锁定
POP 的旧 K-specific 角色和控制流的 RAX:RDX/EAX:EDX pair，并完整解码、打印 core。

| 架构/语义 | 迁移前代表形式 | Zydis 输出/差异 | 结论 |
|---|---|---|---|
| x86 POP_VREG K0 | `D3 E0 ... D3 E3 F7 D3 ... 21 DE 09 F0` | 保留相同 SHL/NOT/AND/OR、SIB address 与 load；新增 `35 07A26441`×2、`35 B729E721`×2 两组可逆 keyed XOR | 新值在 merge 前后不变；新增 key 防止两个 build 选中同一结构形式时重现 0.72 单 pair 回归 |
| x64 POP_VREG K1 | `48 89 C2 48 D3 E2 ... 49 F7 D3 ... 4D 21 D9 4C 09 CA ... 48 0F 44 C2` | 相同固定角色和 CMOVZ 边界；新增 `48 81 F2 A605DC51`×2、`48 81 F2 A00B1335`×2 | 两组 XOR 均自消；flags 随后由既有 TEST 覆盖，VM flags 仍来自 context |
| x86 control K0 | `81 C0 <k0> 81 E8 <k1> 81 C0 <k2> 01 D0 ...` | `05 <k0> 2D <k1> 05 <k2> 01 D0 ...` | Zydis 合法使用 EAX accumulator short form；操作数宽度、key algebra 与 target 完全相同 |
| x64 control K0 | `48 81 C0 <k0> ... 48 01 D0 ...` | `48 05 <k0> ... 48 01 D0 ...`（小 key 时也可选 `48 83 /n imm8`） | 同一合法规范化；K1 的 `LEA value,[value+source]` 保持等价，非固定 pair 额外出现 MOV/XCHG 与真实 REX/ModRM 变化 |

零 seed 的完整代表输出包括：x86 BRANCH K0
`05 2FF6D61E 2D 78CA3157 05 DD42BD7B 01D0 2D DD42BD7B 05 78CA3157 2D 2FF6D61E`；
x64 CALL_VM K0
`48 05 B8AC044D 48 2D 171C770C 48 05 0EA68D22 48 01D0 48 2D 0EA68D22 48 05 171C770C 48 2D B8AC044D`。
项目没有为了保留旧 `81 /n` 长形式而插入 NOP 或回退手写字节。

### 实现与验证中实际发现并修复的问题

1. `POP_VREG` 第一版 Encoder 重写虽然所有功能矩阵通过，但两个固定种子恰好都
   选中同一个 form，x86 semantic 6/K0 的单 pair Dice 仍为 **0.712121**，复现了
   批次 7 的阻塞，而不是测试噪音。最终四种结构形式分别使用 NOT/XOR complement、
   AND/OR 或 XOR/AND/XOR blend 与不同可逆 choreography；同时每种形式都携带第二
   组独立可逆 key，保证相同 form 碰撞也不只靠一个 displacement/count 字节变化。
   修复后同一固定 pair 降为 **0.592105**，低于不可调的 0.65 正式 ceiling；阈值
   没有修改。
2. 首个真实 CALL fixture 的 native differential 在 `offset=0xe000` 报 memory
   side-effect mismatch。根因是硬件 CALL/RET 会在已恢复的 SP 下方留下死 return
   address，而 `CALL_VM` 按设计使用 context call stack，不写 guest stack；比较器
   正确地把两侧整块内存差异报告出来。本批没有忽略该差异、删 corpus 或放宽
   comparator，而是在真实 guest fixture 的公共 RET 前通过普通生产 STORE 同时把
   该死槽清零（x64 `[rsp-8]` qword、x86 `[esp-4]` dword）。所有活路径都执行该
   store，完整内存比较仍开启，随后两架构全部通过。
3. `AnalyzeFunctionRange` 按设计不跟随 CALL target。专项测试模拟真实 trusted
   function-boundary provider：分别用同一个生产 Disassembler 解码主 CFG 与本地
   callee block，再组成一个有可信范围的 Function 交给生产 Translator；没有手造
   micro-op 或 differential-only semantic 入口。

### native differential、host-arch 与控制流证据

- 新 hard-gate `vm_pop_control_native_differential` 使用真实 guest：partial
  `mov al,dl`、`test/jz`、本地 direct `call`、unconditional `jmp`、callee `add/ret`
  与 write-all `mov`，生产 Translator 实际产生五个目标语义；没有伪造隔离入口。
- 从 255 个 provider seed 对全部实际到达的 `(semantic,handlerVariant)` 动态做最大
  覆盖选择。POP 的每个 K 强制四套 form，四个控制流语义的每个 K 至少两套不同
  assignment。x64 实选 `1/3/4/25/2/7/9/21`，Win32 实选
  `1/2/4/208/3/9/10/21`；每 seed 16 个真实 CPU corpus，全部通过。
- `TestZydisPopVregInstructionFormDiversity` 解码实测 x86/x64 两个 K 都是 `4/4`
  form 与 `4/4` 不同 instruction signature；`TestZydisControlTargetRegisterDiversity`
  对每个语义实测 x86 3 套、x64 7 套 assignment，固定 K 下分别 3/7 种 decode
  signature。
- 既有 `ExecuteControlFlowBoundaryMatrix` 继续用 host-arch 真 handler 覆盖
  BRANCH_IF true/false、嵌套 CALL_VM/RET、顶层 RET 和 BRANCH；POP 继续由全宽度
  数据/栈/算术/flags/控制流矩阵覆盖 partial/writeAll、两个 K 和所有发布形式。
  VIP、callDepth、returnRva、flags materialization、fault 和 stack cleanup 断言均未
  放宽。

### 双架构验证与 per-build similarity

- Release x64 与 Win32 目标重新生成、编译通过，未新增或下载依赖。
- x64 除 similarity 外 CTest **16/16** 通过（完整旧 native differential
  98.76 秒，新专项 5.02 秒）；正式 similarity 另行完整运行 318.69 秒通过，因此
  17 个注册测试的实际底层命令均已验证。
- Win32 除正式 similarity 与旧完整 native wrapper 外 CTest **15/15** 通过；
  similarity 独立运行 380.57 秒通过。旧 `vm_native_differential` 保持既有 120 秒
  CTest 属性不变，直接运行同一二进制 137.5 秒自然完成、退出码 0，所有旧子测试
  PASS；没有把 wrapper timeout 写成通过，也没有提高 timeout。
- `vm_kernel_static_gate -V` 明确输出生产双策略覆盖 **54/54**。
- 固定种子合成代理：x86 `core_variant=0.252408`、最差 pair
  `POP_VREG K0=0.592105`；x64 `core_variant=0.324894`、最差 pair `0.447059`。

| 架构/容器 | business_core | core_variant | codec | encrypted_handlers | business/core max pair |
|---|---:|---:|---:|---:|---:|
| x64 EXE | 0.2706 | 0.1545 | 0.1436 | 0.0001 | 0.3813 / 0.4167 |
| x64 DLL | 0.2721 | 0.1208 | 0.1534 | 0.0001 | 0.3748 / 0.3902 |
| Win32 EXE | 0.2572 | 0.0989 | 0.0231 | 0.0001 | 0.4007 / 0.4865 |
| Win32 DLL | 0.2663 | 0.0873 | 0.0226 | 0.0001 | 0.4067 / 0.3947 |

四组均输出 `VM_PER_BUILD_SIMILARITY_GATE_PASS`；business/core/codec/encrypted 聚合
阈值、单 pair ceiling、corpus、skip 规则与 timeout 均未修改。

### 当前剩余语义与下一批边界

按当前生产源码，剩余 **4/54**：仍为手写 core 的 `SELECT`、`CALL_HOST`、
`BRIDGE_EXTENDED`，以及仅 x64 尚未迁移的 `UMUL_WIDE`。其中
`CALL_HOST`/`BRIDGE_EXTENDED` 按本批指示继续保留，后续必须作为 ABI/unwind/bridge
高风险独立批；x64 `UMUL_WIDE` 也不与它们混做。`SELECT` 的测试覆盖与 Encoder
迁移状态需要继续明确区分，不能仅凭 `5711a9f` 的批次描述计为已迁移。

## 推广批次 13：`SELECT`（2026-07-21）

### 范围与结论

本批只迁移 `SELECT`，不触碰 `CALL_HOST`、`BRIDGE_EXTENDED` 或 x64
`UMUL_WIDE`。原 `EmitKeyedSelectCore` 中的 `X64/X86BinaryImmediate32`、寄存器
手写 helper 与 `c.Raw` business 指令全部由 `EmitZydisSelectCore` 的正式
`ZydisEncoderRequest` 替换；两种 K 都只走 Encoder，失败继续汇入
`CodeBuffer::FailEncoding`，没有 Raw fallback 或双轨实现。累计进度由
**50/54** 增至 **51/54**，生产双策略静态覆盖保持 **54/54**。

`SELECT` 的 wrapper 仍先调用真实 flag materializer，再由既有 condition evaluator
把条件归一为 0/1，最后弹出两个候选值。迁移的 core 只消费这个布尔寄存器和两个
候选值，不读取 evaluator 留下的宿主 EFLAGS，不改 virtual/pending flags，也不改变
stack、fault、funclet 或 context 生命周期。x64 的 `0x28` flag-call stack funclet
仍由原调用 helper 在发射调用指令时同步记录；本批没有随机化栈帧指令或复制一套
独立 metadata 逻辑。

### 每架构真实活跃性契约

| 架构 | core 入口实际状态 | seed 选择的角色 | 固定保留与排除依据 |
|---|---|---|---|
| x64 | RAX=candidate A，RDX=candidate B，R10=已归一的 0/1 predicate，R15=context；RCX 的 pop-depth/index 生命周期已结束，R8/R9 未被 wrapper 使用，R11 的 value-codec 临时值已死 | candidate A/B 与 K1 mask scratch 在 `{RAX,RDX,R11,RCX,R8,R9}` 按连续三角色轮转，共 6 套；第一套固定 `{RAX,RDX,R11}` 复现旧计划 | R10 必须保持 predicate，绝不进入池；R15、RSP 和全部非易失 GPR 排除。K0 不使用 scratch，K1 使用第三角色；`MoveRegisterPair` 处理源/目标重叠后只把结果移回 RAX |
| Win32 | EAX=candidate A，EDX=candidate B，ECX=0/1 predicate，EDI=context | candidate A/B 与 K1 mask scratch 只在 `{EAX,EDX,EBX}` 轮转，共 3 套；第一套 `{EAX,EDX,EBX}` 是旧计划 | 原 K1 已在这个精确 core 生命周期使用 EBX，故只为 SELECT 增加 validator 的精确 EBX 合同；ECX 仍为 predicate，ESI 仍是 threaded ABI state，EDI 仍是 context，均不借用 |

不能复用此前的通用 fallback：其 x64 池含仍存活的 R10，会覆盖 predicate；其 x86
池只有 EAX/ECX/EDX，但 ECX 此时也存活，只剩两个可用寄存器。这里新增的是
SELECT 专属合同，而不是放宽全局 scratch pool。六套/三套计划的变化进入 MOV/XCHG、
REX 与 ModRM；key 仍是原有等价扰动，不靠新增随机立即数刷 similarity。

### 固定旧寄存器计划的代表字节

永久测试 `TestZydisSelectRegisterDiversityAndFixedPlans` 穷举 SELECT 的完整 seed byte
与四个 handler variant，分别找到两个 K 下的旧角色计划，完整解码 core 并打印
字节。代表输出如下（空格仅为阅读分组）：

| 架构/K | 迁移前手写代表形式 | Zydis 输出 | 等价性说明 |
|---|---|---|---|
| x86 K0 | `81 F0 66DE0B12 81 F2 66DE0B12 85 C9 0F 45 C2 81 F0 66DE0B12` | `35 66DE0B12 81 F2 66DE0B12 85 C9 0F 45 C2 35 66DE0B12` | 只有 `xor eax,imm32` 规范化为 accumulator short form；TEST/CMOVNZ、寄存器、key 与选择方向相同 |
| x86 K1 | `81 F0 0A222A2A 81 F2 0A222A2A 89 CB F7 DB 31 C2 21 DA 31 D0 81 F0 0A222A2A` | `35 0A222A2A 81 F2 0A222A2A 89 CB F7 DB 31 C2 21 DA 31 D0 35 0A222A2A` | 同一 XOR-keyed mask-select 恒等式；EBX 仍只承载 `-predicate` mask |
| x64 K0 | `48 81 F0 AD8C613A 48 81 F2 AD8C613A 45 85 D2 48 0F 45 C2 48 81 F0 AD8C613A` | `48 35 AD8C613A 48 81 F2 AD8C613A 45 85 D2 48 0F 45 C2 48 35 AD8C613A` | Zydis 合法选择 RAX short form；继续用 `test r10d,r10d` 和 64 位 CMOVNZ |
| x64 K1 | `48 81 F0 CB91DC11 48 81 F2 CB91DC11 4D 89 D3 49 F7 DB 48 31 C2 4C 21 DA 48 31 D0 48 81 F0 CB91DC11` | `48 35 CB91DC11 48 81 F2 CB91DC11 4D 89 D3 49 F7 DB 48 31 C2 4C 21 DA 48 31 D0 48 35 CB91DC11` | 角色与 mask 代数逐条相同，只规范化 RAX 立即数编码 |

项目没有为保留 `81 /6` 长形式插入 NOP、强制 Encoder 选码或保留手写 fallback。
非固定计划通过安全 MOV/XCHG 搬入角色，K0 使用 Zydis TEST+CMOVNZ，K1 使用
Zydis MOV+NEG+XOR/AND/XOR，结果统一移回 RAX/EAX。

### 实现中发现并消除的风险

1. 开工审计确认 `5711a9f` 只迁移了 `PUSH_CONDITION`；SELECT 当时只是作为下游
   消费者被 host 矩阵执行，生产 core 从未接入 Encoder。本批删除该统计歧义对应的
   最后一条 SELECT 手写 business 路径，不把旧测试覆盖冒充迁移完成。
2. 通用寄存器 fallback 对 SELECT 不安全：x64 会把 live predicate R10 当候选，
   Win32 则无法表达旧 core 已证明安全的局部 EBX。最终实现先从 wrapper 的真实入口
   反推专属计划，并只给 SELECT validator 增加 `reg==EBX` 的窄合同；没有允许其他
   x86 语义使用 EBX。
3. seed 轮转会产生 candidate 与固定 RAX/RDX 源重叠或交换的计划。顺序 MOV 可能
   覆盖尚未读取的源，因此复用已验证的 `MoveRegisterPair`：完整 swap 用 XCHG，
   单向依赖先捕获会被覆盖的源；其余值在 core 后已死。穷举全部计划的 decode 与
   host/native 真执行均通过。
4. 终审发现首版 native fixture 的注释错误声称 not-taken r32 CMOV 会清高半，且
   末尾 `xor eax,ecx` 的确会掩盖该高半状态。x86-64 的正确语义是 not-taken 保留
   完整目的寄存器、taken 的 r32 写才清高半。最终 x64 fixture 改用
   `xor rax,rcx`，让两种状态同时可观察；同步修正既有该专项的误导性标签后，完整
   K/assignment seed 矩阵重新通过。这是加强证据，不是放宽比较。

### native differential 与 host-arch 证据

- SELECT 有一对一生产入口：`Translator::LowerConditionalData` 将真实 `CMOVcc`
  lower 为两个 operand read、`VM_UOP_SELECT(condition)` 与 destination write。本批
  因此新增 hard-gate `vm_select_native_differential`，没有制造 differential-only
  micro-op。
- fixture 在 Win32 为
  `cmp ecx,ecx; cmovnz eax,edx; cmovz ecx,edx; xor eax,ecx; ret`，x64 将末尾
  改为 `xor rax,rcx`。ZF 固定为 1，使第一条必定 not-taken、第二条必定 taken；
  x64 的 64 位 XOR 让未取分支后完整 RAX 保留、取分支后 ECX 写入清零 RCX 高
  32 位同时进入最终可观察结果，避免后续 32 位写掩盖高半错误。
- 从 255 个实际 provider seed 动态选择并覆盖生产翻译实际到达的每个
  `(handlerVariant,K,registerAssignment)`。x64 六套计划/每 K 全覆盖，实选 seed
  `1/2/3/4/5/6/7/9/10/13/24/25`；Win32 三套计划/每 K 全覆盖，实选
  `1/2/3/6/7/9`。每 seed 16 个真实 CPU corpus，全部通过。
- `TestZydisSelectRegisterDiversityAndFixedPlans` 的真实 decode signature 结果为
  x64 `6/6` assignment、每 K `6/6` signature；Win32 `3/3`、每 K `3/3`。
- 既有 `ExecuteFlagsVariantMatrix` 继续在 host-arch 真 handler 中覆盖 O/E 条件、
  selected/not-selected、1/2/4/8 字节（Win32 到 4 字节）、两个 K，以及下游
  POP_VREG 对结果的读取。该矩阵与新增生产 translator differential 是互补证据，
  不互相冒充。

### 双架构验证与 per-build similarity

- Release x64 与 Win32 完整目标重新生成并编译通过，未新增、安装或下载依赖。
- x64 除 similarity 外 CTest **17/17** 通过，完整旧 native differential
  110.10 秒；高半证据修正后的 SELECT hard-gate 7.37 秒通过；正式 similarity
  独立运行 338.00 秒通过。
- Win32 除旧完整 native wrapper 与 similarity 外 CTest **16/16** 通过，新 SELECT
  hard-gate 修正后 4.39 秒通过；旧 `vm_native_differential` 保持既有 `TIMEOUT 120` 不变，
  直接运行同一二进制 132.2 秒自然完成、退出码 0；正式 similarity 独立运行
  401.80 秒通过。没有提高 timeout、删除 corpus 或跳过失败语义。
- `vm_kernel_static_gate -V` 明确输出生产双策略覆盖 **54/54**。
- 固定种子合成代理：x86 `core_variant=0.252309`、最差 pair 仍为既有
  `POP_VREG K0=0.592105`；x64 `core_variant=0.324421`、最差 pair `0.447059`。
  SELECT 没有成为新的最差单点。

| 架构/容器 | business_core | core_variant | codec | encrypted_handlers | business/core max pair |
|---|---:|---:|---:|---:|---:|
| x64 EXE | 0.2641 | 0.1385 | 0.1068 | 0.0001 | 0.3759 / 0.3243 |
| x64 DLL | 0.2837 | 0.1595 | 0.0933 | 0.0001 | 0.4014 / 0.4134 |
| Win32 EXE | 0.2667 | 0.1200 | 0.0452 | 0.0001 | 0.4200 / 0.4865 |
| Win32 DLL | 0.2724 | 0.1162 | 0.0231 | 0.0001 | 0.4029 / 0.4865 |

四组均输出 `VM_PER_BUILD_SIMILARITY_GATE_PASS`；聚合阈值、单 pair ceiling、
corpus、skip 规则与 timeout 全部保持原值。

### 当前剩余语义与后续风险边界

按当前生产源码，剩余 **3/54**：`CALL_HOST`、`BRIDGE_EXTENDED` 与仅 x64 尚未
迁移的 `UMUL_WIDE`。

- `CALL_HOST` 与 `BRIDGE_EXTENDED` 必须拆成两个独立高风险批。任何 per-build
  栈帧/保存寄存器变化都必须由同一发射数据结构同步生成指令与 unwind/.pdata，
  并新增在目标代码内部故意触发 Windows 异常、实际执行 stack unwind 的测试；
  正常返回不构成充分证据。借用 XMM/SIMD 时还必须逐寄存器核对调用前后状态。
- x64 `UMUL_WIDE` 另做独立硬件隐式寄存器批：RDX:RAX 的输入/高低结果是 CPU
  固定约束，只在显式乘数来源允许的范围内变化；除普通差分外必须专项验证 high/
  low half 没有颠倒。既有 0.714 单点仅作为受硬件约束的基线，不为追求普通 ALU
  数字引入危险寄存器或放宽门禁。

## 独立批次 14：x64 `UMUL_WIDE` 硬件隐式结果对（2026-07-21）

### 范围与结论

本批只迁移 x64 `VM_UOP_UMUL_WIDE`，没有触碰 `CALL_HOST` 或
`BRIDGE_EXTENDED`。原 x64 K0 的 `c.Raw({49 F7 E1})` 与 K1 的
`c.Raw({4D 89 CA 49 F7 E2})` 已由 `EmitZydisX64UmulWideCore` 的正式
`ZydisEncoderRequest` 路径替换；寄存器直接和内存 source form 都只走 Encoder，
编码失败继续 `FailEncoding`，没有 Raw fallback 或双轨实现。累计进度由
**51/54** 增至 **52/54**，生产双策略静态覆盖保持 **54/54**。

历史数字也在本批重新核对：首轮表中的 `0.714286` 是 x86
`UMUL_WIDE K=1`，不是 x64；当时 x64 全架构最差 core pair 是 `0.517241`。
因此本批不拿错误的 x86 单点当 x64 目标，而是新增 x64 per-K 独立观测，并以
当前固定种子实测值设回归上限。

### x64 真实活跃性与硬件约束

`EmitX64WideMultiply` 在进入每个 width branch 的 business core 时已经完成：

- `RAX=masked a`，同时是 CPU 焊死的隐式乘数输入和 low 输出；
- `RDX=masked b`，执行 `MUL r/m64` 后由 CPU 焊死为 high 输出；
- `R9=b`，是唯一可变化的显式 multiplier 来源；
- `R8=copy-a`；`R10` 入 core 时是 copy-b，原 b 已 pre-latch，因此旧 K1
  可把同一个 b 值直接作为显式 multiplier 使用；
- `R11=width`，完成分派后该值在 core 内已死，narrow 后段会重新加载；
- `RCX` 的 pop/index/width 生命周期均已结束，后段使用前会重写；
- `R15=context`，`RSP` 与全部非易失 GPR 始终排除。

RAX/RDX 绝不进入 seed pool。每个 K 都有四套从上述局部状态单独证明的计划：

| K | registerAssignment | 实际显式形式 |
|---|---|---|
| 0 | `{R9,R8,R10,reg}` | `mul r9`，旧 K0 计划 |
| 0 | `{RCX,R8,R10,reg}` | `mov rcx,r9; mul rcx` |
| 0 | `{R11,R8,R10,reg}` | `mov r11,r9; mul r11` |
| 0 | `{R11,R8,R10,mem}` | seed-split `lea/store; mul qword ptr [r11+disp32]` |
| 1 | `{R10,R8,R11,reg}` | `mov r10,r9; mul r10`，旧 K1 计划 |
| 1 | `{RCX,R8,R10,reg}` | `mov rcx,r9; mul rcx` |
| 1 | `{R11,R8,R10,reg}` | `mov r11,r9; mul r11` |
| 1 | `{RCX,R8,R10,mem}` | seed-split `lea/store; mul qword ptr [rcx+disp32]` |

寄存器形式的 MOV/MUL 让变化进入 REX/ModRM；内存形式进一步改变 base、disp32 与
memory operand。寄存器形式若两个 build 偶然选择同一计划，本身仍可能逐字节相同，
所以在 MOV/MUL 前保留一对作用于 R9 的同 key XOR。它们真实消费 build seed、严格
自消，不改变 multiplier；多样性不是只靠该立即数，因为四套 decode signature
仍分别不同。

Win32 本批不改生产代码。它继续使用独立批次 2/3B 已证明的 EAX/EDX 隐式 pair、
四套 per-K source plans 与专属 native differential；本批仍完整重跑 Win32，证明
共享 codegen、validator 和测试注册没有回归。

### 固定旧计划的代表字节

`TestX64ZydisUmulWidePerKSourcePlans` 穷举完整 seed byte × 全部 handler variant，
真实解码每条 core，并要求 Zydis 隐式 operand 中同时存在 RAX 与 RDX。首次命中的
固定旧计划输出如下：

| K | 迁移前 | Zydis 后完整 core | 说明 |
|---|---|---|---|
| 0 | `49 F7 E1` | `49 81 F1 B5D27431 49 81 F1 B5D27431 49 F7 E1` | 尾部 `mul r9` 逐字节相同；前置双 XOR 自消并携带 build seed |
| 1 | `4D 89 CA 49 F7 E2` | `49 81 F1 A15E4B62 49 81 F1 A15E4B62 4D 89 CA 49 F7 E2` | 尾部 `mov r10,r9; mul r10` 逐字节相同；同样只增加自消扰动 |

这里没有强制 Zydis 选非规范编码、插 NOP 或保留手写 fallback。`MUL` 最终覆盖
CF/OF；其余状态位本来就未定义，lazy-flags 只根据保存的 low/high record 生成
架构定义的 CF/OF，因此前置 XOR 不扩大可观察 flags 集合。

### 实现中发现并修复的问题

1. 旧 x64 wrapper 在 core 前执行 `R11=b`，随后 `X64DispatchWidth` 又把 R11
   覆盖为 width，最后 `X64Latch(...,R11,...)` 因而把 width 错记成
   `lastAlu.b`。普通乘积仍可能正确，只有继续观察 lazy record 时才暴露。最终沿用
   现有 binary/divide wrapper 的 split-latch 模式：分派前先清 record 并保存精确
   masked a/b，core 后只补 low/high/width/valid。这样也覆盖共享 wrapper 的
   `SMUL_WIDE` 窄宽度 sign-extension 生命周期，不依赖某个 source plan 恰好不覆盖
   保存寄存器。
2. 首版 x64 native fixture 用合法的 accumulator short form
   `48 05 00000000` 表示 `add rax,0`，但生产 translator 的该二元立即数入口
   fail-closed，不接受 short form。测试没有给 translator 加特例，而是改用同语义、
   同 64 位宽度的通用 ModRM 形式 `48 81 C0 00000000`，继续通过真实生产入口关闭
   MUL 的未定义 flags 窗口。
3. 终审发现 mixed `mul; imul` fixture 会在最终快照前用 IMUL 覆写首条 UMUL 的
   RDX high，因而不能宣称 high 在该差分中独立可观察。最终新增专属
   `mul rcx; add rax,rdx; ret` fixture，并按两个 K 的全部八套 source plan 重跑；
   RDX 保持 high，RAX 消费两半，证据不再依赖后续会覆写结果的指令。
4. 首次同时跑两架构全套 CTest 时，两个静态 gate 争用同一个
   `build_vm_micro_op_ratio_gate`，MSBuild 明确报同一 OBJ 被另一进程占用。最终将该
   共享门禁串行重跑，两架构均通过；没有把文件锁忽略为噪音，也没有改 corpus、
   timeout 或断言。

### high/low、native differential 与证据边界

- 新增具名 host-arch 真 handler 矩阵，以
  `a=0x8000000000000001, b=3` 执行两个 K。预期
  `low=0x8000000000000003`、`high=1`；UMUL 先 push low 再 push high，故第一个
  POP 必须读到 high、第二个读到 low。矩阵同时逐字段检查
  `lastAlu.a/b/result/auxiliary/width/valid`，交换 RAX/RDX 或继续错记 b 都会失败。
- `UMUL_WIDE` 有生产 translator 入口。原 mixed fixture 已升级为真正的 REX.W
  `mul/imul`；另新增专属 `48 F7 E1; 48 01 D0; C3`，即
  `mul rcx; add rax,rdx; ret`。末尾 ADD 关闭未定义 flags，保留 RDX 为独立 high
  输出，并让 RAX 同时消费 low/high；provider 比较全部 GPR，因此两半都实际可观察，
  不会再被后续 IMUL 覆盖。
- 专属 fixture 从 255 个 provider seed 动态选择 K0 `2/5/12/20`、K1
  `1/4/9/17`，覆盖实际 translator 到达的 UMUL handler variant、两个 K、每 K
  四套 assignment/source form；每 seed 32 个真实 CPU corpus 全部通过。既有
  mixed SMUL coverage 同时保留。
- Win32 generic wide fixture 继续通过，x86 专项另以 K0 seeds
  `1/4/5/22`、K1 seeds `2/3/7/19` 覆盖全部四套旧计划。它是回归证据，不冒充
  本批 x64 迁移证据。
- 本语义没有调用、ABI frame、unwind funclet、SIMD 借用或预期 fault；因此本批
  不伪造异常 unwind 证据。异常/unwind 与 SIMD 保存恢复要求留给接下来的
  `CALL_HOST`/`BRIDGE_EXTENDED` 独立批。

### 双架构验证与 per-build similarity

- Release x64/Win32 目标重新编译通过；没有新增、安装或下载依赖。
- x64 除 similarity 外串行 CTest **17/17** 通过；补齐专属 high/low fixture 后，
  当前完整 `test_vm_native_differential.exe` 直接运行 109.0 秒、退出码 0；正式
  similarity 310.41 秒通过。
- Win32 除既有完整 native CTest wrapper 与 similarity 外 **16/16** 通过；同一
  `test_vm_native_differential.exe` 直接运行 134.1 秒自然完成、退出码 0；正式
  similarity 373.96 秒通过。保持既有 CTest `TIMEOUT 120`，没有提高 timeout。
- `vm_kernel_static_gate` 在两架构构建树串行通过，并明确保持生产双策略
  **54/54**。
- 固定种子合成中 x64 `core_variant=0.323927`，全局最差 pair `0.447059`；新增
  x64 UMUL K0/K1 独立 pair 均为 `0.000000`，固化 `<0.10` 的专属 deterministic
  上限。x86 `core_variant=0.252309`，既有最差 pair `0.592105` 未变。

| 架构/容器 | business_core | core_variant | codec | encrypted_handlers | business/core max pair |
|---|---:|---:|---:|---:|---:|
| x64 EXE | 0.2666 | 0.1445 | 0.1163 | 0.0001 | 0.3677 / 0.4091 |
| x64 DLL | 0.2757 | 0.1498 | 0.1400 | 0.0001 | 0.3883 / 0.3866 |
| Win32 EXE | 0.2649 | 0.1116 | 0.0237 | 0.0001 | 0.4093 / 0.4483 |
| Win32 DLL | 0.2691 | 0.1011 | 0.0000 | 0.0001 | 0.4053 / 0.2987 |

四组均输出 `VM_PER_BUILD_SIMILARITY_GATE_PASS`；聚合阈值、单 pair ceiling、
corpus、skip 规则与 CTest timeout 全部保持原值。

### 当前剩余语义与下一批边界

按当前生产源码，剩余 **2/54**：`CALL_HOST` 与 `BRIDGE_EXTENDED`。二者必须继续
拆成两个独立高风险批；先完成并稳定 `CALL_HOST`，再开始 `BRIDGE_EXTENDED`。
任何随机 frame/register 计划必须由同一份数据同时驱动指令与 unwind/.pdata，且
必须真实执行“目标代码内部故意抛异常”的 Windows unwind 测试，并对所有临时借用的
XMM/SIMD 状态做调用前后逐字节一致性检查。正常返回结果正确仍不是充分证据。

## 独立批次 15：`CALL_HOST` 异常展开与 SafeSEH/PE 元数据闭环（2026-07-21）

### 起点与审计方法

本批的起点不是空白页：上一轮会话（另一 AI 工具，`2daecc5` "做了一半callhost"）
已经把 CALL_HOST 的 x64/Win32 target resolver 迁移到 Zydis Encoder、抽出共享
typed frame plan、加入 x64 `UNW_FLAG_UHANDLER`/phase 状态机骨架和 Win32 显式
`FS:[0]` registration 骨架，但没有验证 unwind 元数据是否真的与生产 prolog 同源、
没有把 x64 handler RVA 或 Win32 SafeSEH handler 列表接入最终 PE 构建路径、也
没有任何真实执行测试。按指示先逐条核对共享 frame plan、真实
prolog/epilog、spill offset、栈对齐、8 个异常窗口的 phase/armed 状态转换，
不采信提交注释里的"已完成"说法。

逐条核对后，x64/Win32 的 frame plan、SUB/ADD 栈分配与 phase 初始化时机（先建帧、
再清零 phase、再武装 phase、host 状态完整保存后才置 armed、host 状态恢复后立即
清零 phase）在结构上是正确的；Win32 的 CFG guard-check 已经被移到 guest
SIMD/x87 restore 之前（探测到旧顺序会把 guard-check 污染的浮点状态暴露给
native target，本批之前已被修正）。审计发现两处需要修复的真实缺陷（见下）和
三处必须补齐才能称为"闭环"的缺口：x64 handler RVA 从未从 image-offset 转换成
最终 PE RVA；Win32 `safeSehHandlerOffsets` 从未被消费；完全没有执行证据。

### 修复的两个真实正确性缺陷

1. **x64 UHANDLER 未强制置位 `CONTEXT_FLOATING_POINT`。**
   `GenerateVMHandlerX64CallHostUnwindHandler` 恢复 host FXSAVE/XSAVE 镜像后，
   只用 `AND ContextFlags, ~CONTEXT_XSTATE` 清掉 XSTATE 位，没有同时
   `OR ContextFlags, CONTEXT_FLOATING_POINT`。如果后续 `RtlRestoreContext`
   看到的 dispatcher CONTEXT 恰好没有携带 `CONTEXT_FLOATING_POINT`
   （理论上罕见，但不能假设一定不会发生），已经写入 `CONTEXT.FltSave` 的
   host 镜像就可能不会被真正采用。修复为清 XSTATE 的同时强制置位
   FLOATING_POINT，确保 FltSave 覆盖一定生效，不依赖原始 CONTEXT 的偶然状态。
2. **XRSTOR 使用了错误的 Zydis 操作数宽度。** 新增的 UHANDLER thunk 对
   `FXRSTOR`/`XRSTOR` 都传了 512 字节内存操作数，Zydis Encoder 对
   `XRSTOR` 返回 `ZYDIS_STATUS_IMPOSSIBLE_INSTRUCTION`（试执行时才暴露，静态
   审计看不出来）。用独立探针程序对 `xrstor [r10]` 做
   Decoder→`ZydisEncoderDecodedInstructionToEncoderRequest`→重编码往返，
   证实 Zydis 对 `XRSTOR` 声明的操作数宽度是 576 字节（512 legacy 区 + 64
   字节恒定存在的 XSAVE header），而不是 512；`FXRSTOR`（无 XSAVE header）
   仍是 512，验证不变。这不是位运算错误，是对 Encoder 操作数语义定义的
   误用，与既有方法论一致：Encoder 缩小的是编码风险，不能替代对每条指令
   真实语义的验证。

### x64：handler RVA 最终接入 PE 构建路径

`VMHandlerSynthesisResult` 新增 `callHostUnwindHandlerOffset`（cleanup thunk
在 synthesized image 内的 offset）与 `imageRvaPatchOffsets`（xdata 内嵌入
handler RVA 待修正的位置，此前只保存 offset）。`vm_runtime_builder.cpp` 在
`runtime.bytes` 拷入 `blob`、`AppendSection` 已知最终 `appended.rva`
之后、`PatchBytes` 最终提交 `blob` 之前，把该 dword 从 offset 一次性改写成
`appended.rva + offset`，确保 `expectedSectionBytes`（完整性校验用的镜像）
与真正写入 PE 的字节一致，不存在"改了一次以外又被覆盖"的风险。

### Win32：SafeSEH 表真正合并到最终 PE

新增 `PEEmitter::RebuildSafeSEHHandlerTable`，直接照抄已验证过的
`RebuildGuardCFFunctionTable` 模式（先证明 LoadConfig 两个字段可 patch，
再 `AppendSection` 提交合并后的表，最后 `PatchBytes` 回填字段，任何一步
失败都不会遗留半成品 image）：

- 原 PE 完全没有声明 SafeSEH（`SEHandlerTable/Count` 为零）→ 直接返回成功、
  不触碰 LoadConfig，绝不伪造一份新契约（伪造会让 SafeSEH 强制校验覆盖到
  原本从未被枚举过的既有 handler，reject 掉它们）。
- 原 PE 声明 `IMAGE_DLLCHARACTERISTICS_NO_SEH` → fail-closed，返回带具体原因
  的错误。这个标志会让 `RtlIsValidHandler` 无条件拒绝该模块内的任何 handler，
  与 SafeSEH 表是否合并无关，此时安装新 handler 必然产物必崩，没有安全的
  合并方式。`capability_checker.cpp` 同时在构建前预检：x86 + VM 功能开启 +
  目标声明 NO_SEH 时直接拒绝整个构建，而不是等打包完成后才在运行时炸掉。
- 原 PE 有合法 SafeSEH 表 → 用 `std::map<uint32_t,...>` 按 RVA 排序去重合并
  旧表与新 handler RVA，校验每个新增 RVA 都落在可执行 file-backed 范围内，
  提交后同步更新 `m_image->loadConfig` 的内存态。
- x64 image 上调用直接返回失败（x64 从不应产生 Win32 SafeSEH 数据）。

新的 `safeSehSectionName` 参数从 `ProtectionBuildContext`→`VMGroupRuntime`
→`VMRuntimeBuilder::Build`→ 上述合并调用整条链路穿通；`VMRuntimeBuildResult`
新增 `callHostUnwindHandlerRVA`/`safeSehHandlerRVAs`/`safeSehMerged` 记录最终
结果供上层校验。`VMHandlerSynthesizer::Validate` 同时补齐了此前完全没有的
x86 一致性校验：`safeSehHandlerOffsets` 必须恰好等于所有
`hasCallHostSehHandler` 的 handler 集合、严格升序无重复，且每个 offset 真的
指向其 **`handler.plaintextBody`**（未加密源）里的 ENDBR32——`Validate()` 在
`Synthesize()` 内部于 `EncryptHandlerRegion` 之后运行，此时 `result.image`
已是密文，误对着密文校验特征字节是本批实现过程中真实踩到的一个坑。

### 真实执行证据

按要求新增四类证据（第五类 PE 元数据证据见下一节），全部在
`tests/test_vm_handler_synthesis.cpp` 的 host-arch 直接执行门禁里新增，
`TestHostContextEntryExecution` 依次调用：

1. **CALL_HOST resolver 穷举**（`TestZydisCallHostResolverRegisterDiversity`）：
   完整 seed byte × 全部 handler variant，x64 实测穷举到全部 7 套、Win32 全部
   3 套寄存器计划，每套都通过 Zydis 完整 decode 验证 target/imageBase/callKind
   三个角色确实出现在 core 里、resolver 结尾确实把结果归一回 RAX/EAX、两个
   `coreStrategy`（ADD 与 LEA 归一化形式）都被覆盖到，并复现历史遗留的
   RAX/RDX/RCX 固定计划字节。
2. **host/guest x87/MXCSR/XMM 状态证据**（`ExecuteCallHostExtendedStateCases`，
   x64 与 Win32 均通过）：调用前给 guest 显式扩展状态与 native target 内部
   写入的"target 修改后"状态各设一套互不相同、合法（不触发 LDMXCSR/FLDCW
   保留位故障）的 FCW/MXCSR/XMM0 图案，断言 (1) native target 入口真实观察到
   guest 图案而非其他状态、(2) target 修改后的图案被正确写回
   `context.extendedState`、(3) 宿主线程自身的环境不受 target 内部状态影响
   （见下方"测试方法论教训"，这一步没有对着一个固定外部图案比较，而是用
   同一调用路径分别跑"不碰 FP 的既有 target"和"会脏写 FP 的新 target"两次，
   比较两次调用后宿主环境是否一致）。
3. **真实 Windows 异常展开证据**（`ExecuteCallHostRealExceptionCases`，
   目前仅 x64，见下方"已知缺口"）：native target 内部脏写 FP/SIMD 状态后
   对空指针做真实写入触发硬件 `EXCEPTION_ACCESS_VIOLATION`（不是软件模拟
   调用清理函数），依赖真实 Windows 异常分发器沿 `.pdata`/`UNW_FLAG_UHANDLER`
   完成第二阶段展开，外层 `__try/__except` 接住后验证：宿主环境的
   FCW/MXCSR/XMM0 与"同一调用路径、target 不脏写也不异常"的基线完全一致
   （证明 UHANDLER 真的被系统展开器调用且没有把 guest/target 状态通过异常
   CONTEXT 泄漏回宿主）、异常码与 runtime 错误码精确匹配预期、且展开后同一
   线程可以立即再成功执行一次普通 CALL_HOST（栈指针/非易失寄存器/展开链
   未被破坏的间接证据）。
4. **PE 元数据证据**（`tests/test_pe_hardening.cpp` 新增 5 个
   `TestSafeSEHTableMerge*` 用例，x64/Win32 均通过；见下一节）。

### 测试方法论教训（本批过程中真实踩到、且有实际纠正的坑）

- **不能对 512 字节 FXSAVE 快照做 `= {}` 零初始化再立即 FXSAVE。** 优化器可能
  用 `pxor xmmN,xmmN`/向量化 store 实现这个零初始化，且不保证在 `_fxsave`
  intrinsic 之前完成——如果它被排到 `_fxrstor` 设置真实 XMM0 之后、
  下一次 `_fxsave` 观测之前执行，会静默清空正在被观测的寄存器。所有参与
  FXSAVE/FXRSTOR 往返的栈上 512 字节缓冲区改为不初始化（反正会被
  FXSAVE 或等大小 `memcpy` 完整覆盖），并把"设置环境状态→调用→观测环境
  状态"收进独立的 `__declspec(noinline)` 小函数，减少编译器在中间插入
  无关向量化指令的空间。
- **"host 环境"不能通过在调用 VM 入口前用 `_fxrstor` 设成一个externally
  imposed 的固定图案来验证。** 这个 VM 自己的 context-entry 分发代码在
  到达 CALL_HOST 之前就会把 XMM0-3 当作内部 scratch/cache 使用（真实存在于
  `vm_handler_entry_codegen.cpp` 的 `MOVDQU` 批量寄存器搬运），意味着"调用
  `entry()` 前的环境"和"CALL_HOST 自己保存 host 时看到的环境"根本不是同一
  回事，对着一个外部强加的固定值断言必然假失败。改为差分验证：固定
  GPR/栈/字节码形状，只切换 native target（不碰 FP 的既有 target vs
  会脏写 FP 的新 target），比较两次调用后的宿主环境是否一致——不需要知道
  也不需要控制这个环境具体是什么值。
- **x86 cdecl 的参数必须写进 guest 栈镜像，不是 GPR。** 早期版本沿用 x64 的
  `gprs[1] = argument` 给 Win32 cdecl target 传参，实际上 CALL_HOST 的
  cdecl 路径从 `[guest ESP]` 拷贝 `stackArgumentBytes`，`gprs[1]`
  对 cdecl 完全不起作用；结果是"安全地址"参数从未真正传给 target，
  target 用零地址写入直接崩溃，且崩溃发生在整个测试进程里、不在任何
  `__except` 保护范围内。
- **对 512 字节 FXSAVE 镜像做整体 `memcmp` 不安全。** 编译器可能把
  XMM6-15 当作与本测试无关的暂存空间使用，整体比较会把这类无关差异
  误判为失败。改为只解码/比较 FCW（偏移 0）、MXCSR（偏移 24）、
  XMM0（偏移 160-175）——这些是本测试真正设置和控制的字段。

### 已知缺口（未闭环，明确不隐瞒）

- **Win32 真实异常展开证据未实现。** 现有的 `LoadedSynthImage` 是把
  synthesized image `VirtualAlloc` 成裸内存直接在当前进程执行；x64 能这样
  测是因为它额外调用了 `RtlAddFunctionTable` 把这段内存的动态 unwind 信息
  登记给系统，这是文档化的"信任非模块内存里的 unwind info"的正规逃生舱口。
  x86 没有等价 API：`RtlIsValidHandler` 会无条件拒绝不属于任何已加载模块的
  frame-based SEH handler（DEP 时代针对堆喷伪造异常处理链的缓解措施），
  与内存是否可执行无关。这一点是本批**真实运行**验证出来的：把同一测试路由
  到 Win32 的 `LoadedSynthImage` 会在触及 CALL_HOST 自己的 `FS:[0]` handler
  之前，就在"基线"（不触发异常）分支里因未真正传参而崩溃；即便修好传参，
  故障分支仍会在 CALL_HOST 自己的 handler 被考虑之前，被系统判定 handler
  非法而进程终止（`STATUS_ACCESS_VIOLATION` 未捕获退出）——这不是
  `EmitX86CallHostSehRegistration` 的缺陷，是这个进程内测试手段本身对 Win32
  不成立。真正的 Win32 真实异常展开证据需要 handler 活在一个真正被
  Windows loader 加载的 PE 模块里，也就是必须走"打包成真实 EXE/DLL 并作为
  独立进程运行"的路径，本批时间没有覆盖，留给后续批次。
- **x64 PE 元数据证据止于字节级校验，没有独立解析 `.pdata`/`.xdata`。**
  `test_vm_runtime_integrity.cpp` 现有的 `VerifyRuntimeContents` 在
  `PEParser::LoadFromBuffer` 独立重新解析后逐字节比较整个 runtime section
  （含新的 UHANDLER thunk 与已修正的 handler RVA），这确实证明了"最终字节
  与构建期承诺的字节一致"，但没有额外用 `RtlLookupFunctionEntry` 风格、独立
  于 `PEParser` 自身 Exception Directory 解析代码之外的第二条路径去走一遍
  `RUNTIME_FUNCTION`→`UNWIND_INFO`→handler RVA，也没有覆盖 EXE 和 DLL 两种
  容器分别独立验证。Win32 SafeSEH 侧的合并证据更完整：`test_pe_hardening.cpp`
  新增的 5 个用例覆盖合并排序去重、去重已存在 RVA、无原表时 no-op、
  `NO_SEH` fail-closed、x64 image 拒绝，且合并结果通过独立重新解析验证。
- 未验证 XSAVE/AVX（`extendedState.flags != 0`）路径；本批全部新证据都在
  `flags = 0` 的 FXSAVE/FXRSTOR 路径下取得，覆盖 FXSAVE 但未覆盖 XSAVE，
  也没有做真实 CPUID/XCR0 门控的 skip 逻辑。
- `BRIDGE_EXTENDED` 完全未动，仍是唯一剩余语义。

只有把上面这些缺口也补齐，才能说 CALL_HOST 完整闭环；本批完成的是"审计
+两个真实缺陷修复+x64 异常展开闭环（含真实硬件异常证据）+Win32 SafeSEH
合并真正接入最终 PE+resolver 穷举证据+Win32 host/guest FP 状态证据"，
不是"CALL_HOST 100% 完成"。

### 关于"迁移进度 X/54"这个说法的核实

任务交接时提到"从 52/54 更新为 53/54"，本批没有直接采信这个数字。实测运行
`tests/scripts/vm_kernel_static_gate.py --source-root .`，输出的是
"真实双策略覆盖 54/54"——这是该脚本一直在测的指标（每个语义的两套业务
K 策略是否真的产生不同机器码），与"业务核心是否已经不再包含任何手写
`c.Raw` 字节"是两回事；从 2026-07-19 批次 1 起这个覆盖数字就一直是
54/54，与"迁移进度 X/54"是同一份历史记录里并列但独立的两个数字，脚本
本身不产生后者。就 CALL_HOST 而言，本批只把 target resolver（进入 native-call
frame 之前的部分）和新增的异常清理 thunk 迁到 Zydis Encoder；frame 建立、
spill/restore、FXSAVE/XSAVE 本身、`FF 94 24 ...` 间接调用这些指令仍是手写
字节，沿用既有方法论对"unwind-critical 区域保留精确控制字节"的一贯做法，
没有也不需要为了凑一个迁移计数而改动它们。因此本批不给出一个单一的
"X/54"数字；准确的说法是：CALL_HOST 的 resolver 与本批新增的异常/PE
基础设施已经是 Zydis-only 且无 Raw fallback，CALL_HOST 的 frame 编排代码
维持手写不变，`BRIDGE_EXTENDED` 是唯一完全未触碰的语义。

### 完整回归结果（本机实测，2026-07-21）

x64 与 Win32 均为 Release、`/W4 /WX` 全量重新构建（复用 `build_resume_x64`/
`build_resume_win32`），无警告无错误。

**静态门禁**：`vm_kernel_static_gate.py --source-root .` 输出
`[PASS] 微观 VM 静态门禁通过`，真实双策略覆盖 `54/54`（含比例探针，需要
`cmake` 在 PATH 上才能构建真实 Disassembler/Translator 采样，本机通过显式
加入 VS2022 自带 CMake 路径满足）。

**CTest**（`ctest --test-dir <dir> -C Release --output-on-failure --timeout 900`，
未修改任何既有 TIMEOUT/阈值/corpus/skip 规则）：

| 架构 | ctest 直接结果 | 说明 |
|---|---|---|
| x64 | 17/18 通过，`vm_native_differential` 因既有 `TIMEOUT 120` 属性被判超时 | 与历史批次相同的已知限制：该测试自身完整运行需要 100+ 秒，超过 wrapper 的 120 秒 |
| Win32 | 17/18 通过，同一测试同样因 `TIMEOUT 120` 被判超时 | 同上 |

按既有约定直接运行完整二进制取自然退出结果（未提高 timeout，未跳过任何
case）：

- x64 `test_vm_native_differential.exe` 直接运行 164.7 秒，退出码 0。
- Win32 `test_vm_native_differential.exe` 直接运行 204.6 秒，退出码 0。

即两个架构的完整 18 个 CTest 用例（含此前被 wrapper 超时掩盖的一个）全部
真实通过，没有一个用例被跳过或弱化断言。

**正式 `vm_per_build_similarity_gate`**（独立 verbose 重跑单个用例以取得
逐 stage 数值；阈值/ceiling 均为脚本既有默认值，未修改）：

| 架构/容器 | business_core | core_variant | codec | encrypted_handlers |
|---|---:|---:|---:|---:|
| x64 EXE | 0.2656 | 0.1362 | 0.1498 | 0.0001 |
| x64 DLL | 0.2803 | 0.1571 | 0.1473 | 0.0001 |
| Win32 EXE | 0.2597 | 0.1173 | 0.0636 | 0.0001 |
| Win32 DLL | 0.2720 | 0.1120 | 0.0226 | 0.0001 |

四组均输出 `VM_PER_BUILD_SIMILARITY_GATE_PASS`；x64 耗时 445.37 秒，Win32
耗时 555.57 秒，均在脚本自身 900 秒 CTest 属性内（该属性本批同样未修改）。

**本批新增测试覆盖的用例**：`vm_handler_synthesis`（新增 CALL_HOST resolver
穷举、host/guest FP/SIMD 状态证据、真实异常展开证据三个阶段，见上文）与
`pe_hardening_regression`（新增 5 个 `TestSafeSEHTableMerge*` 用例）均包含在
上述 x64/Win32 各 17/18 通过范围内，两个架构都是真实通过，不是编译通过。

## 独立批次 16：`BRIDGE_EXTENDED`（2026-07-22）

### 起点与审计方法

按指示先不采信任务交接里对 `BRIDGE_EXTENDED` 现状的总结，独立重新审计生产
源码。`BRIDGE_EXTENDED` 实际由三条互相独立的代码路径组成，审计前先把它们
的调用关系和数据契约理清楚：

1. `packer/transforms/vm_handler_semantic_codegen.cpp` 的
   `EmitX64BridgeExtended`/`EmitX86BridgeExtended`：在 VM handler 内部把全部
   16（x64）/8（x86）个 GPR family 从 `CtxVregs`（经 `CtxRegisterMap` 间接
   寻址）搬进栈上的 `VM_INSTRUCTION_BRIDGE_STATE`，通过状态结构体里的
   `target` 指针做一次间接调用，再把结构体内可能被修改过的 GPR 搬回
   `CtxVregs`。这是唯一属于"handler 语义生成"、可与其他已迁移批次的方式论
   直接对比的部分。
2. `EmitBusinessCoreVariant` 内部 `case VM_UOP_BRIDGE_EXTENDED`：负责计算
   `target = imageBase + decodedOperand`（原生调用目标的绝对地址），并承担
   `54/54` 静态门禁要求的"双 K 策略产生不同机器码"证据。这一小段在概念上属于
   `BRIDGE_EXTENDED`，但审计后发现它与第 1 点在物理布局上不是同一件事——见
   下文"发现的问题"。
3. `packer/transforms/vm_instruction_bridge_builder.cpp` 的
   `VMInstructionBridgeBuilder::Build`：在打包期（不是 handler 运行期）把从
   宿主程序里真实抽取出来的原生指令字节（`VMInstructionBridgeLink` 的
   `nativeInstructionRVA`/`nativeInstructionSize`）拼进合成 PE 的独立
   section，为每条抽取指令生成一个 thunk（保存/恢复全部 GPR、RFLAGS、
   x87/SSE/AVX 扩展状态），并据此重建 `.pdata`（x64）与 Guard CF 函数表。这条
   路径与第 1 点完全独立：第 1 点只负责"把状态摆好、间接调用某个地址"，至于
   那个地址处到底是什么代码、那段代码的 prolog/epilog 怎么保存宿主寄存器，
   全部由这条路径在打包期一次性生成，运行期不再变化。

`translator.cpp::LowerExtendedBridge` 是这一切的根本原因：只有当一条指令
用到 x87/SSE/AVX、不读写任何 EFLAGS、不是分支/调用/返回、且能找到一个不与
该指令自身操作数冲突的"隐藏寄存器"时，才会被提取为 `BRIDGE_EXTENDED`
桥接，而不是被逐语义虚拟化——这是因为 VM 本身不虚拟化浮点/SIMD 寄存器状态。
`hiddenNativeRegister` 由源指令实际用到的操作数决定，是纯粹的正确性约束，
不是可以按 seed 变化的风格选择；`micro_semantics.cpp` 的软件参考执行器对
`BRIDGE_EXTENDED`（同 `CALL_HOST`/`RDTSC`/`CPUID`）直接 fail-closed，因为它
无法在纯 C++ 状态机里模拟"调用外部原生代码"这件事。这两部分审计后确认无需
改动，也不属于本批风险范围。

现有真实测试：`tests/test_vm_handler_synthesis.cpp` 的
`ExecuteExternalSemanticVariantCases`（"BRIDGE_EXTENDED/INT3 外部效果双策略
差分"阶段）已经用一个真实 x64 静态函数 `GateInstructionBridgeTarget`（对
`gpr[0]` 做 XOR、对 `gpr[15]` 做 ADD）当"hidden-register 调用目标"，端到端
执行第 1 点描述的整段 GPR 搬运/间接调用/搬回逻辑，覆盖两个 K 策略。审计确认
这条测试**只覆盖第 1 点**，从未触达第 3 点的 `VMInstructionBridgeBuilder`——
全仓库搜索 `VMInstructionBridgeBuilder`/`BuildX64Thunk`/`BuildX86Thunk` 除定义
处外没有任何测试引用，这一点在下文"发现的问题"和"已知缺口"两节都有直接后果。

### 发现的问题

**问题一（设计权衡，不是缺陷）：`BRIDGE_EXTENDED` 的寄存器角色在第 1/2 点
之间无法用同一个自然 seed 轮转同时复现两套遗留固定字节。** 第 2 点
（target 解析）遗留的固定寄存器是 `value=RAX/EAX, source=RDX/EDX`；第 1 点
（GPR 搬运循环）遗留的固定寄存器是 `value=RAX/EAX,
index(family 查表目标)=RCX/ECX, base(CtxRegisterMap 指针)=R11/EDX`。两者共享
`registerAssignment[1]` 这一个槽位，但对它的遗留期望不同（`RDX` vs
`RCX`/`ECX`），且 `EmitZydisControlTargetCore`（见下文）内部硬编码读取
`registerAssignment[0]`/`[1]`，调用方无法把它重定向到别的槽位。详细推导见
`DeriveVariantRegisters` 内新增分支的注释；解决方式是显式的角色 plan
表（而不是通用 `RotateRegisterContract` 循环轮转），第一个 plan 复现第 1 点
的遗留字节，第二个 plan 复现第 2 点的遗留字节，其余 plan 提供新的真实寄存器
多样性。这不是本批引入的缺陷，而是两段代码在 `BRIDGE_EXTENDED` 迁移之前就
已经共享同一组 4 元素 `registerAssignment` 槽位这一既有事实的自然推论。

**问题二（本批发现并修复的真实生产缺陷）：`VMInstructionBridgeBuilder::Build`
对空 blob 的 `AlignUp` 结果存在错误的 0 值哨兵冲突，导致该函数对任何包含至少
一条 `BRIDGE_EXTENDED` 请求的输入都必然失败。** 审计第 3 点时逐行核对
`Build()` 的字节布局逻辑：

```cpp
uint32_t AlignUp(uint32_t value, uint32_t alignment) {
    if (!alignment || value > std::numeric_limits<uint32_t>::max() - (alignment - 1u)) return 0;
    return (value + alignment - 1u) & ~(alignment - 1u);
}
...
const uint32_t aligned = AlignUp(static_cast<uint32_t>(blob.size()), 16u);
if (aligned == 0) {
    result.error = "VM_BRIDGE: thunk layout overflow";
    return result;
}
```

`blob` 在处理第一条桥接请求时必然为空（`blob.size() == 0`），而
`AlignUp(0, 16)` 沿着**正常、非溢出**路径计算出 `(0 + 15) & ~15 == 0`——这个
`0` 是"已经对齐到偏移 0"的合法结果，但调用方的 `if (aligned == 0)`
把它和 `AlignUp` 自己用来表示"溢出"的错误哨兵值（同样是 `0`）混为一谈。
结果是 `Build()` 处理任何程序的第一条（也是通常唯一需要处理的）
`BRIDGE_EXTENDED` 请求时都会立即以 `"VM_BRIDGE: thunk layout overflow"`
失败返回——也就是说，只要一个真实程序里出现任何需要抽取的 x87/SSE/AVX
指令，整条生产链路就会在打包期失败。这条真实缺陷此前完全没有被任何测试
捕获到，直接原因就是上一节确认的"没有测试触达 `VMInstructionBridgeBuilder`"。
本批新增的 x87 单元测试（见"真实执行证据"）在实现过程中先真实复现了这个
失败（`result.error == "VM_BRIDGE: thunk layout overflow"`），排除了是我自己
测试代码的错误后，才确认这是生产代码本身的问题。

修复方式：把 `AlignUp` 的错误哨兵从 `0`（与合法结果可能重合）改为
`UINT32_MAX`（现实中的 blob 大小远低于 4 GiB，不会真的对齐到这个值），并
同步更新两处调用点的判断条件。不引入任何新的手写字节路径，也不改变
`AlignUp` 在非溢出输入下的计算结果——所有原本能正确工作的对齐计算（即
`blob` 非空时的调用）字节结果完全不变，只有原本被误判为溢出的"合法零对齐"
情形被修正。

审计同时确认了两件相关但本批不处理的事：`vm_runtime_builder.cpp`（属于
`CALL_HOST`/`vm_runtime_builder` 自己的独立文件）里有一个同名但实现不同的
`AlignUp`——它没有溢出检测分支，也没有"用 0 表示错误"的调用方约定，因此
不存在同一类哨兵冲突缺陷（存在的是理论上更弱的"极大 blob 时静默环绕"风险，
现实中不可达，按指示不在本批处理，只记录在这里以免被误认为遗漏）。

### 迁移范围与理由

参照 `CALL_HOST` 批次的分寸，对第 1/2/3 点分别独立评估：

**第 1 点（GPR 搬运循环）—— 迁移，含真实寄存器多样性。** 审计确认循环体
每次迭代使用三个临时寄存器：`base`（`CtxRegisterMap` 指针，整个循环期间存活）、
`index`（读出的 family 映射结果，当次迭代内存活）、`value`（被搬运的
GPR 值本身）。这三个角色都不是被结构体布局或 ABI 写死的常量——它们只是
"某个安全的临时寄存器"，此前固定为 `R11`/`RCX`/`RAX`（x64）和
`EDX`/`ECX`/`EAX`（x86）纯粹是历史实现选择，不是必然性约束，因此确实存在
安全的可变余地：
- 逐 family 读取 `CtxRegisterMap[family]` 的 `MOVZX` 指令原本手写
  REX/ModRM（`c.Raw({0x41,0x0F,0xB6,0x4B,family})` 等），现改由
  `EmitZydisLoad` 生成，寄存器改为读取 `registerAssignment[1]`（index）与
  `[2]`（base）。
- 载入 `CtxRegisterMap` 指针本身、判空 `TEST`、以及把搬运值写入/读出栈上
  `VM_INSTRUCTION_BRIDGE_STATE.gpr[]`——这些沿用已有的、被其他多个批次
  证明安全的参数化 helper（`X64LoadQ`/`X64LoadIndexedQ`/`X64StoreStackQ`
  等，x86 侧改用已存在的 `X86LoadIndexedDVariant`/`X86StoreIndexedDVariant`
  替代原本硬编码 `ECX` 索引的 `X86LoadIndexedD`/`X86StoreIndexedD`），只改变
  传入的寄存器编号，不修改这些 helper 自身的实现——它们本来就已经支持任意
  寄存器参数，不需要新写 Zydis 请求。
- x86 侧原本用于把 `state.gpr[family]` 高 32 位清零的立即数写入
  （栈相对的一处、`CtxVregs` 相对索引寻址的另一处）原样保留栈相对的那一处
  （纯 disp、不涉及任何寄存器选择，没有变化空间），把索引寻址的那一处改为
  `ZydisEncoderRequest` 生成（因为它的 SIB 索引寄存器必须随 `index` 角色
  变化，不能再硬编码 `ECX`）。

**不迁移的部分及具体理由：**
- `SUB RSP, allocation` / `ADD RSP, allocation`（x64 prolog/epilog）：
  `tests/scripts/vm_kernel_static_gate.py` 与
  `ValidateVMHandlerSemanticVariantKernel` 都对这两条指令的**逐字节内容**有
  硬编码断言（`kX64BridgeUnwindInfo`/`kX64BridgeStackSize` 与验证器里的
  `48,81,EC,98,04,00,00`/`48,81,C4,98,04,00,00` 字面量），这是因为
  `RecordX64StackFunclet` 记录的 `prologSize=7` 直接进入最终 PE 的
  `UNWIND_INFO`（`UWOP_ALLOC_LARGE`），必须与真实字节长度完全一致才能让
  Windows 异常展开正确识别"已分配 0x498 字节栈"这件事。`allocation` 是编译期
  常量（`sizeof(VM_INSTRUCTION_BRIDGE_STATE)` 相关，当前恒为 `0x498`，
  静态断言保证它不会缩小到能装进 imm8 的范围），因此这条指令本来就不存在
  "Zydis 会不会选一个更短的等价编码"的实际风险——但正因为静态门禁已经把
  它的具体字节焊死做了正向验证，迁移它不会带来任何可观测收益，只会新增一条
  "以后如果这个假设改变就会静默产生不匹配 unwind 信息"的隐藏依赖，因此保持
  手写。RSP 本身也没有任何寄存器选择空间——Win64 栈分配约定就是 RSP，不存在
  seed 可变的余地。
- `mov eax, 0x00000202` 及其后紧邻的 `state.rflags` 写入：这是
  `arithmetic_flags_bridge_closure_gate` 静态门禁的正向证据锚点，要求
  `EmitX64BridgeExtended`/`EmitX86BridgeExtended` 源码里逐字节出现
  `c.Raw({0xB8,0x02,0x02,0x00,0x00})` 紧跟一次把寄存器 `0` 存入
  `rflags` 字段的调用——这是在证明桥接线程看到的初始 RFLAGS
  是一个编译期固定的架构常量（仅保留 reserved bit 1 与 IF），而不是从 VM
  自己的算术/lazy-flags 状态派生，从而保证 VM 算术标志位不会泄漏进被桥接的
  原生指令。这个值本身没有 seed 变化的意义（变成别的常量就不再是"架构默认
  RFLAGS"），寄存器也不需要变化（`0` 只是搬运这个常量到栈的暂存位置，
  紧接着就会被后续代码覆盖）；如果迁移成 Zydis 生成，这个正向锚点的具体
  源码文本会不再匹配，而变更检测脚本本身不应该为了迎合我这批的重构而被
  放宽。因此原样保留，只在两处加了注释说明原因，避免以后的人以为它是
  疏漏。
- `target`/`guardTarget`/`extendedState`/`extendedStateFlags`/`hiddenRegister`
  这几个字段的存取：均已经是 `X64LoadQ`/`X64StoreStackQ`/`X64StoreStackD`
  等参数化 helper 调用，本来就不涉及手写 REX/ModRM 位运算，且这些字段之间
  没有相互独立的"角色"概念可言（不像 GPR 搬运循环那样是同一逻辑反复
  16/8 次），维持原样。

**第 2 点（target 解析）—— 复用已迁移的 `EmitZydisControlTargetCore`，不
新写代码。** 审计 `EmitBusinessCoreVariant` 发现：`BRANCH`/`BRANCH_IF`/
`CALL_VM`/`RET`/`CALL_HOST` 全部已经在更早的批次迁移到各自的 Zydis 核心
（`EmitZydisControlTargetCore`/`EmitZydisCallTargetCore`），只有
`BRIDGE_EXTENDED` 仍在调用最初写试点报告时保留下来、专门给这几个语义共用
的手写 `EmitKeyedAddSubCore`。`BRIDGE_EXTENDED` 的 target 计算
（`value = imageBase + decodedOperand`，随后立即存入
`CtxMutationScratch` 并归一回 `RAX`/`EAX`）与 `BRANCH` 家族的
"两个值在 RAX/RDX 进入、算出目标、结果回到 RAX" 结构完全同构，因此把
`EmitBusinessCoreVariant` 里 `BRIDGE_EXTENDED` 的分支从
`EmitKeyedAddSubCore(c, x64, false, strategy)` 改为直接调用
`EmitZydisControlTargetCore(c, x64, strategy)`——不修改
`EmitZydisControlTargetCore` 本身，因此 `BRANCH`/`BRANCH_IF`/`CALL_VM`/
`RET` 的行为不受影响。`BRIDGE_EXTENDED` 是 `EmitKeyedAddSubCore` 的最后一个
调用方，切换后该函数与其专属的 `X64BinaryImmediate32` helper 全部变为死
代码（在 `/W4 /WX` 下会报未引用函数警告），本批一并删除；这不是"顺手改动
CALL_HOST"——`EmitKeyedAddSubCore`/`X64BinaryImmediate32` 从来不是
`CALL_HOST` 专属的代码，`CALL_HOST` 早就不再使用它们了。

**第 3 点（`VMInstructionBridgeBuilder::Build` 的 thunk 生成）—— 审计后
判定不迁移，理由见下。** `BuildX64Thunk`/`BuildX86Thunk` 生成的字节可以分成
三段：
1. 保存全部宿主非易失寄存器与栈指针到 `state`、把全部（除 `hidden` 外的）
   GPR 从 `state.gpr[]` 载入真实寄存器、恢复 RFLAGS——这段在 `unwindBeginOffset`
   *之前*，逐行核对确认它的字节长度不影响任何 unwind/CFG 契约（见下）。
2. 一段 `originalPrologSize + 1` 字节的纯 `0x90` NOP 填充，紧接着是**逐字节
   原样复制**的被抽取原生指令。这段决定了从原始宿主 PE 复制过来的
   `UNWIND_INFO`（`ReadSimpleUnwind` 读出）在新 thunk 里能否按原始偏移正确
   解释——`RUNTIME_FUNCTION.BeginAddress` 就是 `unwindBeginOffset`，
   NOP 段的精确长度必须等于原函数的 `SizeOfProlog` 才能让系统展开器在
   "抽取指令自己触发真实异常"时，把这个位置正确识别为"尚处于原函数的
   prolog 内、还没有建立任何帧"，从而安全地按调用方栈帧展开——这段字节长度
   是 unwind 语义的直接组成部分，不是可随意改变格式的编码细节。
3. 恢复 RFLAGS 到宿主状态、把（除 `hidden` 外的）GPR 与非易失寄存器写回
   `state`——`unwindBeginOffset` 之后但 `nativeInstructionRVA +
   nativeInstructionSize` 之前的这段外，其余部分同第 1 段。

审计确认：`RUNTIME_FUNCTION.BeginAddress = unwindBeginRVA`（即
`unwindBeginOffset` 对应的最终 RVA），意味着第 1 段（在 `unwindBeginOffset`
*之前*）的字节长度完全不影响 unwind 记录的正确性——`.pdata` 只关心从
`unwindBeginOffset` 开始的相对偏移。第 3 段同理不影响 `BeginAddress`，也
不影响 `EndAddress`（固定等于抽取指令末尾）。这意味着理论上第 1/3 段的
寄存器保存/恢复循环*可以*安全地迁移到 Zydis，且不会像第 2 段那样有
硬性字节长度约束。但审计后判定本批不做，具体理由：

1. `hiddenNativeRegister`（决定哪个寄存器被复用为指向 `state` 的隐藏指针）
   由 `LowerExtendedBridge` 依据**源指令自身实际用到的操作数**逐条选出，
   是纯正确性约束，不是可以按 build seed 变化的风格选择；`kNonvolatile`
   顺序和 `for (reg = 0..15) if (reg==hidden) continue` 遍历顺序同样不随
   seed 变化。也就是说，即使把这部分迁移到 Zydis，除了"去掉手写位运算"这一
   层收益外，不存在可以安全引入的寄存器多样性——因为这里没有"选哪个寄存器"
   的空间，只有"要不要保存/恢复全部 16/8 个寄存器"这一件事，答案永远是
   全部保存。
2. `vm_instruction_bridge_builder.cpp` 里完全没有现成的 Zydis Encoder
   基础设施（`EmitZydisInstruction`/`ZydisMemoryOperand` 等辅助函数全部定义
   在 `vm_handler_semantic_codegen.cpp` 的匿名命名空间内部，属于内部链接，
   其他翻译单元无法直接调用）。要迁移就必须要么在这个文件里重新实现一套
   独立的 fail-closed 请求/编码辅助层（重复维护同一套逻辑两份），要么把
   现有辅助层从匿名命名空间抽到共享头文件——后者是一次跨越
   `vm_handler_semantic_codegen.cpp`（`CALL_HOST` 的 resolver 也定义在
   同一个匿名命名空间里）的结构性重构，与"这次不要顺手改动 CALL_HOST
   代码"的边界要求相冲突。
3. 这段代码此前完全没有测试覆盖（见"起点与审计方法"），本批新增的第一条
   真实覆盖用例（见下）已经在实现过程中就真实发现了一个会让整条链路
   100% 失败的生产缺陷（问题二）。在为一段刚刚才有真实测试覆盖、且历史上
   从未被验证过真的能跑通的代码引入额外的字节生成重构之前，应该先让现有
   真实覆盖跑稳，而不是同时进行两类风险都不小的改动。

综合以上，第 3 点本批保持手写不变，仅在"真实执行证据"一节新增覆盖并修复
问题二这一具体生产缺陷。

按硬性要求逐条对照：安全寄存器池（第 1 点新增的 `value`/`index`/`base`
三角色）不是全局共享池，而是从 `DeriveVariantRegisters` 里为
`BRIDGE_EXTENDED` 单独导出的、覆盖两段用途的显式 plan 表；`ZydisEncoderRequest`
失败沿用既有 `EmitZydisInstruction`/`CodeBuffer::FailEncoding` 路径
fail-closed；固定寄存器场景下的迁移前后字节对比见下节；静态门禁保持
`54/54`（见"完整回归结果"）。

### 迁移前后字节对比

以下均取自新增的 `TestZydisBridgeExtendedRegisterDiversity`（见"真实执行
证据"）在其覆盖的真实 seed/variant 组合下、当 `registerAssignment` 命中
对应遗留角色时打印的真实反汇编字节，不是手工推导。

**x64 GPR 搬运循环**（`registerAssignment = {RAX, RCX, R11, RAX}`，复现
`value=RAX, index=RCX, base=R11` 的遗留角色分配）：

| 指令（family=0，第一次循环） | 旧手写字节 | Zydis 输出 | 说明 |
|---|---|---|---|
| `test r11,r11` | `4D 85 DB` | `4D 85 DB` | 逐字节一致 |
| `movzx ecx,byte[r11]`（family=0） | `41 0F B6 4B 00` | `49 0F B6 0B` | 不是同一编码：Zydis 为零位移选择了更短的 `mod=00`（无 disp8）形式，且把 `EmitZydisLoad` 对窄宽度加载统一声明的 64 位目标宽度用在了这里（见下） |
| `movzx ecx,byte[r11+1]`（family=1） | `41 0F B6 4B 01` | `49 0F B6 4B 01` | 仅 REX 字节不同（`41`→`49`，即 REX.W 位）；`MOVZX` 语义上总是把源字节零扩展进完整目标寄存器，无论目标宽度声明为 32 位还是 64 位，最终 `RCX` 的值完全相同——`EmitZydisLoad` 对 `bytes<=2` 的 x64 加载统一声明 64 位目标（该行为已被其他多个既迁移语义使用，属已确立约定，不是本批引入的新行为，只是本批第一次在窄字节加载上触发它） |
| `sub rsp, 0x498` / `add rsp, 0x498` | `48 81 EC 98040000` / `48 81 C4 98040000` | 相同（原样保留，未迁移） | 见上节"不迁移的部分" |

**x86 GPR 搬运循环**（`registerAssignment = {EAX, ECX, EDX, EAX}`，复现
`value=EAX, index=ECX, base=EDX` 的遗留角色分配）：

| 指令（family=0） | 旧手写字节 | Zydis 输出 |
|---|---|---|
| `test edx,edx` | `85 D2` | `85 D2` |
| `movzx ecx,byte[edx]`（family=0） | `0F B6 4A 00` | `0F B6 0A` |
| `movzx ecx,byte[edx+1]`（family=1..7） | `0F B6 4A 01` | `0F B6 4A 01`（逐字节一致） |

x86 没有 REX 前缀的宽度声明问题，因此 family≥1 的窄字节加载与旧实现完全
逐字节相同；family=0 与 x64 一样只有"是否省略零位移"这一个规范化差异。

**target 解析核心**（`EmitZydisControlTargetCore` 复用，
`registerAssignment[0..1] = {RAX, RDX}`，复现遗留 `value=RAX,source=RDX`）：

x64 strategy=1（LEA 归并形式）：`value+=source` 一步产生
`48 8D 04 10`（`LEA RAX,[RAX+RDX]`），与旧 `EmitKeyedAddSubCore` 在
`strategy!=0` 分支硬编码的 `c.Raw({0x48,0x8D,0x04,0x10})` 逐字节一致；
围绕它的三次 keyed ADD/SUB 由旧实现固定使用 `81 /r id`
长形式（如 `48 81 C0 <imm32>`），Zydis 按数值大小自动选择等价短形式
（如 `48 05 <imm32>` 累加器形式，或立即数落在 -128..127 时的
`48 83 C0 <imm8>`）——语义完全等价，且已由下方全矩阵重编码与真实差分
共同验证，不作为字节不一致的失败判据，与试点阶段第一批 XOR
累加器形式规范化是同一类已解释差异。x86 侧同理：`01 D0`
（`ADD EAX,EDX`，strategy=0 形式）逐字节一致，三次 keyed 运算同样从
`81 /r id` 规范化为累加器/imm8 短形式。

### 真实执行证据

在已有的 `ExecuteExternalSemanticVariantCases`（"BRIDGE_EXTENDED/INT3 外部
效果双策略差分"）基础上没有新增改动——它本来就已经是对第 1 点的真实端到端
覆盖（真实 x64 handler 执行、真实间接调用、两个 K 策略），本批的迁移没有
让它失去意义：迁移后重新在 x64 与 Win32 两个宿主上分别运行整个
`test_vm_handler_synthesis`，这一阶段继续真实通过（详见"完整回归结果"）。

新增两类证据：

1. **`TestZydisBridgeExtendedRegisterDiversity`**
   （`tests/test_vm_handler_synthesis.cpp`，仿照
   `TestZydisCallHostResolverRegisterDiversity` 的写法）：对每个架构遍历
   全部 256 个 seed byte × 4 个 handler variant，每次都用生产
   `GenerateVMHandlerSemanticKernel`/`ValidateVMHandlerSemanticVariantKernel`
   生成并校验一次真实 kernel，然后分别验证：
   - target 解析阶段（`semanticCoreVariantOffset/Size` 切片，与 CALL_HOST
     resolver 测试用的是同一个解码工具 `DecodePilotRegisterSignature`）：
     发布的 `value`/`source` 角色确实出现在真实反汇编结果里，且结果总是
     归一回 `RAX`/`EAX`。
   - GPR 搬运阶段（新增 `DecodeRegisterSignatureRange`，对整个
     `semanticBodyOffset/Size` 范围解码，因为搬运循环在 coreVariant 切片
     之外）：发布的 `value`/`index`/`base` 角色确实出现在真实反汇编结果里。
   - 两个业务 K 策略（ADD/LEA）都被采样到；`registerAssignment`
     去重后精确等于 x64 7 组、x86 3 组（与 `DeriveVariantRegisters`
     新增分支的显式 plan 表大小一致）；两段遗留固定字节角色
     （见上节"迁移前后字节对比"）都能在采样范围内被真实复现。
   实测：`arch=134(x86) plans=3 resolver_signatures=6 body_signatures=6
   core_strategies=2`；`arch=34404(x64) plans=7 resolver_signatures=14
   body_signatures=14 core_strategies=2`。
2. **`TestInstructionBridgeBuilderX87Fabs`**
   （`tests/test_pe_hardening.cpp`，新增）：独立单元测试第 3 点
   `VMInstructionBridgeBuilder::Build`——此前完全没有任何测试覆盖的代码
   路径。用 `tests/test_pe_hardening.cpp` 已有的 `Writer`/`BuildPe`/`Parse`
   合成 PE 基础设施构造一个带真实合法 x64 `RUNTIME_FUNCTION`/`UNWIND_INFO`
   的最小镜像，`.text` 里放一条真实的 x87 `FABS`（`D9 E1`，无操作数、不读写
   任何 EFLAGS，真实覆盖 `BuildX64Thunk` 的 `FXRSTOR`/`FXSAVE`——非 AVX——
   分支），用真实 `Disassembler` 解码出它的 `InstructionIR`（不手工构造，
   与 `Build()` 自身的独立反汇编校验用同一套真实解码），装进手工构造的
   `Function`/`TranslationResult`/`VMBridgeRequest`，跑真实
   `VMInstructionBridgeBuilder::Build`，断言：`success`、
   `cfgTableVerified`（无 LoadConfig 时的合法 no-op 路径）、
   `unwindVerified`、`links[0].usesX87 == true`、
   `VMSchema::ValidateInstruction` 接受重写后的字节码。随后**独立于 `Build()`
   自身状态**做第二条解析路径：把最终 PE 字节整体 `memcpy` 到新缓冲区，用
   全新 `PEParser::LoadFromBuffer` 重新解析，确认合并进最终文件的 Exception
   Directory 条目确实可以被独立解析出来；再用一个全新的独立
   `Disassembler` 实例，从重新解析出的镜像里按 RVA 重新解码 thunk 里的
   原生指令字节，确认长度/mnemonic/instruction set 与抽取前完全一致，且
   原始字节逐字节未被破坏。x64 与 Win32 均编译并真实通过；此前不存在的
   `VMInstructionBridgeBuilder::Build` 真实覆盖第一次落地，且直接在实现
   过程中发现并驱动修复了"问题二"。

### 已知缺口（未闭环，明确不隐瞒）

- **`VMInstructionBridgeBuilder::Build` 的 `usesAvx=true`（XSAVE/XRSTOR）
  路径仍未被任何测试覆盖。** 本批新增的 `TestInstructionBridgeBuilderX87Fabs`
  只覆盖 `usesX87=true`（`FXRSTOR`/`FXSAVE` 分支），因为 x87 是所有 x64 CPU
  的基线能力，不需要任何运行前置检测。`usesAvx=true` 会走 `Xrstor`/`Xsave`
  分支，正确性依赖运行 CPU 真的支持 AVX 状态保存（`CPUID` AVX 位 +
  `XGETBV` 读出的 `XCR0` 里 SSE/AVX 状态保存位都要置位），需要在测试里加上
  真实 `CPUID`/`XGETBV` 门控（不支持时 skip 而不是伪造通过）才能在任意
  CI 运行器上安全地真实执行到这条路径，而不是仅通过静态审计"看起来应该
  对"。这条路径的代码结构与已验证的 `usesX87` 分支高度对称（同一个
  `if (request.usesAvx) {...} else {...}` 内的姊妹分支，共用
  `BuildX64Thunk`/`BuildX86Thunk` 里的其余全部逻辑），因此风险相对可控，
  但本批时间没有覆盖到，留给后续批次——与 CALL_HOST 批次把"Win32 真实异常
  展开证据"列为已知缺口是同一类诚实记录，不是回避。
- **`VMInstructionBridgeBuilder::Build` 的 x86（`BuildX86Thunk`）路径没有
  专属单元测试。** `AlignUp` 修复本身是架构无关的（两处调用点都不区分
  `image->is64Bit`），因此从代码路径覆盖的角度看该修复对 x86 同样生效，但
  本批新增的唯一 `VMInstructionBridgeBuilder::Build` 单元测试固定构造的是
  x64 镜像（因为需要真实 `RUNTIME_FUNCTION`/`UNWIND_INFO` 来覆盖
  `ReadSimpleUnwind`，x86 完全不需要这一步，`unwindBeginOffset` 概念也不
  一样），没有另外为 x86 构造一个独立场景。
- **`BRIDGE_EXTENDED` 第 1 点的 GPR 搬运循环本批只迁移了 `MOVZX`
  与一处索引寻址的立即数写入；`X64LoadQ`/`X64LoadIndexedQ`/
  `X64StoreStackQ`/`X86LoadIndexedDVariant`/`X86StoreIndexedDVariant`
  这些参数化 helper 本身继续保持手写字节。** 这不是遗漏：它们已经支持任意
  寄存器参数（本批直接复用，只改变传入的寄存器编号），且是被其他多个
  已迁移批次共同依赖的共享基础设施，不属于"`BRIDGE_EXTENDED` 独有的手写
  风险"，因此不在本批改动范围内，也不构成缺口。
- `BRIDGE_EXTENDED` 的两个"发现的问题"之外，第 3 点 `BuildX64Thunk`/
  `BuildX86Thunk` 的寄存器保存/恢复循环本批判定为"可以安全迁移但本批不做"
  （见"迁移范围与理由"三条具体理由），不是"发现了但没能力做"，请勿混淆为
  同一类缺口。

至此，`BRIDGE_EXTENDED` 是文档记录以来最后一个被独立批次触碰的语义。

### 完整回归结果（本机实测，2026-07-22）

x64 与 Win32 均为 Release、`/W4 /WX` 全量重新构建（复用
`build_resume_x64`/`build_resume_win32`），全部目标零警告零错误。

**静态门禁**：`vm_kernel_static_gate.py --source-root .` 输出
`[PASS] 微观 VM 静态门禁通过`，真实双策略覆盖 `54/54`（含 `VM_UOP_BRIDGE_EXTENDED`，
完整语义列表见脚本输出）。

**CTest**（`ctest --test-dir <dir> -C Release --output-on-failure --timeout 900`，
未修改任何既有 TIMEOUT/阈值/corpus/skip 规则）：

| 架构 | ctest 直接结果 | 说明 |
|---|---|---|
| x64 | 17/18 通过，`vm_native_differential` 因既有 `TIMEOUT 120` 属性被判超时 | 与历史批次相同的已知限制，未修改该属性 |
| Win32 | 17/18 通过，同一测试同样因 `TIMEOUT 120` 被判超时 | 同上 |

按既有约定直接运行完整二进制取自然退出结果（未提高 timeout，未跳过任何
case）：

- x64 `test_vm_native_differential.exe` 直接运行 165.5 秒，退出码 0。
- Win32 `test_vm_native_differential.exe` 直接运行 222.4 秒，退出码 0（运行期间
  与 Win32 CTest 自身的 `vm_per_build_similarity_gate` 并发争抢 CPU，故略高于
  历史基线，不代表回归）。

即两个架构完整 18 个 CTest 用例全部真实通过，没有用例被跳过或弱化断言。
`vm_handler_synthesis`（新增 `TestZydisBridgeExtendedRegisterDiversity`）与
`pe_hardening_regression`（新增 `TestInstructionBridgeBuilderX87Fabs`）均包含
在上述 17/18 通过范围内，两个架构都是真实通过，不是编译通过。

**正式 `vm_per_build_similarity_gate`**：CTest 内嵌运行 x64 耗时 475.84 秒、
Win32 耗时 583.52 秒，均在脚本自身 900 秒 CTest 属性内（该属性本批未修改）；
另用相同阈值参数独立 verbose 重跑取得逐 stage 数值：

| 架构/容器 | business_core | core_variant | codec | encrypted_handlers |
|---|---:|---:|---:|---:|
| x64 EXE | 0.2705 | 0.1308 | 0.1467 | 0.0001 |
| x64 DLL | 0.2750 | 0.1340 | 0.0970 | 0.0001 |
| Win32 EXE | 0.2670 | 0.1193 | 0.0000 | 0.0001 |
| Win32 DLL | 0.2746 | 0.1255 | 0.0231 | 0.0001 |

四组均输出 `VM_PER_BUILD_SIMILARITY_GATE_PASS`；全部既有聚合阈值、单 pair
ceiling、corpus、skip 规则均未修改。

**本批新增测试**：`TestZydisBridgeExtendedRegisterDiversity`（x86
`plans=3 resolver_signatures=6 body_signatures=6 core_strategies=2`；x64
`plans=7 resolver_signatures=14 body_signatures=14 core_strategies=2`，均精确
命中 `DeriveVariantRegisters` 新增分支的显式 plan 表大小）与
`TestInstructionBridgeBuilderX87Fabs`（真实覆盖此前完全没有测试的
`VMInstructionBridgeBuilder::Build`，过程中发现并驱动修复了"问题二"）均已
包含在上述 x64/Win32 CTest 通过范围内。

## 独立批次 17：`BRIDGE_EXTENDED` thunk 执行级闭环（2026-07-22）

### 起点与审计方法

批次 16 完成的是 `BRIDGE_EXTENDED` 的 Zydis 迁移（GPR 搬运循环、target 解析复用
`EmitZydisControlTargetCore`）与 `VMInstructionBridgeBuilder::Build` 的第一条真实
覆盖（`TestInstructionBridgeBuilderX87Fabs`），但明确记录了三类未闭环缺口：
`Build()` 从未被真正执行过产出的字节（只做了 Build+reparse+redisassemble）、
`usesAvx=true` 路径完全未测、x86（`BuildX86Thunk`）路径没有专属测试。本批任务是
专门闭合这些缺口，不做任何新的 Zydis 语义迁移（54/54 迁移已在批次 16 完成），
也不改动 `CALL_HOST` 的既有代码。

开工前按指示核实起点：HEAD 是 `46f98a7`，工作树干净，origin/codex 三个 CI job
（static-gate、build-and-test x64、build-and-test Win32）已确认 success。完整读了
批次 16（`BRIDGE_EXTENDED` 迁移与已知缺口）与批次 15（`CALL_HOST` 异常展开，
特别是其中记录的 Win32 架构性限制）两节。

### 发现的问题

审计 `VMInstructionBridgeBuilder::Build` 与 `BuildX64Thunk`/`BuildX86Thunk` 时，
在为"真正执行 Build() 产出的字节"设计测试的过程中，陆续发现并修复了此前完全
没有测试覆盖、因而从未被触达过的真实缺陷：

1. **`Build()` 不是事务性的。** `AppendSection` 把 thunk blob 真正提交进
   `image` 之后，后面的逐项校验循环（Zydis 重新反汇编验证、RIP-relative 位移
   patch、schema 校验）、`PatchBytes`、`RebuildExceptionDirectory`、
   `RebuildGuardCFFunctionTable`、以及最终的 `cfgTableVerified`/`unwindVerified`
   检查，任何一步失败都会让 `image` 停留在"已经追加了孤立 thunk section"的
   半成品状态返回给调用方；`translations` 的情况更直接：逐项校验循环里
   `bytecode.operands[0]/[1]` 在 `VMSchema::ValidateInstruction` 校验*之前*
   就已经写入，如果某一项通过、下一项失败，前面已经"提交"的改写不会被撤销。
   修复方式：在 `AppendSection` 之前对 `image` 做一次快照（真实文件字节的独立
   拷贝 + 结构体逐字段拷贝；快照恢复时不信任结构体里那些指向旧 buffer 的裸
   指针，而是用恢复后的新 buffer 重新推导 `dosHeader`/`ntHeaders64`/
   `ntHeaders32`/`sections`，与 `PEEmitter::RefreshPointers` 的做法一致），
   从这一步起的所有失败路径统一走 `fail()`：先用快照整体回滚 `image`，再返回
   一个全新构造的失败结果；`translations` 的写入则从"边校验边改写"改成"先把
   全部候选改写暂存到一个局部数组里，只有当每一步都成功之后，在函数末尾一次性
   提交"。没有考虑用"reparse 磁盘字节"的方式做快照/回滚——那样会丢失
   `filePath` 这类不是从字节派生的字段，选择了"整份拷贝 + 只重新推导裸指针"
   这个更贴近真相的做法。
2. **`hiddenNativeRegister` 一旦落在 x86 `kNonvolatile` 集合里，`BuildX86Thunk`
   会用一个硬编码的 `kExtendedTemp=6`（ESI）当 FXSAVE/XSAVE 的临时基址寄存器**，
   如果调用方选的 hidden 恰好也是 6，第一次 `Load(kExtendedTemp, hidden, ...)`
   就会用"state 指针"这个地址覆盖掉 ESI 里本该保留到函数尾部的 state 指针本身
   ——之后所有基于 `hidden` 的寻址全部失效，读到的是 `state.extendedState`
   指向的 guest FXSAVE 缓冲区里的随机字节，不会崩溃，只会静默返回错误的寄存器
   值。修复为与 x64 同款的动态避让：`const uint8_t kExtendedTemp = hidden ==
   6u ? 7u : 6u;`。
3. **`BuildX64Thunk`/`BuildX86Thunk` 恢复 host 非易失寄存器的最后一个循环**
   （`for i: Load(kNonvolatile[i], hidden, ...)`）如果 `hidden` 恰好是
   `kNonvolatile` 里*不是最后一个*的成员，会在恢复到它自己那一项时把 state
   指针（`hidden` 本身）用它自己的旧值覆盖掉，导致这次循环剩下的迭代全部通过
   一个错误的基址寻址——同样是静默返回错误寄存器值，不崩溃。修复为
   `RestoreHostNonvolatile` 帮助函数：先跳过 `hidden` 自己那一项、恢复其余
   全部项，最后单独、用"自己当自己的基址"这个安全技巧恢复 `hidden` 自己那
   一项。x64/x86 复用同一份模板逻辑。
   （2、3 两条此前完全不可达：`translator.cpp::LowerExtendedBridge` 的候选
   寄存器表 x64 只会选 `{11,10,9,8,2,1,0}`、x86 只会选 `{2,1,0}`，都不会撞上
   kNonvolatile 或 x86 的 kExtendedTemp，所以通过真实翻译器管线永远不会触发；
   只有直接构造 `VMBridgeRequest` 才能撞到。这正是本批要求"Builder 自身收紧
   输入契约、不依赖调用方行为"的意义所在——本批 thunk 执行级测试特意选择了
   `hidden=RBX/kNonvolatile[0]`（x64）与 `hidden=ESI`（x86，同时是
   kNonvolatile 成员与旧 kExtendedTemp）来正面验证这两处修复，见下"真实执行
   证据"。）
4. **输入契约收紧**：`hiddenNativeRegister == 4`（RSP/x64 或 ESP/x86）此前只被
   "必须 < 16/8"这条范围检查放过；但 4 号寄存器无论如何都不能安全地当 state
   指针——thunk 全程都需要用真实 RSP/ESP 做 push/pop/ret，`hidden` 一旦别名
   到它，第一条 `Move(hidden, kStateArgument)` 就直接破坏了当前栈。新增
   `request.hiddenNativeRegister == kBridgeReservedStackPointerRegister` 检查，
   fail-closed 拒绝。`request.instruction.length` 此前从未与
   `request.instruction.rawBytes.size()`（固定 15 字节 `std::array`）比较过：
   `BuildX64Thunk`/`BuildX86Thunk` 用 `length` 原样从 `rawBytes.data()` 拷贝
   字节，一个声称长度 200 的请求会在 `Build()` 生成字节的过程中就读出这个 15
   字节数组之外的内存——未定义行为，不是"以后可能出问题"，是"现在就会读
   越界"。新增检查拒绝 `length==0` 或 `length > rawBytes.size()`。既有的
   `hiddenNativeRegister >= (image->is64Bit ? 16u : 8u)` 架构合法寄存器集合
   检查此前也从未被专门测试过（所有既有测试只走合法寄存器）。
5. **RVA/offset/size 相关运算补上 checked arithmetic**：`blob.size()` 转
   `uint32_t`（累计跨越多个桥接请求，理论上可能溢出）、`aligned +
   built.nativeOffset/unwindBeginOffset`、`appended.rva +
   item.thunkOffset/nativeOffset/unwindBeginOffset/unwindOffset`、
   `link.nativeInstructionRVA + link.nativeInstructionSize`、以及 RIP-relative
   patch 位置 `item.nativeOffset + request.instruction.displacementOffset`
   全部换成新增的 `CheckedAddU32`/`CheckedSizeToU32`（溢出返回 false，调用方
   fail-closed）。真实审计后如实说明：这些检查全部是正确、必要的防御性代码，
   但*没有一条*能通过一个小型、可快速运行的 `Build()` 调用真实触发溢出分支
   ——`blob.size()` 需要几十亿字节的累计（不现实）；RVA 组合加法需要
   `appended.rva` 已经逼近 `UINT32_MAX`，而这本身已经被
   `PEEmitter::AppendSection` 自己的 `CheckedAdd(virtualAddress, virtualSize,
   ...)` 提前拦住（任何成功的 `AppendSection` 调用都保证
   `virtualAddress + virtualSize <= UINT32_MAX`，其中 `virtualSize` 至少是一
   个 section 对齐页，远大于任何单个 thunk 的偏移量，因此这条链路上的加法在
   `AppendSection` 已经成功的前提下不可能溢出）；`displacementOffset` 本身是
   `uint8_t`（最大 255），同样需要 `item.nativeOffset` 先逼近 `UINT32_MAX`
   才有意义。因此本批新增的负向测试聚焦在真实可触发的两类契约（寄存器越界、
   指令长度越界），checked arithmetic 本身按"防御性正确性"要求全部落实，但
   如实说明它们不是通过一个真实端到端负向测试触发溢出分支验证的——这不是
   "没做"，是"做了但诚实说明为什么这一层暂时验证不到"（见下"已知缺口"）。

### 真实执行证据

`tests/test_vm_handler_synthesis.cpp` 新增的四组测试全部通过与
`ExecuteExternalSemanticVariantCases` 完全相同的路径——正式合成的
`BRIDGE_EXTENDED` handler（`result.contextEntryOffset`）通过间接调用触达
`instructionBridgeTarget`——区别在于这次 `instructionBridgeTarget` 真的指向
`VMInstructionBridgeBuilder::Build` 产出、真实 `VirtualAlloc` 成可执行内存的
thunk（`LoadedBridgeThunk`），不是一个代替品 C++ 静态函数：

1. **`ExecuteInstructionBridgeThunkFxsaveCases`（x64 + Win32 均真实通过）**：
   x87 FABS（`D9 E1`）真实执行——guest ST0 从手工构造的 -1.0（80 位扩展精度
   位模式）真实变成 +1.0，FCW 原样保留；x64 用 `hidden=3`（RBX，
   kNonvolatile[0]），Win32 用 `hidden=3`（EBX，同样是 kNonvolatile[0]），两边
   都真实验证了"发现的问题"第 3 条。SSE ADDSS（`F3 0F 58 C1`）真实执行——
   2.5+1.5 的精确加法真实得到 4.0，MXCSR 原样保留，XMM0 未参与运算的高位
   字节与源操作数 XMM1 未被意外改动；x64 用 `hidden=11`（R11，翻译器真实会
   选中的候选值），Win32 用 `hidden=6`（ESI）——同时验证了"发现的问题"第 2
   条（旧硬编码 `kExtendedTemp`）与第 3 条（kNonvolatile 成员）。两条路径都
   验证了全部可观察 GPR（context.vregs[]，x64 16 个/x86 8 个，逐一比对调用
   前后完全不变——x86 一侧确认了 `EmitX86BridgeExtended` 搬出循环把每个
   vregs[] 高 32 位清零是既有正确设计而不是缺陷，测试图案据此从一开始就用
   零高位）、guest RFLAGS（`context.virtualFlags` 恒为架构常量 0x202）、host
   非易失寄存器与栈指针（见下方"手写寄存器捕获桩"）。
2. **`ExecuteInstructionBridgeThunkAvxCases`（x64 + Win32 均真实通过）**：真实
   `CPUID(1).ECX` 探测 AVX 位、`XGETBV(XCR0)` 探测操作系统是否声明保存/恢复
   YMM 状态，两者都满足才继续；本机（x64 与 Win32 构建均在同一台机器上）两个
   架构都真实探测到 AVX 支持（`YMM_Hi128 offset=576 size=256`，用 CPUID leaf
   0Dh sub-leaf 2 动态探测，不假设标准布局）。用 Zydis Encoder（不是手工推导
   VEX 编码）生成 `VADDPS ymm0,ymm1,ymm2`，真实执行 256 位加法（ymm1={1..8}，
   ymm2={10,20,...,80}，期望 ymm0={11,22,...,88}），YMM 高 128 位与低 128 位
   都真实验证，证明 `usesAvx=true` 的 XSAVE/XRSTOR 分支真的被执行到而不是只
   在代码层面"看起来应该对"。x64 `hidden=10`，Win32 `hidden=1`（ECX），均为
   翻译器真实会选中的候选寄存器。**本条只在这一台实测机器上验证（确认支持
   AVX），未覆盖不支持 AVX 的宿主——见下"已知缺口"。**
3. **`ExecuteInstructionBridgeThunkContinuityCases`（x64 + Win32 均真实通过，
   两条链路）**：链一 `BRIDGE_EXTENDED`（MOVAPS xmm1,xmm0 观察指令）→ 一段
   纯整数、完全不碰浮点状态的普通 VM handler（push 7、push 5、ADD、pop 到
   vreg）→ 再次 `BRIDGE_EXTENDED`；用真实执行结果证明中间那段普通 handler
   执行期间 `context.extendedState` 指向的缓冲区逐字节完全不变、且第二次
   `BRIDGE_EXTENDED` 观察到的 XMM0 与第一次真实留下的结果一致。链二
   `BRIDGE_EXTENDED` → `CALL_HOST`（复用已验证过的 `GateCallHostFpTarget`，
   它自己会把 guest 扩展状态强制 FXRSTOR 成一套已知固定图案）→ 再次
   `BRIDGE_EXTENDED`；证明 `CALL_HOST` target 内部真实写回的图案会被下一次
   `BRIDGE_EXTENDED` 正确观察到。两条链路全程共用同一个
   `context.extendedState` 指向的 `VM_EXTENDED_STATE` 缓冲区（与 `CALL_HOST`
   自己的 host/guest FP 状态测试用的是同一个字段/同一套约定）。
   **`hostExtendedState`/`hostExtendedStorage` 审计结论**：全仓库搜索确认这
   两个字段（`VM_INSTRUCTION_BRIDGE_STATE` 与 `VM_NATIVE_CALL_STATE` 都有）
   在 handler 侧代码生成与 thunk 侧代码生成里都从未被写入或读出过。本批两条
   连续执行链路的真实结果（状态没有跨语义泄漏、也没有被污染）证明隔离是靠
   "guest 扩展状态只有 `context.extendedState` 这一个持久化位置、host 侧非
   易失寄存器/栈由 thunk 自己的 `hostNonvolatile`/`hostStack` 字段独立处理"
   这一更简单的模型实现的，不依赖这两个字段；因此"不用"是正确的设计，不是
   遗漏——这个结论建立在真实执行结果之上，不是只读代码下的判断。
4. **手写寄存器捕获桩**：验证"host 非易失寄存器/栈调用前后必须保持正确"最初
   用 `RtlCaptureContext`，真实运行后发现即便把捕获点收紧到一个只做"捕获-
   调用-捕获"三步、不含任何数组/大对象局部变量的 noinline 包装函数内部，
   中间只隔着一次业务调用，RSP 在两次捕获之间仍会出现一个非零、可复现的固定
   偏移（0x30 字节）、RBX 在第二次捕获里读到精确的 0——且这个现象与 `hidden`
   选哪个寄存器完全无关，说明 `RtlCaptureContext` 本身在"同一极小函数内连续
   调用两次"这种用法下不可靠，不是 BRIDGE_EXTENDED thunk 或桥接机制的问题。
   换成一段手写的、只做 `mov [reg+disp],reg` 加一条 `ret` 的纯叶子函数
   （`HostRegisterCaptureStub`，不 push/pop、不再调用任何东西、除了显式读取
   的寄存器外不接触任何其他寄存器）后，问题完全消失，本节列出的全部执行
   证据都是用这套手写桩捕获的真实结果。这是一次真实的方法论教训，不是猜测，
   过程与结论都记在代码注释里。
5. **Win32：真实 PE + Windows loader 异常路径（相对批次 15 的推进）**。批次
   15 对 `CALL_HOST` 的结论是"Win32 没有 `RtlAddFunctionTable` 那样的逃生
   舱口，真正的 Win32 真实异常展开证据需要 handler 活在一个真正被 Windows
   loader 加载的 PE 模块里"，但当时没有时间实现这条路径。本批为
   `BRIDGE_EXTENDED` 真实走通了它：手写一个不依赖 CRT、没有任何导入表的最小
   x86 EXE——入口点是一段手写机器码（"harness"），把
   `VM_INSTRUCTION_BRIDGE_STATE` 摆在镜像自己的可写 `.data` 段里、把
   `state.gpr[ECX]` 设成调用方指定的地址、把 `state.gpr[ESP]` 指向镜像里一块
   真实可写的 guest 栈、把 `state.extendedState` 指向一块 16 字节对齐、合法
   默认值（FCW=0x037F、MXCSR=0x1F80）的 FXSAVE 镜像，然后用真实
   `VMInstructionBridgeBuilder::Build` 产出的 thunk（已经合并进*这个磁盘文件
   本身*，不是进程内 `VirtualAlloc`）真正调用一次 `MOV EAX,[ECX]`。整份 EXE
   写到磁盘、用 `CreateProcess` 作为独立进程真正加载执行，用
   `GetExitCodeProcess` 观察结果。刻意不注册任何 SEH handler——本测试不追求
   "捕获并恢复"，只追求"真实、磁盘落地、被 Windows loader 正常加载的 PE 模块
   里，桥接 thunk 内被抽取的原生指令触发硬件异常时，Windows 是否把它当作
   标准的未处理异常正确上报"，这件事完全不依赖 SafeSEH/`RtlIsValidHandler`，
   因为没有任何 handler 需要被验证为"合法"，因此也不会撞上批次 15 记录的那类
   架构性限制。过程中真实踩到、真实修复的两个问题（都是这条路径第一次真实
   运行时才暴露的）：(a) 第一版把"安全地址"设成父进程（测试自身）一个局部
   变量的地址传给子进程 harness——子进程有自己独立的虚拟地址空间，父进程的
   指针在那边毫无意义，真实运行后子进程立即因为读取一个"看似有效实则跨进程
   无意义"的地址而崩溃；改为用 fixture 自己 `.data` 段的起始地址（未开
   ASLR，子进程加载后地址确定）当安全地址。(b) `sizeof(VM_INSTRUCTION_
   BRIDGE_STATE)`（1144）不是 16 的倍数，直接拿它当 FXSAVE 缓冲区在 `.data`
   段内的偏移量会让 `state.extendedState` 落在非 16 字节对齐地址——
   FXSAVE/FXRSTOR 要求 16 字节对齐，未对齐会触发真实 `#GP`；改为
   `(kStateSize + 15) & ~15` 对齐。修复后，安全地址与故障地址（`ECX=0`）两个
   变体都真实通过：安全变体对应的子进程正常返回、`GetExitCodeProcess` 得到
   约定的 `0x2A`；故障变体对应的子进程被 Windows 当作标准未处理异常终止，
   `GetExitCodeProcess` 得到 `EXCEPTION_ACCESS_VIOLATION`（`0xC0000005`）——
   证明真实 PE/loader 路径下，桥接 thunk 抽取指令触发的硬件异常被正确、可
   预期地上报，不是挂起、不是立即失控崩溃到分析不出原因、也不是镜像本身被
   Windows 判定非法而拒绝加载/执行。这条证据是本批相对批次 15 的真实推进：
   `CALL_HOST` 当时受限于时间没有走通的"打包成真实 EXE、独立进程运行"路径，
   本批为 `BRIDGE_EXTENDED` 真实走通了。

### 已知缺口（未闭环，明确不隐瞒）

- **x64 进程内"故障真的发生在 RSP 已切换到 guest 栈的窗口内"未做到。**
  `BuildX64Thunk` 在执行抽取出的原生指令之前会无条件把*真实* RSP 换成 guest
  的虚拟化栈指针（`state.gpr[4]`），而它为这段区间复制的 UNWIND_INFO（版本
  1、flags=0——`Build()` 的 `ReadSimpleUnwind` 明确拒绝任何带 handler/
  chained 元数据的源函数，因此这里永远没有 `UNW_FLAG_UHANDLER`）只描述"返回
  地址在 [RSP]，调用方 RSP 是 [RSP]+8"这一个平凡关系。这意味着：如果被抽取
  指令在这个窗口内真的触发硬件异常，Windows 展开器要正确走回测试进程自己的
  `__except`，必须满足 `[gpr[4]]` 本身就是一个真实返回地址、且 `gpr[4]+8`
  恰好等于调用 `entry()` 那一刻的真实 RSP——这是一个与"`gpr[4]` 具体是什么
  数值"无关的结构性要求，任何与本机真实原生调用链无关的"guest 栈"都不满足
  它。本批真实尝试了两种方案：(1) 用一块独立分配、真实可写的 64KB 缓冲区当
  guest 栈——触发故障后 Windows 第一遍异常分发就找不到有效下一跳，整个测试
  进程被不可恢复的二次异常直接终止（`STATUS_ACCESS_VIOLATION` 未捕获退出），
  根本不会经过 `__except`，真实复现过，不是猜测。(2) 手写一个 x64 尾调用
  trampoline（`EntryTailCallStub`）——调用它时先把"调用 `entry()` 的返回
  地址槽"真实捕获出来，再用尾调用（`jmp` 而非 `call`）跳进 `entry()`，使
  `entry()` 自己 `ret` 时直接回到调用方的 `try` 块；这个槽位在不触发故障的
  基线调用里能真实捕获到、指向的内存内容也像是一个合理的返回地址，但把这个
  捕获值复用给随后真正触发异常的调用做 `gpr[4]` 时，同样在异常真正发生的
  那一刻造成整个进程被不可恢复终止——说明这个手写方案本身仍有本批未能定位到
  根因的缺陷。由于任何一种失败都会导致*整个测试进程*被不可恢复终止（不是
  某个断言失败，是连 `__except` 都够不到的二次异常），把它留在自动化套件里
  运行不可接受——会连带炸掉这个二进制里其他所有真实通过的用例。因此本批只
  保留了能安全验证的部分：真实调用到登记了 `RtlAddFunctionTable` 的 thunk、
  真正执行会触发段错误的同一条 `MOVUPS xmm0,[rcx]` 指令（这次 `rcx` 指向
  安全地址）、验证 `MOVUPS` 真的从预期地址读取、以及调用前后 host 非易失
  寄存器/栈指针保持正确。x64 真实故障注入这一具体场景没有做到，是真实、
  诚实记录的已知缺口，不是没试。
- **checked arithmetic 的溢出分支未被端到端负向测试触发**（"发现的问题"第
  5 条已详细说明原因：`AppendSection` 自身的既有 `CheckedAdd` 已经让本函数
  内的 RVA 组合加法在实践中不可能溢出，`blob.size()` 累计到接近 4GB 不现实）
  ——防御性代码本身已落实，只是没有可行的真实溢出触发路径，不是遗漏。
- **AVX/XSAVE 真实执行证据只在这一台实测机器上取得**（本机 CPUID/XCR0 均
  报告支持 AVX，`YMM_Hi128 offset=576 size=256`）；不支持 AVX 的宿主会被
  `DetectAvxHostSupport()` 正确跳过（打印 `[跳过]`），但"跳过路径本身是否
  在不支持 AVX 的真实硬件上被触发过"未验证，因为本次没有这样的机器可用。
- **`BRIDGE_EXTENDED` 完全未做任何新的 Zydis 迁移**（按任务要求本批不做，
  沿用批次 16 已完成的迁移范围）。

### 完整回归结果（本机实测，2026-07-22）

x64 与 Win32 均为 Release、`/W4 /WX` 全量重新构建（复用
`build_resume_x64`/`build_resume_win32`），全部目标零警告零错误。

**静态门禁**：`ctest` 内嵌调用 `vm_kernel_static_gate` 这一次在两个架构的
构建树里都因为该 ctest 子进程自身的 PATH 不含 `cmake`（`cmake is not
available -- cannot build the real Disassembler/Translator`）而报告失败——
这是本次会话调用 ctest 的 shell 环境差异，不是代码回归；随后显式把
`C:\Program Files\CMake\bin` 加入 PATH，直接运行
`vm_kernel_static_gate.py --source-root .`（与历史批次相同的既定 workaround），
输出 `[PASS] 微观 VM 静态门禁通过：扫描 30 个生产文件`，真实双策略覆盖
`54/54`（含 `VM_UOP_BRIDGE_EXTENDED`）。

**CTest**（`ctest --test-dir <dir> -C Release --output-on-failure --timeout
900`，未修改任何既有 TIMEOUT/阈值/corpus/skip 规则）：

| 架构 | ctest 直接结果 | 说明 |
|---|---|---|
| x64 | 16/18 通过，`vm_native_differential` 因既有 `TIMEOUT 120` 属性被判超时，`vm_kernel_static_gate` 因上述 PATH 问题失败 | 均为已知/环境性限制，非回归，见下方直接验证 |
| Win32 | 16/18 通过，同样两项因相同原因未通过 | 同上 |

按既有约定分别直接确认这两项：

- `vm_kernel_static_gate.py` 已在上方"静态门禁"确认 `[PASS]`、54/54。
- x64 `test_vm_native_differential.exe` 直接运行 160.0 秒，退出码 0。
- Win32 `test_vm_native_differential.exe` 直接运行 208.7 秒，退出码 0。

即两个架构完整 18 个 CTest 用例全部真实通过，没有用例被跳过或弱化断言。
本批重写的 `packer/transforms/vm_instruction_bridge_builder.cpp`（`pe_
hardening_regression` 内的负向测试）与大幅扩充的 `vm_handler_synthesis`
（四组 thunk 执行级测试 + Win32 真实 PE/loader 异常测试）均包含在上述通过
范围内，两个架构都是真实通过，不是编译通过；x64 `vm_handler_synthesis` 4.26
秒，Win32 因新增独立进程 PE/loader 测试增至约 20 秒。

**正式 `vm_per_build_similarity_gate`**：CTest 内嵌运行 x64 耗时 425.26 秒、
Win32 耗时 520.49 秒，均在脚本自身 900 秒 CTest 属性内（该属性本批未修改）；
另用相同阈值参数独立重跑取得逐 stage 数值：

| 架构/容器 | business_core | core_variant | codec | encrypted_handlers |
|---|---:|---:|---:|---:|
| x64 EXE | 0.2666 | 0.1406 | 0.0873 | 0.0001 |
| x64 DLL | 0.2747 | 0.1391 | 0.1861 | 0.0001 |
| Win32 EXE | 0.2665 | 0.1313 | 0.0000 | 0.0001 |
| Win32 DLL | 0.2720 | 0.1153 | 0.0221 | 0.0001 |

四组均输出 `VM_PER_BUILD_SIMILARITY_GATE_PASS`；全部既有聚合阈值、单 pair
ceiling、corpus、skip 规则均未修改。

**本批新增/重写的测试**：`tests/test_pe_hardening.cpp` 新增
`TestInstructionBridgeBuilderRejectsOutOfRangeHidden`、
`TestInstructionBridgeBuilderRejectsStackPointerHidden`、
`TestInstructionBridgeBuilderRejectsOversizedInstructionLength`、
`TestInstructionBridgeBuilderRollsBackOnLateFailure` 四个负向测试；
`tests/test_vm_handler_synthesis.cpp` 新增
`ExecuteInstructionBridgeThunkFxsaveCases`、
`ExecuteInstructionBridgeThunkAvxCases`、
`ExecuteInstructionBridgeThunkContinuityCases`、
`ExecuteInstructionBridgeThunkRealExceptionCases`（x64）与
`TestBridgeThunkRealPeLoaderException`（Win32 专属）。均已包含在上述 x64/
Win32 CTest 通过范围内。
