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
