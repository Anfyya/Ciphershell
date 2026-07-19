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
