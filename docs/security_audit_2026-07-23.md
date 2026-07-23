# CipherShell 全项目安全与正确性审计报告

- **审计日期**：2026-07-23
- **审计对象**：`d:\vscode\CipherShell`，分支 `codex`，截至提交 `d124932`
- **审计方式**：只读代码审计（本报告"已修复"章节列出的两处例外），未运行任何加壳/受保护产物；6 个并行子代理分别覆盖不同子系统 + 本人直接核查若干项目级状态与一个子代理失败后的补充人工审计
- **执行者**：Claude Sonnet 5（主对话 + 6 个 general-purpose 子代理，其中 3 个因账户月度额度耗尽中途失败、额度恢复后 resume 续完）
- **约束**：本轮不 commit、不 push，所有改动仅存在于工作区

---

## 0. 结论摘要（先说结论，后面是证据）

1. **VM 虚拟化核心的技术成熟度明显好于预期**：Zydis 真实反汇编 + 统一 IR、K-variant 双策略指令级多样性已经做到 **54/54**（项目 memory 记录的"13/~54"已经过期，本次直接核对代码与静态门禁脚本确认）、decryptor 384 个真实执行验证的变异循环、CSPRNG 驱动（BCryptGenRandom + ChaCha20 keystream 无偏采样）的 opcode/寄存器/handler 布局随机化、Translator 的 fail-closed 纪律非常彻底、CFGFlattener 有三阶段字节级回验。这部分是本次审计里最扎实的部分，6 个子代理里负责这几块的都没有发现 critical/high 级别问题。
2. **但"整机保护强度"和"VM 核心质量"是两件事，且差距很大**：本次审计发现的**最重要问题**是——反调试（`[anti_debug]`）、反 Dump（`[anti_dump]`，含 nanomite）在 `default.toml` 里默认开启、GUI 里呈现为正常可勾选选项、配置解析器完整实现，但**从 `main.cpp` 到具体 transform 全链路零消费、零状态上报**，用户按默认配置跑，得到的产物这两类保护完全没生效，而且没有任何报错或提示。这直接违反项目自己在 `ciphershell.md` 第 0 节反复强调的"不用静默跳过伪造功能完成"红线，是本次审计评级最高的问题。
3. **一个好消息**：字符串加密、导入保护、section 加密、bogus-flow 这四个"确实还没做完"的功能，走的是**正确**的路径——`CapabilityChecker::CheckImage` 会在任何 PE 改动之前就 fatal 拒绝整个构建并给出具体原因，不会伪装成功。这正是 `ciphershell.md` 要求的行为，本次审计里两个独立子代理分别核实过这一点，不应和上面第 2 条的"静默失效"混为一谈。
4. 本轮直接修复了 2 个验证为真实、风险可控的问题（见第 4 章），其余问题均只报告、不修改生产逻辑（按你的要求）。
5. 最终评分与商业 VMP 版本对标见第 6 章。

---

## 1. 审计方法与范围

| 子系统 | 覆盖文件 | 执行方式 |
|---|---|---|
| VM handler 字节码生成层 | `vm_handler_semantic_codegen.cpp`(9312行)、`vm_handler_entry_codegen.cpp`(3784行) | 子代理（额度耗尽后 resume 续完） |
| Translator / Synthesizer / 静态 verifier | `translator.cpp`、`vm_handler_synthesizer.cpp`、`packer/vm/{vm_schema,micro_semantics,vm_verifier}.*` | 子代理（额度耗尽后 resume 续完） |
| PE 解析/写入/桥接/trampoline | `packer/pe_parser/*`、`vm_instruction_bridge_builder.cpp`、`vm_section_emitter.cpp`、`vm_runtime_builder.cpp`、`function_trampoline_patcher.cpp`、`reloc_fixer.cpp`、`stub_builder.cpp`、`loader_import_builder.cpp` | 子代理（一次成功） |
| CFG 构建 / 控制流混淆 | `packer/analysis/*`、`cfg_flattener.cpp`、`opaque_predicates.cpp`、`bogus_flow.cpp`、`nanomite.cpp` | 子代理（额度耗尽后 resume 续完） |
| 数据保护模块 + 工程卫生 | 字符串/导入/section 加密、`packer/config`、`packer/differential`、`packer/mutation`、`packer/signature`、CI/静态门禁 | 子代理（一次成功） |
| 随包分发 runtime/stub（反调试、加密原语等） | `runtime/common/*`、`stub/stage0/*`、`stub/stage1/*` | **子代理被自动安全分类器拦截失败，本人直接接手审计** |
| 项目级状态核实 | `ciphershell.md`、`codex_change.log`、`tests/scripts/vm_kernel_static_gate.py`、CI workflow、`packer/main.cpp` 的 `FEATURE_STATUS`/config 消费链路 | 本人直接核查 |

过程中出现两次意外，如实记录：
- 6 个子代理里有 3 个因为**账户月度花费额度耗尽**中途终止（不是代码问题），额度恢复后用 `SendMessage` resume 续完，最终 6 个子系统全部拿到完整报告。
- 负责 runtime/stub 的子代理被自动安全分类器以"cybersecurity topic"为由拦截（该子系统包含反调试技术清单，触发了误报）。本人直接用 Read/Grep/Bash 接手完成了这部分审计。

---

## 2. 高风险发现

### 2.1 【高】反调试 / 反 Dump：配置从 GUI 到解析器全部真实存在，但在主流程里是"幽灵开关"——默认开启、零消费、零报错

**证据链（每一步都已核实）：**

1. `config/default.toml:69-76` 与 `config/full_example.toml:65` 都有 `[anti_debug]` 段，**默认 7 项里 6 项为 `true`**（`timing_checks`/`hardware_bp_detection`/`software_bp_detection`/`memory_integrity`/`parent_process_check`/`thread_hiding`/`kernel_debugger_check`）；`[anti_dump]` 段默认 `erase_pe_header`/`section_permission_guard`/`nanomite_patches` 全部为 `true`。
2. `packer/config/config_parser.cpp:480-513` 的 `ParseAntiDebugSection`/`ParseAntiDumpSection` 是真实、完整的解析实现，结果存进 `ConfigFile.antiDebug`/`AntiDumpConfig`（`config_parser.h:151-200`）。
3. `packer/gui_win32/main_window.cpp:513-526` 把 `nanomite_patches`（"INT3 Nanomite 技术"）做成 GUI 里默认勾选、可交互的复选框，展示方式与其它"真正生效"的选项没有任何区别（不像同一份代码里 `[control_flow.bogus]` 那样被明确标注为"当前不可用"）。
4. 全仓库 grep `config.antiDebug` / `config.antiDump` / `AntiDumpConfig` / `AntiDebugConfigFile`，**除 `config_parser.cpp` 自身和 GUI 的 TOML 写入代码外，没有任何消费点**——`packer/main.cpp` 全文不出现 `antiDebug`/`AntiDebug` 字样。
5. `packer/main.cpp` 实际会打印的 `FEATURE_STATUS` 名单（逐行核对过全文件）只有：`string_encryption`、`import_protection`、`control_flow.flattening`、`control_flow.bogus`、`vm`、`section_encryption`——**没有 `anti_debug`、也没有 `anti_dump`**，甚至没有 `status=failed`。
6. 承载具体技术实现的 `stub/stage1/anti_debug.cpp`（567行）+ `anti_debug_advanced.cpp`（486行）+ `implicit_response.cpp`（174行）确实存在且技术清单相当完整（时序检测、PEB.BeingDebugged/NtGlobalFlag、硬件断点、代码 CRC 完整性、父进程检测、VM/沙箱指纹、延迟投毒响应等），但只被编译进 `stub/CMakeLists.txt:15-21` 定义的 `stage1_runtime` 静态库目标，**全仓库没有任何 `target_link_libraries` 引用这个目标**——它是一个只为了"证明能编译"而存在、从未被链接进 `ciphershell_packer` 或任何测试的孤立目标。基类 `AntiDebug::GenerateCheckCode`（声明在 `anti_debug.h:116`，本该是对外的 shellcode 生成入口）在 `anti_debug.cpp` 里甚至**没有函数体**——如果真的被引用会直接链接失败。
7. `nanomite.cpp`（269行，`packer/transforms/`，属于 `ciphershell_packer` 编译目标）同样从未被 `main.cpp` 引用（`main.cpp` 甚至没有 `#include "transforms/nanomite.h"`）；即便被接回，其自身实现也不完整——`Inject()` 只统计候选跳转指令，**从未把目标字节改写成 `0xCC`**；`GenerateVEHHandler` 生成的异常处理器命中 `STATUS_BREAKPOINT` 后只是注释占位"查找跳转表，修改 RIP"，实际代码直接 `return EXCEPTION_CONTINUE_EXECUTION` 而不推进 RIP——如果真的接上一处 INT3，这个 handler 会让 CPU 在同一条指令上无限重新触发异常，即时把受保护进程锁死。

**具体场景**：用户使用默认配置（或在 GUI 里勾选反调试/反 Dump 相关选项）打包一个程序，加壳工具没有任何报错，输出文件与关闭这些选项时**逐字节相同**。用户会合理地以为自己的程序具备反调试/反 Dump 能力，实际上一个调试器可以直接附加到受保护进程而不会遇到任何检测。这不是"功能没做完"（那种情况在本项目其它模块里都有清楚的 fail-closed 拒绝，见第 3 章），这是"配置到 GUI 的一整条链路做得足够真实，但在真正执行保护的地方完全没有落地"。

**建议方向（不是本轮直接实施的方案，留给你决策）**：
- 短期：比照 `string_encryption`/`import_protection`/`section_encryption`/`bogus_flow` 已经在用的模式，在 `CapabilityChecker::CheckImage` 里对 `antiDebug`/`antiDump` 任意子选项为 `true` 的情况 fatal 拒绝并给出具体原因，同时把 `default.toml`/`full_example.toml` 里这两段的默认值改成 `false`——这样"看起来开启但实际没用"至少变成"明确拒绝，用户知道要自己关掉"。
- 长期：真正把 `stub/stage1/anti_debug*.cpp` 里已经写好的检测逻辑，按项目"packer 在 pack 期现场发射机器码"的既有架构（参照 `stub_builder.cpp`/`vm_handler_entry_codegen.cpp` 的写法）重新实现并接入 `main.cpp`，而不是复用现在这批孤立、且 `runtime_stub.cpp` 里还带着自创弱加密算法的 stage1 代码（见 2.4 与附录 A）。

---

### 2.2 【中】`vm_verifier.cpp` 对"所有可达路径终止于 RET/EXIT"的检查是必要条件而非充分条件

`ciphershell.md` §11.1 明确要求 verifier 检查"所有可达控制流是否终止于 RET/VMEXIT/受控 bridge"。当前实现（`packer/vm/vm_schema.cpp:839-845` + `packer/vm/vm_verifier.cpp:129-147`）只验证了两个较弱的必要条件的合取：

1. 每条被解码指令从入口可达（BFS 可达性）；
2. record 内**存在**任意一条 `terminal=true` 的指令（如 RET）。

`VM_UOP_BRANCH` 本身 `terminal=false`，一个自循环子图（`B: BRANCH→B`）只要仍是本 record 内的合法指令边界，就能同时满足"可达"和"record 里有 RET"两条，从而通过校验——即使这个自循环子图和真正的 RET 之间根本没有路径连通。触发前提是 Translator/CFG 侧另有 bug（当前未发现），且成品还有 SipHash/ChaCha20 authentication tag 做完整性校验兜底，所以评级为中而非高。但这正是这道"防 Translator bug 的最后静态闸门"存在的核心意义，建议后续补齐"每个可达 SCC 必须能到达至少一个 terminal 指令"的图算法检查。

---

## 3. 中低风险发现

### 3.1 【中，已修复】x64 `.pdata` 可信函数边界不校验 `decodedBytes == size`

`packer/analysis/function_discovery.cpp` 里，x86 递归启发式路径（485-489行）在接受一个函数边界之前会检查 `function.decodedBytes != function.size` 并拒绝有"未探明间隙"的候选——注释明确写"gap can be an inline table or adjacent data"。但紧邻的 x64 `.pdata` 可信路径（328-358行）完全没有这条检查，直接 `push_back`。已核实 `Disassembler::AnalyzeFunctionRange`（`disassembler.cpp:851`）在 `trustedSize != 0` 时会把 `function.size` 直接设为 `.pdata` 声明的完整区间，与递归解码器实际走过的字节数（`decodedBytes`）是两个独立的量——.pdata 区间内完全可能存在没被解码器覆盖的字节（内联跳转表、多入口函数等）。这些函数会被标记 `boundaryTrusted=true` 送入 `CFGFlattener`，其原生字节会被后续 `FunctionTrampolinePatcher` 摧毁/改写。**本轮已直接修复**，见第 4.1 节。

### 3.2 【中】`stub_builder.cpp` 的 x86/x64 loader stub 用 `PEB.ImageBaseAddress` 取"自身镜像基址"，DLL 场景下取到的是宿主 EXE 的基址

`packer/transforms/stub_builder.cpp:189-191`（x64）与 `318-319`（x86）分别用 `gs:[0x60]→[+0x10]` 和 `fs:[0x30]→[+0x08]` 读 PEB 的 `ImageBaseAddress` 字段。这个字段语义是"进程主 EXE 的基址"，与当前执行代码实际所属的模块无关。如果 CipherShell 保护的目标是一个 DLL，这段 loader stub 在 DLL 里执行时算出来的"image base"其实是宿主进程 EXE 的基址，后续所有基于这个错误值的操作（`VirtualProtect` 目标地址、跳回原入口点的目标地址）都会指向宿主进程里一段无关内存。

同一批代码里 `vm_runtime_builder.cpp:404-407` 已经为**完全相同的坑**写了详细注释和正确修复（`LoadOwnImageBaseR9`/`LoadOwnImageBaseEcx`，用 RIP 相对定位或 call/pop 自定位，不依赖 PEB），但这个教训没有传播到 `stub_builder.cpp`。当前这条路径依赖的 `section_encryption` 功能整体被 `CapabilityChecker` fail-closed 拒绝（见 3.5），所以**目前不可达**；但如果这个功能未来被完成并开放给 DLL 场景，这会是一个 100% 必现（不需要特殊触发条件）的错误。建议在开放 `section_encryption`/DLL 支持之前，参照 `vm_runtime_builder.cpp` 已有写法修复。

### 3.3 【低-中】`loader_import_builder.cpp` 与 `stub_builder.cpp::InstallFirstTlsCallback` 绕开 `PEEmitter::PatchBytes`，直接裸指针写 PE 内存

`ciphershell.md` §4.2 明确"禁止保护模块直接通过裸指针随意改 Header"，`PEEmitter` 应是唯一入口。`loader_import_builder.cpp:116-127`（**活代码**，只要 VM 保护启用就会执行）和 `stub_builder.cpp:429-434`（当前因 3.5 而不可达）都是拿到 `PEEmitter::AppendSection` 返回的 `rawOffset` 后，直接对 `image->rawData` 做指针运算 + `memcpy`，不经过 `PatchBytes` 的边界校验。经过手工核算，当前两处的偏移量都严格落在各自数组长度之内，不构成现实越界，但把"这次写入安全"的证明责任从"PEEmitter 每次独立校验"变成了"这个模块自己的账不能记错、且 `AppendSection` 内部布局假设不能变"，属于架构原则违反（不是本次审计范围内唯一一处，`import_obfuscator.cpp:414` 也有相同写法）。建议改为统一走 `PEEmitter::PatchBytes(rva, bytes)`。

### 3.4 【低，当前不可达】一批"编译进二进制但从未被任何生产路径调用"的死代码，且部分自身还有独立 bug

以下模块全仓库 grep 确认**零调用点**（除自身定义外），但仍被编译进 `ciphershell_packer` 或独立目标。如果未来有人以为"文件存在=能力存在"而误接回，会直接引入真实漏洞：

- **`packer/transforms/reloc_fixer.cpp`**：整个文件死代码。`ApplyRelocations`（153-211行）函数签名里**完全没有目标缓冲区大小参数**，`RvaToFileOffset`（17-44行）对"落在第一个 section 之前"的 RVA 不做任何范围校验就直接返回——一旦被接回并喂入一个 stale/越界的重定位项，会在 `imageBase + fileOffset` 处越界写 2/4/8 字节，是经典堆越界写原语。当前真正生效的重定位修复逻辑在 `main.cpp:1736-1762`，走的是 `PEEmitter::RebuildBaseRelocationDirectory`，与这个文件无关。
- **`packer/pe_parser/pe_rebuilder.cpp`**：`RebuildHeaders`/`RebuildSections`/`RebuildOverlay` 三个私有方法（140-267行）从未被唯一的公开入口 `RebuildImage` 调用，且互相之间基于不同步的偏移状态工作；`RebuildOverlay` 对输出缓冲区完全没有边界检查。与 `PERebuilder` 应该"只序列化"的架构原则（`ciphershell.md` §4.3）直接冲突。
- **`packer/pe_parser/dll_packer.cpp`**：整个 `DLLPacker` 类未被使用；`PatchExceptionTable`/`RebuildExportTable`/`ProcessRelocations`/`PreserveTLSCallbacks` 四个方法的函数体里只有描述性注释，**直接 `return true`**，是"编译通过但什么都没干却报告成功"的典型样本（`ciphershell.md` §0.2 明确禁止的模式），只是因为从未被调用而暂时无害。
- **`packer/transforms/opaque_predicates.cpp`**：`GenerateBitCheckCode`（402-424行）用 `BT` 指令（只定义 CF），紧接着却用 `JZ`/`JNZ`（测试 ZF）做条件跳转——两者读取的是完全不同的标志位，即便被接回也起不到不透明谓词该有的效果，还可能悄悄改变原程序实际分支行为。13 种声明的谓词类型里只有 3 种真正产出机器码，其余全部退化成同一份实现；且这些谓词本身都是单变量教科书恒等式（`x²mod4∈{0,1}` 等），抗符号执行/常量传播能力很弱。
- **`packer/transforms/bogus_flow.cpp`**：有"物理交织排布"（`std::shuffle`）和"伪装死代码"的设计意图，但真正产出机器码的 `GenerateBogusCode`（99-135行）自己注释承认"简化...实际实现需要复制原始块的指令"——从未复制过任何真实指令，守护谓词的跳转目标写死为占位符 `0` 且从未被回填。停在"数据结构 + 死代码库"阶段，从未产出可执行的交织代码。
- **`packer/analysis/cfg_builder.cpp`**：`CollectLoopMembers`（453-471行）反向 BFS 越过循环头继续向上游扩展，把 header 之前、循环之外的代码误判为循环成员，污染热点分析的保护等级判断。因其唯一消费者 `BogusFlowInjector` 本身也是孤儿代码，当前无影响。
- **`stub/stage1/runtime_stub.cpp`**（249行，见附录 A）：自创的滚动 XOR"加密"只用了声明的 32 字节密钥中的 4 字节，`StubData` 结构体偏移量硬编码为 `0x1000` 并在注释里自称"假设偏移"，且函数体内直接调用 `VirtualProtect`/`GetModuleHandle` 等需要真实 IAT 的 WinAPI——与该文件自己"用哈希解析函数地址、不依赖导入表"的 shellcode 设计前提自相矛盾，实际上如果被当作无导入表 shellcode 执行会直接失败。综合来看，这个文件读起来像是早于当前"packer 现场发射机器码"架构的一个被放弃的早期原型，建议直接删除而不是修复。

### 3.5 【正面对照，非缺陷】字符串加密 / 导入保护 / section 加密 / bogus-flow：正确的 fail-closed 实现

与 2.1 形成鲜明对比：这四个功能同样"还没做完"（`string_encryptor_advanced.cpp` 的 `PatchStringReferences` 命中引用点后什么也不做但仍返回 `true`、`section_encryptor.cpp`/`string_encryptor.cpp` 实际加密用的是 `runtime_stream_cipher.h` 里一个自创的 32 位状态滚动 XOR 而不是文件里正确实现的 ChaCha20——ChaCha20 只在 `DeriveKey` 里被当作非标准 KDF 用，其注释自己承认"简化的密钥派生...实际应用中应使用更安全的 KDF"），**但 `packer/analysis/capability_checker.cpp:62-91` 的 `CheckImage` 会在任何 PE 改动之前，只要检测到 `sectionEncryption`/`stringEncryption`/`importProtection`/`bogusFlow` 任一 `enabled=true`，立即记一条 fatal issue 并给出具体原因（如"section encryption uses an unauthenticated cipher with a recoverable key"），`main.cpp` 里还有第二层重复的显式拒绝（belt-and-suspenders）。这四个功能的 preset 在 `protection_build_context.cpp:68-82` 里也被硬编码为 `false` 且注释写明原因。全仓库确认没有 `--force` 或 debug 旁路能绕过这三层拒绝。**

结论：这些功能虽未完工，但用户**无法**启用它们、也不会被静默"假成功"，这正是 `ciphershell.md` 要求的正确行为。上面列出的内部实现问题（自创弱加密等）不构成当前风险，只是"如果以后要把这个功能做完，这些具体实现都需要重写，不能直接复用"的记录。

---

## 4. 本轮已直接修复的问题

按你的要求，只修复了范围小、风险可控、已验证（编译通过 + 相关回归测试通过）的问题；改动均未 commit。

### 4.1 `packer/analysis/function_discovery.cpp` —— 补齐 x64 `.pdata` 路径的 `decodedBytes == size` 校验

对应 3.1 的发现。在 x64 `.pdata` 循环里、把候选函数标记为 `boundaryTrusted` 并送入 `result.functions` 之前，新增了和 40 行外的递归启发式路径完全同款的检查：

```cpp
if (function.decodedBytes != function.size) {
    result.issues.push_back({entry.beginAddress,
        "pdata-bounded function range contains undecoded gaps and is not safe to destroy"});
    continue;
}
```

**验证**：`ciphershell_packer`（x64 Release）增量编译零警告零错误；`test_function_discovery.exe`（含真实 MSVC 编译产物的 PE function-discovery 回归测试）运行通过，退出码 0，输出 `real MSVC PE function-discovery regression passed`。

### 4.2 `packer/signature/signature_eliminator.cpp` + `.h` —— section 改名的随机源从 `rand()` 换成 `BCryptGenRandom`

`GenerateRandomName`（每次构建都会真实执行，用于随机化除 `.rsrc`/`.reloc` 外所有 section 名）原先用 libc `rand()`，构造函数里 `srand((unsigned int)time(nullptr))` 播种——state 空间小、按秒计时可被大致推算，项目在 `section_encryptor.cpp` 里已经明确记录过"`rand()` 输出可预测，攻击者可暴力破解密钥"并修复过同类问题，但这处没有跟进。改为使用项目已经在 `protection_build_context.cpp` 里建立的同一套 `BCryptGenRandom(nullptr, ..., BCRYPT_USE_SYSTEM_PREFERRED_RNG)` CSPRNG 模式；`GenerateRandomName` 从 `void` 改为 `bool`，熵源获取失败时返回 `false`，调用方 `RandomizeSectionNames`（本来就是 `bool` 返回值，之前一直硬编码走到 `return true`）现在会如实传播这个失败。

说明：section 名不是保密边界（不参与任何解密/完整性校验），所以这个问题原始严重度是低；修复目的是消除"构建时间戳可以缩小随机名搜索空间"这个已知模式，并让该模块和项目其它地方的随机源策略保持一致。**没有**改动 main.cpp 对 `EliminateSignatures` 返回值的处理（该处本来就不检查任何子步骤的返回值，是更大范围的既有设计，不在本次小修复范围内，见附录 A 备注）。`GenerateRandomDWORD()` 本身在全仓库没有任何调用点（死代码），未一并修改。

**验证**：`ciphershell_packer`（x64 Release）增量编译零警告零错误；`test_fail_closed.exe` 运行通过，退出码 0（该测试直接调用 `SignatureEliminator::EliminateSignatures` 并断言返回 `true`，以及 section 权限保持不变）。

---

## 5. 正面发现（评分依据）

以下是本次审计过程中确认为真实、扎实的能力，作为第 6 章评分的正向依据，避免报告只谈问题、显得比实际情况更差：

- **K-variant 双策略指令级多样性已达 54/54**（项目 memory 记录的"13/~54"、"BSWAP/SAR/ROL/ROR 推迟"均已过期，本次直接核对 `tests/scripts/vm_kernel_static_gate.py` 的 `REQUIRED_REAL_STRATEGY_VARIANT_SEMANTICS` 与 `vm_handler_semantic_codegen.cpp` 的 `HasBusinessCoreVariant` switch 语句逐项确认一致），且生产代码内建 `ValidateBusinessCoreStrategyReemission` 反退化检查——两个策略如果生成完全相同的字节会直接 fail-closed 整个 handler 生成，不是可以被静默绕过的软指标。
- SHL/SHR/SAR/ROL/ROR 的 XOR 秘密分享掩码混淆、LAHF/SAHF、宽乘除法边界（`INT64_MIN/-1` 等）逐位代数验证正确；寄存器分配契约（`DeriveVariantRegisters`）未发现"hidden 寄存器被指令操作数覆盖"类问题（此前 BRIDGE_EXTENDED 出现过的真实缺陷模式，本次复核未在其它地方发现同款）。
- decryptor 每架构 **384 个真实执行验证的变异循环**（8 种 xorshift 位移方案 × 48 种指令拼写组合），有专门测试执行真实解密、检查字节串唯一性、并主动破坏一个 shift 立即数/一个指令后缀来验证生产 exact-byte validator 真的会拒绝。
- `runtime/common/vm_crypto.c` 是规范正确的 ChaCha20（含 HChaCha20 子密钥派生）+ SipHash-2-4 实现，逐项核对 quarter-round 常量、20 轮排列、"expand 32-byte k"常量、状态布局均严格符合 RFC 8439；两套独立手写的 ChaCha20（这一份 + `third_party/chacha20.h`）均未发现算法错误或 key/nonce 复用问题。
- 随机化基础设施是真 CSPRNG：`isaSeed` 通过 `BCryptGenRandom(BCRYPT_USE_SYSTEM_PREFERRED_RNG)` 获取，熵源不可用直接 fail-closed 整个构建；opcode/寄存器/handler 布局的全排列通过 ChaCha20 keystream + 标准无偏拒绝采样派生，未发现 `rand()`/时间种子这类弱随机性问题（`signature_eliminator.cpp` 那一处已在本轮修复，见 4.2）。
- `CFGFlattener`（唯一真正接入主流程并写入 PE 的控制流变换）在生成后、PE 重建后、落盘重新读回后三个阶段各自独立做字节级回验（`memcmp` 实际写入内容 + 复核 relocation/异常目录条目），不是"生成了对象就算数"。
- `Translator::LowerInstruction` 及其全部 `Lower*` 子函数的 fail-closed 纪律非常彻底（约 60 处 `FailInstruction` 调用点逐一核对），没有发现"不支持却返回成功"或"降级为近似指令"的路径；对 CALL_HOST（native bridge）等确实未闭环的能力是老实拒绝，不是伪装。
- PE 解析/写入层（`pe_parser.cpp`/`pe_emitter.cpp`/`pe_utils.h`）的 RVA/offset/size 运算系统性使用"先转 64 位比较、出界即拒绝"或显式 `CheckedAdd` 模式，未发现可导致误判通过的溢出路径。
- **CI 与静态门禁**：两个独立子代理分别复核了 `.github/workflows/ci.yml` 全文和 `tests/scripts/vm_kernel_static_gate.py`（近1900行）的判定逻辑，均未发现任何跳过测试、降低阈值、放宽豁免名单等"悄悄放水"的迹象；门禁脚本对自己的豁免名单（`K_VARIANT_NOT_APPLICABLE`）还做了反向锁定校验，防止未来有人偷偷扩大豁免范围。

---

## 6. 总体评分与商业 VMP 版本对标

**先重申一条本项目自己在此前会话里就明确要求过的原则：不能因为某个正确性/差分测试通过，就说"保护已经可用于生产"——正确性和抗逆向强度是两个独立轴。本次审计在这两个轴之外，又暴露出第三个轴：配置/GUI 呈现的能力是否真的落地到最终产物里。下面按三个轴分别打分，而不是给一个笼统的总分。**

| 维度 | 打分（满分10） | 依据 |
|---|---:|---|
| **VM 核心技术成熟度**（指令级多样性、正确性验证、随机化质量） | **7 / 10** | Zydis 真实解码 + 54/54 K-variant + 差分测试 + CSPRNG 随机化，工程质量对得起"自研 VM 保护"这个定位；扣分项：单一 VM 架构/build（不像 VMProtect 3 那样每个项目生成不同"虚拟 CPU"设计）、SIMD/x87 走 native bridge 而非真虚拟化、verifier 的终止性检查有理论缺口（2.2）。 |
| **作为完整产品今天实际能提供的保护强度**（默认配置下，一个真实攻击者面对受保护程序会遇到什么） | **3 / 10** | 反调试/反Dump 完全不生效（2.1）；字符串/导入/section 加密诚实关闭（3.5，好现象但等于"暂无这层保护"）；唯一真正生效、写入 PE 的控制流变换（CFGFlattener）默认关闭且仅对窄条件的叶子函数生效；今天面对一个默认配置打出来的受保护程序，调试器可以直接附加、字符串导入表明文可见，只有显式指定且满足条件的函数会进入 VM。 |
| **工程诚信/fail-closed 合规度**（配置的功能是否真的按声明的状态运行，还是会静默偏离） | **6 / 10** | 大多数模块（VM 主链路、CFGFlattener、四个已知未完工的加密/控制流功能）都严格遵守；反调试/反Dump 这一整类是明确的例外，且是本次审计里唯一违反"不静默伪造完成"红线的地方。 |

### 6.1 "现在到了哪个版本的商业 VMP"

这个问题不适合用一个线性版本号回答，因为"VM 核心"和"整机保护"现在处于完全不同的成熟度：

- **单看 VM 虚拟化引擎本身的技术含量**（指令多样性策略、handler 混淆、差分正确性验证的严谨程度），大致相当于 **VMProtect 2.x 中后期**的核心虚拟化质量，个别技术点（MBA 混合布尔算术、构建期反退化自校验）已经摸到 VMProtect 3.x 惯用手法的边——这一层的地基是认真打的，不是玩具级实现。
- 但**作为一个今天就能拿去保护真实商业软件的完整产品**，由于反调试/反 Dump 完全没有落地、字符串/导入/数据保护还在诚实的"未完工拒绝"阶段、控制流混淆默认关闭且适用面很窄，实际到手的成品保护强度**低于 VMProtect 1.x**（哪怕是十几年前的老版本，它默认也会真正启用一些反调试和导入保护）——不是因为核心技术差，而是因为"引擎"和"整车"之间还有一段没组装完的距离，且这段距离目前是被"看起来已经装好了"的假象遮住的（2.1）。
- 一句话总结：**你现在拥有一台调校得相当认真的 VM 保护引擎，但还没有一辆能开上路的车**。把 2.1 列出的反调试/反Dump 断层接上、把 CFGFlattener 的默认策略打开、把字符串/导入/section 保护做完整，是从"引擎扎实"走到"产品能打"最短的路径。

---

## 附录 A：其余低风险/信息性发现（不影响评分，供归档）

- `packer/vm/micro_semantics.cpp/h`：`registerCount` 缺少对 `gpr` 数组物理大小（32）的显式钳制，纯粹靠调用方自律（当前唯一调用方已保证安全）；该执行器只是 packer 自身进程内的差分模拟器，不随 runtime 出货，风险仅限于未来新增调用路径时的防御纵深缺口。
- `packer/transforms/vm_handler_synthesizer.cpp:436-441`：`semanticCoreOffset`/`semanticCoreVariantOffset` 两处偏移相加缺少与同函数其它字段一致的溢出前置检查；当前数值量级离 `UINT32_MAX` 有数量级差距，不可实际触发，属于同一函数内部防御覆盖不一致。
- `runtime/common/vm_crypto.c`：敏感缓冲区清零用普通循环（非 `volatile`/无编译器屏障），编译器理论上有权把这些"之后不再读取"的死存储优化掉，建议换成有编译器屏障保证的清零方式。
- `stub/stage1/anti_debug.cpp`/`anti_debug_advanced.cpp`：本身技术清单完整，但基类 `AntiDebug::GenerateCheckCode` 缺少函数体（见 2.1 第 6 点），是这批孤儿代码"连自己内部也没完全闭环"的又一证据。
- `llvm_pass/StringEncryption.cpp`：字符串"加密"是单字节 XOR，暴力枚举/可打印字符统计即可还原，是本次审计范围内最弱的一处加密实现；但根目录 `CMakeLists.txt` 没有 `add_subdirectory(llvm_pass)`，需要用户自行安装 LLVM 开发包并手动接入编译流程，与"给已编译 PE 加壳"的核心产品路径完全无关，物理隔离于默认构建。
- `packer/signature/signature_eliminator.cpp` 的 `EliminateSignatures`：函数内部 5 个子步骤（`RandomizeSectionNames`/`ClearRichHeader`/`ClearDebugDirectory`/`ClearTimestamps`/`ClearChecksum`）的返回值均未被检查，函数体末尾硬编码 `return true`；本轮 4.2 只让 `RandomizeSectionNames` 自己的返回值变得诚实，没有改动 `EliminateSignatures` 对它的处理方式（那是更大范围的既有设计，超出本轮"小修复"范围）。`main.cpp` 调用 `EliminateSignatures` 时也不检查其返回值。
- `packer/config`：`EliminationConfig::addFakeImports`/`addFakeResources` 两个字段被解析但从未被 `signature_eliminator.cpp` 读取，纯代码卫生问题。
- `packer/differential/`（2111行）：确认这套"原生 CPU vs 合成 handler 差分测试"基础设施的定位是**构建期正确性质量门禁**，不是运行时保护能力，评分时未计入保护强度。
- `packer/mutation/`（278行）：如实盘点，当前覆盖的是"字节级映射层"（opcode 编号/寄存器编号/handler 排列/少量指令变体的 Fisher-Yates 置换），不是"每次构建生成完全不同解释器结构"的结构级多态；278 行的体量与这个范围匹配，没有虚报也没有做到更深层次。
- `packer/signature/`（544行）：如实盘点，是针对 4 家已知同类竞品壳（VMProtect/Themida/UPX/ASPack）section 名 + 1 条通用入口点启发式的窄范围规避，不是通用特征扫描引擎；消除动作（改名、清 Rich Header/时间戳/Checksum）本身有效。

---

## 附录 B：本轮验证方式说明

第 4 章的两处修复均通过以下方式验证，未凭空声称"应该没问题"：

1. `MSBuild` 增量编译 `ciphershell_packer.vcxproj`（x64 Release，项目既有 `/W4 /WX` 设置），确认零警告零错误。
2. 分别编译并运行 `test_function_discovery.exe`（含 `function_discovery_fixture` 真实 MSVC 编译产物样本）与 `test_fail_closed.exe`，均退出码 0、断言全部通过。

未做的验证（如实说明，不掩饰）：
- 未运行完整 ctest 套件（本次审计聚焦代码级发现，没有对全部 18 个测试目标做回归）。
- 未在 GitHub Actions 远端 CI 上验证这两处改动（本轮未 push，按你的要求）。
- 第 2、3 章列出的其余问题均未做任何代码改动，也就没有可供验证的编译/测试结果。
