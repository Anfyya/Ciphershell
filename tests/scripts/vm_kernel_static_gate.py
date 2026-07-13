#!/usr/bin/env python3
"""CipherShell 微操作 VM 内核源码硬门禁。

该脚本只读取源码，不运行加壳产物。它刻意使用否定式硬门禁：旧的定长
粗粒度 ISA、固定 runtime blob、集中解释循环或算术 flags bridge 只要仍在
生产路径中出现，就直接失败，避免双轨和 fallback 被误报为完成。
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".h", ".hpp", ".inc", ".asm"}

# 旧 v3 ISA 的完整语义名。微操作可以表达同样的算术原语，但不得再以
# x86 操作数形态（RR/RC/RM/MR 等）作为一条 VM 指令。
LEGACY_COARSE_OPCODES = {
    "VM_NOP",
    "VM_MOV_RR", "VM_MOV_RC", "VM_MOV_RM", "VM_MOV_MR",
    "VM_MOV_RM8", "VM_MOV_MR8", "VM_MOV_RM16", "VM_MOV_MR16",
    "VM_LEA", "VM_XCHG", "VM_PUSH_R", "VM_PUSH_C", "VM_PUSH_MEM",
    "VM_POP_R", "VM_POP_MEM", "VM_PUSHAD", "VM_POPAD", "VM_PUSHF",
    "VM_POPF", "VM_ADD_RR", "VM_ADD_RC", "VM_SUB_RR", "VM_SUB_RC",
    "VM_MUL_RR", "VM_IMUL_RR", "VM_IMUL_RRC", "VM_DIV_RR",
    "VM_IDIV_RR", "VM_NEG_R", "VM_INC_R", "VM_DEC_R", "VM_ADC_RR",
    "VM_SBB_RR", "VM_ADD_RM", "VM_ADD_MR", "VM_AND_RR", "VM_AND_RC",
    "VM_OR_RR", "VM_OR_RC", "VM_XOR_RR", "VM_XOR_RC", "VM_NOT_R",
    "VM_SHL_RR", "VM_SHL_RC", "VM_SHR_RR", "VM_SHR_RC", "VM_SAR_RR",
    "VM_SAR_RC", "VM_ROL_RR", "VM_ROR_RR", "VM_BT_RR", "VM_BTS_RR",
    "VM_BTR_RR", "VM_BSWAP", "VM_ADC_RC", "VM_SBB_RC", "VM_NEG_M",
    "VM_INC_M", "VM_DEC_M", "VM_SHL_MR", "VM_SHL_MC", "VM_SHR_MR",
    "VM_SHR_MC", "VM_SAR_MR", "VM_SAR_MC", "VM_ROL_RC", "VM_ROR_RC",
    "VM_CMP_RR", "VM_CMP_RC", "VM_TEST_RR", "VM_TEST_RC", "VM_CMP_RM",
    "VM_CMP_MR", "VM_TEST_RM", "VM_TEST_MR", "VM_JMP", "VM_JZ",
    "VM_JNZ", "VM_JA", "VM_JB", "VM_JG", "VM_JL", "VM_JGE", "VM_JLE",
    "VM_JO", "VM_JNO", "VM_JS", "VM_JNS", "VM_CALL_VM", "VM_RET_VM",
    "VM_CALL_NATIVE", "VM_VMENTER", "VM_VMEXIT", "VM_SYSCALL", "VM_JAE",
    "VM_JBE", "VM_JP", "VM_JNP", "VM_CMOV_RR", "VM_CMOV_RM", "VM_SET_R",
    "VM_SET_M", "VM_CALL_IMPORT", "VM_CALL_INDIRECT_R", "VM_CALL_INDIRECT_M",
    "VM_ANTI_DEBUG", "VM_CRC_CHECK", "VM_RDTSC", "VM_CPUID", "VM_INT3",
    "VM_MOVZX_RR", "VM_MOVZX_RM", "VM_MOVSX_RR", "VM_MOVSX_RM",
    "VM_MOVSXD_RR", "VM_MOVSXD_RM", "VM_MOV_MC", "VM_XCHG_RM",
    "VM_SUB_RM", "VM_SUB_MR", "VM_ADC_RM", "VM_ADC_MR", "VM_SBB_RM",
    "VM_SBB_MR", "VM_AND_RM", "VM_AND_MR", "VM_OR_RM", "VM_OR_MR",
    "VM_XOR_RM", "VM_XOR_MR", "VM_BRIDGE_SIMD", "VM_BRIDGE_X87",
    "VM_ROL_MR", "VM_ROL_MC", "VM_ROR_MR", "VM_ROR_MC",
    "VM_SIGN_EXTEND_ACC", "VM_EXTEND_ACC", "VM_LEAVE", "VM_CLC", "VM_STC",
    "VM_CMC", "VM_LAHF", "VM_SAHF",
}

FIXED_SCHEMA_IDENTIFIERS = {
    "VM_BYTECODE_INSTRUCTION",
    "VM_INSTRUCTION_SIZE",
}

FIXED_RUNTIME_IDENTIFIERS = {
    "kVMRuntimeX64Image",
    "kVMRuntimeX86Image",
    "kVMRuntimeX64ImageSize",
    "kVMRuntimeX86ImageSize",
    "vm_runtime_blobs",
    "CS_RUNTIME_X64_HEADER",
    "CS_RUNTIME_X86_HEADER",
}

CENTRAL_DISPATCH_IDENTIFIERS = {
    "vm_handler_variants",
    "execute_instruction",
}

MISLEADING_DIFFERENTIAL_IDENTIFIERS = {
    "VMDifferentialVerifier",
    "VMDifferentialConfig",
    "VMDifferentialResult",
}

MICRO_EXECUTOR_NATIVE_FLAG_IDENTIFIERS = {
    "VM_INSTRUCTION_BRIDGE_STATE",
    "VM_NATIVE_CALL_STATE",
    "vm_instruction_bridge",
    "vm_native_call_bridge",
    "__readeflags",
    "__writeeflags",
    "__readeflags",
    "__writeeflags",
}


@dataclass(frozen=True)
class Violation:
    path: Path
    line: int
    rule: str
    detail: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    return parser.parse_args()


def production_files(root: Path) -> list[Path]:
    fixed = [
        root / "CMakeLists.txt",
        root / "packer" / "CMakeLists.txt",
        root / "packer" / "main.cpp",
    ]
    trees = [
        root / "runtime" / "common",
        root / "packer" / "vm",
        root / "packer" / "mutation",
        root / "stub" / "vm",
    ]
    transform_names = (
        "translator", "vm_section_emitter", "vm_runtime_builder",
        "vm_instruction_bridge_builder", "vm_handler_synthesizer",
        "vm_handler_semantic_codegen", "vm_handler_entry_codegen",
    )
    files = [path for path in fixed if path.is_file()]
    for tree in trees:
        if tree.is_dir():
            files.extend(
                path for path in tree.rglob("*")
                if path.is_file() and path.suffix.lower() in SOURCE_SUFFIXES
            )
    transforms = root / "packer" / "transforms"
    for name in transform_names:
        files.extend(path for path in transforms.glob(name + ".*") if path.is_file())
    return sorted(set(files))


def strip_comments_and_literals(text: str) -> str:
    """保留换行与大致列宽，移除注释/字面量，避免文档说明触发门禁。"""
    pattern = re.compile(
        r"//[^\n]*|/\*.*?\*/|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'",
        re.DOTALL,
    )

    def blank(match: re.Match[str]) -> str:
        return "".join("\n" if ch == "\n" else " " for ch in match.group(0))

    return pattern.sub(blank, text)


def identifier_hits(
    path: Path,
    code: str,
    identifiers: Iterable[str],
    rule: str,
) -> list[Violation]:
    wanted = set(identifiers)
    hits: list[Violation] = []
    for match in re.finditer(r"\b[A-Za-z_][A-Za-z0-9_]*\b", code):
        token = match.group(0)
        if token not in wanted:
            continue
        hits.append(Violation(path, code.count("\n", 0, match.start()) + 1, rule, token))
    return hits


def arithmetic_bridge_hits(path: Path, code: str) -> list[Violation]:
    """阻止算术 flags 借 native/instruction bridge 计算或回读。"""
    # SIMD/x87 的正式 bridge 可以保存/恢复 rflags，因此不能在全仓库用
    # “bridge 与 flags 相邻”这种弱启发式。真正的铁律是：共享生产微语义
    # executor（handler lowering 与差分门禁共同依赖）不得链接任何 native
    # bridge 或主机 flags intrinsic。
    hits: list[Violation] = []
    if "VMMicroSemanticExecutor" in code:
        hits.extend(identifier_hits(
            path,
            code,
            MICRO_EXECUTOR_NATIVE_FLAG_IDENTIFIERS,
            "arithmetic-flags-native-bridge",
        ))
    if path.name == "vm_handler_semantic_codegen.cpp":
        # PUSHF/POPF/LAHF/SAHF would turn host EFLAGS into the VM arithmetic
        # result (or vice versa), reopening the exact native-flags bridge that
        # lazy flags is designed to close.  Handler-internal comparisons may
        # use Jcc/SETcc, but these four state-transfer instructions are banned.
        for match in re.finditer(r"0x(?:9C|9D|9E|9F)\b", code, re.IGNORECASE):
            hits.append(Violation(
                path,
                code.count("\n", 0, match.start()) + 1,
                "arithmetic-flags-native-transfer-opcode",
                match.group(0),
            ))
    return hits


def extract_function_body(code: str, name: str) -> str | None:
    """Brace-matched extraction so the coverage check survives reformatting
    without depending on a single brittle multi-line regex."""
    match = re.search(re.escape(name) + r"\s*\([^{]*\)\s*\{", code)
    if not match:
        return None
    depth = 1
    index = match.end()
    while index < len(code) and depth > 0:
        if code[index] == "{":
            depth += 1
        elif code[index] == "}":
            depth -= 1
        index += 1
    if depth != 0:
        return None
    return code[match.end():index - 1]


def extract_switch_semantic_blocks(body: str) -> list[str]:
    blocks: list[str] = []
    for match in re.finditer(r"switch\s*\(semantic\)\s*\{", body):
        depth = 1
        index = match.end()
        while index < len(body) and depth > 0:
            if body[index] == "{":
                depth += 1
            elif body[index] == "}":
                depth -= 1
            index += 1
        if depth == 0:
            blocks.append(body[match.end():index - 1])
    return blocks


def case_segments(switch_body: str) -> dict[str, str]:
    segments: dict[str, str] = {}
    matches = list(re.finditer(r"case (VM_UOP_[A-Z0-9_]+):", switch_body))
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(switch_body)
        segment = switch_body[match.end():end]
        segments[match.group(1)] = segments.get(match.group(1), "") + segment
    return segments


def consume_statement(text: str, index: int) -> tuple[str, int]:
    """Consume one ';'-terminated statement or one brace-delimited block
    starting at (whitespace-skipped) index.  Returns (text, next_index)."""
    while index < len(text) and text[index].isspace():
        index += 1
    if index < len(text) and text[index] == "{":
        depth = 1
        start = index
        index += 1
        while index < len(text) and depth > 0:
            if text[index] == "{":
                depth += 1
            elif text[index] == "}":
                depth -= 1
            index += 1
        return text[start:index], index
    start = index
    depth = 0
    while index < len(text):
        ch = text[index]
        if ch in "({":
            depth += 1
        elif ch in ")}":
            depth -= 1
        elif ch == ";" and depth == 0:
            index += 1
            break
        index += 1
    return text[start:index], index


def has_real_strategy_branch(segment: str) -> bool:
    """A real K-variant core branches on `strategy` with two arms whose
    emitted code actually differs; forwarding `strategy` unused, or an
    if/else pair that emits byte-identical code on both arms, does not
    count."""
    for match in re.finditer(r"if\s*\(\s*strategy\s*(?:==|!=)\s*[^)]*\)", segment):
        then_text, next_index = consume_statement(segment, match.end())
        rest = segment[next_index:]
        stripped = rest.lstrip()
        if not stripped.startswith("else"):
            continue
        else_index = next_index + (len(rest) - len(stripped)) + len("else")
        else_text, _ = consume_statement(segment, else_index)
        if re.sub(r"\s+", "", then_text) != re.sub(r"\s+", "", else_text):
            return True
    return False


def real_strategy_variant_semantics(semantic_code: str) -> set[str]:
    """Semantics where EmitBusinessCoreVariant branches on `strategy` with two
    genuinely different emitted code arms, in *both* the x64 and x86
    switches.  A case that only forwards `strategy` without an actual
    strategy-conditioned branch, or whose branches emit identical code,
    must not count as a real K-variant core."""
    body = extract_function_body(semantic_code, "bool EmitBusinessCoreVariant")
    if body is None:
        return set()
    switch_blocks = extract_switch_semantic_blocks(body)
    if len(switch_blocks) < 2:
        return set()
    per_arch_real: list[set[str]] = []
    for switch_body in switch_blocks:
        real: set[str] = set()
        for semantic, segment in case_segments(switch_body).items():
            if has_real_strategy_branch(segment):
                real.add(semantic)
        per_arch_real.append(real)
    common = per_arch_real[0]
    for extra in per_arch_real[1:]:
        common &= extra
    return common


# Coverage floor for genuinely branching (not just name-existence) K variants.
# ADD/SUB/AND/OR/XOR/NOT/NEG/MUL already satisfy this today; the assertion
# exists so future work on the remaining micro-op semantics is forced through
# the same structural bar instead of being reported done via a
# string-presence check alone.
MINIMUM_REAL_STRATEGY_VARIANT_SEMANTICS = 8


def require_markers(root: Path, files: list[Path], code_by_path: dict[Path, str]) -> list[Violation]:
    joined = "\n".join(code_by_path[path] for path in files)
    required = {
        "micro-op-enum": ("VM_MICRO_OPCODE",),
        "operand-codec": ("VMOperandCodec", "VM_OPERAND_CODEC"),
        "lazy-flags-record": (
            "VM_PENDING_FLAGS", "VMPendingFlags", "VMLazyFlagsState",
            "VM_LAZY_FLAGS_RECORD",
        ),
        "pack-time-handler-synth": ("VMHandlerSynthesizer",),
        "direct-threaded-tail": ("dispatchTailOffset", "dispatch_tail_offset"),
        "reference-runtime-fingerprint-gate": (
            "kReferenceRuntimes", "VerifyNoReferenceRuntimeBlob",
        ),
        "per-build-decryptor-plan": ("decryptorMutationPlan",),
        "per-build-decryptor-live-code": ("decryptorLogicDigest",),
        "ir-model-preflight-is-explicit": ("VMIRModelPreflightVerifier",),
        "native-evidence-provider-contract": (
            "VMNativeDifferentialEvidenceProvider",
        ),
    }
    violations: list[Violation] = []
    for rule, alternatives in required.items():
        if not any(marker in joined for marker in alternatives):
            violations.append(Violation(root, 1, "missing-production-marker", rule))

    # K variants must be evidenced by emitted instructions.  A shuffled result
    # descriptor plus a large skipped random island is not a semantic variant.
    semantic_path = root / "packer" / "transforms" / "vm_handler_semantic_codegen.cpp"
    synth_path = root / "packer" / "transforms" / "vm_handler_synthesizer.cpp"
    semantic = code_by_path.get(semantic_path, "")
    synth = code_by_path.get(synth_path, "")
    variant_markers = (
        "DeriveVariantRegisters",
        "EmitExecutableSeedJunk",
        "EmitLiveIdentityMBA",
        "EmitOpaqueEvenProductPredicate",
        "ValidateVMHandlerSemanticVariantKernel",
    )
    for marker in variant_markers:
        if marker not in semantic:
            violations.append(Violation(
                semantic_path, 1, "missing-live-k-variant-evidence", marker))
    if "ValidateVMHandlerSemanticVariantKernel" not in synth:
        violations.append(Violation(
            synth_path, 1, "synth-does-not-verify-k-variant-bytes",
            "ValidateVMHandlerSemanticVariantKernel"))

    # Name-existence above only proves the K-variant machinery exists
    # somewhere in the file; it says nothing about how many semantics it
    # actually covers.  Count semantics whose EmitBusinessCoreVariant branch
    # really differs byte-for-byte per strategy in both architectures, and
    # fail if that count has not grown past the historical ADD/SUB/AND/OR/
    # XOR/NOT/NEG/MUL baseline of 8.
    real_variant_semantics = real_strategy_variant_semantics(semantic)
    if len(real_variant_semantics) < MINIMUM_REAL_STRATEGY_VARIANT_SEMANTICS:
        violations.append(Violation(
            semantic_path, 1, "insufficient-real-k-variant-coverage",
            f"only {len(real_variant_semantics)} semantic(s) "
            f"({', '.join(sorted(real_variant_semantics)) or 'none'}) have a "
            "strategy-conditioned EmitBusinessCoreVariant branch with two "
            f"distinct emitted byte sequences in both x64 and x86; need >= "
            f"{MINIMUM_REAL_STRATEGY_VARIANT_SEMANTICS}, not just the ADD/SUB/"
            "AND/OR/XOR/NOT/NEG/MUL baseline"))
    if "0x48,0x83,0xEC,0x28,0xFF,0xD0" not in synth or \
       "0x48,0x83,0xC4,0x28" not in synth:
        violations.append(Violation(
            synth_path, 1, "x64-direct-tail-call-abi",
            "decoder call lacks aligned Win64 shadow space"))
    if re.search(r"EmitOpaqueIsland\s*\([^;]*\b4096u?\b", synth, re.DOTALL):
        violations.append(Violation(
            synth_path, 1, "similarity-dominated-by-unreachable-island", "4096"))
    return violations


def main() -> int:
    args = parse_args()
    root = args.source_root.resolve()
    files = production_files(root)
    if not files:
        print("[FAIL] 未找到生产源码", file=sys.stderr)
        return 2

    raw_by_path: dict[Path, str] = {}
    code_by_path: dict[Path, str] = {}
    violations: list[Violation] = []
    for path in files:
        raw = path.read_text(encoding="utf-8", errors="strict")
        raw_by_path[path] = raw
        code = strip_comments_and_literals(raw)
        code_by_path[path] = code
        violations.extend(identifier_hits(
            path, code, LEGACY_COARSE_OPCODES, "legacy-coarse-opcode"))
        violations.extend(identifier_hits(
            path, code, FIXED_SCHEMA_IDENTIFIERS, "fixed-48-byte-schema"))
        violations.extend(identifier_hits(
            path, code, FIXED_RUNTIME_IDENTIFIERS, "fixed-runtime-blob"))
        violations.extend(identifier_hits(
            path, code, CENTRAL_DISPATCH_IDENTIFIERS, "central-dispatch"))
        violations.extend(identifier_hits(
            path, code, MISLEADING_DIFFERENTIAL_IDENTIFIERS,
            "software-model-mislabeled-as-native-differential"))
        violations.extend(arithmetic_bridge_hits(path, code))

    main_raw = raw_by_path.get(root / "packer" / "main.cpp", "")
    if '"VM_DIFFERENTIAL_PASS' in main_raw:
        violations.append(Violation(
            root / "packer" / "main.cpp", 1,
            "software-model-mislabeled-as-native-differential",
            "VM_DIFFERENTIAL_PASS"))
    if "evidence=software_model_only" not in main_raw or \
       "VM_NATIVE_DIFFERENTIAL_FAIL" not in main_raw:
        violations.append(Violation(
            root / "packer" / "main.cpp", 1,
            "missing-production-native-differential-fail-closed-log",
            "IR model/native evidence boundary"))

    violations.extend(require_markers(root, files, code_by_path))
    if violations:
        print(f"[FAIL] 微操作 VM 静态门禁发现 {len(violations)} 个违规点：", file=sys.stderr)
        maximum_reported = 250
        for item in violations[:maximum_reported]:
            try:
                relative = item.path.relative_to(root)
            except ValueError:
                relative = item.path
            print(
                f"  {relative}:{item.line}: {item.rule}: {item.detail}",
                file=sys.stderr,
            )
        if len(violations) > maximum_reported:
            print(
                f"  ... 另有 {len(violations) - maximum_reported} 个违规点未展开",
                file=sys.stderr,
            )
        return 1

    print(f"[PASS] 微操作 VM 静态门禁通过（扫描 {len(files)} 个生产文件）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
