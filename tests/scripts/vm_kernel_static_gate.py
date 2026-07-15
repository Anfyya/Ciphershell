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
        # lazy flags is designed to close.  CALL_HOST is the sole deliberate
        # exception: an external native ABI boundary must restore the guest
        # input flags and capture the callee's output flags.  Its bodies do not
        # implement arithmetic and are execution-differential tested as a
        # bridge.  Handler-internal arithmetic remains under the hard ban.
        arithmetic_code = code
        for function_name in ("void EmitX64CallHost", "void EmitX86CallHost"):
            call_host_body = extract_function_body(code, function_name)
            if call_host_body is not None:
                arithmetic_code = arithmetic_code.replace(call_host_body, "")
        for match in re.finditer(
                r"0x(?:9C|9D|9E|9F)\b", arithmetic_code, re.IGNORECASE):
            hits.append(Violation(
                path,
                arithmetic_code.count("\n", 0, match.start()) + 1,
                "arithmetic-flags-native-transfer-opcode",
                match.group(0),
            ))
    return hits


def extract_function_body(code: str, name: str) -> str | None:
    """Brace-matched extraction so the coverage check survives reformatting
    without depending on a single brittle multi-line regex."""
    match = re.search(
        re.escape(name) +
        r"\s*\([^;{]*\)\s*(?:const\s*)?(?:noexcept\s*)?\{",
        code,
    )
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


# 只有这四项不适用 K 业务核心，不能把“不好做”追加成第五项：
# - CPUID/RDTSC 各自只有一条固定硬件编码；软件模拟返回值是另一套工程，
#   不是同一硬件语义的第二条等价机器码。
# - TRAP/EXIT 是失败兜底与退出边界，不承载需要隐藏的业务逻辑。
K_VARIANT_NOT_APPLICABLE = {
    "VM_UOP_CPUID": "single fixed hardware encoding",
    "VM_UOP_RDTSC": "single fixed hardware encoding",
    "VM_UOP_TRAP": "failure boundary, not business logic",
    "VM_UOP_EXIT": "exit boundary, not business logic",
}
EXPECTED_K_VARIANT_NOT_APPLICABLE = {
    "VM_UOP_CPUID", "VM_UOP_RDTSC", "VM_UOP_TRAP", "VM_UOP_EXIT",
}

# 逐名锁定已经闭环的真实业务核心，而不是只守一个可被“移除 A、补上 B”
# 绕过的数量下限。
REQUIRED_REAL_STRATEGY_VARIANT_SEMANTICS = {
    "VM_UOP_PUSH_VREG", "VM_UOP_PUSH_IMM", "VM_UOP_PUSH_FLAGS",
    "VM_UOP_PUSH_IP", "VM_UOP_PUSH_IMAGE_BASE", "VM_UOP_POP_VREG",
    "VM_UOP_LOAD_TEMP", "VM_UOP_STORE_TEMP", "VM_UOP_DUP",
    "VM_UOP_SWAP", "VM_UOP_ROT", "VM_UOP_DROP", "VM_UOP_LOAD",
    "VM_UOP_STORE", "VM_UOP_ADD", "VM_UOP_ADD_CARRY", "VM_UOP_SUB",
    "VM_UOP_SUB_BORROW", "VM_UOP_MUL", "VM_UOP_UMUL_WIDE",
    "VM_UOP_SMUL_WIDE", "VM_UOP_UDIV_WIDE", "VM_UOP_IDIV_WIDE",
    "VM_UOP_AND", "VM_UOP_OR", "VM_UOP_XOR", "VM_UOP_NOT",
    "VM_UOP_NEG", "VM_UOP_SHL", "VM_UOP_SHR", "VM_UOP_SAR",
    "VM_UOP_ROL", "VM_UOP_ROR", "VM_UOP_BIT_TEST", "VM_UOP_BIT_SET",
    "VM_UOP_BIT_RESET", "VM_UOP_BSWAP", "VM_UOP_ZERO_EXTEND",
    "VM_UOP_SIGN_EXTEND", "VM_UOP_FLAGS_LAZY",
    "VM_UOP_FLAGS_MATERIALIZE", "VM_UOP_FLAGS_WRITE",
    "VM_UOP_FLAGS_UPDATE", "VM_UOP_FLAGS_PACK_AH",
    "VM_UOP_FLAGS_UNPACK_AH", "VM_UOP_PUSH_CONDITION", "VM_UOP_SELECT",
    "VM_UOP_BRANCH", "VM_UOP_BRANCH_IF", "VM_UOP_CALL_VM",
    "VM_UOP_CALL_HOST", "VM_UOP_RET", "VM_UOP_BRIDGE_EXTENDED",
    "VM_UOP_INT3",
}
MINIMUM_REAL_STRATEGY_VARIANT_SEMANTICS = len(
    REQUIRED_REAL_STRATEGY_VARIANT_SEMANTICS)
# VM_UOP_COUNT 当前为 58；扣除上述四项，最终目标是 54。
TARGET_REAL_STRATEGY_VARIANT_SEMANTICS = 54


def reference_runtime_fingerprint_gate(root: Path) -> list[Violation]:
    """Parse every fingerprint tuple, verify its rolling-window arithmetic,
    bind it one-to-one to the provenance manifest, and inspect the actual
    rolling SHA-256 scan.  Merely retaining the old symbol names is not
    evidence."""
    source_path = root / "packer" / "transforms" / "vm_runtime_builder.cpp"
    document_path = root / "docs" / "reference_runtime_fingerprints.md"
    violations: list[Violation] = []
    if not source_path.is_file() or not document_path.is_file():
        missing = source_path if not source_path.is_file() else document_path
        return [Violation(missing, 1, "reference-runtime-fingerprint-gate",
                          "source or provenance manifest is missing")]
    raw = source_path.read_text(encoding="utf-8", errors="strict")
    document = document_path.read_text(encoding="utf-8", errors="strict")
    begin = raw.find("kReferenceRuntimes")
    end = raw.find("}};", begin)
    if begin < 0 or end < 0:
        return [Violation(source_path, 1, "reference-runtime-fingerprint-gate",
                          "fingerprint initializer is not brace-complete")]
    initializer = raw[begin:end + 3]
    entry_pattern = re.compile(
        r"\{\s*(\d+)u\s*,\s*0x([0-9A-Fa-f]+)ULL\s*,\s*"
        r"0x([0-9A-Fa-f]+)ULL\s*,\s*\{([^}]+)\}\s*,\s*"
        r'"([^"]+)"\s*,\s*"([^"]+)"\s*\}',
        re.DOTALL,
    )
    entries: list[dict[str, object]] = []
    for match in entry_pattern.finditer(initializer):
        sha_bytes = [int(value, 16) for value in
                     re.findall(r"0x([0-9A-Fa-f]{2})", match.group(4))]
        entries.append({
            "size": int(match.group(1)),
            "rolling": int(match.group(2), 16),
            "power": int(match.group(3), 16),
            "sha": "".join(f"{value:02x}" for value in sha_bytes),
            "sha_count": len(sha_bytes),
            "name": match.group(5),
            "id": match.group(6),
        })
    expected_rows = {
        "legacy-msvc-x64-full-bb01871": (
            "retired-x64-runtime-text", 23552, 0x2C5FC69EE2383E78,
            0xE6224086755CFF01,
            "fa0c6f3e275f620bf51f19af5f1cd3a46ec10431176d53eb4296637acc5a26dc"),
        "legacy-msvc-x86-full-bb01871": (
            "retired-x86-runtime-text", 24064, 0xA15835EC2011743A,
            0xA9A6C919725EFF01,
            "bb843d6555cf8dfc531ae404c7974c21d1bfeac36fc6362986565724a3d34398"),
        "legacy-msvc-x64-probe-bb01871": (
            "retired-x64-runtime-probe-text", 11776, 0x72544B6CBFEC2E4F,
            0xC3455FA1BA2EFF01,
            "0bca0748cc32c713f415563cc82ed93d621c53e59ba9f67998af98da36dbfdd0"),
        "legacy-msvc-x86-probe-bb01871": (
            "retired-x86-runtime-probe-text", 11776, 0xB58E1DFE08EE6C7E,
            0xC3455FA1BA2EFF01,
            "2b25ce2779b50e4d4e4340f638773e5c76cdbdcb3c93d9f768fe4911b36af7ff"),
    }
    expected_ids = set(expected_rows)
    actual_ids = {str(entry["id"]) for entry in entries}
    if len(entries) != 4 or actual_ids != expected_ids:
        violations.append(Violation(
            source_path, 1, "reference-runtime-fingerprint-gate",
            f"expected exactly four provenance-bound rows; got {sorted(actual_ids)}"))
    if len({str(entry["sha"]) for entry in entries}) != len(entries) or \
       len({str(entry["name"]) for entry in entries}) != len(entries):
        violations.append(Violation(
            source_path, 1, "reference-runtime-fingerprint-gate",
            "fingerprint SHA/name values are duplicated"))

    table_pattern = re.compile(
        r"^\| `([^`]+)` \|[^|]*\|\s*(\d+)\s*\|\s*"
        r"`([0-9a-fA-F]{16})`\s*\|\s*`([0-9a-fA-F]{16})`\s*\|\s*"
        r"`([0-9a-fA-F]{64})`\s*\|$",
        re.MULTILINE,
    )
    documented = {
        match.group(1): (
            int(match.group(2)), int(match.group(3), 16),
            int(match.group(4), 16), match.group(5).lower())
        for match in table_pattern.finditer(document)
    }
    for entry in entries:
        size = int(entry["size"])
        expected_power = pow(257, size - 1, 1 << 64) if size else 0
        if int(entry["sha_count"]) != 32 or size == 0 or \
           int(entry["power"]) != expected_power:
            violations.append(Violation(
                source_path, 1, "reference-runtime-fingerprint-gate",
                f"{entry['id']} has malformed SHA/size/rolling leading power"))
        documented_row = documented.get(str(entry["id"]))
        code_row = (size, int(entry["rolling"]), int(entry["power"]),
                    str(entry["sha"]))
        expected_row = expected_rows.get(str(entry["id"]))
        full_code_row = (str(entry["name"]),) + code_row
        if expected_row != full_code_row:
            violations.append(Violation(
                source_path, 1, "reference-runtime-fingerprint-gate",
                f"historical byte fingerprint changed: {entry['id']}"))
        if documented_row != code_row:
            violations.append(Violation(
                document_path, 1, "reference-runtime-fingerprint-gate",
                f"manifest row does not byte-match C++ tuple: {entry['id']}"))
    for required_text in (
        "bb01871c9ec0037270b3d1bcf9346a190ee252ff",
        "36c261f3c6cd6354df966c04438330032f8bfc40",
        "/NODEFAULTLIB", "/MACHINE:X64", "/MACHINE:X86",
        "file-backed `.text`", "temporary extraction utility",
    ):
        if required_text not in document:
            violations.append(Violation(
                document_path, 1, "reference-runtime-fingerprint-gate",
                f"provenance manifest omits {required_text}"))

    code = strip_comments_and_literals(raw)
    body = extract_function_body(code, "bool VerifyNoReferenceRuntimeBlob")
    normalized = re.sub(r"\s+", "", body or "")
    scan_requirements = (
        "rolling==reference.rollingHash",
        "Sha256Digest(bytes+offset,reference.size)==reference.sha256",
        "rolling-=static_cast<uint64_t>(bytes[offset])*reference.leadingPower",
        "reference.provenanceId",
    )
    for evidence in scan_requirements:
        if evidence not in normalized:
            violations.append(Violation(
                source_path, 1, "reference-runtime-fingerprint-gate",
                f"real rolling/SHA/provenance scan evidence missing: {evidence}"))
    final_verify = extract_function_body(
        code, "bool VMRuntimeBuilder::VerifyRuntimeContents") or ""
    if "VerifyNoReferenceRuntimeBlob(image->rawData,image->rawSize,error)" not in \
            re.sub(r"\s+", "", final_verify):
        violations.append(Violation(
            source_path, 1, "reference-runtime-fingerprint-gate",
            "the final-image verifier does not execute the fingerprint scan"))
    return violations


def decryptor_coverage_gate(root: Path) -> list[Violation]:
    """Verify production choice cardinality, exact-byte self-validation and
    exhaustive native execution coverage.  Digest/result field names alone do
    not satisfy either decryptor rule."""
    header_path = root / "packer" / "transforms" / "vm_handler_entry_codegen.h"
    entry_path = root / "packer" / "transforms" / "vm_handler_entry_codegen.cpp"
    synth_path = root / "packer" / "transforms" / "vm_handler_synthesizer.cpp"
    test_path = root / "tests" / "test_vm_decryptor_coverage.cpp"
    cmake_path = root / "tests" / "CMakeLists.txt"
    document_path = root / "docs" / "decryptor_mutation_coverage.md"
    workflow_path = root / ".github" / "workflows" / "ci.yml"
    paths = (header_path, entry_path, synth_path, test_path, cmake_path,
             document_path, workflow_path)
    for path in paths:
        if not path.is_file():
            return [Violation(path, 1, "per-build-decryptor-live-code",
                              "production or execution-coverage source is missing")]
    header = header_path.read_text(encoding="utf-8", errors="strict")
    entry_raw = entry_path.read_text(encoding="utf-8", errors="strict")
    synth = strip_comments_and_literals(
        synth_path.read_text(encoding="utf-8", errors="strict"))
    test = test_path.read_text(encoding="utf-8", errors="strict")
    cmake = cmake_path.read_text(encoding="utf-8", errors="strict")
    document = document_path.read_text(encoding="utf-8", errors="strict")
    workflow = workflow_path.read_text(encoding="utf-8", errors="strict")
    violations: list[Violation] = []

    shift_region_match = re.search(
        r"VM_DECRYPTOR_SHIFT_PLANS\s*=\s*\{\{(.*?)\}\};", header,
        re.DOTALL)
    shifts = [] if not shift_region_match else [
        tuple(int(value) for value in triple)
        for triple in re.findall(
            r"\{\{\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\}\}",
            shift_region_match.group(1))
    ]
    expected_shifts = [
        (13, 7, 17), (7, 9, 13), (17, 11, 5), (5, 15, 21),
        (11, 5, 23), (19, 3, 7), (23, 13, 9), (3, 17, 25),
    ]
    if shifts != expected_shifts:
        violations.append(Violation(
            header_path, 1, "per-build-decryptor-plan",
            f"eight concrete xorshift triples changed or are not parseable: {shifts}"))
    if not re.search(
            r"VM_DECRYPTOR_INSTRUCTION_PLAN_COUNT\s*=\s*48u", header):
        violations.append(Violation(
            header_path, 1, "per-build-decryptor-plan",
            "dense 48-layout instruction-plan cardinality is missing"))

    entry_code = strip_comments_and_literals(entry_raw)
    decode_body = extract_function_body(
        entry_code, "DecryptorInstructionChoices DecodeDecryptorInstructionPlan")
    decode_normalized = re.sub(r"\s+", "", decode_body or "")
    for field in ("rotateInverse", "addInverse", "xorLoad",
                  "pointerIncrement", "counterDecrement"):
        if f"choices.{field}" not in decode_normalized:
            violations.append(Violation(
                entry_path, 1, "per-build-decryptor-plan",
                f"dense instruction plan does not drive {field}"))
    if decode_normalized.count("%2u") != 4 or \
       decode_normalized.count("%3u") != 1 or \
       decode_normalized.count("/2u") != 3 or \
       decode_normalized.count("/3u") != 1:
        violations.append(Violation(
            entry_path, 1, "per-build-decryptor-plan",
            "instruction plan is not the declared 2*2*2*3*2 Cartesian product"))

    build_body = extract_function_body(entry_code, "bool BuildDecryptor") or ""
    for field in ("rotateInverse", "addInverse", "xorLoad",
                  "pointerIncrement", "counterDecrement"):
        if f"instructionPlan.{field}" not in build_body:
            violations.append(Violation(
                entry_path, 1, "per-build-decryptor-live-code",
                f"generated live loop does not branch on {field}"))
    # Both architectures must contain every alternative byte form. These are
    # emitted bytes, not comments or symbol names.
    byte_forms = (
        "{0xC0,0xC8}", "{0xC0,0xC0}", "0x2C", "0x04",
        "{0x44,0x30,0xE0}", "{0x44,0x89,0xE2,0x30,0xD0}",
        "{0x48,0xFF,0xC6}", "{0x48,0x83,0xC6,0x01}",
        "{0x48,0x8D,0x76,0x01}", "{0xFF,0xCF}", "{0x83,0xEF,0x01}",
        "{0x32,0x45,0xEC}", "{0x8A,0x55,0xEC,0x30,0xD0}",
        "0x46", "{0x83,0xC6,0x01}", "{0x8D,0x76,0x01}",
        "{0xFF,0x4D,0xE4}", "{0x83,0x6D,0xE4,0x01}",
    )
    compact_entry = re.sub(r"\s+", "", entry_raw)
    for form in byte_forms:
        if re.sub(r"\s+", "", form) not in compact_entry:
            violations.append(Violation(
                entry_path, 1, "per-build-decryptor-live-code",
                f"emitted instruction form is missing: {form}"))
    validate_body = extract_function_body(
        entry_code,
        "bool VMHandlerEntryCodegen::ValidateDecryptorMutationEncoding") or ""
    for evidence in (
        "VM_DECRYPTOR_SHIFT_PLANS", "VM_DECRYPTOR_INSTRUCTION_PLAN_COUNT",
        "DecryptorShiftEvidence", "DecryptorInstructionEvidence",
        "CountByteSequence", "occurrences != 1u", "occurrences != 0u",
    ):
        if evidence not in validate_body:
            violations.append(Violation(
                entry_path, 1, "per-build-decryptor-live-code",
                f"exact active-loop byte validator omits {evidence}"))
    main_validate = extract_function_body(
        entry_code, "bool VMHandlerEntryCodegen::Validate") or ""
    if "ValidateDecryptorMutationEncoding" not in main_validate:
        violations.append(Violation(
            entry_path, 1, "per-build-decryptor-live-code",
            "production entry validation does not invoke exact-byte validation"))
    generate_body = extract_function_body(
        entry_code, "VMHandlerEntryCodegenResult VMHandlerEntryCodegen::Generate") or ""
    generate_normalized = re.sub(r"\s+", "", generate_body)
    if "BuildDecryptor(config,result)" not in generate_normalized or \
       "Validate(config,result,validationError)" not in generate_normalized:
        violations.append(Violation(
            entry_path, 1, "per-build-decryptor-live-code",
            "production generation does not build and exact-validate the decryptor"))

    derive_body = extract_function_body(synth, "CipherParameters DeriveCipher") or ""
    for evidence in (
        "VM_DECRYPTOR_SHIFT_PLANS", "VM_DECRYPTOR_INSTRUCTION_PLAN_COUNT",
        "parameters.shiftLeftA", "parameters.shiftRightB",
        "parameters.shiftLeftC", "parameters.instructionVariant",
    ):
        if evidence not in derive_body:
            violations.append(Violation(
                synth_path, 1, "per-build-decryptor-plan",
                f"per-build derivation omits {evidence}"))
    pack_body = extract_function_body(synth, "uint32_t PackCipherMutationPlan") or ""
    for field in ("shiftLeftA", "shiftRightB", "shiftLeftC",
                  "instructionVariant"):
        if field not in pack_body:
            violations.append(Violation(
                synth_path, 1, "per-build-decryptor-plan",
                f"published mutation plan omits {field}"))

    test_evidence = (
        "expectedPairs == 384u",
        "shiftPlan < VM_DECRYPTOR_SHIFT_PLANS.size()",
        "instructionPlan < VM_DECRYPTOR_INSTRUCTION_PLAN_COUNT",
        "generator.Generate(config)",
        "ValidateDecryptorMutationEncoding",
        "ExecutePlan(config, generated)",
        "activeLoops.size() == expectedPairs",
        "std::equal(plaintext.begin(), plaintext.end()",
        "gTrace.protectCalls == 2u", "gTrace.flushCalls == 1u",
        "requestedProtections[0] == 0x04u",
        "requestedProtections[1] == 0x20u",
        "firstShiftImmediate",
        "shift-immediate corruption escaped byte validation",
        "instruction-form corruption escaped byte validation",
    )
    for evidence in test_evidence:
        if evidence not in test:
            violations.append(Violation(
                test_path, 1, "per-build-decryptor-live-code",
                f"exhaustive native execution/negative evidence missing: {evidence}"))
    if "add_test(NAME vm_decryptor_coverage" not in cmake or \
       'LABELS "vm;decryptor;hard-gate"' not in cmake:
        violations.append(Violation(
            cmake_path, 1, "per-build-decryptor-live-code",
            "exhaustive decryptor execution test is not a registered hard gate"))
    for evidence in (
        "rotate(2) * add(2) * xor-load(2) * pointer(3) * counter(2) = 48",
        "384 active", "0x301-byte corpus", "RW -> instruction-cache flush -> RX",
    ):
        if evidence not in document:
            violations.append(Violation(
                document_path, 1, "per-build-decryptor-plan",
                f"decryptor combination/evidence manifest omits {evidence}"))
    if "platform: [x64, Win32]" not in workflow or \
       '-A ${{ matrix.platform }}' not in workflow:
        violations.append(Violation(
            workflow_path, 1, "per-build-decryptor-live-code",
            "Windows CI does not execute the hard gate on both x64 and x86"))
    return violations


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
    # fail if that count regresses from the historical 13-semantic baseline:
    # ADD/SUB/AND/OR/XOR/NOT/NEG/MUL/BIT_TEST/BIT_SET/BIT_RESET/SHL/SHR.
    real_variant_semantics = real_strategy_variant_semantics(semantic)
    exemption_names = set(K_VARIANT_NOT_APPLICABLE)
    if exemption_names != EXPECTED_K_VARIANT_NOT_APPLICABLE:
        violations.append(Violation(
            semantic_path, 1, "unauthorized-k-variant-exemption",
            "exemptions must be exactly CPUID/RDTSC/TRAP/EXIT; got " +
            ", ".join(sorted(exemption_names))))
    missing_required = (
        REQUIRED_REAL_STRATEGY_VARIANT_SEMANTICS - real_variant_semantics)
    if missing_required:
        violations.append(Violation(
            semantic_path, 1, "missing-required-real-k-variant-semantics",
            ", ".join(sorted(missing_required))))
    if len(real_variant_semantics) < MINIMUM_REAL_STRATEGY_VARIANT_SEMANTICS:
        violations.append(Violation(
            semantic_path, 1, "insufficient-real-k-variant-coverage",
            f"only {len(real_variant_semantics)} semantic(s) "
            f"({', '.join(sorted(real_variant_semantics)) or 'none'}) have a "
            "strategy-conditioned EmitBusinessCoreVariant branch with two "
            f"distinct emitted byte sequences in both x64 and x86; need >= "
            f"{MINIMUM_REAL_STRATEGY_VARIANT_SEMANTICS}, not just the ADD/SUB/"
            "AND/OR/XOR/NOT/NEG/MUL/BIT_TEST/BIT_SET/BIT_RESET historical baseline"))
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
    violations.extend(reference_runtime_fingerprint_gate(root))
    violations.extend(decryptor_coverage_gate(root))

    # 进度可见性：把当前真正达到双策略（两架构各自发出字节不同且非外围包装）
    # 的语义集合打印到 stdout，CI 摘要里一眼能看到"做到哪了、还差多少"，
    # 不用再问 AI。即便本次运行 FAIL 也照打，便于定位是覆盖率不足还是别的。
    semantic_path = root / "packer" / "transforms" / "vm_handler_semantic_codegen.cpp"
    real_variant_semantics = real_strategy_variant_semantics(
        code_by_path.get(semantic_path, ""))
    achieved = sorted(real_variant_semantics)
    print(
        f"[progress] 双策略语义覆盖 {len(achieved)}/{TARGET_REAL_STRATEGY_VARIANT_SEMANTICS}"
        f"（达标阈值 {MINIMUM_REAL_STRATEGY_VARIANT_SEMANTICS}）："
        f"{', '.join(achieved) if achieved else 'none'}"
    )
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
