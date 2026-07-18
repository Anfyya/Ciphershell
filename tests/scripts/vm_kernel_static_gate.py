#!/usr/bin/env python3
"""CipherShell 微操作 VM 内核源码硬门禁。

该脚本只读取源码，不运行加壳产物。它刻意使用否定式硬门禁：旧的定长
粗粒度 ISA、固定 runtime blob、集中解释循环或算术 flags bridge 只要仍在
生产路径中出现，就直接失败，避免双轨和 fallback 被误报为完成。
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
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

# 算术标志（CF/PF/AF/ZF/SF/OF）真正的产生/消费点：VM 内部的 pending-flags
# 记录、lastAlu 快照、materialize 例程本身，以及软件模型执行器里的等价物。
FLAG_STATE_IDENTIFIERS = {
    "VM_FLAG_CF", "VM_FLAG_PF", "VM_FLAG_AF", "VM_FLAG_ZF", "VM_FLAG_SF",
    "VM_FLAG_OF", "VM_FLAG_STATUS_MASK", "VM_FLAG_ARCHITECTURAL_MASK",
    "CtxPendingFlags", "CtxLastAlu", "CtxVirtualFlags", "CtxFlagMaterializer",
    "VM_LAZY_FLAGS_RECORD", "MaterializeFlags", "flagMaterializer",
    "BuildFlagMaterializer",
}

# ciphershellpro.md §8 点名的 VM_BRIDGE_SIMD/VM_BRIDGE_X87：本仓库里这两个
# v3 遗留操作码名字已经不存在（LEGACY_COARSE_OPCODES 早已禁止），真正在生产
# 路径里承担同一职责的是 AVX/x87 原生指令桥接机制——
# VMInstructionBridgeBuilder 生成的 thunk、VM_INSTRUCTION_BRIDGE_STATE、
# VM_MICRO_BRIDGE_AVX/X87 掩码位，以及 handler 里触发它的
# EmitX64/86BridgeExtended。检查必须落在这套真实机制上，而不是继续找一个
# 已经不存在的旧符号名字。
BRIDGE_STATE_IDENTIFIERS = {
    "VM_INSTRUCTION_BRIDGE_STATE", "VMInstructionBridgeBuilder",
    "VMInstructionBridgeLink", "usesAvx", "usesX87", "VM_MICRO_BRIDGE_AVX",
    "VM_MICRO_BRIDGE_X87", "VM_MICRO_BRIDGE_KNOWN_MASK",
    "VM_MICRO_BRIDGE_HIDDEN_REGISTER_MASK", "VM_MICRO_BRIDGE_LINKED",
    "Fxsave", "Fxrstor", "Xsave", "Xrstor", "extendedState",
    "extendedStateFlags", "EmitX64BridgeExtended", "EmitX86BridgeExtended",
    "VM_UOP_BRIDGE_EXTENDED", "nativeCallBridge", "CtxNativeCallBridge",
    "VM_NATIVE_CALL_STATE", "vm_native_call_bridge", "vm_instruction_bridge",
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


def subprocess_environment(
    source: Iterable[tuple[str, str]] | None = None,
    *,
    windows: bool | None = None,
) -> dict[str, str]:
    """Build an environment with one key per Windows case-folded name.

    Python dictionaries are case-sensitive even though a Windows environment
    block is not.  A runner that contributes both ``Path`` and ``PATH`` can
    therefore hand MSBuild two logically identical variables and trigger
    MSB6001 while it constructs a child process.  Normalizing Windows names to
    uppercase before *every* configure/build/probe subprocess makes the block
    unique without deleting any environment variable.
    """
    items = list(os.environ.items() if source is None else source)
    is_windows = os.name == "nt" if windows is None else windows
    if not is_windows:
        return dict(items)
    result: dict[str, str] = {}
    for key, value in items:
        result[key.upper()] = value
    # Keep this executable invariant next to construction rather than assuming
    # future refactors preserve it.
    if len(result) != len({key.casefold() for key in result}):
        raise RuntimeError("Windows subprocess environment is not case-unique")
    return result


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


ARITHMETIC_FLAG_TRANSFER_OPCODES = {0x9C, 0x9D, 0x9E, 0x9F}


def _modrm_encoded_length(data: list[int], index: int) -> int:
    """Return ModRM/SIB/displacement length, clamped to a literal Raw block.

    This is deliberately a small source-emission decoder rather than a search
    for byte values: 0x9c is a perfectly ordinary ModRM byte (for example in
    ``lea r11,[r15+rdx*8+disp32]``), and must never be treated as PUSHF.
    """
    if index >= len(data):
        return 0
    start = index
    modrm = data[index]
    index += 1
    mod = modrm >> 6
    rm = modrm & 7
    if mod != 3 and rm == 4 and index < len(data):
        sib = data[index]
        index += 1
        if mod == 0 and (sib & 7) == 5:
            index += 4
    elif mod == 0 and rm == 5:
        index += 4
    if mod == 1:
        index += 1
    elif mod == 2:
        index += 4
    return min(index, len(data)) - start


def _literal_instruction_shape(
    data: list[int], start: int,
) -> tuple[int, int]:
    """Return ``(instruction_length, opcode_index)`` for literal Raw bytes.

    The gate only needs enough decoding to distinguish opcode positions from
    ModRM/SIB/displacement/immediate positions. Unknown opcodes consume the
    remainder of that Raw emission (fail-safe against false PUSHF reports),
    while the instruction forms emitted by this code generator are covered by
    the tables below. Dynamic immediates emitted by a following U8/U32/U64 are
    naturally clamped at the end of this Raw block.
    """
    index = start
    legacy_prefixes = {
        0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65, 0x66, 0x67,
    }
    while index < len(data) and data[index] in legacy_prefixes:
        index += 1
    while index < len(data) and 0x40 <= data[index] <= 0x4F:
        index += 1
    if index >= len(data):
        return max(1, len(data) - start), index

    opcode_index = index
    opcode = data[index]
    index += 1
    has_modrm = False
    immediate = 0

    if opcode == 0x0F:
        if index >= len(data):
            return len(data) - start, opcode_index
        second = data[index]
        index += 1
        # Two-byte control/system opcodes without ModRM. Everything else used
        # by the production emitter (CMOVcc/SETcc/BT*/SHLD/SHRD/IMUL/MOVZX...)
        # has ModRM; near Jcc instead has a rel32 immediate.
        if 0x80 <= second <= 0x8F:
            immediate = 4
        elif second not in {
            0x05, 0x07, 0x0B, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
            0x77, 0xA0, 0xA1, 0xA2, 0xA8, 0xA9, 0xAA,
        }:
            has_modrm = True
    elif opcode in ARITHMETIC_FLAG_TRANSFER_OPCODES:
        pass
    elif opcode in range(0x70, 0x80) or opcode in {
        0x6A, 0xA8, 0xCD, 0xEB,
    }:
        immediate = 1
    elif opcode in {
        0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D,
        0x68, 0xA9, 0xE8, 0xE9,
    }:
        immediate = 4
    elif 0xB0 <= opcode <= 0xB7:
        immediate = 1
    elif 0xB8 <= opcode <= 0xBF:
        immediate = 4
    elif (
        opcode <= 0x3B and (opcode & 0x07) <= 3
    ) or opcode in {
        0x62, 0x63, 0x69, 0x6B,
        *range(0x80, 0x90),
        0xC0, 0xC1, 0xC6, 0xC7,
        0xD0, 0xD1, 0xD2, 0xD3,
        0xF6, 0xF7, 0xFE, 0xFF,
    }:
        has_modrm = True

    modrm = data[index] if has_modrm and index < len(data) else None
    if has_modrm:
        index += _modrm_encoded_length(data, index)
        if opcode in {0x6B, 0x80, 0x82, 0x83, 0xC0, 0xC1, 0xC6}:
            immediate = 1
        elif opcode in {0x69, 0x81, 0xC7}:
            immediate = 4
        elif opcode == 0xF6 and modrm is not None and ((modrm >> 3) & 7) <= 1:
            immediate = 1
        elif opcode == 0xF7 and modrm is not None and ((modrm >> 3) & 7) <= 1:
            immediate = 4
    elif opcode not in ARITHMETIC_FLAG_TRANSFER_OPCODES and opcode not in {
        *range(0x40, 0x60),
        *range(0x90, 0xA0),
        0x60, 0x61, 0x90, 0xC2, 0xC3, 0xC9, 0xCA, 0xCB,
        0xCC, 0xCE, 0xCF, 0xD7, 0xEC, 0xED, 0xEE, 0xEF,
        0xF4, 0xF5, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD,
    } and opcode != 0x0F and immediate == 0:
        return len(data) - start, opcode_index

    return max(1, min(len(data), index + immediate) - start), opcode_index


def _raw_flag_transfer_opcode_indices(data: list[int]) -> list[int]:
    """Locate 9C..9F only when they decode as an instruction opcode."""
    hits: list[int] = []
    index = 0
    while index < len(data):
        length, opcode_index = _literal_instruction_shape(data, index)
        if opcode_index < len(data) and \
                data[opcode_index] in ARITHMETIC_FLAG_TRANSFER_OPCODES:
            hits.append(opcode_index)
        index += max(1, length)
    return hits


def arithmetic_flag_transfer_emissions(code: str) -> list[tuple[int, str]]:
    """Find structured U8/Raw emission points for PUSHF/POPF/LAHF/SAHF."""
    hits: list[tuple[int, str]] = []
    u8_pattern = re.compile(
        r"\b[A-Za-z_]\w*\.U8\(\s*(0x9[cd-f])\s*\)", re.IGNORECASE)
    for match in u8_pattern.finditer(code):
        hits.append((match.start(1), f"U8({match.group(1)})"))

    raw_pattern = re.compile(
        r"\b[A-Za-z_]\w*\.Raw\s*\(\s*\{(?P<body>.*?)\}\s*\)",
        re.DOTALL)
    literal_pattern = re.compile(r"^\s*0x([0-9a-f]{1,2})(?:u)?\s*$", re.IGNORECASE)
    for match in raw_pattern.finditer(code):
        values: list[int] = []
        offsets: list[int] = []
        cursor = match.start("body")
        for item in match.group("body").split(","):
            literal = literal_pattern.fullmatch(item)
            if literal is None:
                values = []
                break
            values.append(int(literal.group(1), 16))
            value_match = re.search(r"0x[0-9a-f]{1,2}", item, re.IGNORECASE)
            offsets.append(cursor + (value_match.start() if value_match else 0))
            cursor += len(item) + 1
        for byte_index in _raw_flag_transfer_opcode_indices(values):
            hits.append((
                offsets[byte_index],
                f"Raw opcode 0x{values[byte_index]:02X} at byte {byte_index}",
            ))
    return sorted(hits)


def static_gate_internal_self_check() -> list[str]:
    """Exercise the two parsers whose false positives can disable CI itself."""
    errors: list[str] = []
    environment = subprocess_environment(
        [("Path", "first"), ("PATH", "second"), ("ComSpec", "cmd.exe")],
        windows=True,
    )
    if environment != {"PATH": "second", "COMSPEC": "cmd.exe"}:
        errors.append(
            "Windows environment folding did not remove the Path/PATH alias")

    # The first two 0x9c bytes are ModRM fields, not PUSHF.  The remaining
    # U8, leading Raw opcode, and second instruction in a multi-instruction
    # Raw block are real transfer opcodes and must all be found.
    sample = """
        c.Raw({0x4F,0x8D,0x9C,0xD7});
        c.Raw({0x4C,0x8D,0x9C,0x24});
        c.U8(0x9D);
        c.Raw({0x66,0x9E});
        c.Raw({0x90,0x9C});
    """
    details = [detail for _, detail in arithmetic_flag_transfer_emissions(sample)]
    if details != [
        "U8(0x9D)",
        "Raw opcode 0x9E at byte 1",
        "Raw opcode 0x9C at byte 1",
    ]:
        errors.append(
            "structured flag-transfer emission parser self-check failed: " +
            repr(details))
    return errors


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
                blank = "".join(
                    "\n" if ch == "\n" else " " for ch in call_host_body)
                arithmetic_code = arithmetic_code.replace(call_host_body, blank, 1)
        for offset, detail in arithmetic_flag_transfer_emissions(arithmetic_code):
            hits.append(Violation(
                path,
                arithmetic_code.count("\n", 0, offset) + 1,
                "arithmetic-flags-native-transfer-opcode",
                detail,
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


TOP_LEVEL_FUNCTION_RE = re.compile(
    r"^[A-Za-z_][\w:<>,\*&\s]*?\b([A-Za-z_]\w*)\s*\(([^;{]*)\)\s*"
    r"(?:const\s*)?(?:noexcept\s*)?\{",
    re.MULTILINE | re.DOTALL,
)


def extract_top_level_functions(code: str) -> list[tuple[str, int, str]]:
    """Enumerate every brace-matched function definition that starts at
    column 0, in source order, as (name, start_offset, body).  This
    codebase's actual formatting convention is that top-level function
    definitions are never indented and their bodies always are, so column-0
    reliably separates real function boundaries from nested blocks without
    needing a real C++ parser."""
    functions: list[tuple[str, int, str]] = []
    search_from = 0
    for match in TOP_LEVEL_FUNCTION_RE.finditer(code):
        if match.start() < search_from:
            continue
        line_start = code.rfind("\n", 0, match.start()) + 1
        if code[line_start:match.start()].strip(" "):
            continue
        depth = 1
        index = match.end()
        while index < len(code) and depth > 0:
            if code[index] == "{":
                depth += 1
            elif code[index] == "}":
                depth -= 1
            index += 1
        if depth != 0:
            continue
        functions.append((match.group(1), match.start(), code[match.end():index - 1]))
        search_from = index
    return functions


def split_switch_case_segments(body: str) -> list[str]:
    """Split a function body into one segment per `switch` case/default label
    (generalized beyond `switch (semantic)` -- this codebase also dispatches
    on things like `instruction.opcode`), plus whatever code sits outside
    any switch.  A single VM_UOP dispatcher legitimately touches both flag
    state (its ALU cases) and bridge state (its VM_UOP_BRIDGE_EXTENDED case)
    in the same function; checking the whole function body would flag that
    as a false co-occurrence, so real closure only makes sense evaluated
    case-by-case."""
    segments: list[str] = []
    outside = body
    for switch_match in re.finditer(r"switch\s*\([^)]*\)\s*\{", body):
        depth = 1
        index = switch_match.end()
        while index < len(body) and depth > 0:
            if body[index] == "{":
                depth += 1
            elif body[index] == "}":
                depth -= 1
            index += 1
        if depth != 0:
            continue
        switch_body = body[switch_match.end():index - 1]
        outside = outside.replace(body[switch_match.start():index], "")
        case_matches = list(re.finditer(
            r"(?:case\s+[A-Za-z_][\w:]*\s*:|default\s*:)", switch_body))
        if not case_matches:
            segments.append(switch_body)
            continue
        for position, case_match in enumerate(case_matches):
            end = (case_matches[position + 1].start()
                   if position + 1 < len(case_matches) else len(switch_body))
            segments.append(switch_body[case_match.end():end])
    segments.append(outside)
    return segments


def arithmetic_flags_bridge_closure_gate(root: Path) -> list[Violation]:
    """静态证明:CF/PF/AF/ZF/SF/OF 的产生或消费,在真正承担 handler 生成/
    差分执行职责的生产文件里,不存在任何直接依赖 AVX/x87 原生指令桥接
    (ciphershellpro.md §8 所称的 VM_BRIDGE_SIMD/VM_BRIDGE_X87)的代码路径。

    做法:把每个文件拆成顶层函数,再把每个函数按 switch case 拆成更细的
    代码段(否则像 EmitBusinessCoreVariant / ExecuteOne 这类同时覆盖全部
    VM_UOP 的大 switch,会在同一个函数体内同时看到 ALU 分支引用的 flag
    标识符和 VM_UOP_BRIDGE_EXTENDED 分支引用的 bridge 标识符,产生误报)。
    对每个代码段分别检查 FLAG_STATE_IDENTIFIERS 与 BRIDGE_STATE_IDENTIFIERS
    是否同时出现;只要同一段代码里两者都命中,就说明标志位的产生/消费和
    bridge 状态耦合在了一起,直接判违规。

    再叠加一条字节级正向证据:桥接 thunk 写入 VM_INSTRUCTION_BRIDGE_STATE.
    rflags 的值必须是编译期固定立即数 0x00000202(仅保留 x86 RFLAGS 位 1
    的架构常量和 IF),而不是从 VM 自己的 pending/lastAlu 标志状态加载——
    这样即使两边未来改用同一个标识符名字,数值层面的输入隔离依然可查。
    """
    semantic_path = root / "packer" / "transforms" / "vm_handler_semantic_codegen.cpp"
    entry_path = root / "packer" / "transforms" / "vm_handler_entry_codegen.cpp"
    bridge_builder_path = root / "packer" / "transforms" / "vm_instruction_bridge_builder.cpp"
    micro_semantics_path = root / "packer" / "vm" / "micro_semantics.cpp"
    paths = (semantic_path, entry_path, bridge_builder_path, micro_semantics_path)
    violations: list[Violation] = []
    for path in paths:
        if not path.is_file():
            violations.append(Violation(
                path, 1, "arithmetic-flags-bridge-closure",
                "required source file is missing"))
    if violations:
        return violations

    found_flag_evidence = False
    found_bridge_evidence = False
    for path in paths:
        code = strip_comments_and_literals(
            path.read_text(encoding="utf-8", errors="strict"))
        for name, start, body in extract_top_level_functions(code):
            for segment in split_switch_case_segments(body):
                tokens = set(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", segment))
                flag_hits = tokens & FLAG_STATE_IDENTIFIERS
                bridge_hits = tokens & BRIDGE_STATE_IDENTIFIERS
                if flag_hits:
                    found_flag_evidence = True
                if bridge_hits:
                    found_bridge_evidence = True
                if flag_hits and bridge_hits:
                    line = code.count("\n", 0, start) + 1
                    violations.append(Violation(
                        path, line, "arithmetic-flags-bridge-closure",
                        f"{name}: arithmetic-flag state {sorted(flag_hits)} "
                        f"and AVX/x87 bridge state {sorted(bridge_hits)} "
                        "co-occur in the same code path"))
    if violations:
        return violations
    if not found_flag_evidence or not found_bridge_evidence:
        violations.append(Violation(
            semantic_path, 1, "arithmetic-flags-bridge-closure",
            f"gate found no evidence to check against (flags={found_flag_evidence}, "
            f"bridge={found_bridge_evidence}) -- identifiers likely renamed "
            "out from under this gate"))
        return violations

    semantic_code = strip_comments_and_literals(
        semantic_path.read_text(encoding="utf-8", errors="strict"))
    rflags_seed_pattern = re.compile(
        r"c\.Raw\(\{0xB8,0x02,0x02,0x00,0x00\}\);"
        r"[A-Za-z0-9_]*StoreStack[QD]\(c,(?:stateBase\+)?"
        r"offsetof\(VM_INSTRUCTION_BRIDGE_STATE,rflags\),0\)")
    for function_name in ("void EmitX64BridgeExtended", "void EmitX86BridgeExtended"):
        body = extract_function_body(semantic_code, function_name)
        if body is None:
            violations.append(Violation(
                semantic_path, 1, "arithmetic-flags-bridge-closure",
                f"could not locate {function_name} to verify its rflags seed"))
            continue
        normalized = re.sub(r"\s+", "", body)
        if not rflags_seed_pattern.search(normalized):
            violations.append(Violation(
                semantic_path, 1, "arithmetic-flags-bridge-closure",
                f"{function_name} does not seed VM_INSTRUCTION_BRIDGE_STATE."
                "rflags with the fixed architectural constant 0x202 -- the "
                "bridged native instruction may be inheriting VM arithmetic "
                "flags as input"))
    return violations


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


def business_core_semantics(semantic_code: str) -> set[str]:
    """Return the exact semantic set declared by HasBusinessCoreVariant.

    Source-level ``if (strategy)`` counting is intentionally absent here.  It
    misses differences introduced through helpers and seed-derived immediates,
    and can be gamed by branches that never affect executable bytes.  The
    production validator below must re-emit both strategies and compare the
    resulting machine-code vectors; this parser locks the complete 54-semantic
    allow-list over which that executable check is required.
    """
    body = extract_function_body(semantic_code, "bool HasBusinessCoreVariant")
    if body is None:
        return set()
    return set(re.findall(r"case\s+(VM_UOP_[A-Z0-9_]+)\s*:", body))


def emitted_business_core_semantics(semantic_code: str) -> set[str]:
    """Return semantics with EmitBusinessCoreVariant cases on both arches."""
    body = extract_function_body(semantic_code, "bool EmitBusinessCoreVariant")
    if body is None:
        return set()
    switch_blocks = extract_switch_semantic_blocks(body)
    if len(switch_blocks) < 2:
        return set()
    per_arch: list[set[str]] = []
    for switch_body in switch_blocks:
        per_arch.append(set(case_segments(switch_body)))
    common = per_arch[0]
    for extra in per_arch[1:]:
        common &= extra
    return common


def strategy_reemission_evidence_errors(semantic_code: str) -> list[str]:
    """Check executable evidence for two strategies under one production config.

    The helper is production code, called fail-closed by the main result
    validator.  It must directly re-emit strategy 0 and 1, resolve both code
    buffers, reject empty output, and reject byte-identical output.  These are
    structural call/data-flow markers, not a count of strategy branches.
    """
    errors: list[str] = []
    helper = extract_function_body(
        semantic_code, "bool ValidateBusinessCoreStrategyReemission")
    if helper is None:
        return ["ValidateBusinessCoreStrategyReemission is missing"]
    normalized = re.sub(r"\s+", "", helper)
    unrolled_strategies = set(re.findall(
        r"EmitBusinessCoreVariant\([^;]*?,(0u|1u)\)", normalized))
    looped_strategies = (
        "std::array<std::vector<uint8_t>,2>" in normalized and
        re.search(
            r"for\(uint8_tstrategy=0;strategy<"
            r"static_cast<uint8_t>\(\w+\.size\(\)\);\+\+strategy\)",
            normalized,
        ) is not None and
        re.search(
            r"EmitBusinessCoreVariant\([^;]*?,strategy\)", normalized)
        is not None
    )
    if unrolled_strategies != {"0u", "1u"} and not looped_strategies:
        errors.append(
            "helper does not directly re-emit EmitBusinessCoreVariant for "
            "both strategy 0 and strategy 1")
    if "ConfigurePermutationPlans(code,config)" not in normalized or \
            "config.semantic,strategy" not in normalized:
        errors.append(
            "both strategy emissions are not bound to the same production config")
    minimum_per_buffer_checks = 1 if looped_strategies else 2
    if normalized.count(".Resolve(") < minimum_per_buffer_checks:
        errors.append("both strategy code buffers are not resolved")
    if normalized.count(".bytes.empty()") < minimum_per_buffer_checks:
        errors.append("both strategy byte vectors are not checked for emptiness")
    if looped_strategies and \
            "emitted[strategy]=std::move(code.bytes)" not in normalized:
        errors.append(
            "resolved strategy bytes are not retained in distinct result slots")
    if not (
        re.search(r"\w+\.bytes==\w+\.bytes", normalized) or
        re.search(r"\w+\[0\]==\w+\[1\]", normalized)
    ):
        errors.append(
            "strategy byte vectors are not compared byte-for-byte for equality")

    validator = extract_function_body(
        semantic_code, "bool ValidateVMHandlerSemanticVariantKernel")
    validator_normalized = re.sub(r"\s+", "", validator or "")
    fail_closed_call = re.search(
        r"if\(!ValidateBusinessCoreStrategyReemission\(config,[^;{}]*\)\)"
        r"\{[^{}]*returnfalse;[^{}]*\}",
        validator_normalized,
    )
    if fail_closed_call is None:
        errors.append(
            "ValidateVMHandlerSemanticVariantKernel does not call the "
            "re-emission helper fail-closed")
    return errors


def real_strategy_variant_semantics(semantic_code: str) -> set[str]:
    """Semantics backed by production two-strategy machine-code evidence."""
    if strategy_reemission_evidence_errors(semantic_code):
        return set()
    return business_core_semantics(semantic_code)


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


def _sipround(v0: int, v1: int, v2: int, v3: int, mask64: int) -> tuple[int, int, int, int]:
    def rotl64(x: int, b: int) -> int:
        x &= mask64
        return ((x << b) | (x >> (64 - b))) & mask64
    v0 = (v0 + v1) & mask64
    v1 = rotl64(v1, 13)
    v1 ^= v0
    v0 = rotl64(v0, 32)
    v2 = (v2 + v3) & mask64
    v3 = rotl64(v3, 16)
    v3 ^= v2
    v0 = (v0 + v3) & mask64
    v3 = rotl64(v3, 21)
    v3 ^= v0
    v2 = (v2 + v1) & mask64
    v1 = rotl64(v1, 17)
    v1 ^= v2
    v2 = rotl64(v2, 32)
    return v0, v1, v2, v3


def _siphash24(data: bytes, key: bytes, iv: tuple[int, int, int, int]) -> int:
    """Reference SipHash-2-4 (2 compression rounds, 4 finalization rounds),
    parameterized by the IV constants extracted from vm_crypto.c so this is
    provably the same primitive vm_siphash24() implements, not a lookalike."""
    mask64 = (1 << 64) - 1
    k0 = int.from_bytes(key[0:8], "little")
    k1 = int.from_bytes(key[8:16], "little")
    v0, v1, v2, v3 = (iv[0] ^ k0, iv[1] ^ k1, iv[2] ^ k0, iv[3] ^ k1)
    length = len(data)
    pos = 0
    while pos + 8 <= length:
        m = int.from_bytes(data[pos:pos + 8], "little")
        v3 ^= m
        v0, v1, v2, v3 = _sipround(v0, v1, v2, v3, mask64)
        v0, v1, v2, v3 = _sipround(v0, v1, v2, v3, mask64)
        v0 ^= m
        pos += 8
    tail = 0
    for i, b in enumerate(data[pos:]):
        tail |= b << (i * 8)
    final_block = tail | ((length & 0xFF) << 56)
    v3 ^= final_block
    v0, v1, v2, v3 = _sipround(v0, v1, v2, v3, mask64)
    v0, v1, v2, v3 = _sipround(v0, v1, v2, v3, mask64)
    v0 ^= final_block
    v2 ^= 0xFF
    for _ in range(4):
        v0, v1, v2, v3 = _sipround(v0, v1, v2, v3, mask64)
    return (v0 ^ v1 ^ v2 ^ v3) & mask64


def vm_group_seed_divergence_gate(root: Path) -> list[Violation]:
    """Re-derive the VM Variant Group seed arithmetic in Python from the
    literal constants/expressions parsed out of the source, then actually
    execute it for a battery of sample build seeds and function addresses.

    A gate that only greps for "vm_group" / "VMGroupRuntime" would pass even
    if every group silently reused group 0's seed (groups exist "in name"
    but produce identical opcode-map/dispatch-key entropy).  This instead
    proves the numeric divergence property: DeriveVMGroupSeed(seed, 0) must
    equal seed unchanged (single-group backward compatibility), every other
    group must produce a pairwise-distinct 32-byte seed AND a pairwise-
    distinct GetSeedFingerprint()-equivalent SipHash-2-4 value (the actual
    uint64 that becomes Translator/VMHandlerSynthesisConfig buildSeed), and
    AssignVMGroupId must actually spread candidate functions across more
    than one group rather than collapsing to a constant."""
    main_path = root / "packer" / "main.cpp"
    mutation_path = root / "packer" / "mutation" / "mutation_engine.cpp"
    crypto_path = root / "runtime" / "common" / "vm_crypto.c"
    violations: list[Violation] = []
    for path in (main_path, mutation_path, crypto_path):
        if not path.is_file():
            violations.append(Violation(path, 1, "vm-group-seed-divergence-gate",
                                        "required source file is missing"))
    if violations:
        return violations

    main_code = strip_comments_and_literals(
        main_path.read_text(encoding="utf-8", errors="strict"))
    mutation_code = strip_comments_and_literals(
        mutation_path.read_text(encoding="utf-8", errors="strict"))
    crypto_code = strip_comments_and_literals(
        crypto_path.read_text(encoding="utf-8", errors="strict"))

    mix_body = extract_function_body(main_code, "MixVMGroupSeed")
    derive_body = extract_function_body(main_code, "DeriveVMGroupSeed")
    assign_body = extract_function_body(main_code, "AssignVMGroupId")
    fingerprint_body = extract_function_body(
        mutation_code, "MutationEngine::GetSeedFingerprint")
    siphash_init_body = extract_function_body(crypto_code, "vm_siphash24_init")
    if None in (mix_body, derive_body, assign_body, fingerprint_body, siphash_init_body):
        return [Violation(main_path, 1, "vm-group-seed-divergence-gate",
                          "one or more seed-derivation functions were not found")]

    mix_norm = re.sub(r"\s+", "", mix_body or "")
    derive_norm = re.sub(r"\s+", "", derive_body or "")
    assign_norm = re.sub(r"\s+", "", assign_body or "")
    fingerprint_norm = re.sub(r"\s+", "", fingerprint_body or "")
    siphash_init_norm = re.sub(r"\s+", "", siphash_init_body or "")

    # 结构性证据：确认 groupId / functionEntryAddress 真的被混进了种子，
    # 不是带了参数却没用上；GetSeedFingerprint 真的把种子喂给 SipHash。
    structural_requirements = (
        (derive_norm, "if(groupId==0)returnbuildSeed", derive_body),
        (derive_norm, "static_cast<uint64_t>(groupId)<<32", derive_body),
        (assign_norm, "if(groupCount<=1)return0", assign_body),
        (assign_norm, "^functionEntryAddress^", assign_body),
        (assign_norm, "static_cast<uint32_t>(mixed%groupCount)", assign_body),
        (fingerprint_norm,
         "vm_siphash24(m_config.seed.data()+16,16,m_config.seed.data())",
         fingerprint_body),
    )
    for haystack, needle, _source in structural_requirements:
        if needle not in haystack:
            violations.append(Violation(
                main_path, 1, "vm-group-seed-divergence-gate",
                f"expected mixing expression missing: {needle}"))
    if violations:
        return violations

    # 只查子串"存在"挡不住"在真正逻辑前插一条提前 return 把它架空"这种
    # 破坏——substring 检查不关心控制流，插入的死代码同样会通过。用
    # return 语句计数钉死控制流形状：两个函数都必须恰好是"一个提前退出
    # 分支 + 一个真正计算后的 return"，多一个 return 就必然是分支被架空
    # 或逻辑被重写，必须先失败再排查。
    expected_return_count = 2
    if derive_norm.count("return") != expected_return_count:
        violations.append(Violation(
            main_path, 1, "vm-group-seed-divergence-gate",
            f"DeriveVMGroupSeed has {derive_norm.count('return')} return "
            f"statements, expected exactly {expected_return_count} "
            "(groupId==0 early-out + the real derivation) -- control flow "
            "may have been shadowed by an extra early return"))
    if assign_norm.count("return") != expected_return_count:
        violations.append(Violation(
            main_path, 1, "vm-group-seed-divergence-gate",
            f"AssignVMGroupId has {assign_norm.count('return')} return "
            f"statements, expected exactly {expected_return_count} "
            "(groupCount<=1 early-out + the real assignment) -- control flow "
            "may have been shadowed by an extra early return"))
    if violations:
        return violations

    # SipHash-2-4 IV 常量必须与标准实现一致，这样下面 Python 侧的重放
    # 才是同一个原语，而不是看起来像的另一套算法。
    expected_iv = (0x736F6D6570736575, 0x646F72616E646F6D,
                   0x6C7967656E657261, 0x7465646279746573)
    iv_matches = re.findall(r"0x([0-9A-Fa-f]{16})ULL", siphash_init_norm)
    if [int(value, 16) for value in iv_matches[:4]] != list(expected_iv):
        violations.append(Violation(
            crypto_path, 1, "vm-group-seed-divergence-gate",
            "vm_siphash24_init IV constants do not match the standard SipHash-2-4 IV"))
        return violations

    mask64 = (1 << 64) - 1
    multiplier_matches = re.findall(r"value\*=0x([0-9A-Fa-f]+)ULL", mix_norm)
    lane_tag_match = re.search(
        r"\^\(0x([0-9A-Fa-f]+)ULL\*\(lane\+1\)\)\^0x([0-9A-Fa-f]+)ULL", derive_norm)
    assign_tag_match = re.search(
        r"functionEntryAddress\^0x([0-9A-Fa-f]+)ULL", assign_norm)
    if len(multiplier_matches) != 2 or lane_tag_match is None or assign_tag_match is None:
        violations.append(Violation(
            main_path, 1, "vm-group-seed-divergence-gate",
            "could not extract avalanche/tag constants for numeric replay"))
        return violations
    mul_a, mul_b = (int(value, 16) for value in multiplier_matches)
    lane_multiplier = int(lane_tag_match.group(1), 16)
    derive_tag = int(lane_tag_match.group(2), 16)
    assign_tag = int(assign_tag_match.group(1), 16)

    def mix(value: int) -> int:
        value &= mask64
        value ^= value >> 33
        value = (value * mul_a) & mask64
        value ^= value >> 33
        value = (value * mul_b) & mask64
        value ^= value >> 33
        return value

    def derive_group_seed(seed: bytes, group_id: int) -> bytes:
        if group_id == 0:
            return seed
        out = bytearray(32)
        for lane in range(4):
            base = int.from_bytes(seed[lane * 8:lane * 8 + 8], "little")
            mixed = mix(base ^ ((group_id & mask64) << 32) ^
                        ((lane_multiplier * (lane + 1)) & mask64) ^ derive_tag)
            out[lane * 8:lane * 8 + 8] = mixed.to_bytes(8, "little")
        return bytes(out)

    def assign_group_id(seed: bytes, function_entry: int, group_count: int) -> int:
        if group_count <= 1:
            return 0
        base = int.from_bytes(seed[0:8], "little")
        mixed = mix(base ^ (function_entry & mask64) ^ assign_tag)
        return mixed % group_count

    def seed_fingerprint(seed: bytes) -> int:
        return _siphash24(seed[16:32], seed[0:16], expected_iv)

    # 固定种子的 PRNG 只是为了让每次 CI 跑出同一批样例，不代表种子本身
    # 弱——真正的 build seed 仍然来自 BCryptGenRandom。
    sample_rng = __import__("random").Random(0xC1DE5EED)
    sample_seeds = [
        bytes(sample_rng.getrandbits(8) for _ in range(32)) for _ in range(6)
    ]
    probe_group_count = 5
    for seed in sample_seeds:
        if derive_group_seed(seed, 0) != seed:
            violations.append(Violation(
                main_path, 1, "vm-group-seed-divergence-gate",
                "DeriveVMGroupSeed(seed, 0) is not identical to the build seed"))
            break
        derived = [derive_group_seed(seed, g) for g in range(probe_group_count)]
        if len(set(derived)) != len(derived):
            violations.append(Violation(
                main_path, 1, "vm-group-seed-divergence-gate",
                "two different vm_group ids derived the same 32-byte group seed"))
            break
        fingerprints = [seed_fingerprint(value) for value in derived]
        if len(set(fingerprints)) != len(fingerprints):
            violations.append(Violation(
                main_path, 1, "vm-group-seed-divergence-gate",
                "two different vm_group ids produced the same operand-codec "
                "seed fingerprint (the value that becomes Translator/"
                "VMHandlerSynthesisConfig buildSeed)"))
            break
    if violations:
        return violations

    seen_group_ids: set[int] = set()
    for address in range(0, 256 * 7, 7):
        seen_group_ids.add(
            assign_group_id(sample_seeds[0], address, probe_group_count))
    if len(seen_group_ids) < 3:
        violations.append(Violation(
            main_path, 1, "vm-group-seed-divergence-gate",
            f"AssignVMGroupId only produced {sorted(seen_group_ids)} across "
            f"256 sample function addresses with {probe_group_count} groups "
            "-- function-to-group assignment looks degenerate"))
    return violations


def dispatch_table_encoding_gate(root: Path) -> list[Violation]:
    """Numerically replay both production dispatch-table codecs.

    This gate extracts the real seed-domain/hash/key/rotate constants from the
    synthesizer, independently implements both forward and inverse transforms,
    and exercises them at 32- and 64-bit pointer widths.  It also pins the
    generated decoder to the inverse immediates and requires the Windows
    isolated native-differential test to execute both selected schemes.
    """
    synth_path = root / "packer" / "transforms" / "vm_handler_synthesizer.cpp"
    entry_path = root / "packer" / "transforms" / "vm_handler_entry_codegen.cpp"
    native_test_path = root / "tests" / "test_vm_native_differential.cpp"
    violations: list[Violation] = []
    for path in (synth_path, entry_path, native_test_path):
        if not path.is_file():
            violations.append(Violation(
                path, 1, "dispatch-table-codec-numeric-gate",
                "required source file is missing"))
    if violations:
        return violations

    synth = strip_comments_and_literals(
        synth_path.read_text(encoding="utf-8", errors="strict"))
    entry = strip_comments_and_literals(
        entry_path.read_text(encoding="utf-8", errors="strict"))
    native_test = strip_comments_and_literals(
        native_test_path.read_text(encoding="utf-8", errors="strict"))
    hash_body = extract_function_body(synth, "HashBytes")
    derive_body = extract_function_body(synth, "DeriveVMDispatchTableCodec")
    encode_body = extract_function_body(synth, "EncodeDispatchTableTarget")
    decode_body = extract_function_body(synth, "DecodeDispatchTableTarget")
    decoder_body = extract_function_body(entry, "bool BuildOperandDecoder")
    if None in (hash_body, derive_body, encode_body, decode_body, decoder_body):
        return [Violation(
            synth_path, 1, "dispatch-table-codec-numeric-gate",
            "one or more dispatch codec functions were not found")]

    hash_norm = re.sub(r"\s+", "", hash_body or "")
    derive_norm = re.sub(r"\s+", "", derive_body or "")
    encode_norm = re.sub(r"\s+", "", encode_body or "")
    decode_norm = re.sub(r"\s+", "", decode_body or "")
    decoder_norm = re.sub(r"\s+", "", decoder_body or "")
    native_test_norm = re.sub(r"\s+", "", native_test)

    initial_match = re.search(r"uint64_thash=([0-9]+)ULL\^domain", hash_norm)
    multiply_match = re.search(r"hash\*=([0-9]+)ULL", hash_norm)
    hash_shift_match = re.search(r"hash\^=hash>>([0-9]+)u", hash_norm)
    domain_match = re.search(
        r"kDispatchCodecDomain=0x([0-9A-Fa-f]+)ULL", derive_norm)
    key_match = re.search(
        r"\(material>>([0-9]+)u\)&0x([0-9A-Fa-f]+)ULL\)\|([0-9]+)u",
        derive_norm)
    rotate_match = re.search(
        r"\(\(material>>([0-9]+)u\)%([0-9]+)u\)\+([0-9]+)u",
        derive_norm)
    if None in (initial_match, multiply_match, hash_shift_match,
                domain_match, key_match, rotate_match):
        return [Violation(
            synth_path, 1, "dispatch-table-codec-numeric-gate",
            "could not extract the production codec derivation constants")]

    structural = (
        (derive_norm, "VMDispatchTableEncoding::XorKeyedTable",
         "dispatch-table-xor-keyed-numeric-gate"),
        (derive_norm, "VMDispatchTableEncoding::AddRotateKeyedTable",
         "dispatch-table-add-rotate-numeric-gate"),
        (encode_norm, "(targetOffset^codec.key)&mask",
         "dispatch-table-xor-keyed-numeric-gate"),
        (decode_norm, "(encodedTarget^codec.key)&mask",
         "dispatch-table-xor-keyed-numeric-gate"),
        (encode_norm, "(targetOffset+codec.key)&mask",
         "dispatch-table-add-rotate-numeric-gate"),
        (decode_norm, "encodedTarget,codec.rotate,pointerSize)-codec.key)&mask",
         "dispatch-table-add-rotate-numeric-gate"),
        (decoder_norm,
         "code.Raw({0x48,0x35});code.U32(config.dispatchTableCodec.key)",
         "dispatch-table-xor-keyed-numeric-gate"),
        (decoder_norm,
         "{0x48,0xC1,0xC8,config.dispatchTableCodec.rotate,0x48,0x2D}",
         "dispatch-table-add-rotate-numeric-gate"),
        (decoder_norm,
         "code.Raw({0x4C,0x01,0xF0,0x48,0x2D});code.U32(config.layout.dispatchTableOffset)",
         "dispatch-table-codec-runtime-base-gate"),
        (decoder_norm,
         "code.Raw({0x01,0xD8,0x2D});code.U32(config.layout.dispatchTableOffset)",
         "dispatch-table-codec-runtime-base-gate"),
    )
    for haystack, needle, rule in structural:
        if needle not in haystack:
            violations.append(Violation(
                entry_path if haystack == decoder_norm else synth_path,
                1, rule, f"production writer/decoder evidence missing: {needle}"))
    for evidence, rule in (
        ("TestDispatchTableEncodingSchemesExecuteNatively",
         "dispatch-table-codec-native-differential-gate"),
        ("XorKeyedTable",
         "dispatch-table-xor-keyed-numeric-gate"),
        ("AddRotateKeyedTable",
         "dispatch-table-add-rotate-numeric-gate"),
        ("RunDifferentialCase(function,translation,build,16,true",
         "dispatch-table-codec-native-differential-gate"),
    ):
        if evidence not in native_test_norm:
            violations.append(Violation(
                native_test_path, 1, rule,
                f"isolated native execution evidence missing: {evidence}"))
    if violations:
        return violations

    mask64 = (1 << 64) - 1
    initial = int(initial_match.group(1))
    multiplier = int(multiply_match.group(1))
    hash_shift = int(hash_shift_match.group(1))
    domain = int(domain_match.group(1), 16)
    key_shift = int(key_match.group(1))
    key_mask = int(key_match.group(2), 16)
    key_or = int(key_match.group(3))
    rotate_shift = int(rotate_match.group(1))
    rotate_modulus = int(rotate_match.group(2))
    rotate_add = int(rotate_match.group(3))

    def production_hash(seed: bytes) -> int:
        value = (initial ^ domain) & mask64
        for byte in seed:
            value ^= byte
            value = (value * multiplier) & mask64
            value ^= value >> hash_shift
        return value & mask64

    def rotl(value: int, count: int, bits: int) -> int:
        width_mask = (1 << bits) - 1
        count &= bits - 1
        value &= width_mask
        return value if count == 0 else (
            ((value << count) | (value >> (bits - count))) & width_mask)

    def rotr(value: int, count: int, bits: int) -> int:
        width_mask = (1 << bits) - 1
        count &= bits - 1
        value &= width_mask
        return value if count == 0 else (
            ((value >> count) | (value << (bits - count))) & width_mask)

    selected: set[int] = set()
    for seed_domain in range(1, 257):
        seed = bytes(
            ((seed_domain * 0x5D + index * 0x9B + (index * index)) & 0xFF)
            for index in range(32))
        material = production_hash(seed)
        scheme = material & 1
        selected.add(scheme)
        key = ((material >> key_shift) & key_mask) | key_or
        rotate = ((material >> rotate_shift) % rotate_modulus) + rotate_add
        if key == 0 or key > 0x7FFFFFFF or not (1 <= rotate <= 31):
            violations.append(Violation(
                synth_path, 1, "dispatch-table-codec-numeric-gate",
                f"derived invalid key/rotate for seed sample {seed_domain}"))
            break
        for bits in (32, 64):
            width_mask = (1 << bits) - 1
            for target in (0, 0x1000, 0x12345, 0x7FFFFF00):
                if scheme == 0:
                    encoded = (target ^ key) & width_mask
                    decoded = (encoded ^ key) & width_mask
                else:
                    encoded = rotl((target + key) & width_mask, rotate, bits)
                    decoded = (rotr(encoded, rotate, bits) - key) & width_mask
                if decoded != target or encoded == target:
                    rule = ("dispatch-table-xor-keyed-numeric-gate"
                            if scheme == 0 else
                            "dispatch-table-add-rotate-numeric-gate")
                    violations.append(Violation(
                        synth_path, 1, rule,
                        f"numeric replay failed: bits={bits} target={target:#x} "
                        f"encoded={encoded:#x} decoded={decoded:#x}"))
                    return violations
    if selected != {0, 1}:
        violations.append(Violation(
            synth_path, 1, "dispatch-table-codec-seed-selection-gate",
            "sampled build seeds did not select both production codecs"))
    return violations


def micro_op_heavy_ratio_statistical_gate(root: Path) -> list[Violation]:
    """ciphershellpro.md §8"双射抗性":静态度量"x86 指令 : 微操作"平均比
    ≥ 阈值，抽样确认无 1:1 粗粒度直译残留。

    tests/test_vm_micro_core.cpp 里已有的检查只在一两个手写的 2~5 条指令
    的玩具函数上验证过这个比例；那不是"有代表性的样本函数集合"，只是单个
    孤立测试点。这里做两件事：

    1. 结构性证明 Translator::FinalizeProgram 对 Heavy 密度真的 fail-closed
       ——ratio 不够就拒绝产出，而不是只记录不阻断。
    2. 实际构建并运行 tests/scripts/vm_micro_op_ratio_probe.cpp：它用真实
       的生产 Disassembler + Translator，对一批经汇编器验证过的、覆盖
       ALU/逻辑/移位/位测试/乘除/分支/循环/cmov/setcc/符号扩展/lea/栈/xchg
       的代表性 x86-64 函数字节做 Heavy 虚拟化，汇总真实的
       微操作数:原生指令数整体比例。Disassembler/Translator 都不触碰任何
       Windows API，所以这一步在 Linux 静态门禁 job 里就能真正跑通，不需要
       等 Windows-only 的 ctest。
    """
    translator_path = root / "packer" / "transforms" / "translator.cpp"
    probe_path = root / "tests" / "scripts" / "vm_micro_op_ratio_probe.cpp"
    probe_cmake_path = root / "packer" / "CMakeLists.txt"
    zydis_cmake_path = root / "third_party" / "zydis" / "CMakeLists.txt"
    for path in (translator_path, probe_path, probe_cmake_path):
        if not path.is_file():
            return [Violation(path, 1, "micro-op-heavy-ratio-statistical-gate",
                              "required source file is missing")]

    violations: list[Violation] = []

    # 第 1 步：结构性确认 fail-closed 逻辑真的在生产路径里，而不是只有
    # microOpRatio 字段被算出来但从未拦截任何东西。
    translator_code = strip_comments_and_literals(
        translator_path.read_text(encoding="utf-8", errors="strict"))
    finalize_body = extract_function_body(
        translator_code, "bool Translator::FinalizeProgram")
    finalize_norm = re.sub(r"\s+", "", finalize_body or "")
    required_fail_closed = (
        "if(result.density==VMMicroDensity::Heavy&&"
        "result.microOpRatio<static_cast<double>(m_config.heavyMinimumRatio)){"
        "returnfalse;}")
    if required_fail_closed not in finalize_norm:
        violations.append(Violation(
            translator_path, 1, "micro-op-heavy-ratio-statistical-gate",
            "Translator::FinalizeProgram no longer fail-closes a Heavy "
            "translation whose microOpRatio is below heavyMinimumRatio"))
    if "result.microOpCount=static_cast<uint32_t>(result.instructions.size())" \
            not in finalize_norm or \
       "result.microOpRatio=result.nativeInstructionCount==0" not in finalize_norm:
        violations.append(Violation(
            translator_path, 1, "micro-op-heavy-ratio-statistical-gate",
            "Translator::FinalizeProgram no longer computes microOpCount/"
            "microOpRatio from the real emitted instruction stream"))
    if violations:
        return violations

    # 第 2 步：真正构建并运行 probe，而不是只检查它的源码存在。
    if not zydis_cmake_path.is_file():
        return [Violation(
            zydis_cmake_path, 1, "micro-op-heavy-ratio-statistical-gate",
            "third_party/zydis submodule is not checked out -- run "
            "`git submodule update --init --recursive` before this gate "
            "can build the real Translator")]
    process_environment = subprocess_environment()
    environment_path = next(
        (value for key, value in process_environment.items()
         if key.casefold() == "path"),
        None,
    )
    cmake = shutil.which("cmake", path=environment_path)
    if cmake is None:
        return [Violation(
            probe_path, 1, "micro-op-heavy-ratio-statistical-gate",
            "cmake is not available -- cannot build the real Disassembler/"
            "Translator to measure the ratio on representative samples")]

    build_dir = root / "build_vm_micro_op_ratio_gate"
    configure = subprocess.run(
        [cmake, "-S", str(root), "-B", str(build_dir),
         "-DCMAKE_BUILD_TYPE=Release"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=300, env=process_environment)
    if configure.returncode != 0:
        return [Violation(
            probe_path, 1, "micro-op-heavy-ratio-statistical-gate",
            "cmake configure failed:\n" + configure.stdout[-4000:] +
            configure.stderr[-4000:])]

    build = subprocess.run(
        [cmake, "--build", str(build_dir),
         "--target", "vm_micro_op_ratio_probe", "--config", "Release", "-j"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=900, env=process_environment)
    if build.returncode != 0:
        return [Violation(
            probe_path, 1, "micro-op-heavy-ratio-statistical-gate",
            "building vm_micro_op_ratio_probe against the real Translator "
            "failed:\n" + build.stdout[-4000:] + build.stderr[-4000:])]

    # Single-config generators (Makefiles/Ninja) put the binary straight in
    # bin/; multi-config generators (Visual Studio) nest it under bin/<CONFIG>/
    # regardless of the -DCMAKE_BUILD_TYPE passed at configure time, since
    # that variable is a single-config-only concept and config is instead
    # selected by --config at build time.
    candidates = [
        build_dir / "bin" / "vm_micro_op_ratio_probe",
        build_dir / "bin" / "vm_micro_op_ratio_probe.exe",
        build_dir / "bin" / "Release" / "vm_micro_op_ratio_probe.exe",
        build_dir / "bin" / "Debug" / "vm_micro_op_ratio_probe.exe",
    ]
    exe = next((candidate for candidate in candidates if candidate.is_file()), None)
    if exe is None:
        return [Violation(
            probe_path, 1, "micro-op-heavy-ratio-statistical-gate",
            f"build succeeded but the probe executable was not found in any of: "
            + ", ".join(str(candidate) for candidate in candidates))]

    run = subprocess.run(
        [str(exe)], capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=120,
        env=process_environment)
    output = run.stdout + run.stderr
    aggregate_match = re.search(
        r"\[aggregate\] samples=(\d+) native=(\d+) micro=(\d+) "
        r"ratio=([\d.]+) threshold=(\d+)", output)
    if run.returncode != 0 or "VM_MICRO_RATIO_PROBE_PASS" not in output or \
            aggregate_match is None:
        return [Violation(
            probe_path, 1, "micro-op-heavy-ratio-statistical-gate",
            "representative-sample ratio probe did not pass:\n" + output[-4000:])]

    samples = int(aggregate_match.group(1))
    aggregate_ratio = float(aggregate_match.group(4))
    threshold = int(aggregate_match.group(5))
    if samples < 10:
        violations.append(Violation(
            probe_path, 1, "micro-op-heavy-ratio-statistical-gate",
            f"only {samples} representative samples produced statistics -- "
            "not enough to call this a representative sample set"))
    if aggregate_ratio < float(threshold):
        violations.append(Violation(
            probe_path, 1, "micro-op-heavy-ratio-statistical-gate",
            f"aggregate ratio {aggregate_ratio} across {samples} "
            f"representative samples is below the {threshold}:1 threshold"))
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

    # Lock the complete 54-business-semantic surface, then require production
    # code to re-emit strategy 0/1 under the same config and reject identical
    # machine code.  We deliberately do not count `if (strategy)` source
    # branches: helper-driven and seed-immediate variants defeat that heuristic,
    # while dead/byte-identical branches can falsely satisfy it.
    exemption_names = set(K_VARIANT_NOT_APPLICABLE)
    if exemption_names != EXPECTED_K_VARIANT_NOT_APPLICABLE:
        violations.append(Violation(
            semantic_path, 1, "unauthorized-k-variant-exemption",
            "exemptions must be exactly CPUID/RDTSC/TRAP/EXIT; got " +
            ", ".join(sorted(exemption_names))))
    implemented_semantics = business_core_semantics(semantic)
    missing_required = REQUIRED_REAL_STRATEGY_VARIANT_SEMANTICS - implemented_semantics
    unexpected = implemented_semantics - REQUIRED_REAL_STRATEGY_VARIANT_SEMANTICS
    if missing_required or unexpected:
        violations.append(Violation(
            semantic_path, 1, "business-k-variant-semantic-set-mismatch",
            "missing=[" + ", ".join(sorted(missing_required)) +
            "]; unexpected=[" + ", ".join(sorted(unexpected)) + "]"))
    emitted_semantics = emitted_business_core_semantics(semantic)
    missing_emission = implemented_semantics - emitted_semantics
    if missing_emission:
        violations.append(Violation(
            semantic_path, 1, "business-k-variant-emission-set-mismatch",
            "HasBusinessCoreVariant semantics missing from one or both "
            "EmitBusinessCoreVariant architecture switches: " +
            ", ".join(sorted(missing_emission))))
    if len(REQUIRED_REAL_STRATEGY_VARIANT_SEMANTICS) != \
            TARGET_REAL_STRATEGY_VARIANT_SEMANTICS:
        violations.append(Violation(
            semantic_path, 1, "business-k-variant-target-regressed",
            f"locked semantic set has "
            f"{len(REQUIRED_REAL_STRATEGY_VARIANT_SEMANTICS)} entries; expected "
            f"exactly {TARGET_REAL_STRATEGY_VARIANT_SEMANTICS}"))
    for detail in strategy_reemission_evidence_errors(semantic):
        violations.append(Violation(
            semantic_path, 1,
            "missing-executable-two-strategy-reemission-evidence", detail))
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
    self_check_errors = static_gate_internal_self_check()
    if self_check_errors:
        print("[FAIL] 静态门禁内部自检失败：", file=sys.stderr)
        for detail in self_check_errors:
            print(f"  {detail}", file=sys.stderr)
        return 2
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
    violations.extend(vm_group_seed_divergence_gate(root))
    violations.extend(dispatch_table_encoding_gate(root))
    violations.extend(arithmetic_flags_bridge_closure_gate(root))
    violations.extend(micro_op_heavy_ratio_statistical_gate(root))

    # 进度可见性：只有完整语义集合和生产双策略重发射证据同时存在，才把
    # 语义计入覆盖；源码里出现多少个 if(strategy) 不再参与门禁结论。
    semantic_path = root / "packer" / "transforms" / "vm_handler_semantic_codegen.cpp"
    real_variant_semantics = real_strategy_variant_semantics(
        code_by_path.get(semantic_path, ""))
    achieved = sorted(real_variant_semantics)
    print(
        f"[progress] 生产双策略重发射语义覆盖 "
        f"{len(achieved)}/{TARGET_REAL_STRATEGY_VARIANT_SEMANTICS}"
        f"（要求完整 {MINIMUM_REAL_STRATEGY_VARIANT_SEMANTICS}）："
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
