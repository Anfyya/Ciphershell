#!/usr/bin/env python3
"""ciphershellpro.md §8.1 "跨 seed 字节多样性防回退门禁" 校验:同一份输入用
两次独立构建（各自的 build seed 都来自 ciphershell.exe 内部
BCryptGenRandom，本脚本不覆盖、不注入固定种子），比较两次产物里 handler
机器码字节的相似度必须低于按架构分别校准的阈值，并且 opcode map / 分发键
（dispatch key）/ 微操作选择（variant selector）四个自检摘要必须两两不同。
只证明字节层面的多样性没有退化，不证明攻击者的分析框架/去虚拟化流程无法
跨产品复用，见 ciphershellpro.md §8.1 的完整边界说明。

这是 Windows-only 校验：ciphershell.exe 只处理 PE 输入，且这里比较的是
MSVC 工具链下的真实完整构建产物，不在非 Windows 环境下运行或伪造。CI 的
Windows job 负责实际调用本脚本（见 .github/workflows/ci.yml）。

本脚本对 DLL 与 EXE 各跑两次真实的 ciphershell.exe，并实际执行四个加壳
产物。打包器通过显式 --vm-handler-evidence sidecar 写出“本次正式
VMHandlerSynthesizer 生成、随后被正式 runtime 加密使用”的非 junk 明文
handler 体；sidecar 正文有独立摘要并与同次构建日志绑定。脚本按
(vm_group, semantic, K-variant) 对齐逐字节比较，随机密文和随机 junk 都不能
人为压低相似度。opcode map / 分发键 / 微操作选择摘要仍必须分别变化。
"""

from __future__ import annotations

import argparse
from collections import Counter
import math
import re
import struct
import subprocess
import sys
from pathlib import Path


RUNTIME_SECTION_RE = re.compile(
    r"VM_RUNTIME_SECTION vm_group=(\d+) rva=0x([0-9a-fA-F]+) "
    r"raw=0x([0-9a-fA-F]+) size=0x([0-9a-fA-F]+) entry=0x([0-9a-fA-F]+)"
)
RUNTIME_DIGESTS_RE = re.compile(
    r"VM_RUNTIME_DIGESTS vm_group=(\d+) opcode_map=0x([0-9a-fA-F]+) "
    r"handler_body=0x([0-9a-fA-F]+) dispatch_key=0x([0-9a-fA-F]+) "
    r"variant_selector=0x([0-9a-fA-F]+) "
    r"encrypted_handlers_offset=0x([0-9a-fA-F]+) "
    r"encrypted_handlers_size=0x([0-9a-fA-F]+)"
)
STATIC_CHECK_PASS_RE = re.compile(r"VM_STATIC_CHECK_PASS module=VMStaticLinkChecker vm_group=(\d+) records=(\d+)")
PLAINTEXT_DIGEST_RE = re.compile(
    r"VM_HANDLER_PLAINTEXT_DIGEST vm_group=(\d+) "
    r"digest=0x([0-9a-fA-F]+) handlers=(\d+) records=(\d+)"
)
VM_RECORD_RE = re.compile(
    r"VM_RECORD vm_group=(\d+) function_rva=0x([0-9a-fA-F]+) "
    r"original_size=0x([0-9a-fA-F]+) "
    r"trampoline_rva=0x([0-9a-fA-F]+) "
    r"trampoline_size=0x([0-9a-fA-F]+) patch_type=([^ ]+) "
    r"bytecode_offset=0x([0-9a-fA-F]+) "
    r"bytecode_size=0x([0-9a-fA-F]+) "
    r"guest_stack_size=0x([0-9a-fA-F]+) opcode_count=(\d+)"
)
RETURN_FLAGS_RE = re.compile(
    r"VM_RETURN_FLAGS mask=0x([0-9a-fA-F]+) "
    r"values=0x([0-9a-fA-F]+),0x([0-9a-fA-F]+),0x([0-9a-fA-F]+)"
)
RUNTIME_RESULT_RE = re.compile(
    r"VM_RUNTIME_RESULT add=(-?\d+) sub=(-?\d+) max_ab=(-?\d+) "
    r"max_ba=(-?\d+) zero_true=(-?\d+) zero_false=(-?\d+) "
    r"local=(-?\d+) ptr_owned=(\d+) ptr_initial=(-?\d+) "
    r"read_initial=(-?\d+) write_old1=(-?\d+) ptr_after_write=(-?\d+) "
    r"read_after_write=(-?\d+) write_old2=(-?\d+) ptr_final=(-?\d+) "
    r"read_final=(-?\d+) flags_sub=(-?\d+)"
)
TRACE_HEADER_RE = re.compile(
    r"VM_RUNTIME_TRACE_HEADER group=(\d+) architecture=(32|64) "
    r"trace_rva=0x([0-9a-fA-F]+) capacity=(\d+) count=(\d+) "
    r"overflow=(\d+) build_id=([0-9a-fA-F]{32})"
)
TRACE_EVENT_RE = re.compile(
    r"VM_RUNTIME_TRACE_EVENT group=(\d+) sequence=(\d+) "
    r"function_rva=0x([0-9a-fA-F]+) "
    r"bytecode_end=0x([0-9a-fA-F]+) semantic=(\d+) variant=(\d+)"
)
ABI_RESULT_RE = re.compile(
    r"VM_ABI_RESULT architecture=(32|64) packed=(0|1) "
    r"stack_delta=(-?\d+) gpr=(\d+)/(\d+) xmm=(\d+)/(\d+) return=(-?\d+)"
)
UNWIND_RESULT_RE = re.compile(
    r"VM_UNWIND_RESULT architecture=64 metadata=1 lookup=4/4 "
    r"body=1 lea=1 pop=1 ret=1 gpr=8/8 xmm=10/10"
)
STDCALL_RESULT_RE = re.compile(
    r"VM_X86_STDCALL_RESULT packed=(0|1) metadata=(0|1) ret_imm16=8"
)
TARGET_EXPORT_NAMES = {
    "add", "sub2", "max2", "is_zero", "local1",
    "relocated_ptr", "relocated_read", "relocated_write",
}

# Independent per-(vm_group,semantic,K) pair ceilings.  The aggregate
# similarity below is a Dice score pooled over every live handler pair
# (`pairs` in the printed line), so it is a population mean: it can stay
# comfortably under its own threshold while one specific handler pair is far
# more similar across the two seeds than that average suggests.  These
# ceilings gate `max_pair_similarity` independently so a single degenerate
# handler cannot hide behind a healthy mean.
#
# Values are calibrated from 3 independent real-seed runs each on x64 and
# Win32 (12 EXE/DLL samples total; see codex_change.log v2.7.2) rather than
# a single sample, because max_pair is a max-over-~64-72-pairs statistic and
# is measurably noisier run-to-run than the aggregate it sits next to: the
# worst observed core_variant pair alone ranged 0.39-0.52 across 3 x64 runs
# with no code change in between. Ceilings sit well above the observed
# range (not just above one sample) so the check has real teeth against a
# future regression without being flaky against that already-measured
# seed-to-seed spread:
#   business_core max_pair observed range across all runs: 0.38-0.41
#   core_variant  max_pair observed range across all runs: 0.37-0.52
#   codec         max_pair observed range across all runs: 0.00-0.19
#   encrypted_handlers max_pair observed: ~0.0001 (ciphertext; stays ~0)
MAX_PAIR_CEILINGS = {
    "business_core": 0.55,
    "core_variant": 0.65,
    "codec": 0.30,
    "encrypted_handlers": 0.15,
}


class GateFailure(Exception):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ciphershell", type=Path, required=True,
                        help="path to the built ciphershell(.exe) packer")
    parser.add_argument("--sample", type=Path, required=True,
                        help="path to the sample PE input to pack twice")
    parser.add_argument("--runner", type=Path, required=True,
                        help="same-architecture MSVC runner that executes the packed DLL")
    parser.add_argument("--exe-sample", type=Path, required=True,
                        help="same-architecture MSVC EXE whose exported VM targets execute in main")
    parser.add_argument("--workdir", type=Path, required=True,
                        help="scratch directory for the two build outputs")
    parser.add_argument("--config", type=Path, required=True,
                        help="toml config forcing [vm].enabled=true and a "
                             "single variant_group_count=1 (group id must be "
                             "comparable across two independently-seeded "
                             "builds; the default adaptive group count "
                             "assigns the same candidate function to a "
                             "different group id per build)")
    parser.add_argument(
        "--similarity-threshold", type=float, default=0.15,
        help="legacy alias for the delivered encrypted-handler threshold; "
             "values above the 0.15 hard ceiling are rejected")
    parser.add_argument(
        "--encrypted-similarity-threshold", type=float,
        help="max delivered encrypted-handler 4-gram Dice similarity "
             "(default: --similarity-threshold, hard ceiling: 0.15)")
    parser.add_argument(
        "--codec-similarity-threshold", type=float, default=0.15,
        help="max persistent value-codec 4-gram Dice similarity "
             "(hard ceiling: 0.15)")
    parser.add_argument(
        "--business-core-similarity-threshold", type=float, required=True,
        help="max business-lowering 4-gram Dice similarity after removing "
             "codec ranges (hard ceiling: 0.32). This is an anti-regression "
             "baseline measured separately per target architecture (see "
             "codex_change.log v2.7.2), not a validated attacker-difficulty "
             "bound, so it has no single shared default: the caller "
             "(tests/CMakeLists.txt) must pass the value for the "
             "architecture actually being built")
    parser.add_argument(
        "--core-variant-similarity-threshold", type=float, default=0.35,
        help="max core-variant 4-gram Dice similarity "
             "(hard ceiling: 0.35)")
    return parser.parse_args()


def run_build(ciphershell: Path, sample: Path, output: Path, config: Path,
              evidence: Path) -> str:
    output.unlink(missing_ok=True)
    evidence.unlink(missing_ok=True)
    proc = subprocess.run(
        [str(ciphershell), str(sample), "-o", str(output), "-c", str(config),
         "--vm-handler-evidence", str(evidence)],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=600)
    log = proc.stdout + proc.stderr
    if proc.returncode != 0:
        raise GateFailure(
            f"ciphershell build failed (exit={proc.returncode}) writing "
            f"{output}:\n{log}")
    if not output.is_file():
        raise GateFailure(f"ciphershell reported success but {output} was not created:\n{log}")
    if not evidence.is_file():
        raise GateFailure(
            f"ciphershell reported success but plaintext handler evidence "
            f"{evidence} was not created:\n{log}")
    return log


def parse_return_flags(log: str, output: Path) -> tuple[int, int, int, int]:
    matches = RETURN_FLAGS_RE.findall(log)
    if len(matches) != 1:
        raise GateFailure(
            f"runtime did not publish exactly one returned-flags record for "
            f"{output}:\n{log}")
    return tuple(int(value, 16) for value in matches[0])


def parse_runtime_result(log: str, output: Path) -> tuple[int, ...]:
    matches = RUNTIME_RESULT_RE.findall(log)
    if len(matches) != 1:
        raise GateFailure(
            f"runtime did not publish exactly one deterministic export/side-"
            f"effect result for {output}:\n{log}")
    return tuple(int(value) for value in matches[0])


def validate_abi_evidence(log: str, output: Path, expect_packed: bool) -> None:
    matches = ABI_RESULT_RE.findall(log)
    if len(matches) != 1:
        raise GateFailure(
            f"runtime did not publish exactly one ABI result for {output}:\n{log}")
    architecture, packed, stack_delta, gpr_ok, gpr_total, xmm_ok, \
        xmm_total, returned = (int(value) for value in matches[0])
    expected_packed = 1 if expect_packed else 0
    expected_return = 0x12345678 - 0x10203040
    if packed != expected_packed or stack_delta != 0 or \
            returned != expected_return:
        raise GateFailure(
            f"runtime ABI result is not bound to the requested raw/packed "
            f"execution for {output}: {matches[0]}")
    if architecture == 64:
        if (gpr_ok, gpr_total, xmm_ok, xmm_total) != (8, 8, 10, 10):
            raise GateFailure(f"x64 nonvolatile ABI evidence failed for {output}")
        unwind_count = len(UNWIND_RESULT_RE.findall(log))
        if unwind_count != (1 if expect_packed else 0) or \
                STDCALL_RESULT_RE.search(log):
            raise GateFailure(
                f"x64 packed unwind evidence is missing, duplicated, or mixed "
                f"with x86 evidence for {output}")
    elif architecture == 32:
        if (gpr_ok, gpr_total, xmm_ok, xmm_total) != (4, 4, 0, 0):
            raise GateFailure(f"x86 nonvolatile ABI evidence failed for {output}")
        stdcall_matches = STDCALL_RESULT_RE.findall(log)
        expected_stdcall = (str(expected_packed), str(expected_packed))
        if len(stdcall_matches) != 1 or stdcall_matches[0] != expected_stdcall or \
                UNWIND_RESULT_RE.search(log):
            raise GateFailure(
                f"x86 stdcall RET 8 evidence is missing, malformed, or mixed "
                f"with x64 evidence for {output}")
    else:
        raise GateFailure(f"unsupported ABI evidence architecture for {output}")


def run_packed_runtime(
        runner: Path, output: Path, expect_trace: bool = False
        ) -> tuple[tuple[int, int, int, int], tuple[int, ...], str]:
    command = [str(runner)]
    if expect_trace:
        command.append("--expect-trace")
    command.append(str(output))
    proc = subprocess.run(
        command, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=60)
    log = proc.stdout + proc.stderr
    if proc.returncode != 0 or "VM_PACKED_RUNTIME_PASS" not in log:
        raise GateFailure(
            f"packed VM runtime execution failed (exit={proc.returncode}) for "
            f"{output}:\n{log}")
    validate_abi_evidence(log, output, expect_trace)
    return parse_return_flags(log, output), parse_runtime_result(log, output), log


def run_packed_exe(
        runner: Path, output: Path, expect_trace: bool = False
        ) -> tuple[tuple[int, int, int, int], tuple[int, ...], str]:
    proc = subprocess.run(
        [str(runner), "--exe-trace" if expect_trace else "--exe", str(output)],
        capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=60)
    log = proc.stdout + proc.stderr
    if proc.returncode != 0 or "VM_PACKED_EXE_RUNTIME_PASS" not in log or \
            "VM_FORCE_RELOCATE_POLICY_APPLIED" not in log:
        raise GateFailure(
            f"packed VM EXE execution failed (exit={proc.returncode}) for "
            f"{output}:\n{log}")
    validate_abi_evidence(log, output, expect_trace)
    return parse_return_flags(log, output), parse_runtime_result(log, output), log


def assert_forced_relocation_exe_layout(output: Path) -> None:
    data = output.read_bytes()
    if len(data) < 0x100:
        raise GateFailure(f"packed EXE is too small to be a PE: {output}")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    optional = pe_offset + 4 + 20
    if pe_offset > len(data) - 24 or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise GateFailure(f"packed EXE has invalid NT headers: {output}")
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic == 0x10B:
        image_base = struct.unpack_from("<I", data, optional + 28)[0]
        directories = optional + 96
    elif magic == 0x20B:
        image_base = struct.unpack_from("<Q", data, optional + 24)[0]
        directories = optional + 112
    else:
        raise GateFailure(f"packed EXE has unknown optional-header magic: {output}")
    if optional > len(data) - 72 or directories > len(data) - 48:
        raise GateFailure(f"packed EXE optional header is truncated: {output}")
    image_size = struct.unpack_from("<I", data, optional + 56)[0]
    dll_characteristics = struct.unpack_from("<H", data, optional + 70)[0]
    reloc_rva, reloc_size = struct.unpack_from("<II", data, directories + 5 * 8)
    if image_size == 0 or image_base == 0:
        raise GateFailure(f"packed EXE has an invalid image range: {output}")
    if dll_characteristics & 0x40 == 0 or reloc_rva == 0 or reloc_size == 0:
        raise GateFailure(
            f"packed EXE cannot be relocated by the OS loader: {output}")


def parse_pe_exports(path: Path) -> dict[str, int]:
    """Parse the real PE export name->RVA table without third-party modules."""
    data = path.read_bytes()
    if len(data) < 0x100:
        raise GateFailure(f"PE is too small for an export table: {path}")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset > len(data) - 24 or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise GateFailure(f"invalid PE headers while reading exports: {path}")
    file_header = pe_offset + 4
    section_count = struct.unpack_from("<H", data, file_header + 2)[0]
    optional_size = struct.unpack_from("<H", data, file_header + 16)[0]
    optional = file_header + 20
    if optional > len(data) or optional_size > len(data) - optional:
        raise GateFailure(f"truncated PE optional header: {path}")
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic == 0x10B:
        directory_offset = optional + 96
    elif magic == 0x20B:
        directory_offset = optional + 112
    else:
        raise GateFailure(f"unknown PE optional-header magic: {path}")
    if directory_offset > optional + optional_size - 8:
        raise GateFailure(f"PE has no export data directory: {path}")
    export_rva, export_size = struct.unpack_from("<II", data, directory_offset)
    section_table = optional + optional_size
    if section_count == 0 or section_count > 96 or \
            section_table > len(data) or section_count * 40 > len(data) - section_table:
        raise GateFailure(f"invalid PE section table: {path}")
    sections: list[tuple[int, int, int, int]] = []
    for index in range(section_count):
        entry = section_table + index * 40
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
            "<IIII", data, entry + 8)
        sections.append((virtual_address, max(virtual_size, raw_size),
                         raw_offset, raw_size))

    def rva_to_offset(rva: int, size: int) -> int:
        if rva < 0 or size < 0:
            raise GateFailure(f"negative export-table range in {path}")
        for virtual_address, span, raw_offset, raw_size in sections:
            if rva < virtual_address:
                continue
            delta = rva - virtual_address
            if delta <= span and size <= span - delta and \
                    delta <= raw_size and size <= raw_size - delta and \
                    raw_offset <= len(data) and delta + size <= len(data) - raw_offset:
                return raw_offset + delta
        raise GateFailure(
            f"export-table RVA 0x{rva:x}+0x{size:x} is not file-backed in {path}")

    if export_rva == 0 or export_size < 40:
        raise GateFailure(f"PE has no real export directory: {path}")
    export_offset = rva_to_offset(export_rva, 40)
    function_count, name_count = struct.unpack_from("<II", data, export_offset + 20)
    functions_rva, names_rva, ordinals_rva = struct.unpack_from(
        "<III", data, export_offset + 28)
    if function_count == 0 or name_count == 0 or \
            function_count > 65536 or name_count > 65536:
        raise GateFailure(f"invalid PE export counts: {path}")
    functions = rva_to_offset(functions_rva, function_count * 4)
    names = rva_to_offset(names_rva, name_count * 4)
    ordinals = rva_to_offset(ordinals_rva, name_count * 2)
    exports: dict[str, int] = {}
    for index in range(name_count):
        name_rva = struct.unpack_from("<I", data, names + index * 4)[0]
        name_offset = rva_to_offset(name_rva, 1)
        end = data.find(b"\0", name_offset, min(len(data), name_offset + 4096))
        if end < 0:
            raise GateFailure(f"unterminated PE export name: {path}")
        try:
            name = data[name_offset:end].decode("ascii")
        except UnicodeDecodeError as exc:
            raise GateFailure(f"non-ASCII PE export name in {path}") from exc
        ordinal = struct.unpack_from("<H", data, ordinals + index * 2)[0]
        if ordinal >= function_count or name in exports:
            raise GateFailure(f"invalid or duplicate PE export in {path}: {name}")
        function_rva = struct.unpack_from("<I", data, functions + ordinal * 4)[0]
        if function_rva == 0 or export_rva <= function_rva < export_rva + export_size:
            raise GateFailure(f"null/forwarded PE export is not executable: {path}:{name}")
        exports[name] = function_rva
    return exports


def exact_target_export_rvas(path: Path) -> set[int]:
    exports = parse_pe_exports(path)
    if set(exports) != TARGET_EXPORT_NAMES:
        raise GateFailure(
            f"PE export names are not the fixed eight-target contract in {path}: "
            f"actual={sorted(exports)} expected={sorted(TARGET_EXPORT_NAMES)}")
    rvas = {exports[name] for name in TARGET_EXPORT_NAMES}
    if len(rvas) != len(TARGET_EXPORT_NAMES):
        raise GateFailure(f"fixed target exports alias the same RVA in {path}")
    return rvas


def parse_groups(log: str) -> dict[int, dict[str, int]]:
    """Return {vm_group: {rva, raw, size, entry, opcode_map, handler_body,
    dispatch_key, variant_selector, encrypted_handlers_offset,
    encrypted_handlers_size, records}} merged from all diagnostic lines for
    that group. A group missing any required field is dropped -- callers
    must treat an empty result as "VM protection never actually applied",
    not silently skip the comparison."""
    groups: dict[int, dict[str, int]] = {}
    for match in RUNTIME_SECTION_RE.finditer(log):
        group = int(match.group(1))
        entry = groups.setdefault(group, {})
        entry["raw"] = int(match.group(3), 16)
        entry["size"] = int(match.group(4), 16)
    for match in RUNTIME_DIGESTS_RE.finditer(log):
        group = int(match.group(1))
        entry = groups.setdefault(group, {})
        entry["opcode_map"] = int(match.group(2), 16)
        entry["handler_body"] = int(match.group(3), 16)
        entry["dispatch_key"] = int(match.group(4), 16)
        entry["variant_selector"] = int(match.group(5), 16)
        entry["encrypted_handlers_offset"] = int(match.group(6), 16)
        entry["encrypted_handlers_size"] = int(match.group(7), 16)
    for match in STATIC_CHECK_PASS_RE.finditer(log):
        group = int(match.group(1))
        entry = groups.setdefault(group, {})
        entry["records"] = int(match.group(2))
    for match in PLAINTEXT_DIGEST_RE.finditer(log):
        group = int(match.group(1))
        entry = groups.setdefault(group, {})
        entry["semantic_plaintext_digest"] = int(match.group(2), 16)
        entry["semantic_handler_count"] = int(match.group(3))
        entry["semantic_record_count"] = int(match.group(4))
    for match in VM_RECORD_RE.finditer(log):
        group = int(match.group(1))
        entry = groups.setdefault(group, {})
        entry["vm_records"] = entry.get("vm_records", 0) + 1
        record_rvas = entry.setdefault("record_rvas", set())
        if not isinstance(record_rvas, set):
            raise GateFailure("internal VM record-RVA accumulator corruption")
        function_rva = int(match.group(2), 16)
        if function_rva in record_rvas:
            entry["invalid_vm_records"] = entry.get("invalid_vm_records", 0) + 1
        record_rvas.add(function_rva)
        original_size = int(match.group(3), 16)
        trampoline_rva = int(match.group(4), 16)
        trampoline_size = int(match.group(5), 16)
        patch_type = match.group(6)
        bytecode_size = int(match.group(8), 16)
        guest_stack_size = int(match.group(9), 16)
        opcode_count = int(match.group(10))
        if (original_size == 0 or trampoline_rva == 0 or
                trampoline_size == 0 or patch_type == "none" or
                bytecode_size == 0 or guest_stack_size == 0 or
                opcode_count == 0):
            entry["invalid_vm_records"] = entry.get("invalid_vm_records", 0) + 1
    required = ("raw", "size", "opcode_map", "handler_body", "dispatch_key",
                "variant_selector", "encrypted_handlers_offset",
                "encrypted_handlers_size", "records", "vm_records",
                "record_rvas",
                "semantic_plaintext_digest", "semantic_handler_count",
                "semantic_record_count")
    complete = {g: fields for g, fields in groups.items()
                if all(key in fields for key in required)}
    return complete


def semantic_evidence_digest(material: bytes) -> int:
    # CSVMPLN3 binds the exact production core plus every mandatory persistent
    # value-codec range.  Core and codec are scored separately below; neither
    # unreachable storage islands nor one large segment can dilute the other.
    domain = 0x4353564D504C4E33
    mask = (1 << 64) - 1
    value = 1469598103934665603 ^ domain
    for byte in material:
        value ^= byte
        value = (value * 1099511628211) & mask
        value ^= value >> 29
    return value if value != 0 else domain | 1


def record_bytecode_digest(function_rva: int, bytecode: bytes) -> int:
    domain = 0x4353564D52454332 ^ function_rva
    mask = (1 << 64) - 1
    value = 1469598103934665603 ^ domain
    for byte in bytecode:
        value ^= byte
        value = (value * 1099511628211) & mask
        value ^= value >> 29
    return value if value != 0 else domain | 1


def load_plaintext_evidence(
        path: Path) -> tuple[int, dict[int, dict[str, object]]]:
    """Read the versioned sidecar written by the actual pack run.

    Only synthesizer-published semantic-body ranges are present: randomized
    junk handlers and the jump-over opaque islands in each handler's storage
    envelope are deliberately excluded.  For every semantic referenced by
    bytecode, the sidecar must contain all four production K variants.  Ranges
    are compared independently by (semantic, K), avoiding false mismatch from
    one variable-length handler shifting every handler that follows it.
    """
    data = path.read_bytes()
    cursor = 0

    def take(size: int) -> bytes:
        nonlocal cursor
        if size < 0 or cursor > len(data) or size > len(data) - cursor:
            raise GateFailure(f"truncated plaintext handler evidence: {path}")
        value = data[cursor:cursor + size]
        cursor += size
        return value

    if take(8) != b"CSVMPLN3":
        raise GateFailure(f"invalid plaintext handler evidence magic: {path}")
    architecture, group_count = struct.unpack("<II", take(8))
    if architecture not in (32, 64) or group_count == 0 or group_count > 64:
        raise GateFailure(
            f"invalid plaintext handler evidence header: {path}")
    groups: dict[int, dict[str, object]] = {}
    for _ in range(group_count):
        group, digest, handler_count, record_count, trace_rva, \
            trace_capacity, build_id = struct.unpack(
                "<IQIIII16s", take(44))
        if group in groups or handler_count == 0 or handler_count > 4096 or \
                record_count == 0 or record_count > 4096 or \
                trace_rva == 0 or trace_capacity == 0 or \
                trace_capacity > 1048576 or build_id == bytes(16):
            raise GateFailure(
                f"invalid plaintext handler group table in {path}")
        handlers: dict[tuple[int, int], tuple[int, int, int, bytes]] = {}
        vm_architecture = 0x86 if architecture == 32 else 0x8664
        canonical = bytearray(struct.pack(
            "<IIII16s", vm_architecture, group, trace_rva, trace_capacity,
            build_id))
        canonical.extend(struct.pack("<II", handler_count, record_count))
        for _ in range(handler_count):
            record_header = take(4)
            semantic, slot, variant, reserved = struct.unpack("<BBBB", record_header)
            range_header = take(24)
            handler_body_size, core_offset, core_size, core_variant_offset, \
                core_variant_size, codec_range_count = struct.unpack(
                    "<IIIIII", range_header)
            if reserved != 0 or semantic == 0xFF or slot == 0xFF or \
                    handler_body_size == 0 or \
                    handler_body_size > 1024 * 1024 or \
                    core_size == 0 or core_size > 1024 * 1024 or \
                    core_offset > handler_body_size or \
                    core_size > handler_body_size - core_offset or \
                    codec_range_count > 64 or \
                    ((core_variant_size == 0) != (core_variant_offset == 0)) or \
                    (core_variant_size != 0 and
                     (core_variant_offset < core_offset or
                      core_variant_size > core_size -
                        (core_variant_offset - core_offset))):
                raise GateFailure(
                    f"invalid plaintext handler record in {path}")
            key = (semantic, variant)
            if key in handlers:
                raise GateFailure(
                    f"duplicate plaintext handler key {key} in {path}")
            core = take(core_size)
            codec_ranges: list[tuple[int, int]] = []
            previous_end = core_offset
            for _ in range(codec_range_count):
                raw_codec_range = take(8)
                codec_offset, codec_size = struct.unpack(
                    "<II", raw_codec_range)
                if codec_size < 32 or codec_offset < previous_end or \
                        codec_offset < core_offset or \
                        codec_size > core_size - (codec_offset - core_offset):
                    raise GateFailure(
                        f"invalid or overlapping value-codec range in {path}")
                codec_ranges.append((codec_offset, codec_size))
                previous_end = codec_offset + codec_size

            codec = bytearray()
            for codec_offset, codec_size in codec_ranges:
                relative = codec_offset - core_offset
                codec.extend(core[relative:relative + codec_size])
            variant_relative = (core_variant_offset - core_offset
                                if core_variant_size else 0)
            core_variant = (core[variant_relative:
                                 variant_relative + core_variant_size]
                            if core_variant_size else b"")

            # The business stage is the complete production core with only
            # value-codec ranges removed.  core_variant remains part of that
            # real lowering, but is also gated independently so the surrounding
            # business instructions cannot dilute it.  Short selector/lowering
            # ranges are legal evidence and are scored by the explicit
            # short-segment rule in four_gram_counts(); they are never dropped.
            excluded_ranges = [
                (offset - core_offset, size, "codec")
                for offset, size in codec_ranges
            ]
            excluded_ranges.sort()
            business_core = bytearray()
            cursor_in_core = 0
            for relative, size, stage_name in excluded_ranges:
                if relative < cursor_in_core:
                    raise GateFailure(
                        f"overlapping {stage_name} evidence range in {path}")
                business_core.extend(core[cursor_in_core:relative])
                cursor_in_core = relative + size
            business_core.extend(core[cursor_in_core:])
            canonical.extend(record_header)
            canonical.extend(range_header)
            canonical.extend(core)
            for codec_offset, codec_size in codec_ranges:
                canonical.extend(struct.pack("<II", codec_offset, codec_size))
            handlers[key] = {
                "slot": slot,
                "handler_body_size": handler_body_size,
                "core_offset": core_offset,
                "core": core,
                "business_core": bytes(business_core),
                "core_variant": core_variant,
                "codec": bytes(codec),
                "codec_ranges": codec_ranges,
            }
        records: dict[int, dict[str, object]] = {}
        referenced_handlers: set[tuple[int, int]] = set()
        for _ in range(record_count):
            record_header = take(24)
            function_rva, bytecode_offset, bytecode_size, bytecode_digest, \
                reference_count = struct.unpack("<IIIQI", record_header)
            if function_rva == 0 or function_rva in records or \
                    bytecode_size == 0 or bytecode_size > 16 * 1024 * 1024 or \
                    reference_count == 0 or reference_count > 1024 * 1024:
                raise GateFailure(
                    f"invalid plaintext bytecode record in {path}")
            bytecode = take(bytecode_size)
            if record_bytecode_digest(function_rva, bytecode) != bytecode_digest:
                raise GateFailure(
                    f"plaintext bytecode digest mismatch in {path}, "
                    f"function_rva=0x{function_rva:x}")
            references: list[tuple[int, int, int, int]] = []
            expected_offset = 0
            reference_bytes = bytearray()
            for _ in range(reference_count):
                raw_reference = take(12)
                relative_offset, encoded_size, semantic, variant, reserved = \
                    struct.unpack("<IIBBH", raw_reference)
                if reserved != 0 or semantic == 0 or semantic == 0xFF or \
                        variant >= 4 or encoded_size == 0 or \
                        relative_offset != expected_offset or \
                        relative_offset > bytecode_size or \
                        encoded_size > bytecode_size - relative_offset:
                    raise GateFailure(
                        f"invalid plaintext bytecode handler reference in {path}, "
                        f"function_rva=0x{function_rva:x}")
                expected_offset += encoded_size
                references.append(
                    (relative_offset, encoded_size, semantic, variant))
                referenced_handlers.add((semantic, variant))
                reference_bytes.extend(raw_reference)
            if expected_offset != bytecode_size:
                raise GateFailure(
                    f"handler references do not cover plaintext bytecode in {path}, "
                    f"function_rva=0x{function_rva:x}")
            canonical.extend(record_header)
            canonical.extend(bytecode)
            canonical.extend(reference_bytes)
            records[function_rva] = {
                "bytecode_offset": bytecode_offset,
                "bytecode": bytecode,
                "references": references,
            }
        handler_keys = set(handlers)
        if not referenced_handlers.issubset(handler_keys):
            raise GateFailure(
                f"plaintext evidence is missing referenced handlers in "
                f"{path}, group={group}")
        referenced_semantics = {
            semantic for semantic, _ in referenced_handlers}
        handler_semantics = {semantic for semantic, _ in handler_keys}
        if handler_semantics != referenced_semantics:
            raise GateFailure(
                f"plaintext evidence contains a semantic that no VM record "
                f"references in {path}, group={group}")
        expected_variants = {0, 1, 2, 3}
        incomplete_variants = {
            semantic: sorted(
                variant for key_semantic, variant in handler_keys
                if key_semantic == semantic)
            for semantic in sorted(handler_semantics)
            if {variant for key_semantic, variant in handler_keys
                if key_semantic == semantic} != expected_variants
        }
        if incomplete_variants:
            raise GateFailure(
                f"plaintext evidence does not contain the complete production "
                f"K=0..3 set for every referenced semantic in {path}, "
                f"group={group}: {incomplete_variants}")
        if semantic_evidence_digest(bytes(canonical)) != digest:
            raise GateFailure(
                f"plaintext handler evidence digest mismatch in {path}, group={group}")
        groups[group] = {
            "digest": digest, "handlers": handlers, "records": records,
            "trace_rva": trace_rva, "trace_capacity": trace_capacity,
            "build_id": build_id}
    if cursor != len(data):
        raise GateFailure(f"trailing bytes in plaintext handler evidence: {path}")
    return architecture, groups


def assert_trace_binding_tamper_rejected(path: Path, workdir: Path) -> None:
    data = bytearray(path.read_bytes())
    # CSVMPLN3 fixed header is 16 bytes; first group traceRVA starts at +20
    # within the 44-byte group header.  Changing it must invalidate the
    # canonical digest that binds trace storage to handler/reference evidence.
    trace_rva_offset = 16 + 20
    if len(data) <= trace_rva_offset:
        raise GateFailure(f"sidecar too small for trace-binding tamper test: {path}")
    data[trace_rva_offset] ^= 0x01
    tampered = workdir / "tampered_trace_binding.handlers"
    tampered.unlink(missing_ok=True)
    tampered.write_bytes(data)
    try:
        try:
            load_plaintext_evidence(tampered)
        except GateFailure:
            return
        raise GateFailure("tampered sidecar trace binding was accepted")
    finally:
        tampered.unlink(missing_ok=True)


def parse_runtime_trace(log: str, label: str) -> dict[int, dict[str, object]]:
    traces: dict[int, dict[str, object]] = {}
    for match in TRACE_HEADER_RE.finditer(log):
        group = int(match.group(1))
        if group in traces:
            raise GateFailure(f"{label} emitted duplicate trace header for group={group}")
        traces[group] = {
            "architecture": int(match.group(2)),
            "trace_rva": int(match.group(3), 16),
            "capacity": int(match.group(4)),
            "count": int(match.group(5)),
            "overflow": int(match.group(6)),
            "build_id": bytes.fromhex(match.group(7)),
            "events": [],
        }
    for match in TRACE_EVENT_RE.finditer(log):
        group = int(match.group(1))
        if group not in traces:
            raise GateFailure(f"{label} emitted a trace event without its header")
        events = traces[group]["events"]
        if not isinstance(events, list):
            raise GateFailure(f"{label} trace event storage is invalid")
        events.append((
            int(match.group(2)), int(match.group(3), 16),
            int(match.group(4), 16), int(match.group(5)),
            int(match.group(6))))
    if not traces:
        raise GateFailure(f"{label} emitted no production VM runtime trace")
    for group, trace in traces.items():
        events = trace["events"]
        if trace["overflow"] != 0 or trace["count"] == 0 or \
                not isinstance(events, list) or len(events) != trace["count"] or \
                [event[0] for event in events] != list(range(1, len(events) + 1)):
            raise GateFailure(
                f"{label} has an incomplete, overflowed, or non-contiguous "
                f"runtime trace for group={group}")
    return traces


def validate_runtime_trace(
        label: str,
        runtime_log: str,
        groups: dict[int, dict[str, int]],
        evidence: dict[int, dict[str, object]],
        target_rvas: set[int]) -> None:
    traces = parse_runtime_trace(runtime_log, label)
    if set(traces) != set(groups) or set(traces) != set(evidence):
        raise GateFailure(
            f"{label} trace/group/sidecar group ids disagree: "
            f"trace={sorted(traces)} log={sorted(groups)} "
            f"sidecar={sorted(evidence)}")
    logged_records: set[int] = set()
    sidecar_records: set[int] = set()
    traced_functions: set[int] = set()
    for group in sorted(traces):
        trace = traces[group]
        proof = evidence[group]
        record_rvas = groups[group].get("record_rvas")
        records = proof.get("records")
        if not isinstance(record_rvas, set) or not isinstance(records, dict):
            raise GateFailure(f"{label} has malformed VM record evidence")
        logged_records.update(record_rvas)
        sidecar_records.update(records)
        if trace["architecture"] not in (32, 64) or \
                trace["trace_rva"] != proof.get("trace_rva") or \
                trace["capacity"] != proof.get("trace_capacity") or \
                trace["build_id"] != proof.get("build_id"):
            raise GateFailure(
                f"{label} runtime trace header is not bound to sidecar "
                f"group={group}")
        expected_refs: dict[int, set[tuple[int, int, int]]] = {}
        observed_refs: dict[int, set[tuple[int, int, int]]] = {}
        for function_rva, record in records.items():
            references = record.get("references")
            if not isinstance(references, list) or not references:
                raise GateFailure(
                    f"{label} sidecar record has no micro references: "
                    f"0x{function_rva:x}")
            expected_refs[function_rva] = {
                (offset + encoded_size, semantic, variant)
                for offset, encoded_size, semantic, variant in references
            }
            observed_refs[function_rva] = set()
        events = trace["events"]
        if not isinstance(events, list):
            raise GateFailure(f"{label} trace event list is invalid")
        for _, function_rva, bytecode_end, semantic, variant in events:
            if function_rva not in expected_refs or \
                    (bytecode_end, semantic, variant) not in \
                        expected_refs[function_rva]:
                raise GateFailure(
                    f"{label} traced an event absent from its exact sidecar "
                    f"decode plan: function=0x{function_rva:x} "
                    f"end=0x{bytecode_end:x} semantic={semantic} variant={variant}")
            observed_refs[function_rva].add(
                (bytecode_end, semantic, variant))
            traced_functions.add(function_rva)
        missing = {
            function_rva: sorted(expected_refs[function_rva] - observed)
            for function_rva, observed in observed_refs.items()
            if expected_refs[function_rva] != observed
        }
        if missing:
            raise GateFailure(
                f"{label} did not execute every designed micro reference: {missing}")
    if logged_records != target_rvas or sidecar_records != target_rvas or \
            traced_functions != target_rvas:
        raise GateFailure(
            f"{label} native-fallback closure failed: exports={sorted(target_rvas)} "
            f"VM_RECORD={sorted(logged_records)} sidecar={sorted(sidecar_records)} "
            f"trace={sorted(traced_functions)}")


def four_gram_counts(material: bytes) -> Counter[tuple[int, bytes]]:
    """Return a multiset of byte 4-grams with an exact short-range rule.

    A nonempty range shorter than four bytes contributes one token containing
    both its exact length and exact bytes.  Thus two identical short ranges
    score 1.0 and every non-identical short pair scores 0.0; short evidence is
    never silently dropped.  For normal ranges, an insertion shifts at most
    the nearby 4-grams instead of making an identical suffix look unrelated.
    """
    if not material:
        raise GateFailure("cannot score an empty live handler stage")
    if len(material) < 4:
        return Counter({(len(material), material): 1})
    return Counter(
        (4, material[index:index + 4])
        for index in range(len(material) - 3))


def four_gram_dice(left: bytes, right: bytes) -> tuple[float, int, int]:
    left_grams = four_gram_counts(left)
    right_grams = four_gram_counts(right)
    intersection = sum((left_grams & right_grams).values())
    total = sum(left_grams.values()) + sum(right_grams.values())
    if total == 0:
        raise GateFailure("4-gram Dice denominator is empty")
    return 2.0 * intersection / total, intersection, total


def assert_distinct_core_variant(
        kind: str, label: str, left: bytes, right: bytes) -> None:
    if not left or not right:
        raise GateFailure(
            f"{kind} {label} has an empty core_variant in one build")
    if left == right:
        raise GateFailure(
            f"{kind} {label} core_variant is byte-identical across seeds")


def run_similarity_negative_self_checks() -> None:
    """Fail closed if the scorer regresses to position-by-position zip logic."""
    suffix = bytes(range(64))
    inserted = b"\xff" + suffix
    similarity, _, _ = four_gram_dice(suffix, inserted)
    if similarity < 0.95:
        raise GateFailure(
            "internal 4-gram self-check failed: a one-byte prefix made an "
            "identical suffix appear dissimilar")
    try:
        assert_distinct_core_variant(
            "self-check", "group=0 semantic=1 K=0", suffix, suffix)
    except GateFailure:
        pass
    else:
        raise GateFailure(
            "internal core_variant self-check failed: identical cores were accepted")


def aggregate_stage_similarity(
        kind: str, stage: str,
        pairs: list[tuple[str, bytes, bytes]]) -> dict[str, object]:
    if not pairs:
        raise GateFailure(f"{kind} has no aligned {stage} evidence")
    intersection = 0
    total = 0
    max_pair_similarity = -1.0
    max_pair_label = ""
    for label, left, right in pairs:
        similarity, pair_intersection, pair_total = four_gram_dice(left, right)
        intersection += pair_intersection
        total += pair_total
        if similarity > max_pair_similarity:
            max_pair_similarity = similarity
            max_pair_label = label
    if total == 0:
        raise GateFailure(f"{kind} {stage} evidence has an empty denominator")
    return {
        "similarity": 2.0 * intersection / total,
        "intersection": intersection,
        "total": total,
        "pairs": len(pairs),
        "max_pair_similarity": max_pair_similarity,
        "max_pair_label": max_pair_label,
    }


def plaintext_stage_similarities(
        kind: str,
        groups1: dict[int, dict[str, int]],
        groups2: dict[int, dict[str, int]],
        evidence1: dict[int, dict[str, object]],
        evidence2: dict[int, dict[str, object]],
        group_ids: list[int]) -> dict[str, dict[str, object]]:
    expected_groups = set(group_ids)
    if set(groups1) != expected_groups or set(groups2) != expected_groups or \
            set(evidence1) != expected_groups or set(evidence2) != expected_groups:
        raise GateFailure(
            f"{kind} log/sidecar group sets are not exactly aligned: "
            f"log1={sorted(groups1)} log2={sorted(groups2)} "
            f"sidecar1={sorted(evidence1)} sidecar2={sorted(evidence2)}")

    stage_pairs: dict[str, list[tuple[str, bytes, bytes]]] = {
        "business_core": [], "core_variant": [], "codec": []}
    for group in group_ids:
        proof1 = evidence1[group]
        proof2 = evidence2[group]
        if proof1["digest"] != groups1[group]["semantic_plaintext_digest"] or \
           proof2["digest"] != groups2[group]["semantic_plaintext_digest"]:
            raise GateFailure(
                f"{kind} plaintext evidence is not bound to vm_group={group} diagnostics")
        handlers1 = proof1["handlers"]
        handlers2 = proof2["handlers"]
        records1 = proof1["records"]
        records2 = proof2["records"]
        if not isinstance(handlers1, dict) or not isinstance(handlers2, dict) or \
                not isinstance(records1, dict) or not isinstance(records2, dict):
            raise GateFailure(f"{kind} plaintext evidence has invalid tables")
        if len(handlers1) != groups1[group]["semantic_handler_count"] or \
           len(handlers2) != groups2[group]["semantic_handler_count"]:
            raise GateFailure(
                f"{kind} plaintext handler count disagrees with vm_group={group} diagnostics")
        if len(records1) != groups1[group]["semantic_record_count"] or \
           len(records2) != groups2[group]["semantic_record_count"] or \
           set(records1) != set(records2):
            raise GateFailure(
                f"{kind} per-record handler references differ by function RVA "
                f"in vm_group={group}")

        keys1 = set(handlers1)
        keys2 = set(handlers2)
        if keys1 != keys2:
            raise GateFailure(
                f"{kind} vm_group={group} handler (semantic,K) sets differ: "
                f"seed1={sorted(keys1)} seed2={sorted(keys2)}")
        if not keys1:
            raise GateFailure(
                f"{kind} vm_group={group} has no live handler keys")

        # Alignment is exactly (group, semantic, K).  There is deliberately no
        # cross-K permutation and no missing-key denominator penalty: either
        # build publishing a different key set is a hard evidence failure.
        for semantic, variant in sorted(keys1):
            label = f"group={group} semantic={semantic} K={variant}"
            handler1 = handlers1[(semantic, variant)]
            handler2 = handlers2[(semantic, variant)]
            if not isinstance(handler1, dict) or not isinstance(handler2, dict):
                raise GateFailure(f"{kind} {label} handler record is malformed")
            business1 = handler1.get("business_core")
            business2 = handler2.get("business_core")
            core_variant1 = handler1.get("core_variant")
            core_variant2 = handler2.get("core_variant")
            codec1 = handler1.get("codec")
            codec2 = handler2.get("codec")
            if not all(isinstance(value, bytes) for value in (
                    business1, business2, core_variant1, core_variant2,
                    codec1, codec2)):
                raise GateFailure(f"{kind} {label} stage bytes are malformed")
            if not business1 or not business2:
                raise GateFailure(
                    f"{kind} {label} has no business lowering after removing "
                    "codec ranges")
            if bool(codec1) != bool(codec2):
                raise GateFailure(
                    f"{kind} {label} has persistent value-codec evidence in "
                    "only one build")
            assert_distinct_core_variant(
                kind, label, core_variant1, core_variant2)
            stage_pairs["business_core"].append(
                (label, business1, business2))
            stage_pairs["core_variant"].append(
                (label, core_variant1, core_variant2))
            # Stack-neutral semantics legitimately have no value-codec range.
            # Score only exact keys where both builds publish that live stage;
            # aggregate_stage_similarity still fails closed if the entire
            # packed product contains no codec-bearing handler at all.
            if codec1:
                stage_pairs["codec"].append((label, codec1, codec2))

    return {
        stage: aggregate_stage_similarity(kind, stage, pairs)
        for stage, pairs in stage_pairs.items()
    }


def extract_encrypted_handler_regions(
        kind: str, output: Path,
        groups: dict[int, dict[str, int]]) -> dict[int, bytes]:
    """Read the delivered ciphertext from each real packed PE runtime section."""
    data = output.read_bytes()
    regions: dict[int, bytes] = {}
    for group, fields in sorted(groups.items()):
        raw = fields["raw"]
        runtime_size = fields["size"]
        offset = fields["encrypted_handlers_offset"]
        size = fields["encrypted_handlers_size"]
        if raw == 0 or runtime_size == 0 or size == 0 or \
                offset > runtime_size or size > runtime_size - offset or \
                raw > len(data) or offset > len(data) - raw or \
                size > len(data) - raw - offset:
            raise GateFailure(
                f"{kind} packed PE has a non-file-backed encrypted handler "
                f"range for vm_group={group}: raw=0x{raw:x} "
                f"runtime_size=0x{runtime_size:x} offset=0x{offset:x} "
                f"size=0x{size:x} file_size=0x{len(data):x}")
        regions[group] = data[raw + offset:raw + offset + size]
    if not regions:
        raise GateFailure(f"{kind} packed PE has no encrypted handler regions")
    return regions


def encrypted_handler_similarity(
        kind: str, output1: Path, output2: Path,
        groups1: dict[int, dict[str, int]],
        groups2: dict[int, dict[str, int]],
        group_ids: list[int]) -> dict[str, object]:
    regions1 = extract_encrypted_handler_regions(kind, output1, groups1)
    regions2 = extract_encrypted_handler_regions(kind, output2, groups2)
    expected = set(group_ids)
    if set(regions1) != expected or set(regions2) != expected:
        raise GateFailure(
            f"{kind} encrypted-handler group sets are not exactly aligned")
    return aggregate_stage_similarity(
        kind, "encrypted_handlers", [
            (f"group={group}", regions1[group], regions2[group])
            for group in group_ids
        ])


def exact_group_ids(
        kind: str,
        groups1: dict[int, dict[str, int]],
        groups2: dict[int, dict[str, int]]) -> list[int]:
    if not groups1 or not groups2:
        raise GateFailure(
            f"{kind} VM protection was not applied in both builds: "
            f"seed1={sorted(groups1)} seed2={sorted(groups2)}")
    if set(groups1) != set(groups2):
        raise GateFailure(
            f"{kind} builds produced different VM group sets: "
            f"seed1={sorted(groups1)} seed2={sorted(groups2)}")
    return sorted(groups1)


def report_and_gate_similarities(
        kind: str,
        stages: dict[str, dict[str, object]],
        encrypted: dict[str, object],
        thresholds: dict[str, float]) -> None:
    results = dict(stages)
    results["encrypted_handlers"] = encrypted
    for stage in ("business_core", "core_variant", "codec",
                  "encrypted_handlers"):
        result = results[stage]
        similarity = float(result["similarity"])
        threshold = thresholds[stage]
        max_pair_similarity = float(result["max_pair_similarity"])
        max_pair_ceiling = MAX_PAIR_CEILINGS[stage]
        print(
            f"[{kind.lower()}-diversity] stage={stage} "
            f"pairs={result['pairs']} "
            f"matching_4grams={2 * int(result['intersection'])}/"
            f"{int(result['total'])} dice={similarity:.4f} "
            f"max_pair={max_pair_similarity:.4f} "
            f"max_pair_key={result['max_pair_label']} "
            f"threshold={threshold:.4f} "
            f"max_pair_ceiling={max_pair_ceiling:.4f}")
        if similarity >= threshold:
            raise GateFailure(
                f"{kind} {stage} 4-gram Dice similarity {similarity:.4f} "
                f"is not below the independent {threshold:.4f} threshold")
        # The aggregate check above is a population mean over every live
        # (vm_group,semantic,K) pair and can pass while one specific pair is
        # far more similar across seeds than that mean suggests.  Gate the
        # single worst pair independently so it cannot hide behind the
        # aggregate; see MAX_PAIR_CEILINGS for how these were calibrated.
        if max_pair_similarity >= max_pair_ceiling:
            raise GateFailure(
                f"{kind} {stage} single-pair 4-gram Dice similarity "
                f"{max_pair_similarity:.4f} at {result['max_pair_label']} "
                f"is not below the independent per-pair ceiling "
                f"{max_pair_ceiling:.4f}; the aggregate mean can stay low "
                "while this one handler pair does not")


def resolve_thresholds(args: argparse.Namespace) -> dict[str, float]:
    encrypted = (args.encrypted_similarity_threshold
                 if args.encrypted_similarity_threshold is not None
                 else args.similarity_threshold)
    thresholds = {
        "business_core": args.business_core_similarity_threshold,
        "core_variant": args.core_variant_similarity_threshold,
        "codec": args.codec_similarity_threshold,
        "encrypted_handlers": encrypted,
    }
    hard_ceilings = {
        # 0.32 replaces the old 0.35, which was never validated against any
        # attacker-difficulty bound. It is NOT a single fresh sample rounded
        # up: an initial v2.7.2 attempt used 0.30/0.28 from 4 local samples
        # per architecture, and real CSPRNG-seeded CI runs immediately
        # exceeded 0.28 twice in a row on Win32 (0.2856, 0.2863) -- real
        # per-build seeds vary enough that a 1-2 sample margin is not
        # reliable. v2.7.3 recalibrated from 16 x64 + 9 Win32 independent
        # real-seed samples (see codex_change.log): both architectures'
        # business_core lands at mean~0.28/0.275, stdev~0.006/0.007, so
        # 0.32 sits about 6 stdev above the mean on both -- comfortably
        # past the measured spread without being an arbitrary number. This
        # ceiling only bounds how loose --business-core-similarity-threshold
        # may be set (a per-architecture anti-regression baseline supplied
        # by the caller); it is not itself a claim about analysis difficulty.
        "business_core": 0.32,
        "core_variant": 0.35,
        "codec": 0.15,
        "encrypted_handlers": 0.15,
    }
    for stage, threshold in thresholds.items():
        ceiling = hard_ceilings[stage]
        if not math.isfinite(threshold) or threshold <= 0.0 or \
                threshold > ceiling:
            raise GateFailure(
                f"invalid {stage} threshold {threshold!r}; it must be in "
                f"(0,{ceiling}] and cannot loosen the quantitative gate")
    return thresholds


def main() -> int:
    args = parse_args()
    if not args.ciphershell.is_file():
        print(f"[FAIL] ciphershell not found: {args.ciphershell}", file=sys.stderr)
        return 2
    if not args.sample.is_file():
        print(f"[FAIL] sample input not found: {args.sample}", file=sys.stderr)
        return 2
    if not args.runner.is_file() or not args.exe_sample.is_file():
        print(f"[FAIL] runtime fixture missing: runner={args.runner} "
              f"exe={args.exe_sample}", file=sys.stderr)
        return 2
    if not args.config.is_file():
        print(f"[FAIL] config not found: {args.config}", file=sys.stderr)
        return 2
    args.workdir.mkdir(parents=True, exist_ok=True)
    output1 = args.workdir / "per_build_similarity_gate_1.dll"
    output2 = args.workdir / "per_build_similarity_gate_2.dll"
    exe_output1 = args.workdir / "per_build_exe_gate_1.exe"
    exe_output2 = args.workdir / "per_build_exe_gate_2.exe"
    evidence1_path = args.workdir / "per_build_similarity_gate_1.handlers"
    evidence2_path = args.workdir / "per_build_similarity_gate_2.handlers"
    exe_evidence1_path = args.workdir / "per_build_exe_gate_1.handlers"
    exe_evidence2_path = args.workdir / "per_build_exe_gate_2.handlers"

    try:
        run_similarity_negative_self_checks()
        thresholds = resolve_thresholds(args)
        raw_dll_targets = exact_target_export_rvas(args.sample)
        raw_exe_targets = exact_target_export_rvas(args.exe_sample)
        # Establish the real-CPU baseline twice before packing. Both PE
        # containers execute under the same forced-relocation conditions as
        # their protected counterparts, and each CaptureBinaryFunctionFlags wrapper
        # performs PUSHF/POPF capture immediately after CALL returns.
        raw_dll_flags1, raw_dll_result1, _ = run_packed_runtime(
            args.runner, args.sample)
        raw_dll_flags2, raw_dll_result2, _ = run_packed_runtime(
            args.runner, args.sample)
        raw_exe_flags1, raw_exe_result1, _ = run_packed_exe(
            args.runner, args.exe_sample)
        raw_exe_flags2, raw_exe_result2, _ = run_packed_exe(
            args.runner, args.exe_sample)
        if raw_dll_flags1 != raw_dll_flags2 or \
           raw_exe_flags1 != raw_exe_flags2 or \
           raw_dll_flags1 != raw_exe_flags1 or \
           raw_dll_result1 != raw_dll_result2 or \
           raw_exe_result1 != raw_exe_result2 or \
           raw_dll_result1 != raw_exe_result1:
            raise GateFailure(
                "unprotected MSVC DLL/EXE flags, returns, or memory-side-"
                "effect baselines are unstable or container-inconsistent")
        log1 = run_build(args.ciphershell, args.sample, output1, args.config,
                         evidence1_path)
        log2 = run_build(args.ciphershell, args.sample, output2, args.config,
                         evidence2_path)
        packed_dll_flags1, packed_dll_result1, packed_dll_runtime_log1 = \
            run_packed_runtime(args.runner, output1, expect_trace=True)
        packed_dll_flags2, packed_dll_result2, packed_dll_runtime_log2 = \
            run_packed_runtime(args.runner, output2, expect_trace=True)
        exe_log1 = run_build(
            args.ciphershell, args.exe_sample, exe_output1, args.config,
            exe_evidence1_path)
        exe_log2 = run_build(
            args.ciphershell, args.exe_sample, exe_output2, args.config,
            exe_evidence2_path)
        assert_forced_relocation_exe_layout(exe_output1)
        assert_forced_relocation_exe_layout(exe_output2)
        packed_exe_flags1, packed_exe_result1, packed_exe_runtime_log1 = \
            run_packed_exe(args.runner, exe_output1, expect_trace=True)
        packed_exe_flags2, packed_exe_result2, packed_exe_runtime_log2 = \
            run_packed_exe(args.runner, exe_output2, expect_trace=True)
        if any(flags != raw_dll_flags1 for flags in (
                packed_dll_flags1, packed_dll_flags2,
                packed_exe_flags1, packed_exe_flags2)):
            raise GateFailure(
                "protected DLL/EXE returned flags differ from the repeated "
                "unprotected real-CPU baseline")
        if any(result != raw_dll_result1 for result in (
                packed_dll_result1, packed_dll_result2,
                packed_exe_result1, packed_exe_result2)):
            raise GateFailure(
                "protected DLL/EXE export returns or memory side effects differ "
                "from the repeated unprotected real-CPU baseline")
        architecture1, evidence1 = load_plaintext_evidence(evidence1_path)
        assert_trace_binding_tamper_rejected(evidence1_path, args.workdir)
        architecture2, evidence2 = load_plaintext_evidence(evidence2_path)
        exe_architecture1, exe_evidence1 = load_plaintext_evidence(
            exe_evidence1_path)
        exe_architecture2, exe_evidence2 = load_plaintext_evidence(
            exe_evidence2_path)
        if len({architecture1, architecture2, exe_architecture1,
                exe_architecture2}) != 1:
            raise GateFailure(
                "DLL and EXE plaintext evidence architectures do not match")
        if exact_target_export_rvas(output1) != raw_dll_targets or \
           exact_target_export_rvas(output2) != raw_dll_targets or \
           exact_target_export_rvas(exe_output1) != raw_exe_targets or \
           exact_target_export_rvas(exe_output2) != raw_exe_targets:
            raise GateFailure(
                "packer changed the fixed eight export name->RVA contract")

        exe_groups1 = parse_groups(exe_log1)
        exe_groups2 = parse_groups(exe_log2)
        exe_group_ids = exact_group_ids("EXE", exe_groups1, exe_groups2)
        if sum(exe_groups1[group]["records"] for group in exe_group_ids) != 8 or \
           sum(exe_groups2[group]["records"] for group in exe_group_ids) != 8:
            raise GateFailure("packed EXE builds did not contain all eight VM records")
        if any(exe_groups1[group]["vm_records"] != exe_groups1[group]["records"] or
               exe_groups2[group]["vm_records"] != exe_groups2[group]["records"] or
               exe_groups1[group].get("invalid_vm_records", 0) != 0 or
               exe_groups2[group].get("invalid_vm_records", 0) != 0
               for group in exe_group_ids):
            raise GateFailure(
                "packed EXE metadata did not contain a complete trampoline, "
                "bytecode body, guest stack, and nonempty opcode stream for every record")
        for group in exe_group_ids:
            for digest_name in ("opcode_map", "handler_body", "dispatch_key", "variant_selector"):
                if exe_groups1[group][digest_name] == exe_groups2[group][digest_name]:
                    raise GateFailure(
                        f"EXE vm_group={group}: {digest_name} did not vary across seeds")
        validate_runtime_trace(
            "EXE seed1", packed_exe_runtime_log1, exe_groups1,
            exe_evidence1, raw_exe_targets)
        validate_runtime_trace(
            "EXE seed2", packed_exe_runtime_log2, exe_groups2,
            exe_evidence2, raw_exe_targets)
        exe_stages = plaintext_stage_similarities(
            "EXE", exe_groups1, exe_groups2, exe_evidence1, exe_evidence2,
            exe_group_ids)
        exe_encrypted = encrypted_handler_similarity(
            "EXE", exe_output1, exe_output2, exe_groups1, exe_groups2,
            exe_group_ids)
        report_and_gate_similarities(
            "EXE", exe_stages, exe_encrypted, thresholds)
        print(f"[exe-runtime] groups={exe_group_ids} "
              f"records1={sum(exe_groups1[g]['records'] for g in exe_group_ids)} "
              f"records2={sum(exe_groups2[g]['records'] for g in exe_group_ids)}")

        groups1 = parse_groups(log1)
        groups2 = parse_groups(log2)
        group_ids = exact_group_ids("DLL", groups1, groups2)
        if sum(groups1[group]["records"] for group in group_ids) != 8 or \
           sum(groups2[group]["records"] for group in group_ids) != 8:
            raise GateFailure("packed DLL builds did not contain all eight VM records")
        if any(groups1[group]["vm_records"] != groups1[group]["records"] or
               groups2[group]["vm_records"] != groups2[group]["records"] or
               groups1[group].get("invalid_vm_records", 0) != 0 or
               groups2[group].get("invalid_vm_records", 0) != 0
               for group in group_ids):
            raise GateFailure(
                "packed DLL metadata did not contain a complete trampoline, "
                "bytecode body, guest stack, and nonempty opcode stream for every record")

        for group in group_ids:
            g1, g2 = groups1[group], groups2[group]
            for digest_name in ("opcode_map", "handler_body", "dispatch_key", "variant_selector"):
                if g1[digest_name] == g2[digest_name]:
                    raise GateFailure(
                        f"vm_group={group}: {digest_name} digest is identical across "
                        f"both independently-seeded builds (0x{g1[digest_name]:x}) "
                        "-- accidental determinism, opcode map / dispatch key / "
                        "micro-op selection did not actually change per build")
            print(f"[group] vm_group={group} records1={g1['records']} "
                  f"records2={g2['records']}")

        validate_runtime_trace(
            "DLL seed1", packed_dll_runtime_log1, groups1, evidence1,
            raw_dll_targets)
        validate_runtime_trace(
            "DLL seed2", packed_dll_runtime_log2, groups2, evidence2,
            raw_dll_targets)

        dll_stages = plaintext_stage_similarities(
            "DLL", groups1, groups2, evidence1, evidence2, group_ids)
        dll_encrypted = encrypted_handler_similarity(
            "DLL", output1, output2, groups1, groups2, group_ids)
        report_and_gate_similarities(
            "DLL", dll_stages, dll_encrypted, thresholds)
    except GateFailure as failure:
        print(f"[FAIL] {failure}", file=sys.stderr)
        return 1

    print("VM_PER_BUILD_SIMILARITY_GATE_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
