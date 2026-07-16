#!/usr/bin/env python3
"""ciphershellpro.md §8 "Per-build 差异度" 校验:同一份输入用两次独立构建
（各自的 build seed 都来自 ciphershell.exe 内部 BCryptGenRandom，本脚本不
覆盖、不注入固定种子），比较两次产物里 handler 机器码字节的相似度必须
< 15%，并且 opcode map / 分发键（dispatch key）/ 微操作选择（variant
selector）四个自检摘要必须两两不同。

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
import itertools
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
TARGET_EXPORT_NAMES = {
    "add", "sub2", "max2", "is_zero", "local1",
    "relocated_ptr", "relocated_read", "relocated_write",
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
    parser.add_argument("--similarity-threshold", type=float, default=0.15,
                        help="max allowed handler-body byte similarity (0..1)")
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
    envelope are deliberately excluded. Ranges are compared independently by
    (semantic, K-variant), avoiding false mismatch from one variable-length
    handler shifting every handler that follows it.
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

            business_core = bytearray()
            codec = bytearray()
            cursor_in_core = 0
            for codec_offset, codec_size in codec_ranges:
                relative = codec_offset - core_offset
                business_core.extend(core[cursor_in_core:relative])
                codec.extend(core[relative:relative + codec_size])
                cursor_in_core = relative + codec_size
            business_core.extend(core[cursor_in_core:])
            variant_relative = (core_variant_offset - core_offset
                                if core_variant_size else 0)
            core_variant = (core[variant_relative:
                                 variant_relative + core_variant_size]
                            if core_variant_size else b"")
            if len(business_core) < 32 or \
                    (codec_ranges and len(codec) < 32) or \
                    (core_variant_size and len(core_variant) < 32):
                raise GateFailure(
                    f"plaintext evidence has an undersized meaningful stage in {path}")
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
        if referenced_handlers != set(handlers):
            raise GateFailure(
                f"plaintext evidence contains unreferenced or missing handlers in "
                f"{path}, group={group}")
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
    # CSVMPLN2 fixed header is 16 bytes; first group traceRVA starts at +20
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


def plaintext_similarity(
        kind: str,
        groups1: dict[int, dict[str, int]],
        groups2: dict[int, dict[str, int]],
        evidence1: dict[int, dict[str, object]],
        evidence2: dict[int, dict[str, object]],
        common_groups: list[int]) -> tuple[float, int, int]:
    matches = 0
    denominator = 0
    for group in common_groups:
        if group not in evidence1 or group not in evidence2:
            raise GateFailure(
                f"{kind} plaintext evidence is missing vm_group={group}")
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

        for function_rva in sorted(records1):
            refs1 = records1[function_rva]["references"]
            refs2 = records2[function_rva]["references"]
            keys1 = {(reference[2], reference[3]) for reference in refs1}
            keys2 = {(reference[2], reference[3]) for reference in refs2}
            semantics = sorted(
                {key[0] for key in keys1} | {key[0] for key in keys2})
            for semantic in semantics:
                bodies1 = [handlers1[key][3] for key in sorted(keys1)
                           if key[0] == semantic]
                bodies2 = [handlers2[key][3] for key in sorted(keys2)
                           if key[0] == semantic]
                left_total = sum(len(body) for body in bodies1)
                right_total = sum(len(body) for body in bodies2)
                denominator += max(left_total, right_total)
                if len(bodies1) > len(bodies2):
                    bodies1, bodies2 = bodies2, bodies1
                if not bodies1:
                    continue
                best = 0
                for pairing in itertools.permutations(bodies2, len(bodies1)):
                    candidate = sum(
                        sum(1 for left, right in zip(body1, body2)
                            if left == right)
                        for body1, body2 in zip(bodies1, pairing))
                    best = max(best, candidate)
                # Choose the most-similar valid pairing. This is conservative:
                # differing K selectors cannot obtain a lower score merely by
                # changing variant numbers or instruction order.
                matches += best
    if denominator == 0:
        raise GateFailure(f"{kind} plaintext evidence contains no handler bytes")
    return matches / denominator, matches, denominator


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
        common_exe_groups = sorted(set(exe_groups1) & set(exe_groups2))
        if not common_exe_groups:
            raise GateFailure(
                "VM protection was not applied to a common group in both EXE builds")
        if sum(exe_groups1[group]["records"] for group in common_exe_groups) != 8 or \
           sum(exe_groups2[group]["records"] for group in common_exe_groups) != 8:
            raise GateFailure("packed EXE builds did not contain all eight VM records")
        if any(exe_groups1[group]["vm_records"] != exe_groups1[group]["records"] or
               exe_groups2[group]["vm_records"] != exe_groups2[group]["records"] or
               exe_groups1[group].get("invalid_vm_records", 0) != 0 or
               exe_groups2[group].get("invalid_vm_records", 0) != 0
               for group in common_exe_groups):
            raise GateFailure(
                "packed EXE metadata did not contain a complete trampoline, "
                "bytecode body, guest stack, and nonempty opcode stream for every record")
        for group in common_exe_groups:
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
        exe_similarity, exe_matches, exe_bytes = plaintext_similarity(
            "EXE", exe_groups1, exe_groups2, exe_evidence1, exe_evidence2,
            common_exe_groups)
        if exe_similarity >= args.similarity_threshold:
            raise GateFailure(
                f"EXE handler-body byte similarity {exe_similarity:.4f} across two "
                f"independently-seeded builds is not below the "
                f"{args.similarity_threshold:.4f} threshold")
        print(f"[exe-runtime] groups={common_exe_groups} "
              f"records1={sum(exe_groups1[g]['records'] for g in common_exe_groups)} "
              f"records2={sum(exe_groups2[g]['records'] for g in common_exe_groups)} "
              f"plaintext_matches={exe_matches}/{exe_bytes} "
              f"similarity={exe_similarity:.4f}")

        groups1 = parse_groups(log1)
        groups2 = parse_groups(log2)
        if not groups1 or not groups2:
            raise GateFailure(
                "VM protection was not actually applied to any group in "
                f"one of the two builds (build1 groups={sorted(groups1)}, "
                f"build2 groups={sorted(groups2)}) -- nothing to compare. "
                "Full build1 log:\n" + log1 + "\nFull build2 log:\n" + log2)
        common_groups = sorted(set(groups1) & set(groups2))
        if not common_groups:
            raise GateFailure(
                f"builds produced disjoint VM group ids (build1={sorted(groups1)}, "
                f"build2={sorted(groups2)}) -- cannot compare handler bodies")
        if sum(groups1[group]["records"] for group in common_groups) != 8 or \
           sum(groups2[group]["records"] for group in common_groups) != 8:
            raise GateFailure("packed DLL builds did not contain all eight VM records")
        if any(groups1[group]["vm_records"] != groups1[group]["records"] or
               groups2[group]["vm_records"] != groups2[group]["records"] or
               groups1[group].get("invalid_vm_records", 0) != 0 or
               groups2[group].get("invalid_vm_records", 0) != 0
               for group in common_groups):
            raise GateFailure(
                "packed DLL metadata did not contain a complete trampoline, "
                "bytecode body, guest stack, and nonempty opcode stream for every record")

        for group in common_groups:
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

        similarity, plaintext_matches, plaintext_bytes = plaintext_similarity(
            "DLL", groups1, groups2, evidence1, evidence2, common_groups)
        print(f"[aggregate] groups={common_groups} "
              f"plaintext_matches={plaintext_matches}/{plaintext_bytes} "
              f"similarity={similarity:.4f} "
              f"threshold={args.similarity_threshold:.4f}")

        if similarity >= args.similarity_threshold:
            raise GateFailure(
                f"handler-body byte similarity {similarity:.4f} across two "
                f"independently-seeded builds is not below the "
                f"{args.similarity_threshold:.4f} threshold")
    except GateFailure as failure:
        print(f"[FAIL] {failure}", file=sys.stderr)
        return 1

    print("VM_PER_BUILD_SIMILARITY_GATE_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
