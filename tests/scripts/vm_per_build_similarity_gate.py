#!/usr/bin/env python3
"""ciphershellpro.md §8 "Per-build 差异度" 校验:同一份输入用两次独立构建
（各自的 build seed 都来自 ciphershell.exe 内部 BCryptGenRandom，本脚本不
覆盖、不注入固定种子），比较两次产物里 handler 机器码字节的相似度必须
< 15%，并且 opcode map / 分发键（dispatch key）/ 微操作选择（variant
selector）四个自检摘要必须两两不同。

这是 Windows-only 校验：ciphershell.exe 只处理 PE 输入，且这里比较的是
MSVC 工具链下的真实完整构建产物，不在非 Windows 环境下运行或伪造。CI 的
Windows job 负责实际调用本脚本（见 .github/workflows/ci.yml）。

本脚本只做“黑盒”事情：跑两次真实的 ciphershell.exe、解析它自己打印到
stdout 的 VM_RUNTIME_SECTION / VM_RUNTIME_DIGESTS 诊断行（main.cpp 里
VMRuntimeBuilder 自检早已算好的 opcodeMapDigest/handlerBodyDigest/
dispatchKeyDigest/variantSelectorDigest 和 encryptedHandlers 字节范围，
原样打印，不是本脚本另起一套协议），据此从两个产物文件里各自读出对应的
handler 密文字节区间，逐字节比较。
"""

from __future__ import annotations

import argparse
import re
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


class GateFailure(Exception):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ciphershell", type=Path, required=True,
                        help="path to the built ciphershell(.exe) packer")
    parser.add_argument("--sample", type=Path, required=True,
                        help="path to the sample PE input to pack twice")
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


def run_build(ciphershell: Path, sample: Path, output: Path, config: Path) -> str:
    proc = subprocess.run(
        [str(ciphershell), str(sample), "-o", str(output), "-c", str(config)],
        capture_output=True, text=True, timeout=600)
    log = proc.stdout + proc.stderr
    if proc.returncode != 0:
        raise GateFailure(
            f"ciphershell build failed (exit={proc.returncode}) writing "
            f"{output}:\n{log}")
    if not output.is_file():
        raise GateFailure(f"ciphershell reported success but {output} was not created:\n{log}")
    return log


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
    required = ("raw", "size", "opcode_map", "handler_body", "dispatch_key",
                "variant_selector", "encrypted_handlers_offset",
                "encrypted_handlers_size", "records")
    complete = {g: fields for g, fields in groups.items()
                if all(key in fields for key in required)}
    return complete


def extract_encrypted_handlers(pe_path: Path, group: dict[str, int]) -> bytes:
    file_offset = group["raw"] + group["encrypted_handlers_offset"]
    size = group["encrypted_handlers_size"]
    data = pe_path.read_bytes()
    if file_offset < 0 or size == 0 or file_offset + size > len(data):
        raise GateFailure(
            f"encrypted-handler range offset=0x{file_offset:x} size=0x{size:x} "
            f"is outside {pe_path} (file size 0x{len(data):x})")
    return data[file_offset:file_offset + size]


def byte_similarity(left: bytes, right: bytes) -> float:
    """Fraction of aligned byte positions that match, out of max(len).
    Extra bytes in the longer blob (e.g. a different junk-handler count
    changed total size) count as mismatches, not as ignored/trimmed -- a
    build that pads with different-length junk is still evidence the two
    builds differ, and silently trimming to min-length would inflate the
    similarity score."""
    if not left and not right:
        return 1.0
    denominator = max(len(left), len(right))
    matches = sum(1 for a, b in zip(left, right) if a == b)
    return matches / denominator


def main() -> int:
    args = parse_args()
    if not args.ciphershell.is_file():
        print(f"[FAIL] ciphershell not found: {args.ciphershell}", file=sys.stderr)
        return 2
    if not args.sample.is_file():
        print(f"[FAIL] sample input not found: {args.sample}", file=sys.stderr)
        return 2
    if not args.config.is_file():
        print(f"[FAIL] config not found: {args.config}", file=sys.stderr)
        return 2
    args.workdir.mkdir(parents=True, exist_ok=True)
    output1 = args.workdir / "per_build_similarity_gate_1.exe"
    output2 = args.workdir / "per_build_similarity_gate_2.exe"

    try:
        log1 = run_build(args.ciphershell, args.sample, output1, args.config)
        log2 = run_build(args.ciphershell, args.sample, output2, args.config)

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

        combined1 = bytearray()
        combined2 = bytearray()
        for group in common_groups:
            g1, g2 = groups1[group], groups2[group]
            for digest_name in ("opcode_map", "handler_body", "dispatch_key", "variant_selector"):
                if g1[digest_name] == g2[digest_name]:
                    raise GateFailure(
                        f"vm_group={group}: {digest_name} digest is identical across "
                        f"both independently-seeded builds (0x{g1[digest_name]:x}) "
                        "-- accidental determinism, opcode map / dispatch key / "
                        "micro-op selection did not actually change per build")
            blob1 = extract_encrypted_handlers(output1, g1)
            blob2 = extract_encrypted_handlers(output2, g2)
            combined1.extend(blob1)
            combined2.extend(blob2)
            print(f"[group] vm_group={group} build1_size=0x{len(blob1):x} "
                  f"build2_size=0x{len(blob2):x} records1={g1['records']} "
                  f"records2={g2['records']}")

        similarity = byte_similarity(bytes(combined1), bytes(combined2))
        print(f"[aggregate] groups={common_groups} build1_bytes={len(combined1)} "
              f"build2_bytes={len(combined2)} similarity={similarity:.4f} "
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
