#!/usr/bin/env python3
"""CipherShell Static Analysis - L1~L5 对比报告"""
import struct, sys, os

FILES = {
    '原始': r'D:\vs2022\vmp\x64\Debug\vmp.exe',
    'L1':   r'd:\vscode\CipherShell\tests\samples\vmp_L1.exe',
    'L2':   r'd:\vscode\CipherShell\tests\samples\vmp_L2.exe',
    'L3':   r'd:\vscode\CipherShell\tests\samples\vmp_L3.exe',
    'L4':   r'd:\vscode\CipherShell\tests\samples\vmp_L4.exe',
    'L5':   r'd:\vscode\CipherShell\tests\samples\vmp_L5.exe',
}

def read_pe(path):
    with open(path, 'rb') as f:
        return bytearray(f.read())

def pe_info(data, label):
    pe_off = struct.unpack('<I', data[0x3C:0x40])[0]
    ns = struct.unpack('<H', data[pe_off+6:pe_off+8])[0]
    oh = struct.unpack('<H', data[pe_off+20:pe_off+22])[0]
    ep = struct.unpack('<I', data[pe_off+40:pe_off+44])[0]
    ib = struct.unpack('<Q', data[pe_off+48:pe_off+56])[0]
    si = struct.unpack('<I', data[pe_off+80:pe_off+84])[0]
    sb = pe_off + 24 + oh
    sections = []
    for i in range(ns):
        s = sb + i*40
        name = data[s:s+8].rstrip(b'\x00').decode('ascii', errors='replace')
        va = struct.unpack('<I', data[s+12:s+16])[0]
        vs = struct.unpack('<I', data[s+8:s+12])[0]
        ro = struct.unpack('<I', data[s+20:s+24])[0]
        rs = struct.unpack('<I', data[s+16:s+20])[0]
        ch = struct.unpack('<I', data[s+36:s+40])[0]
        flags = []
        if ch & 0x20000000: flags.append('X')
        if ch & 0x40000000: flags.append('R')
        if ch & 0x80000000: flags.append('W')
        if ch & 0x00000020: flags.append('CODE')
        sections.append((name, va, vs, ro, rs, '|'.join(flags)))
    return ep, ib, si, len(data), sections

# ===== 1. PE 结构对比 =====
print("=" * 75)
print("CipherShell L1-L5 静态分析报告")
print("=" * 75)

print("\n【1. PE 结构对比】")
print(f"{'等级':<8} {'文件大小':>10} {'入口点':>10} {'Section数':>10} {'SizeOfImage':>12}")
print("-" * 55)
for label, path in FILES.items():
    data = read_pe(path)
    ep, ib, si, fsize, secs = pe_info(data, label)
    print(f"{label:<8} {fsize:>10} {hex(ep):>10} {len(secs):>10} {hex(si):>12}")

print("\n【2. Section 列表对比（原始 vs L1）】")
for label in ['原始', 'L1']:
    data = read_pe(FILES[label])
    _, _, _, _, secs = pe_info(data, label)
    print(f"\n  [{label}]")
    for i, (n, va, vs, ro, rs, fl) in enumerate(secs):
        print(f"    [{i:2d}] {n:8s} VA={hex(va):10s} VS={hex(vs):8s} file_off={hex(ro):8s} file_sz={rs:6d} [{fl}]")

# ===== 2. 字符串扫描对比 =====
print("\n\n【3. 可打印字符串数量对比】")
for label, path in FILES.items():
    data = read_pe(path)
    count = 0
    i = 0
    while i < len(data) - 4:
        if 0x20 <= data[i] <= 0x7E:
            j = i
            while j < len(data) and 0x20 <= data[j] <= 0x7E:
                j += 1
            if j - i >= 4:
                count += 1
                i = j
            else:
                i += 1
        else:
            i += 1
    print(f"  {label}: {count} 个可打印字符串 (>=4chars)")

# ===== 3. .text 段前 256 字节十六进制对比 =====
print("\n\n【4. .text 段前 128 字节十六进制】")
orig_data = read_pe(FILES['原始'])
pe_off = struct.unpack('<I', orig_data[0x3C:0x40])[0]
oh = struct.unpack('<H', orig_data[pe_off+20:pe_off+22])[0]
sb = pe_off + 24 + oh
orig_text_off = 0
for i in range(struct.unpack('<H', orig_data[pe_off+6:pe_off+8])[0]):
    s = sb + i*40
    name = orig_data[s:s+8].rstrip(b'\x00')
    if name == b'.text':
        orig_text_off = struct.unpack('<I', orig_data[s+20:s+24])[0]
        break

for label in FILES:
    data = read_pe(FILES[label])
    pe_off2 = struct.unpack('<I', data[0x3C:0x40])[0]
    oh2 = struct.unpack('<H', data[pe_off2+20:pe_off2+22])[0]
    sb2 = pe_off2 + 24 + oh2
    text_off = 0
    for i in range(struct.unpack('<H', data[pe_off2+6:pe_off2+8])[0]):
        s2 = sb2 + i*40
        name = data[s2:s2+8].rstrip(b'\x00')
        if name == b'.text':
            text_off = struct.unpack('<I', data[s2+20:s2+24])[0]
            break
    if text_off:
        print(f"\n  [{label}] .text hex (first 80 bytes):")
        chunk = data[text_off:text_off+80]
        for i in range(0, 80, 16):
            hex_part = ' '.join(f'{b:02x}' for b in chunk[i:i+16])
            ascii_part = ''.join(chr(b) if 0x20<=b<=0x7E else '.' for b in chunk[i:i+16])
            print(f"    {text_off+i:06x}: {hex_part:<48s} {ascii_part}")

# ===== 4. 入口点前 64 字节（stub 代码）=====
print("\n\n【5. 入口点代码对比（L1 的 stub vs 原始入口代码）】")
for label in ['原始', 'L1']:
    data = read_pe(FILES[label])
    ep, _, _, _, _ = pe_info(data, label)
    peo = struct.unpack('<I', data[0x3C:0x40])[0]
    oho = struct.unpack('<H', data[peo+20:peo+22])[0]
    sbo = peo + 24 + oho
    ep_file_off = 0
    for i in range(struct.unpack('<H', data[peo+6:peo+8])[0]):
        s = sbo + i*40
        va = struct.unpack('<I', data[s+12:s+16])[0]
        vs = struct.unpack('<I', data[s+8:s+12])[0]
        ro = struct.unpack('<I', data[s+20:s+24])[0]
        if va <= ep < va + vs:
            ep_file_off = ro + (ep - va)
            break
    if ep_file_off:
        print(f"\n  [{label}] EntryPoint code ({hex(ep)}):")
        chunk = data[ep_file_off:ep_file_off+64]
        for i in range(0, 64, 16):
            hex_part = ' '.join(f'{b:02x}' for b in chunk[i:i+16])
            ascii_part = ''.join(chr(b) if 0x20<=b<=0x7E else '.' for b in chunk[i:i+16])
            print(f"    {ep_file_off+i:06x}: {hex_part:<48s} {ascii_part}")

# ===== 5. 导入表 DLL 对比 =====
print("\n\n【6. 导入表 DLL 对比（前10个）】")
for label in ['原始', 'L2', 'L3', 'L4', 'L5']:
    data = read_pe(FILES[label])
    peo = struct.unpack('<I', data[0x3C:0x40])[0]
    import_rva = struct.unpack('<I', data[peo+24+8*16:peo+24+8*16+4])[0]  # IMAGE_DIRECTORY_ENTRY_IMPORT = 1
    import_size = struct.unpack('<I', data[peo+24+8*16+4:peo+24+8*16+8])[0]
    if import_rva == 0:
        print(f"  [{label}] 导入表已清除!")
        continue
    oh3 = struct.unpack('<H', data[peo+20:peo+22])[0]
    sb3 = peo + 24 + oh3
    import_file_off = 0
    for i in range(struct.unpack('<H', data[peo+6:peo+8])[0]):
        s = sb3 + i*40
        va = struct.unpack('<I', data[s+12:s+16])[0]
        vs = struct.unpack('<I', data[s+8:s+12])[0]
        ro = struct.unpack('<I', data[s+20:s+24])[0]
        if va <= import_rva < va + vs:
            import_file_off = ro + (import_rva - va)
            break
    if import_file_off:
        print(f"  [{label}] (offset {hex(import_file_off)}):")
        off = import_file_off
        for _ in range(10):
            if off + 20 > len(data): break
            name_rva = struct.unpack('<I', data[off+12:off+16])[0]
            if name_rva == 0: break
            # resolve name RVA to file offset
            name_off = 0
            for i2 in range(struct.unpack('<H', data[peo+6:peo+8])[0]):
                s2 = sb3 + i2*40
                va2 = struct.unpack('<I', data[s2+12:s2+16])[0]
                vs2 = struct.unpack('<I', data[s2+8:s2+12])[0]
                ro2 = struct.unpack('<I', data[s2+20:s2+24])[0]
                if va2 <= name_rva < va2 + vs2:
                    name_off = ro2 + (name_rva - va2)
                    break
            if name_off and name_off < len(data):
                end = data.find(0, name_off)
                if end > name_off:
                    dll = data[name_off:end].decode('ascii', errors='replace')
                    print(f"    {dll}")
            off += 20

# ===== 6. 熵值分析 =====
print("\n\n【7. .text 段熵值（信息熵，越高越随机/加密效果越好）】")
import math
for label in FILES:
    data = read_pe(FILES[label])
    peo = struct.unpack('<I', data[0x3C:0x40])[0]
    oho = struct.unpack('<H', data[peo+20:peo+22])[0]
    sbo = peo + 24 + oho
    text_off2 = 0; text_sz = 0
    for i in range(struct.unpack('<H', data[peo+6:peo+8])[0]):
        s = sbo + i*40
        name = data[s:s+8].rstrip(b'\x00')
        if name == b'.text':
            text_off2 = struct.unpack('<I', data[s+20:s+24])[0]
            text_sz = struct.unpack('<I', data[s+16:s+20])[0]
            break
    if text_off2 and text_sz:
        chunk = data[text_off2:text_off2+text_sz]
        freq = [0]*256
        for b in chunk: freq[b] += 1
        entropy = 0
        for f in freq:
            if f > 0:
                p = f / len(chunk)
                entropy -= p * math.log2(p)
        max_entropy = math.log2(256)  # = 8
        pct = entropy / max_entropy * 100
        bar = '█' * int(pct/2) + '░' * (50 - int(pct/2))
        print(f"  {label}: 熵={entropy:.2f} / 8.00 ({pct:.0f}%) {bar}")

print("\n" + "=" * 75)
print("分析完成")
print("=" * 75)
