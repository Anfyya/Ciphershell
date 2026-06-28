import struct, sys
path = sys.argv[1] if len(sys.argv) > 1 else 'd:/vscode/CipherShell/tests/samples/hello_protected.exe'
with open(path, 'rb') as f:
    data = f.read()
pe_off = struct.unpack('<I', data[0x3C:0x40])[0]
ns = struct.unpack('<H', data[pe_off+6:pe_off+8])[0]
opt_hdr_size = struct.unpack('<H', data[pe_off+20:pe_off+22])[0]
print(f"File: {len(data)} bytes, Sections: {ns}")
ep = struct.unpack('<I', data[pe_off+40:pe_off+44])[0]
image_base = struct.unpack('<Q', data[pe_off+48:pe_off+56])[0]
si = struct.unpack('<I', data[pe_off+80:pe_off+84])[0]
print(f"ImageBase: {hex(image_base)}, EntryPoint: {hex(ep)}, SizeOfImage: {hex(si)}")
sec_base = pe_off + 24 + opt_hdr_size
for i in range(ns):
    so = sec_base + i*40
    name = data[so:so+8].rstrip(b'\x00').decode('ascii', errors='replace')
    vs = struct.unpack('<I', data[so+8:so+12])[0]
    va = struct.unpack('<I', data[so+12:so+16])[0]
    rs = struct.unpack('<I', data[so+16:so+20])[0]
    ro = struct.unpack('<I', data[so+20:so+24])[0]
    ch = struct.unpack('<I', data[so+36:so+40])[0]
    flags = []
    if ch & 0x20000000: flags.append('X')
    if ch & 0x40000000: flags.append('R')
    if ch & 0x80000000: flags.append('W')
    if ch & 0x00000020: flags.append('CODE')
    print(f"  [{i}] {name:8s} VA={hex(va):10s} VS={hex(vs):10s} RO={hex(ro):10s} RS={hex(rs):8s} {'|'.join(flags)}")
# Print first 48 bytes of stub section
last_ro = struct.unpack('<I', data[sec_base+(ns-1)*40+20:sec_base+(ns-1)*40+24])[0]
print(f"\nStub section raw offset: {hex(last_ro)}")
stub_data = data[last_ro:last_ro+80]
print("Stub bytes (hex):", stub_data.hex())
print("Stub disasm:")
for b in stub_data:
    pass
# Simple disasm of first few instructions
i = 0
while i < min(50, len(stub_data)):
    b = stub_data[i]
    if b == 0x53: print(f"  {i:02x}: push rbx"); i+=1
    elif b == 0x56: print(f"  {i:02x}: push rsi"); i+=1
    elif b == 0x57: print(f"  {i:02x}: push rdi"); i+=1
    elif b == 0x65 and stub_data[i+1]==0x48: print(f"  {i:02x}: mov rax, gs:[0x60]"); i+=9
    elif b == 0x48 and stub_data[i+1]==0x8B and stub_data[i+2]==0x40: print(f"  {i:02x}: mov rax, [rax+{stub_data[i+3]:x}]"); i+=4
    elif b == 0x49 and stub_data[i+1]==0x89: print(f"  {i:02x}: mov r12, rax"); i+=3
    elif b == 0x48 and stub_data[i+1]==0x8D and stub_data[i+2]==0xB0: disp=struct.unpack('<I',stub_data[i+3:i+7])[0]; print(f"  {i:02x}: lea rsi, [rax+{hex(disp)}]"); i+=7
    elif b == 0xB9: imm=struct.unpack('<I',stub_data[i+1:i+5])[0]; print(f"  {i:02x}: mov ecx, {hex(imm)}"); i+=5
    elif b == 0x48 and stub_data[i+1]==0x31: print(f"  {i:02x}: xor rdx, rdx"); i+=3
    elif b == 0x85: print(f"  {i:02x}: test ecx, ecx"); i+=2
    elif b == 0x74: print(f"  {i:02x}: jz +{stub_data[i+1]}"); i+=2
    elif b == 0x8A and stub_data[i+1]==0x1C: print(f"  {i:02x}: mov bl, [rsi+rdx]"); i+=3
    elif b == 0x80 and stub_data[i+1]==0xF3: print(f"  {i:02x}: xor bl, {hex(stub_data[i+2])}"); i+=3
    elif b == 0x88 and stub_data[i+1]==0x1C: print(f"  {i:02x}: mov [rsi+rdx], bl"); i+=3
    elif b == 0x48 and stub_data[i+1]==0xFF and stub_data[i+2]==0xC6: print(f"  {i:02x}: inc rsi"); i+=3
    elif b == 0x48 and stub_data[i+1]==0xFF and stub_data[i+2]==0xC2: print(f"  {i:02x}: inc rdx"); i+=3
    elif b == 0xFF and stub_data[i+1]==0xC9: print(f"  {i:02x}: dec ecx"); i+=2
    elif b == 0x48 and stub_data[i+1]==0x83 and stub_data[i+2]==0xE2: print(f"  {i:02x}: and rdx, {stub_data[i+3]}"); i+=4
    elif b == 0xEB: print(f"  {i:02x}: jmp {i+2+int.from_bytes(stub_data[i+1:i+2],'little',signed=True)}"); i+=2
    elif b == 0x4C and stub_data[i+1]==0x89: print(f"  {i:02x}: mov rax, r12"); i+=3
    elif b == 0x48 and stub_data[i+1]==0x05: disp=struct.unpack('<I',stub_data[i+3:i+7])[0]; print(f"  {i:02x}: add rax, {hex(disp)}"); i+=7
    elif b == 0x5F: print(f"  {i:02x}: pop rdi"); i+=1
    elif b == 0x5E: print(f"  {i:02x}: pop rsi"); i+=1
    elif b == 0x5B: print(f"  {i:02x}: pop rbx"); i+=1
    elif b == 0xFF and stub_data[i+1]==0xE0: print(f"  {i:02x}: jmp rax"); i+=2
    else: print(f"  {i:02x}: db {hex(b)}"); i+=1
