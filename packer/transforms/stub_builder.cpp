#include "stub_builder.h"
#include <cstring>
#include <iostream>

namespace CipherShell {

static std::vector<BYTE> build_x86(const CS_STUB_PARAMS& p) {
    std::vector<BYTE> c;
    auto b = [&](uint8_t v) { c.push_back(v); };
    auto d = [&](uint32_t v) { for(int i=0;i<4;i++) c.push_back((uint8_t)(v>>(i*8))); };

    b(0x60);                     // pushad

    // --- Anti-Debug: Check PEB->BeingDebugged ---
    b(0x64); b(0xA1); d(0x30);   // mov eax, fs:[0x30]  (PEB)
    b(0x0F); b(0xB6); b(0x40); b(0x02); // movzx eax, byte [eax+2] (BeingDebugged)
    b(0x85); b(0xC0);            // test eax, eax
    b(0x74); uint8_t jz1 = (uint8_t)c.size(); b(0x00); // jz no_debug
    b(0x31); b(0xC0);            // xor eax,eax
    b(0xFF); b(0xE0);            // jmp eax -> crash
    c[jz1] = (uint8_t)(c.size() - jz1 - 1);

    // ImageBase via PEB
    b(0x64); b(0xA1); d(0x30);   // mov eax, fs:[0x30]
    b(0x8B); b(0x40); b(0x08);   // mov eax, [eax+8] -> ImageBase
    b(0x89); b(0xC5);            // mov ebp, eax (save ImageBase)

    // esi = section addr, ecx = sectionSize
    b(0x89); b(0xC6);            // mov esi, eax
    b(0x81); b(0xC6); d(p.sectionRVA);
    b(0xB9); d(p.sectionSize);
    b(0x85); b(0xC9);
    DWORD jzPos86 = (DWORD)c.size();
    b(0x74); uint8_t jzSkip86 = (uint8_t)c.size(); b(0x00);

    // lea edi, [key_table] — use call/pop trick for position-independent code
    b(0xE8); d(0);               // call $+5 (push next instr addr)
    // key_table follows immediately after decrypt loop + jmp

    // xor edx, edx (key index)
    b(0x31); b(0xD2);

    // === decrypt loop ===
    DWORD lpx = (DWORD)c.size();
    b(0x8A); b(0x04); b(0x17);   // mov al, [edi + edx]
    b(0x30); b(0x06);            // xor [esi], al
    b(0x46);                     // inc esi
    b(0x42);                     // inc edx
    b(0x83); b(0xFA); b(32);     // cmp edx, 32
    b(0x72); b(0x02);            // jb no_wrap
    b(0x31); b(0xD2);            // xor edx, edx (wrap)
    b(0x49);                     // dec ecx
    b(0x75);
    int jbx = (int)lpx - (int)c.size() - 1;
    b((uint8_t)(jbx & 0xFF));    // jnz loop

    c[jzSkip86] = (uint8_t)(c.size() - jzSkip86 - 1);

    // JMP OEP
    b(0x61);                     // popad
    b(0x89); b(0xE8);            // mov eax, ebp
    b(0x05); d(p.oepRVA);        // add eax, oepRVA
    b(0xFF); b(0xE0);            // jmp eax

    // === Embedded 32-byte key table ===
    DWORD keyStart = (DWORD)c.size();
    for (int i = 0; i < 32; i++) c.push_back(p.key[i]);

    // 回填 call/pop trick: edi = &key_table
    // call $+5 的返回地址正好是 key_table 的起始
    // call 指令位于 (jzSkip86 patched 之后, 即 c[jzSkip86+1] 开始)
    // 即 offset = jzPos86+2
    // 修正：call 指令的偏移量 = keyStart - (call_insn_addr + 5)
    DWORD callInsnAddr = jzPos86 + 2; // after jz, before "call $+5"
    *(DWORD*)(c.data() + callInsnAddr + 1) = keyStart - (callInsnAddr + 5);

    return c;
}

static std::vector<BYTE> build_x64(const CS_STUB_PARAMS& p) {
    std::vector<BYTE> c;
    auto b = [&](uint8_t v) { c.push_back(v); };
    auto d = [&](uint32_t v) { for(int i=0;i<4;i++) c.push_back((uint8_t)(v>>(i*8))); };

    // PEB traversal: rax = gs:[0x60] = PEB
    b(0x65); b(0x48); b(0x8B); b(0x04); b(0x25); d(0x60); // mov rax, gs:[0x60]

    // --- Anti-Debug: Check PEB->BeingDebugged (offset +0x02) ---
    b(0x80); b(0x78); b(0x02); b(0x00);  // cmp byte [rax+0x02], 0
    b(0x74); uint8_t jzDebug = (uint8_t)c.size(); b(0x00); // je continue (patch)
    b(0x48); b(0x31); b(0xC0);           // xor rax, rax (0)
    b(0xFF); b(0xE0);                     // jmp rax -> crash
    c[jzDebug] = (uint8_t)(c.size() - jzDebug - 1);

    // rbx = ImageBase (PEB+0x10)
    b(0x65); b(0x48); b(0x8B); b(0x04); b(0x25); d(0x60);
    b(0x48); b(0x8B); b(0x58); b(0x10); // mov rbx, [rax+0x10]

    // rsi = rbx + sectionRVA, ecx = sectionSize
    b(0x48); b(0x8D); b(0xB3); d(p.sectionRVA);
    b(0xB9); d(p.sectionSize);
    b(0x85); b(0xC9);
    DWORD jzPos = (DWORD)c.size();
    b(0x0F); b(0x84); d(0);            // jz -> done (skip decrypt)

    // lea rdi, [rip + key_table] — 32-byte key follows stub code
    // 在 x64 上 RIP-relative 寻址: lea rdi, [rip + offset]
    DWORD keyOffPos = (DWORD)c.size();
    b(0x48); b(0x8D); b(0x3D); d(0);   // lea rdi, [rip + 0] (patch later)

    // xor edx, edx (key index)
    b(0x31); b(0xD2);

    // === decrypt loop ===
    DWORD lp = (DWORD)c.size();
    b(0x8A); b(0x04); b(0x17);         // mov al, [rdi + rdx]
    b(0x30); b(0x06);                   // xor [rsi], al
    b(0x48); b(0xFF); b(0xC6);          // inc rsi
    b(0xFF); b(0xC2);                   // inc edx
    b(0x83); b(0xFA); b(32);            // cmp edx, 32
    b(0x72); b(0x02);                   // jb no_wrap
    b(0x31); b(0xD2);                   // xor edx, edx (wrap)
    // no_wrap:
    b(0xFF); b(0xC9);                   // dec ecx
    b(0x75);
    int jb2 = (int)lp - (int)c.size() - 1;
    b((uint8_t)(jb2 & 0xFF));           // jnz loop

    // patch jz: skip decrypt if sectionSize == 0
    *(DWORD*)(c.data() + jzPos + 2) = (DWORD)(c.size() - (jzPos + 6));

    // Anti-dump: mov dword [rbx+0x3C], 0
    b(0xC7); b(0x43); b(0x3C); d(0);

    // JMP OEP
    b(0x48); b(0x8D); b(0x83); d(p.oepRVA);
    b(0xFF); b(0xE0);

    // === Embedded 32-byte key table ===
    // 填充 key[0..31]
    for (int i = 0; i < 32; i++) c.push_back(p.key[i]);

    // 回填 RIP-relative offset: key_table 距离 lea 指令末尾的距离
    DWORD keyDist = (DWORD)(c.size() - 32) - (keyOffPos + 7);
    *(DWORD*)(c.data() + keyOffPos + 3) = keyDist;

    return c;
}

StubBuilder::StubBuilder() {}
StubBuilder::~StubBuilder() {}

bool StubBuilder::GenerateX86Stub(const CS_STUB_PARAMS& p, BYTE** out, DWORD* sz) {
    auto v = build_x86(p);
    *sz = (DWORD)v.size();
    *out = new BYTE[*sz];
    memcpy(*out, v.data(), *sz);
    return true;
}

bool StubBuilder::GenerateX64Stub(const CS_STUB_PARAMS& p, BYTE** out, DWORD* sz) {
    auto v = build_x64(p);
    *sz = (DWORD)v.size();
    *out = new BYTE[*sz];
    memcpy(*out, v.data(), *sz);
    return true;
}

bool StubBuilder::EmbedStub(CS_PE_IMAGE* img,
    const std::vector<CS_ENCRYPTED_SECTION>& encSections, DWORD oep)
{
    if (!img || encSections.empty()) return false;
    const auto& e = encSections[0];

    CS_STUB_PARAMS p; memset(&p,0,sizeof(p));
    p.magic=0x43535350; p.oepRVA=oep;
    p.sectionRVA=e.originalRVA; p.sectionSize=e.encryptedSize;
    memcpy(p.key, e.sectionKey.key, 32); p.keySize=32;

    BYTE* sd=nullptr; DWORD ss=0;
    if(!(img->is64Bit ? GenerateX64Stub(p,&sd,&ss):GenerateX86Stub(p,&sd,&ss)))
    { std::cerr<<"Stub gen failed\n"; return false; }

    DWORD fa = img->is64Bit ? img->ntHeaders64->OptionalHeader.FileAlignment
                            : img->ntHeaders32->OptionalHeader.FileAlignment;
    DWORD sa = img->is64Bit ? img->ntHeaders64->OptionalHeader.SectionAlignment
                            : img->ntHeaders32->OptionalHeader.SectionAlignment;
    if(fa<0x200)fa=0x200; if(sa<0x1000)sa=0x1000;

    DWORD lfe=0, lve=0;
    for(WORD i=0;i<img->numSections;i++){
        DWORD fe=img->sections[i].PointerToRawData+img->sections[i].SizeOfRawData;
        DWORD ve=img->sections[i].VirtualAddress+
            ((img->sections[i].Misc.VirtualSize+sa-1)&~(sa-1));
        if(fe>lfe)lfe=fe; if(ve>lve)lve=ve;
    }
    DWORD sfo=(lfe+fa-1)&~(fa-1), sfs=(ss+fa-1)&~(fa-1);
    DWORD srv=(lve+sa-1)&~(sa-1),   svs=(ss+sa-1)&~(sa-1);

    DWORD ns=sfo+sfs;
    // 保留 overlay 数据（如有）
    DWORD overlaySize = 0;
    if (img->rawSize > lfe) overlaySize = img->rawSize - lfe;
    ns += overlaySize;

    BYTE* nd=new BYTE[ns]; memset(nd,0,ns);
    memcpy(nd,img->rawData,img->rawSize);
    if (overlaySize) memcpy(nd + sfo + sfs, img->rawData + lfe, overlaySize);
    memcpy(nd+sfo,sd,ss); delete[] sd;

    DWORD po=img->dosHeader->e_lfanew;
    // 释放旧的 rawData，避免内存泄漏
    delete[] img->rawData;
    img->rawData=nd; img->rawSize=ns;
    img->dosHeader=(PIMAGE_DOS_HEADER)nd;
    // 根据架构设置正确的 NT Headers 指针
    if (img->is64Bit) {
        img->ntHeaders64=(PIMAGE_NT_HEADERS64)(nd+po);
    } else {
        img->ntHeaders32=(PIMAGE_NT_HEADERS32)(nd+po);
    }

    WORD ns2=img->numSections+1;
    PIMAGE_SECTION_HEADER secs=IMAGE_FIRST_SECTION(img->ntHeaders64);
    memset(&secs[img->numSections],0,sizeof(IMAGE_SECTION_HEADER));
    memcpy(secs[img->numSections].Name,".cstub",6);
    secs[img->numSections].Misc.VirtualSize=svs;
    secs[img->numSections].VirtualAddress=srv;
    secs[img->numSections].SizeOfRawData=sfs;
    secs[img->numSections].PointerToRawData=sfo;
    secs[img->numSections].Characteristics=IMAGE_SCN_CNT_CODE|IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_READ;

    img->numSections=ns2; img->sections=secs;
    img->ntHeaders64->FileHeader.NumberOfSections=ns2;
    img->ntHeaders64->OptionalHeader.SizeOfImage=srv+svs;
    img->ntHeaders64->OptionalHeader.AddressOfEntryPoint=srv;

    std::cout<<"  Stub embedded: "<<ss<<" bytes, EP=0x"<<std::hex<<srv
             <<" OEP=0x"<<oep<<std::dec<<"\n";
    return true;
}

} // namespace CipherShell
