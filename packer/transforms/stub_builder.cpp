#include "stub_builder.h"
#include <cstring>
#include <iostream>
#include <new>

namespace CipherShell {

static void emit8(std::vector<BYTE>& c, uint8_t v) { c.push_back(v); }
static void emit32(std::vector<BYTE>& c, uint32_t v) {
    for (int i = 0; i < 4; i++) c.push_back((uint8_t)(v >> (i * 8)));
}
static size_t emit32_placeholder(std::vector<BYTE>& c) {
    size_t pos = c.size();
    emit32(c, 0);
    return pos;
}
static void patch32(std::vector<BYTE>& c, size_t pos, uint32_t v) {
    for (int i = 0; i < 4; i++) c[pos + i] = (uint8_t)(v >> (i * 8));
}
static void patch_rel8(std::vector<BYTE>& c, size_t immPos, size_t target) {
    int disp = (int)target - (int)(immPos + 1);
    c[immPos] = (uint8_t)(disp & 0xFF);
}
static void patch_rel32(std::vector<BYTE>& c, size_t immPos, size_t target) {
    int32_t disp = (int32_t)((int64_t)target - (int64_t)(immPos + 4));
    patch32(c, immPos, (uint32_t)disp);
}

static void append_task_table(std::vector<BYTE>& c, const std::vector<CS_STUB_PARAMS>& tasks) {
    emit32(c, (uint32_t)tasks.size());
    for (const auto& t : tasks) {
        emit32(c, t.sectionRVA);
        emit32(c, t.sectionSize);
        for (int i = 0; i < 32; i++) emit8(c, t.key[i]);
    }
}

static std::vector<CS_STUB_PARAMS> one_task(const CS_STUB_PARAMS& p) {
    std::vector<CS_STUB_PARAMS> tasks;
    tasks.push_back(p);
    return tasks;
}

static std::vector<BYTE> build_x86_multi(const std::vector<CS_STUB_PARAMS>& tasks, DWORD oepRVA) {
    std::vector<BYTE> c;

    emit8(c, 0x60);                              // pushad

    // Anti-debug: PEB->BeingDebugged
    emit8(c, 0x64); emit8(c, 0xA1); emit32(c, 0x30);       // mov eax, fs:[0x30]
    emit8(c, 0x0F); emit8(c, 0xB6); emit8(c, 0x40); emit8(c, 0x02); // movzx eax, byte [eax+2]
    emit8(c, 0x85); emit8(c, 0xC0);                         // test eax, eax
    emit8(c, 0x74); size_t noDebug = c.size(); emit8(c, 0);  // jz continue
    emit8(c, 0x31); emit8(c, 0xC0);                         // xor eax, eax
    emit8(c, 0xFF); emit8(c, 0xE0);                         // jmp eax
    patch_rel8(c, noDebug, c.size());

    // ebp = ImageBase
    emit8(c, 0x64); emit8(c, 0xA1); emit32(c, 0x30);         // mov eax, fs:[0x30]
    emit8(c, 0x8B); emit8(c, 0x40); emit8(c, 0x08);          // mov eax, [eax+8]
    emit8(c, 0x89); emit8(c, 0xC5);                         // mov ebp, eax

    // edi = task table (call/pop PIC)
    size_t callAddr = c.size();
    emit8(c, 0xE8); emit32(c, 0);                           // call next
    emit8(c, 0x5F);                                         // pop edi
    emit8(c, 0x81); emit8(c, 0xC7); size_t addTableImm = emit32_placeholder(c); // add edi, table-pop

    emit8(c, 0x8B); emit8(c, 0x0F);                         // mov ecx, [edi] ; count
    emit8(c, 0x83); emit8(c, 0xC7); emit8(c, 0x04);          // add edi, 4

    size_t outer = c.size();
    emit8(c, 0x85); emit8(c, 0xC9);                         // test ecx, ecx
    emit8(c, 0x0F); emit8(c, 0x84); size_t doneJz = emit32_placeholder(c);

    emit8(c, 0x89); emit8(c, 0xEE);                         // mov esi, ebp
    emit8(c, 0x03); emit8(c, 0x37);                         // add esi, [edi] ; rva
    emit8(c, 0x8B); emit8(c, 0x5F); emit8(c, 0x04);          // mov ebx, [edi+4] ; size
    emit8(c, 0x31); emit8(c, 0xD2);                         // xor edx, edx ; key index

    size_t inner = c.size();
    emit8(c, 0x85); emit8(c, 0xDB);                         // test ebx, ebx
    emit8(c, 0x74); size_t nextJz = c.size(); emit8(c, 0);
    emit8(c, 0x8A); emit8(c, 0x44); emit8(c, 0x17); emit8(c, 0x08); // mov al, [edi+edx+8]
    emit8(c, 0x30); emit8(c, 0x06);                         // xor [esi], al
    emit8(c, 0x46);                                         // inc esi
    emit8(c, 0x42);                                         // inc edx
    emit8(c, 0x83); emit8(c, 0xFA); emit8(c, 32);            // cmp edx, 32
    emit8(c, 0x72); size_t noWrap = c.size(); emit8(c, 0);   // jb no_wrap
    emit8(c, 0x31); emit8(c, 0xD2);                         // xor edx, edx
    patch_rel8(c, noWrap, c.size());
    emit8(c, 0x4B);                                         // dec ebx
    emit8(c, 0x75); size_t loopJnz = c.size(); emit8(c, 0);  // jnz inner
    patch_rel8(c, loopJnz, inner);

    size_t next = c.size();
    patch_rel8(c, nextJz, next);
    emit8(c, 0x83); emit8(c, 0xC7); emit8(c, 40);            // add edi, entry size
    emit8(c, 0x49);                                         // dec ecx
    emit8(c, 0xE9); size_t outerJmp = emit32_placeholder(c); // jmp outer
    patch_rel32(c, outerJmp, outer);

    size_t done = c.size();
    patch_rel32(c, doneJz, done);
    emit8(c, 0x61);                                         // popad

    // Reload ImageBase after popad and jump to OEP once.
    emit8(c, 0x64); emit8(c, 0xA1); emit32(c, 0x30);         // mov eax, fs:[0x30]
    emit8(c, 0x8B); emit8(c, 0x40); emit8(c, 0x08);          // mov eax, [eax+8]
    emit8(c, 0x05); emit32(c, oepRVA);                      // add eax, oepRVA
    emit8(c, 0xFF); emit8(c, 0xE0);                         // jmp eax

    size_t tableStart = c.size();
    uint32_t addImm = (uint32_t)(tableStart - (callAddr + 5));
    patch32(c, addTableImm, addImm);
    append_task_table(c, tasks);

    return c;
}

static std::vector<BYTE> build_x64_multi(const std::vector<CS_STUB_PARAMS>& tasks, DWORD oepRVA) {
    std::vector<BYTE> c;

    // rbx = PEB
    emit8(c, 0x65); emit8(c, 0x48); emit8(c, 0x8B); emit8(c, 0x04); emit8(c, 0x25); emit32(c, 0x60);

    // Anti-debug: PEB->BeingDebugged
    emit8(c, 0x80); emit8(c, 0x78); emit8(c, 0x02); emit8(c, 0x00); // cmp byte [rax+2], 0
    emit8(c, 0x74); size_t noDebug = c.size(); emit8(c, 0);         // jz continue
    emit8(c, 0x48); emit8(c, 0x31); emit8(c, 0xC0);                 // xor rax, rax
    emit8(c, 0xFF); emit8(c, 0xE0);                                 // jmp rax
    patch_rel8(c, noDebug, c.size());

    // rbx = ImageBase
    emit8(c, 0x65); emit8(c, 0x48); emit8(c, 0x8B); emit8(c, 0x04); emit8(c, 0x25); emit32(c, 0x60);
    emit8(c, 0x48); emit8(c, 0x8B); emit8(c, 0x58); emit8(c, 0x10);  // mov rbx, [rax+0x10]

    // r8 = task table
    size_t leaTable = c.size();
    emit8(c, 0x4C); emit8(c, 0x8D); emit8(c, 0x05); size_t tableDisp = emit32_placeholder(c); // lea r8, [rip+table]
    emit8(c, 0x41); emit8(c, 0x8B); emit8(c, 0x08);                 // mov ecx, [r8]
    emit8(c, 0x49); emit8(c, 0x83); emit8(c, 0xC0); emit8(c, 0x04); // add r8, 4

    size_t outer = c.size();
    emit8(c, 0x85); emit8(c, 0xC9);                                 // test ecx, ecx
    emit8(c, 0x0F); emit8(c, 0x84); size_t doneJz = emit32_placeholder(c);

    emit8(c, 0x41); emit8(c, 0x8B); emit8(c, 0x30);                 // mov esi, [r8]
    emit8(c, 0x41); emit8(c, 0x8B); emit8(c, 0x50); emit8(c, 0x04); // mov edx, [r8+4]
    emit8(c, 0x48); emit8(c, 0x8D); emit8(c, 0x34); emit8(c, 0x33); // lea rsi, [rbx+rsi]
    emit8(c, 0x49); emit8(c, 0x8D); emit8(c, 0x78); emit8(c, 0x08); // lea rdi, [r8+8]
    emit8(c, 0x45); emit8(c, 0x31); emit8(c, 0xC9);                 // xor r9d, r9d

    size_t inner = c.size();
    emit8(c, 0x85); emit8(c, 0xD2);                                 // test edx, edx
    emit8(c, 0x74); size_t nextJz = c.size(); emit8(c, 0);
    emit8(c, 0x42); emit8(c, 0x8A); emit8(c, 0x04); emit8(c, 0x0F); // mov al, [rdi+r9]
    emit8(c, 0x30); emit8(c, 0x06);                                 // xor [rsi], al
    emit8(c, 0x48); emit8(c, 0xFF); emit8(c, 0xC6);                 // inc rsi
    emit8(c, 0x41); emit8(c, 0xFF); emit8(c, 0xC1);                 // inc r9d
    emit8(c, 0x41); emit8(c, 0x83); emit8(c, 0xF9); emit8(c, 32);   // cmp r9d, 32
    emit8(c, 0x72); size_t noWrap = c.size(); emit8(c, 0);          // jb no_wrap
    emit8(c, 0x45); emit8(c, 0x31); emit8(c, 0xC9);                 // xor r9d, r9d
    patch_rel8(c, noWrap, c.size());
    emit8(c, 0xFF); emit8(c, 0xCA);                                 // dec edx
    emit8(c, 0x75); size_t loopJnz = c.size(); emit8(c, 0);         // jnz inner
    patch_rel8(c, loopJnz, inner);

    size_t next = c.size();
    patch_rel8(c, nextJz, next);
    emit8(c, 0x49); emit8(c, 0x83); emit8(c, 0xC0); emit8(c, 40);   // add r8, entry size
    emit8(c, 0xFF); emit8(c, 0xC9);                                 // dec ecx
    emit8(c, 0xE9); size_t outerJmp = emit32_placeholder(c);        // jmp outer
    patch_rel32(c, outerJmp, outer);

    size_t done = c.size();
    patch_rel32(c, doneJz, done);

    // Existing anti-dump behavior: erase e_lfanew before transferring control.
    emit8(c, 0xC7); emit8(c, 0x43); emit8(c, 0x3C); emit32(c, 0);

    emit8(c, 0x48); emit8(c, 0x8D); emit8(c, 0x83); emit32(c, oepRVA); // lea rax, [rbx+oep]
    emit8(c, 0xFF); emit8(c, 0xE0);                                     // jmp rax

    size_t tableStart = c.size();
    patch_rel32(c, tableDisp, tableStart);
    append_task_table(c, tasks);

    return c;
}

static std::vector<BYTE> build_x86(const CS_STUB_PARAMS& p) {
    return build_x86_multi(one_task(p), p.oepRVA);
}

static std::vector<BYTE> build_x64(const CS_STUB_PARAMS& p) {
    return build_x64_multi(one_task(p), p.oepRVA);
}

StubBuilder::StubBuilder() {}
StubBuilder::~StubBuilder() {}

bool StubBuilder::GenerateX86Stub(const CS_STUB_PARAMS& p, BYTE** out, DWORD* sz) {
    if (!out || !sz) return false;
    auto v = build_x86(p);
    *sz = (DWORD)v.size();
    *out = new(std::nothrow) BYTE[*sz];
    if (!*out) return false;
    memcpy(*out, v.data(), *sz);
    return true;
}

bool StubBuilder::GenerateX64Stub(const CS_STUB_PARAMS& p, BYTE** out, DWORD* sz) {
    if (!out || !sz) return false;
    auto v = build_x64(p);
    *sz = (DWORD)v.size();
    *out = new(std::nothrow) BYTE[*sz];
    if (!*out) return false;
    memcpy(*out, v.data(), *sz);
    return true;
}

bool StubBuilder::EmbedStub(CS_PE_IMAGE* img,
    const std::vector<CS_ENCRYPTED_SECTION>& encSections, DWORD oep)
{
    if (!img || encSections.empty()) return false;

    std::vector<CS_STUB_PARAMS> tasks;
    tasks.reserve(encSections.size());
    for (const auto& e : encSections) {
        if (e.encryptedSize == 0) continue;
        CS_STUB_PARAMS p{};
        p.magic = 0x43535350;
        p.oepRVA = oep;
        p.sectionRVA = e.originalRVA;
        p.sectionSize = e.encryptedSize;
        memcpy(p.key, e.sectionKey.key, 32);
        p.keySize = 32;
        tasks.push_back(p);
    }
    if (tasks.empty()) return false;

    std::vector<BYTE> stub = img->is64Bit ? build_x64_multi(tasks, oep)
                                          : build_x86_multi(tasks, oep);
    if (stub.empty()) return false;

    DWORD ss = (DWORD)stub.size();
    DWORD fa = img->is64Bit ? img->ntHeaders64->OptionalHeader.FileAlignment
                            : img->ntHeaders32->OptionalHeader.FileAlignment;
    DWORD sa = img->is64Bit ? img->ntHeaders64->OptionalHeader.SectionAlignment
                            : img->ntHeaders32->OptionalHeader.SectionAlignment;
    if (fa < 0x200) fa = 0x200;
    if (sa < 0x1000) sa = 0x1000;

    DWORD lfe = 0, lve = 0;
    for (WORD i = 0; i < img->numSections; i++) {
        DWORD fe = img->sections[i].PointerToRawData + img->sections[i].SizeOfRawData;
        DWORD ve = img->sections[i].VirtualAddress +
            ((img->sections[i].Misc.VirtualSize + sa - 1) & ~(sa - 1));
        if (fe > lfe) lfe = fe;
        if (ve > lve) lve = ve;
    }

    DWORD sfo = (lfe + fa - 1) & ~(fa - 1);
    DWORD sfs = (ss + fa - 1) & ~(fa - 1);
    DWORD srv = (lve + sa - 1) & ~(sa - 1);
    DWORD svs = (ss + sa - 1) & ~(sa - 1);

    DWORD newSectionHeaderEnd = (DWORD)((BYTE*)&img->sections[img->numSections + 1] - img->rawData);
    DWORD firstRaw = img->sections[0].PointerToRawData;
    if (firstRaw != 0 && newSectionHeaderEnd > firstRaw) {
        std::cerr << "  错误: PE 头部没有足够空间添加 stub section" << std::endl;
        return false;
    }

    DWORD overlaySize = 0;
    if (img->rawSize > lfe) overlaySize = img->rawSize - lfe;
    DWORD ns = sfo + sfs + overlaySize;

    BYTE* nd = new(std::nothrow) BYTE[ns];
    if (!nd) return false;
    memset(nd, 0, ns);
    DWORD copyPrefix = (img->rawSize < lfe) ? img->rawSize : lfe;
    memcpy(nd, img->rawData, copyPrefix);
    memcpy(nd + sfo, stub.data(), ss);
    if (overlaySize) memcpy(nd + sfo + sfs, img->rawData + lfe, overlaySize);

    DWORD po = img->dosHeader->e_lfanew;
    delete[] img->rawData;
    img->rawData = nd;
    img->rawSize = ns;
    img->dosHeader = (PIMAGE_DOS_HEADER)nd;
    if (img->is64Bit) {
        img->ntHeaders64 = (PIMAGE_NT_HEADERS64)(nd + po);
    } else {
        img->ntHeaders32 = (PIMAGE_NT_HEADERS32)(nd + po);
    }

    WORD ns2 = img->numSections + 1;
    PIMAGE_SECTION_HEADER secs = img->is64Bit
        ? IMAGE_FIRST_SECTION(img->ntHeaders64)
        : IMAGE_FIRST_SECTION(img->ntHeaders32);


    memset(&secs[img->numSections], 0, sizeof(IMAGE_SECTION_HEADER));
    memcpy(secs[img->numSections].Name, ".cstub", 6);
    secs[img->numSections].Misc.VirtualSize = svs;
    secs[img->numSections].VirtualAddress = srv;
    secs[img->numSections].SizeOfRawData = sfs;
    secs[img->numSections].PointerToRawData = sfo;
    secs[img->numSections].Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

    img->numSections = ns2;
    img->sections = secs;
    if (img->is64Bit) {
        img->ntHeaders64->FileHeader.NumberOfSections = ns2;
        img->ntHeaders64->OptionalHeader.SizeOfImage = srv + svs;
        img->ntHeaders64->OptionalHeader.AddressOfEntryPoint = srv;
    } else {
        img->ntHeaders32->FileHeader.NumberOfSections = ns2;
        img->ntHeaders32->OptionalHeader.SizeOfImage = srv + svs;
        img->ntHeaders32->OptionalHeader.AddressOfEntryPoint = srv;
    }

    std::cout << "  Stub embedded: " << ss << " bytes, tasks=" << tasks.size()
              << ", EP=0x" << std::hex << srv << "  OEP=0x" << oep << std::dec << "\n";
    return true;
}

} // namespace CipherShell
