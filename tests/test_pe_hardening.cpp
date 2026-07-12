// CipherShell PE 解析/发射加固回归测试
//
// 覆盖本次主要改动：
//   - Load Config 短结构（GuardFlags 缺失仍合法）/ declared Size 越界拒绝，目录 RVA
//     指向真实 .rdata（而非退化成 0）
//   - SafeSEH handler 完整验证（合法 / handler 落在非可执行段拒绝），PE32 字段按
//     真实 32 位宽度写入
//   - TLS：Start/End 区间必须落在同一个 file-backed section（拒绝跨 section 的
//     端点各自合法但整体不合法）、AddressOfIndex 必须容纳完整 DWORD、回调数组
//     终止符与逐项可执行性校验、回调扫描严格限制在自身所在 section 内（不越界
//     读到下一个 section 或 overlay）
//   - x64 Exception Directory：Begin<End、代码区间必须整体可执行且 file-backed
//     （含仅虚存尾部拒绝）、条目不重叠；UnwindData 必须是完整合法的 UNWIND_INFO——
//     Version 与 CapabilityChecker 共用同一份受支持范围 [1,2]、CountOfCodes 对应的
//     UnwindCode 数组必须落在文件范围内、按 Flags 校验 handler RVA 或链式
//     RUNTIME_FUNCTION 尾部结构
//   - Delay Import：INT / IAT / ModuleHandle / Bound / Unload 表分别独立测试合法与
//     非法两种情形，及无终止项 / Size 非 32 倍数 / VA-based 负面场景
//   - Resource（循环 / 名称截断 / data 越界）
//   - Security / WIN_CERTIFICATE（合法链 / dwLength 越界 / 对齐错误）
//   - Debug payload 越界拒绝；PEEmitter 追加 section 场景下真实回填并同步
//     PointerToRawData/AddressOfRawData
//   - PEEmitter：追加 section 后 Security/Debug/overlay 偏移同步、连续追加无重复偏移、
//     失败回滚（image 不变）、header relocation 后 section 偏移同步
//   - 负面测试普遍核对 img->isValid 与 errorMessage 中的目录关键字，确认解析确实
//     因目标目录本身畸形而失败，而非巧合地留空容器
//
// 本文件通过 ctest 实际运行（见 tests/CMakeLists.txt 的 pe_hardening_regression），
// 全部断言要求真实通过，而不仅是编译通过。
// 受 /W4 /WX 约束，使用始终求值的检查宏（Release 下 assert 会被编译为空）。

#include "../packer/pe_parser/pe_parser.h"
#include "../packer/pe_parser/pe_emitter.h"
#include "../packer/pe_parser/pe_utils.h"

#include <cstring>
#include <cstdint>
#include <vector>
#include <string>

#define CS_TEST_CHECK(cond) do { if (!(cond)) std::abort(); } while (0)

namespace {

constexpr uint32_t kFileAlign = 0x200;
constexpr uint32_t kSecAlign = 0x1000;

uint32_t AlignUp(uint32_t v, uint32_t a) { return a ? (v + a - 1) & ~(a - 1) : v; }

// 简易字节写入器：按需扩展缓冲区。
struct Writer {
    std::vector<uint8_t> buf;
    size_t pos = 0;
    void ensure(size_t n) { if (buf.size() < pos + n) buf.resize(pos + n, 0); }
    void put(const void* p, size_t n) { ensure(n); std::memcpy(buf.data() + pos, p, n); pos += n; }
    void u32(uint32_t v) { put(&v, 4); }
    void u16(uint16_t v) { put(&v, 2); }
    void u64(uint64_t v) { put(&v, 8); }
    void pad(size_t n) { ensure(n); pos += n; }
    void seek(size_t p) { if (buf.size() < p) buf.resize(p, 0); pos = p; }
    size_t mark() const { return pos; }
};

struct DirEntry { uint32_t index; uint32_t value; uint32_t size; };

struct PeLayout {
    std::vector<uint8_t> bytes;
    uint32_t textVA = 0;
    uint32_t textFileOff = 0;
    uint32_t rdataVA = 0;
    uint32_t rdataFileOff = 0;
    uint32_t rdataRawSize = 0;
    uint32_t overlayFileOff = 0;
};

// 构造一个 PE。textData 为 .text（可执行）原始字节；rdata 为 .rdata（可读）原始字节；
// dirs 为数据目录（index, value, size）。security(index=4) 的 value 是文件偏移。
// tightHeaders=true 时把 SizeOfHeaders 与 .text 原始偏移设为 section table 末尾（未对齐），
// 使追加一条 section header 时必然触发 header relocation。
PeLayout BuildPe(bool is64, const std::vector<uint8_t>& textData,
                 const std::vector<uint8_t>& rdata, const std::vector<DirEntry>& dirs,
                 const std::vector<uint8_t>& overlay, bool tightHeaders = false)
{
    const uint32_t ntOff = sizeof(IMAGE_DOS_HEADER);
    const uint32_t ntSize = is64 ? sizeof(IMAGE_NT_HEADERS64) : sizeof(IMAGE_NT_HEADERS32);
    const uint32_t secTableOff = ntOff + ntSize;
    const bool hasRdata = !rdata.empty();
    const uint32_t numSec = 1 + (hasRdata ? 1 : 0);  // .text (+ .rdata)
    const uint32_t secTableEnd = secTableOff + numSec * sizeof(IMAGE_SECTION_HEADER);

    const uint32_t headersRaw = tightHeaders ? secTableEnd : AlignUp(secTableEnd, kFileAlign);
    const uint32_t textRaw = AlignUp(static_cast<uint32_t>(textData.size()), kFileAlign);
    const uint32_t rdataRaw = hasRdata ? AlignUp(static_cast<uint32_t>(rdata.size()), kFileAlign) : 0;

    const uint32_t textVA = 0x1000;
    const uint32_t textSpan = (std::max)(static_cast<uint32_t>(textData.size()), textRaw);
    const uint32_t rdataVA = AlignUp(textVA + textSpan, kSecAlign);

    const uint32_t textFileOff = headersRaw;
    const uint32_t rdataFileOff = headersRaw + textRaw;
    const uint32_t overlayFileOff = rdataFileOff + rdataRaw;
    const uint32_t totalSize = overlayFileOff + static_cast<uint32_t>(overlay.size());

    PeLayout lay;
    lay.bytes.assign(totalSize, 0);

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(lay.bytes.data());
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = static_cast<LONG>(ntOff);

    std::memcpy(lay.bytes.data() + ntOff, "PE\0\0", 4);
    auto* fh = reinterpret_cast<IMAGE_FILE_HEADER*>(lay.bytes.data() + ntOff + 4);
    fh->Machine = is64 ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_MACHINE_I386;
    fh->NumberOfSections = static_cast<WORD>(numSec);
    fh->SizeOfOptionalHeader = is64 ? sizeof(IMAGE_OPTIONAL_HEADER64) : sizeof(IMAGE_OPTIONAL_HEADER32);

    if (is64) {
        auto* oh = reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(lay.bytes.data() + secTableOff - sizeof(IMAGE_OPTIONAL_HEADER64));
        oh->Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        oh->FileAlignment = kFileAlign;
        oh->SectionAlignment = kSecAlign;
        oh->SizeOfHeaders = headersRaw;
        oh->NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        oh->ImageBase = 0x140000000ULL;
        oh->AddressOfEntryPoint = textVA;
        oh->SizeOfImage = AlignUp(rdataVA + (hasRdata ? (std::max)(static_cast<uint32_t>(rdata.size()), rdataRaw) : 0), kSecAlign);
        oh->BaseOfCode = textVA;
    } else {
        auto* oh = reinterpret_cast<IMAGE_OPTIONAL_HEADER32*>(lay.bytes.data() + secTableOff - sizeof(IMAGE_OPTIONAL_HEADER32));
        oh->Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
        oh->FileAlignment = kFileAlign;
        oh->SectionAlignment = kSecAlign;
        oh->SizeOfHeaders = headersRaw;
        oh->NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        oh->ImageBase = 0x10000000;
        oh->AddressOfEntryPoint = textVA;
        oh->SizeOfImage = AlignUp(rdataVA + (hasRdata ? (std::max)(static_cast<uint32_t>(rdata.size()), rdataRaw) : 0), kSecAlign);
        oh->BaseOfCode = textVA;
    }

    // 数据目录。
    auto* nt64 = is64 ? reinterpret_cast<IMAGE_NT_HEADERS64*>(lay.bytes.data() + ntOff) : nullptr;
    auto* nt32 = is64 ? nullptr : reinterpret_cast<IMAGE_NT_HEADERS32*>(lay.bytes.data() + ntOff);
    for (const auto& d : dirs) {
        if (is64) {
            nt64->OptionalHeader.DataDirectory[d.index].VirtualAddress = d.value;
            nt64->OptionalHeader.DataDirectory[d.index].Size = d.size;
        } else {
            nt32->OptionalHeader.DataDirectory[d.index].VirtualAddress = d.value;
            nt32->OptionalHeader.DataDirectory[d.index].Size = d.size;
        }
    }

    // section table。
    auto* secs = reinterpret_cast<IMAGE_SECTION_HEADER*>(lay.bytes.data() + secTableOff);
    std::memcpy(secs[0].Name, ".text", 5);
    secs[0].VirtualAddress = textVA;
    secs[0].Misc.VirtualSize = static_cast<DWORD>(textData.size());
    secs[0].SizeOfRawData = textRaw;
    secs[0].PointerToRawData = textFileOff;
    secs[0].Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
    if (hasRdata) {
        std::memcpy(secs[1].Name, ".rdata", 6);
        secs[1].VirtualAddress = rdataVA;
        secs[1].Misc.VirtualSize = static_cast<DWORD>(rdata.size());
        secs[1].SizeOfRawData = rdataRaw;
        secs[1].PointerToRawData = rdataFileOff;
        secs[1].Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
    }

    // 原始数据。
    std::memcpy(lay.bytes.data() + textFileOff, textData.data(), textData.size());
    if (hasRdata) std::memcpy(lay.bytes.data() + rdataFileOff, rdata.data(), rdata.size());
    if (!overlay.empty()) std::memcpy(lay.bytes.data() + overlayFileOff, overlay.data(), overlay.size());

    lay.textVA = textVA; lay.textFileOff = textFileOff;
    lay.rdataVA = rdataVA; lay.rdataFileOff = rdataFileOff; lay.rdataRawSize = rdataRaw;
    lay.overlayFileOff = overlayFileOff;
    return lay;
}

CipherShell::CS_PE_IMAGE* Parse(const PeLayout& lay) {
    BYTE* buf = new BYTE[lay.bytes.size()];
    std::memcpy(buf, lay.bytes.data(), lay.bytes.size());
    CipherShell::PEParser parser;
    return parser.LoadFromBuffer(buf, static_cast<DWORD>(lay.bytes.size()));
}

// ============================================================================
// Load Config
// ============================================================================

void TestLoadConfigShortNoGuardFlags() {
    // declared Size 仅覆盖到 SecurityCookie 之前，不含 GuardFlags。
    Writer rd;
    const size_t lcOff = rd.mark();
    const uint32_t declaredSize = offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, SecurityCookie) +
        sizeof(DWORD64);  // 到 SecurityCookie，未到 GuardFlags
    rd.u32(declaredSize);            // Size
    rd.pad(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, SecurityCookie) - sizeof(DWORD));
    rd.u64(0xDEADBEEF12345678ULL);   // SecurityCookie
    // 不写 GuardFlags。

    std::vector<DirEntry> dirs = {
        {IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, static_cast<uint32_t>(0x2000 + lcOff), declaredSize}
    };
    auto lay = BuildPe(true, {0xCC, 0xCC, 0xCC, 0xCC}, rd.buf, dirs, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(img && img->isValid);
    CS_TEST_CHECK(img->loadConfig.valid);
    CS_TEST_CHECK(img->loadConfig.securityCookie == 0xDEADBEEF12345678ULL);
    CS_TEST_CHECK(img->loadConfig.guardFlags == 0);     // GuardFlags 缺失按零
    CS_TEST_CHECK(!img->loadConfig.hasCFG);             // 不得因缺 GuardFlags 拒绝整个 PE
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestLoadConfigDeclaredSizeExceedsAvailable() {
    // declared Size 远大于 rdata 实际可用范围。
    Writer rd;
    const size_t lcOff = rd.mark();
    rd.u32(0x10000);  // 声称 64KB，但 rdata 只有几十字节
    rd.pad(32);
    std::vector<DirEntry> dirs = {
        {IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, static_cast<uint32_t>(0x2000 + lcOff), 0x10000}
    };
    auto lay = BuildPe(true, {0xCC}, rd.buf, dirs, {});
    auto* img = Parse(lay);
    // declaredSize > rawAvailable → 解析失败。
    CS_TEST_CHECK(!img->loadConfig.valid);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestLoadConfigShortNoSEHandler() {
    // declared Size 不足以包含 SEHandlerTable/Count，相关字段不读取。
    Writer rd;
    const size_t lcOff = rd.mark();
    const uint32_t declaredSize = sizeof(DWORD);  // 只有 Size 字段
    rd.u32(declaredSize);
    std::vector<DirEntry> dirs = {
        {IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, static_cast<uint32_t>(0x2000 + lcOff), declaredSize}
    };
    auto lay = BuildPe(false, {0xCC, 0xCC}, rd.buf, dirs, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(img && img->isValid);
    CS_TEST_CHECK(img->loadConfig.valid);
    CS_TEST_CHECK(img->loadConfig.seHandlerTable == 0);
    CS_TEST_CHECK(img->loadConfig.safeSEHHandlerRVAs.empty());
    CipherShell::PEParser p; p.FreeImage(img);
}

// ============================================================================
// SafeSEH
// ============================================================================

void TestSafeSEHValid() {
    // x86 PE：handler 表在 .rdata，每个 handler RVA 指向 .text（可执行）。
    Writer rd;
    const size_t lcOff = rd.mark();
    rd.u32(sizeof(IMAGE_LOAD_CONFIG_DIRECTORY32));  // Size
    rd.pad(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, SEHandlerTable) - sizeof(DWORD));
    // 先占位 SEHandlerTable/Count，表数据紧跟。PE32 的 SEHandlerTable 是 32 位 VA
    // （DWORD 字段），必须按 32 位写入，否则会错位覆盖紧随其后的 SEHandlerCount。
    const size_t sehTableRel = rd.mark();
    rd.u32(0);  // SEHandlerTable (32 位 VA) 占位
    rd.u32(2);  // SEHandlerCount
    // handler 表：2 个 DWORD，指向 .text 内 RVA。
    const size_t tableDataOff = rd.mark();
    uint32_t h1 = 0x1000;  // .text 入口
    uint32_t h2 = 0x1002;
    rd.u32(h1);
    rd.u32(h2);

    const uint32_t imageBase = 0x10000000;
    const uint32_t tableRVA = /*rdataVA*/ 0x2000 + static_cast<uint32_t>(tableDataOff);
    const uint32_t tableVA = imageBase + tableRVA;
    // 回填 SEHandlerTable VA（32 位）。
    std::memcpy(rd.buf.data() + sehTableRel, &tableVA, sizeof(uint32_t));

    std::vector<DirEntry> dirs = {
        {IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, static_cast<uint32_t>(0x2000 + lcOff),
         sizeof(IMAGE_LOAD_CONFIG_DIRECTORY32)}
    };
    auto lay = BuildPe(false, {0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC}, rd.buf, dirs, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(img && img->isValid);
    CS_TEST_CHECK(img->loadConfig.valid);
    CS_TEST_CHECK(img->loadConfig.safeSEHHandlerRVAs.size() == 2);
    CS_TEST_CHECK(img->loadConfig.safeSEHHandlerRVAs[0] == 0x1000);
    CS_TEST_CHECK(img->loadConfig.safeSEHHandlerRVAs[1] == 0x1002);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestSafeSEHHandlerNotExecutable() {
    // handler RVA 指向 .rdata（非可执行）→ 拒绝。
    Writer rd;
    const size_t lcOff = rd.mark();
    rd.u32(sizeof(IMAGE_LOAD_CONFIG_DIRECTORY32));
    rd.pad(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, SEHandlerTable) - sizeof(DWORD));
    // SEHandlerTable 是 PE32 的 32 位 VA 字段，必须按 32 位写入。
    const size_t sehTableRel = rd.mark();
    rd.u32(0);
    rd.u32(1);
    const size_t tableDataOff = rd.mark();
    const uint32_t imageBase = 0x10000000;
    uint32_t badHandler = 0x2000;  // .rdata，不可执行
    rd.u32(badHandler);
    const uint32_t tableRVA = 0x2000 + static_cast<uint32_t>(tableDataOff);
    const uint32_t tableVA = imageBase + tableRVA;
    std::memcpy(rd.buf.data() + sehTableRel, &tableVA, sizeof(uint32_t));

    std::vector<DirEntry> dirs = {
        {IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, static_cast<uint32_t>(0x2000 + lcOff),
         sizeof(IMAGE_LOAD_CONFIG_DIRECTORY32)}
    };
    auto lay = BuildPe(false, {0xCC, 0xCC, 0xCC, 0xCC}, rd.buf, dirs, {});
    auto* img = Parse(lay);
    // handler 落在非可执行段 → 整个 Load Config 解析失败。
    CS_TEST_CHECK(!img->loadConfig.valid);
    CipherShell::PEParser p; p.FreeImage(img);
}

// ============================================================================
// TLS
// ============================================================================

constexpr uint64_t kTlsImageBase = 0x140000000ULL;
constexpr uint32_t kTlsRdataVA = 0x2000;

struct TlsLayout {
    std::vector<uint8_t> rdata;
    size_t dirRel = 0;
};

// 构造一个合法的 x64 TLS 目录：模板数据 [Start,End) 落在 .rdata 内，AddressOfIndex
// 指向 .rdata 内一个 4 字节槽，AddressOfCallBacks 指向一个以 0 结尾的回调 VA 数组
// （默认 1 个回调，指向 .text 入口）。返回 rdata 缓冲区与 TLS 目录结构体的相对偏移，
// 调用方可据此直接改写缓冲区构造负面场景。
TlsLayout BuildTlsValid() {
    Writer rd;
    const size_t dirRel = rd.mark();
    rd.pad(sizeof(IMAGE_TLS_DIRECTORY64));
    const size_t templateRel = rd.mark();
    rd.u32(0xAAAAAAAA);  // 4 字节模板数据
    const size_t indexRel = rd.mark();
    rd.u32(0);           // AddressOfIndex 槽
    const size_t callbacksRel = rd.mark();
    rd.u64(kTlsImageBase + 0x1000);  // 1 个回调，指向 .text 入口（可执行）
    rd.u64(0);                       // 终止符

    auto va = [&](size_t rel) { return kTlsImageBase + kTlsRdataVA + static_cast<uint64_t>(rel); };
    IMAGE_TLS_DIRECTORY64 tlsDir{};
    tlsDir.StartAddressOfRawData = va(templateRel);
    tlsDir.EndAddressOfRawData = va(templateRel) + 4;
    tlsDir.AddressOfIndex = va(indexRel);
    tlsDir.AddressOfCallBacks = va(callbacksRel);
    std::memcpy(rd.buf.data() + dirRel, &tlsDir, sizeof(tlsDir));

    return {std::move(rd.buf), dirRel};
}

void TestTlsValid() {
    auto tls = BuildTlsValid();
    std::vector<DirEntry> dirs = {
        {IMAGE_DIRECTORY_ENTRY_TLS, kTlsRdataVA + static_cast<uint32_t>(tls.dirRel),
         sizeof(IMAGE_TLS_DIRECTORY64)}
    };
    auto lay = BuildPe(true, {0xCC, 0xCC, 0xCC, 0xCC}, tls.rdata, dirs, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(img && img->isValid);
    CS_TEST_CHECK(img->tls.valid);
    CS_TEST_CHECK(img->tls.callbackAddresses.size() == 1);
    CS_TEST_CHECK(img->tls.callbackAddresses[0] == kTlsImageBase + 0x1000);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestTlsStartAfterEnd() {
    auto tls = BuildTlsValid();
    IMAGE_TLS_DIRECTORY64 tlsDir{};
    std::memcpy(&tlsDir, tls.rdata.data() + tls.dirRel, sizeof(tlsDir));
    std::swap(tlsDir.StartAddressOfRawData, tlsDir.EndAddressOfRawData);  // Start > End
    std::memcpy(tls.rdata.data() + tls.dirRel, &tlsDir, sizeof(tlsDir));

    std::vector<DirEntry> dirs = {
        {IMAGE_DIRECTORY_ENTRY_TLS, kTlsRdataVA + static_cast<uint32_t>(tls.dirRel),
         sizeof(IMAGE_TLS_DIRECTORY64)}
    };
    auto lay = BuildPe(true, {0xCC, 0xCC, 0xCC, 0xCC}, tls.rdata, dirs, {});
    auto* img = Parse(lay);
    // 目标错误：Start > End，必须因 TLS 目录本身畸形而拒绝整个 PE（而不是巧合失败）。
    CS_TEST_CHECK(!img->isValid);
    CS_TEST_CHECK(!img->tls.valid);
    CS_TEST_CHECK(img->errorMessage.find("TLS") != std::string::npos);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestTlsCrossSectionRange() {
    // Start 落在 .text，End 落在 .rdata：两个端点各自都能映射，但整个区间并不落在
    // 同一个 file-backed section 内——必须整体拒绝，而不能仅靠校验两个端点判断合法。
    auto tls = BuildTlsValid();
    IMAGE_TLS_DIRECTORY64 tlsDir{};
    std::memcpy(&tlsDir, tls.rdata.data() + tls.dirRel, sizeof(tlsDir));
    tlsDir.StartAddressOfRawData = kTlsImageBase + 0x1000;         // .text 入口
    tlsDir.EndAddressOfRawData = kTlsImageBase + kTlsRdataVA + 4;  // .rdata 内
    std::memcpy(tls.rdata.data() + tls.dirRel, &tlsDir, sizeof(tlsDir));

    std::vector<DirEntry> dirs = {
        {IMAGE_DIRECTORY_ENTRY_TLS, kTlsRdataVA + static_cast<uint32_t>(tls.dirRel),
         sizeof(IMAGE_TLS_DIRECTORY64)}
    };
    auto lay = BuildPe(true, {0xCC, 0xCC, 0xCC, 0xCC}, tls.rdata, dirs, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(!img->isValid);
    CS_TEST_CHECK(!img->tls.valid);
    CS_TEST_CHECK(img->errorMessage.find("TLS") != std::string::npos);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestTlsIndexTooSmall() {
    // AddressOfIndex 指向 .rdata 对齐区的最后 1 字节：首字节可映射，但容不下完整的
    // 4 字节 DWORD，必须拒绝。
    auto tls = BuildTlsValid();
    IMAGE_TLS_DIRECTORY64 tlsDir{};
    std::memcpy(&tlsDir, tls.rdata.data() + tls.dirRel, sizeof(tlsDir));
    tlsDir.AddressOfIndex = kTlsImageBase + kTlsRdataVA + kFileAlign - 1;  // 对齐区最后 1 字节
    std::memcpy(tls.rdata.data() + tls.dirRel, &tlsDir, sizeof(tlsDir));

    std::vector<DirEntry> dirs = {
        {IMAGE_DIRECTORY_ENTRY_TLS, kTlsRdataVA + static_cast<uint32_t>(tls.dirRel),
         sizeof(IMAGE_TLS_DIRECTORY64)}
    };
    auto lay = BuildPe(true, {0xCC, 0xCC, 0xCC, 0xCC}, tls.rdata, dirs, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(!img->isValid);
    CS_TEST_CHECK(!img->tls.valid);
    CS_TEST_CHECK(img->errorMessage.find("TLS") != std::string::npos);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestTlsCallbackNotExecutable() {
    // 回调 VA 指向 .rdata（非可执行）→ 拒绝。
    auto tls = BuildTlsValid();
    IMAGE_TLS_DIRECTORY64 tlsDir{};
    std::memcpy(&tlsDir, tls.rdata.data() + tls.dirRel, sizeof(tlsDir));
    const uint64_t callbacksVA = tlsDir.AddressOfCallBacks;
    const size_t callbacksRel = static_cast<size_t>(callbacksVA - kTlsImageBase - kTlsRdataVA);
    const uint64_t badCallback = kTlsImageBase + kTlsRdataVA;  // .rdata 自身，不可执行
    std::memcpy(tls.rdata.data() + callbacksRel, &badCallback, sizeof(badCallback));

    std::vector<DirEntry> dirs = {
        {IMAGE_DIRECTORY_ENTRY_TLS, kTlsRdataVA + static_cast<uint32_t>(tls.dirRel),
         sizeof(IMAGE_TLS_DIRECTORY64)}
    };
    auto lay = BuildPe(true, {0xCC, 0xCC, 0xCC, 0xCC}, tls.rdata, dirs, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(!img->isValid);
    CS_TEST_CHECK(!img->tls.valid);
    CS_TEST_CHECK(img->errorMessage.find("TLS") != std::string::npos);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestTlsCallbackNotTerminated() {
    // 回调数组一直填到文件对齐边界为止，全部是合法且可执行的重复 VA，故意不留终止符：
    // 必须因为“扫描耗尽文件范围仍未找到 NULL 终止符”而拒绝——不能被对齐 padding 的
    // 零字节意外“救回”，也不能因为目标非法而提前失败于无关原因。
    Writer rd;
    const size_t dirRel = rd.mark();
    rd.pad(sizeof(IMAGE_TLS_DIRECTORY64));
    const size_t templateRel = rd.mark();
    rd.u32(0xAAAAAAAA);
    const size_t indexRel = rd.mark();
    rd.u32(0);
    const size_t callbacksRel = rd.mark();
    const uint64_t validCallback = kTlsImageBase + 0x1000;  // .text 入口，合法且可执行
    while (rd.buf.size() % kFileAlign != 0) {
        rd.u64(validCallback);
    }

    auto va = [&](size_t rel) { return kTlsImageBase + kTlsRdataVA + static_cast<uint64_t>(rel); };
    IMAGE_TLS_DIRECTORY64 tlsDir{};
    tlsDir.StartAddressOfRawData = va(templateRel);
    tlsDir.EndAddressOfRawData = va(templateRel) + 4;
    tlsDir.AddressOfIndex = va(indexRel);
    tlsDir.AddressOfCallBacks = va(callbacksRel);
    std::memcpy(rd.buf.data() + dirRel, &tlsDir, sizeof(tlsDir));

    std::vector<DirEntry> dirs = {
        {IMAGE_DIRECTORY_ENTRY_TLS, kTlsRdataVA + static_cast<uint32_t>(dirRel),
         sizeof(IMAGE_TLS_DIRECTORY64)}
    };
    auto lay = BuildPe(true, {0xCC, 0xCC, 0xCC, 0xCC}, rd.buf, dirs, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(!img->isValid);
    CS_TEST_CHECK(!img->tls.valid);
    CS_TEST_CHECK(img->errorMessage.find("TLS") != std::string::npos);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestTlsCallbackScanConfinedToOwnSection() {
    // 回调数组填满 .rdata 自身对齐区域（全部合法且可执行，.rdata 内无终止符），
    // 紧随其后的 overlay 前 8 字节是 0——如果扫描越界读到 .rdata 之外，会被误判为
    // 合法的 NULL 终止符而错误放行。必须确认扫描严格限制在回调数组自身所在
    // section 的 file-backed 范围内，正确因“未在自身 section 内终止”而拒绝。
    Writer rd;
    const size_t dirRel = rd.mark();
    rd.pad(sizeof(IMAGE_TLS_DIRECTORY64));
    const size_t templateRel = rd.mark();
    rd.u32(0xAAAAAAAA);
    const size_t indexRel = rd.mark();
    rd.u32(0);
    const size_t callbacksRel = rd.mark();
    const uint64_t validCallback = kTlsImageBase + 0x1000;  // .text 入口，合法且可执行
    while (rd.buf.size() % kFileAlign != 0) {
        rd.u64(validCallback);
    }

    auto va = [&](size_t rel) { return kTlsImageBase + kTlsRdataVA + static_cast<uint64_t>(rel); };
    IMAGE_TLS_DIRECTORY64 tlsDir{};
    tlsDir.StartAddressOfRawData = va(templateRel);
    tlsDir.EndAddressOfRawData = va(templateRel) + 4;
    tlsDir.AddressOfIndex = va(indexRel);
    tlsDir.AddressOfCallBacks = va(callbacksRel);
    std::memcpy(rd.buf.data() + dirRel, &tlsDir, sizeof(tlsDir));

    std::vector<DirEntry> dirs = {
        {IMAGE_DIRECTORY_ENTRY_TLS, kTlsRdataVA + static_cast<uint32_t>(dirRel),
         sizeof(IMAGE_TLS_DIRECTORY64)}
    };
    // overlay 前 8 字节是 0：修复前越界扫描到这里会被误判为终止符（本测试即用于
    // 证伪那个行为）。
    std::vector<uint8_t> overlay(8, 0);
    auto lay = BuildPe(true, {0xCC, 0xCC, 0xCC, 0xCC}, rd.buf, dirs, overlay);
    auto* img = Parse(lay);
    CS_TEST_CHECK(!img->isValid);
    CS_TEST_CHECK(!img->tls.valid);
    CS_TEST_CHECK(img->errorMessage.find("TLS") != std::string::npos);
    CipherShell::PEParser p; p.FreeImage(img);
}

// ============================================================================
// x64 Exception Directory
// ============================================================================

constexpr uint32_t kExcTextVA = 0x1000;
constexpr uint32_t kExcRdataVA = 0x2000;

// 合法的 UNWIND_INFO 最小固定头部：Version=1, Flags=0, 无 prolog/UnwindCode。
std::vector<uint8_t> BuildUnwindInfoValid() {
    return {0x01, 0x00, 0x00, 0x00};
}

void TestExceptionValid() {
    Writer rd;
    const size_t entryRel = rd.mark();
    rd.pad(sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY));
    const size_t unwindRel = rd.mark();
    auto unwind = BuildUnwindInfoValid();
    rd.put(unwind.data(), unwind.size());

    IMAGE_RUNTIME_FUNCTION_ENTRY entry{};
    entry.BeginAddress = kExcTextVA;
    entry.EndAddress = kExcTextVA + 8;
    entry.UnwindData = kExcRdataVA + static_cast<uint32_t>(unwindRel);
    std::memcpy(rd.buf.data() + entryRel, &entry, sizeof(entry));

    std::vector<DirEntry> dirs = {
        {IMAGE_DIRECTORY_ENTRY_EXCEPTION, kExcRdataVA + static_cast<uint32_t>(entryRel),
         sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)}
    };
    auto lay = BuildPe(true, std::vector<uint8_t>(8, 0xCC), rd.buf, dirs, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(img && img->isValid);
    CS_TEST_CHECK(img->exceptions.entries.size() == 1);
    CS_TEST_CHECK(img->exceptions.entries[0].beginAddress == kExcTextVA);
    CS_TEST_CHECK(img->exceptions.entries[0].endAddress == kExcTextVA + 8);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestExceptionBeginNotLessThanEnd() {
    Writer rd;
    const size_t entryRel = rd.mark();
    rd.pad(sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY));
    const size_t unwindRel = rd.mark();
    auto unwind = BuildUnwindInfoValid();
    rd.put(unwind.data(), unwind.size());

    IMAGE_RUNTIME_FUNCTION_ENTRY entry{};
    entry.BeginAddress = kExcTextVA + 8;
    entry.EndAddress = kExcTextVA;  // Begin >= End
    entry.UnwindData = kExcRdataVA + static_cast<uint32_t>(unwindRel);
    std::memcpy(rd.buf.data() + entryRel, &entry, sizeof(entry));

    std::vector<DirEntry> dirs = {
        {IMAGE_DIRECTORY_ENTRY_EXCEPTION, kExcRdataVA + static_cast<uint32_t>(entryRel),
         sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)}
    };
    auto lay = BuildPe(true, std::vector<uint8_t>(8, 0xCC), rd.buf, dirs, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(!img->isValid);
    CS_TEST_CHECK(img->exceptions.entries.empty());
    CS_TEST_CHECK(img->errorMessage.find("exception") != std::string::npos);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestExceptionRangeNotExecutable() {
    // BeginAddress/EndAddress 落在 .rdata（可读但不可执行）→ 拒绝。
    Writer rd;
    const size_t entryRel = rd.mark();
    rd.pad(sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY));
    const size_t unwindRel = rd.mark();
    auto unwind = BuildUnwindInfoValid();
    rd.put(unwind.data(), unwind.size());

    IMAGE_RUNTIME_FUNCTION_ENTRY entry{};
    entry.BeginAddress = kExcRdataVA;
    entry.EndAddress = kExcRdataVA + 4;
    entry.UnwindData = kExcRdataVA + static_cast<uint32_t>(unwindRel);
    std::memcpy(rd.buf.data() + entryRel, &entry, sizeof(entry));

    std::vector<DirEntry> dirs = {
        {IMAGE_DIRECTORY_ENTRY_EXCEPTION, kExcRdataVA + static_cast<uint32_t>(entryRel),
         sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)}
    };
    auto lay = BuildPe(true, std::vector<uint8_t>(8, 0xCC), rd.buf, dirs, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(!img->isValid);
    CS_TEST_CHECK(img->exceptions.entries.empty());
    CS_TEST_CHECK(img->errorMessage.find("exception") != std::string::npos);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestExceptionRangeNotFileBacked() {
    // 人为把 .text 的 VirtualSize 撑大到 SizeOfRawData 之外（模拟仅虚存、无文件支持
    // 的尾部区域，且刻意不越界到 .rdata），异常表条目落在该尾部必须被拒绝。
    Writer rd;
    const size_t entryRel = rd.mark();
    rd.pad(sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY));
    const size_t unwindRel = rd.mark();
    auto unwind = BuildUnwindInfoValid();
    rd.put(unwind.data(), unwind.size());

    IMAGE_RUNTIME_FUNCTION_ENTRY entry{};
    entry.BeginAddress = kExcTextVA + kFileAlign;  // .text raw 边界（0x200）之外
    entry.EndAddress = entry.BeginAddress + 8;
    entry.UnwindData = kExcRdataVA + static_cast<uint32_t>(unwindRel);
    std::memcpy(rd.buf.data() + entryRel, &entry, sizeof(entry));

    std::vector<DirEntry> dirs = {
        {IMAGE_DIRECTORY_ENTRY_EXCEPTION, kExcRdataVA + static_cast<uint32_t>(entryRel),
         sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)}
    };
    auto lay = BuildPe(true, std::vector<uint8_t>(8, 0xCC), rd.buf, dirs, {});
    // 撑大 .text 的 VirtualSize 到 0x1000（仍严格小于 .rdata 的 VA 0x2000，不产生重叠），
    // 使 [kFileAlign, kFileAlign+8) 落在“仅虚存”的尾部而非 .rdata。
    auto* secs = reinterpret_cast<IMAGE_SECTION_HEADER*>(
        lay.bytes.data() + sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64));
    secs[0].Misc.VirtualSize = 0x1000;
    auto* img = Parse(lay);
    CS_TEST_CHECK(!img->isValid);
    CS_TEST_CHECK(img->exceptions.entries.empty());
    CS_TEST_CHECK(img->errorMessage.find("exception") != std::string::npos);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestExceptionOverlappingRanges() {
    // 两个条目按 BeginAddress 排列后仍互相重叠（第二个的 Begin < 第一个的 End）→ 拒绝。
    Writer rd;
    const size_t entriesRel = rd.mark();
    rd.pad(sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY) * 2);
    const size_t unwindRel = rd.mark();
    auto unwind = BuildUnwindInfoValid();
    rd.put(unwind.data(), unwind.size());

    IMAGE_RUNTIME_FUNCTION_ENTRY entries[2]{};
    entries[0].BeginAddress = kExcTextVA;
    entries[0].EndAddress = kExcTextVA + 0x10;
    entries[0].UnwindData = kExcRdataVA + static_cast<uint32_t>(unwindRel);
    entries[1].BeginAddress = kExcTextVA + 0x08;  // 落在 entries[0] 范围内 → 重叠
    entries[1].EndAddress = kExcTextVA + 0x18;
    entries[1].UnwindData = kExcRdataVA + static_cast<uint32_t>(unwindRel);
    std::memcpy(rd.buf.data() + entriesRel, entries, sizeof(entries));

    std::vector<DirEntry> dirs = {
        {IMAGE_DIRECTORY_ENTRY_EXCEPTION, kExcRdataVA + static_cast<uint32_t>(entriesRel),
         sizeof(entries)}
    };
    auto lay = BuildPe(true, std::vector<uint8_t>(0x18, 0xCC), rd.buf, dirs, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(!img->isValid);
    CS_TEST_CHECK(img->exceptions.entries.empty());
    CS_TEST_CHECK(img->errorMessage.find("exception") != std::string::npos);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestExceptionUnwindHeaderTooShort() {
    // UnwindData 指向文件末尾前仅剩 2 字节的位置：首字节可映射，但容不下完整的
    // 4 字节 UNWIND_INFO 固定头部，必须拒绝。
    Writer rd;
    const size_t entryRel = rd.mark();
    rd.pad(sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY));
    // 用合法字节填满到对齐边界前 2 字节处，让 UnwindData 指向的位置只剩 2 字节可读。
    while (rd.buf.size() % kFileAlign != kFileAlign - 2) {
        rd.buf.push_back(0);
    }
    const size_t unwindRel = rd.mark();

    IMAGE_RUNTIME_FUNCTION_ENTRY entry{};
    entry.BeginAddress = kExcTextVA;
    entry.EndAddress = kExcTextVA + 8;
    entry.UnwindData = kExcRdataVA + static_cast<uint32_t>(unwindRel);
    std::memcpy(rd.buf.data() + entryRel, &entry, sizeof(entry));

    std::vector<DirEntry> dirs = {
        {IMAGE_DIRECTORY_ENTRY_EXCEPTION, kExcRdataVA + static_cast<uint32_t>(entryRel),
         sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)}
    };
    auto lay = BuildPe(true, std::vector<uint8_t>(8, 0xCC), rd.buf, dirs, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(!img->isValid);
    CS_TEST_CHECK(img->exceptions.entries.empty());
    CS_TEST_CHECK(img->errorMessage.find("exception") != std::string::npos);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestExceptionUnwindBadVersion() {
    // UnwindData 完整可读 4 字节，但 Version 字段落在支持范围 [1,2] 之外 → 拒绝。
    Writer rd;
    const size_t entryRel = rd.mark();
    rd.pad(sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY));
    const size_t unwindRel = rd.mark();
    rd.buf.push_back(0x03);  // Version=3：超出解析器与 CapabilityChecker 共同支持的 [1,2]
    rd.buf.push_back(0x00);
    rd.buf.push_back(0x00);
    rd.buf.push_back(0x00);

    IMAGE_RUNTIME_FUNCTION_ENTRY entry{};
    entry.BeginAddress = kExcTextVA;
    entry.EndAddress = kExcTextVA + 8;
    entry.UnwindData = kExcRdataVA + static_cast<uint32_t>(unwindRel);
    std::memcpy(rd.buf.data() + entryRel, &entry, sizeof(entry));

    std::vector<DirEntry> dirs = {
        {IMAGE_DIRECTORY_ENTRY_EXCEPTION, kExcRdataVA + static_cast<uint32_t>(entryRel),
         sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)}
    };
    auto lay = BuildPe(true, std::vector<uint8_t>(8, 0xCC), rd.buf, dirs, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(!img->isValid);
    CS_TEST_CHECK(img->exceptions.entries.empty());
    CS_TEST_CHECK(img->errorMessage.find("exception") != std::string::npos);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestExceptionUnwindVersion2Accepted() {
    // Version=2 是解析器与 CapabilityChecker::IsFunctionVmSafe 共同支持的版本
    // （PEUtils::kUnwindInfoMaxVersion），必须被接受而不是拒绝。
    Writer rd;
    const size_t entryRel = rd.mark();
    rd.pad(sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY));
    const size_t unwindRel = rd.mark();
    rd.buf.push_back(0x02);  // Version=2, Flags=0
    rd.buf.push_back(0x00);
    rd.buf.push_back(0x00);
    rd.buf.push_back(0x00);

    IMAGE_RUNTIME_FUNCTION_ENTRY entry{};
    entry.BeginAddress = kExcTextVA;
    entry.EndAddress = kExcTextVA + 8;
    entry.UnwindData = kExcRdataVA + static_cast<uint32_t>(unwindRel);
    std::memcpy(rd.buf.data() + entryRel, &entry, sizeof(entry));

    std::vector<DirEntry> dirs = {
        {IMAGE_DIRECTORY_ENTRY_EXCEPTION, kExcRdataVA + static_cast<uint32_t>(entryRel),
         sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)}
    };
    auto lay = BuildPe(true, std::vector<uint8_t>(8, 0xCC), rd.buf, dirs, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(img && img->isValid);
    CS_TEST_CHECK(img->exceptions.entries.size() == 1);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestExceptionUnwindCodeArrayTruncated() {
    // CountOfCodes 声明的 UNWIND_CODE 数组（每项 2 字节，奇数向上补齐到偶数）超出
    // 文件实际范围 → 拒绝。
    Writer rd;
    const size_t entryRel = rd.mark();
    rd.pad(sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY));
    const size_t unwindRel = rd.mark();
    rd.buf.push_back(0x01);  // Version=1, Flags=0
    rd.buf.push_back(0x00);  // SizeOfProlog
    rd.buf.push_back(0xFF);  // CountOfCodes=255：数组需要 255(向上补偶=256)*2=512 字节，
                              // 远超本测试实际提供的数据。
    rd.buf.push_back(0x00);  // FrameRegister/FrameOffset
    // 故意不再写任何 UnwindCode 数据。

    IMAGE_RUNTIME_FUNCTION_ENTRY entry{};
    entry.BeginAddress = kExcTextVA;
    entry.EndAddress = kExcTextVA + 8;
    entry.UnwindData = kExcRdataVA + static_cast<uint32_t>(unwindRel);
    std::memcpy(rd.buf.data() + entryRel, &entry, sizeof(entry));

    std::vector<DirEntry> dirs = {
        {IMAGE_DIRECTORY_ENTRY_EXCEPTION, kExcRdataVA + static_cast<uint32_t>(entryRel),
         sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)}
    };
    auto lay = BuildPe(true, std::vector<uint8_t>(8, 0xCC), rd.buf, dirs, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(!img->isValid);
    CS_TEST_CHECK(img->exceptions.entries.empty());
    CS_TEST_CHECK(img->errorMessage.find("exception") != std::string::npos);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestExceptionUnwindHandlerValid() {
    // Flags=UNW_FLAG_EHANDLER，CountOfCodes=0，尾部 4 字节 handler RVA 指向 .text
    // （可执行、file-backed）→ 接受。
    Writer rd;
    const size_t entryRel = rd.mark();
    rd.pad(sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY));
    const size_t unwindRel = rd.mark();
    rd.buf.push_back(static_cast<uint8_t>(0x01 | (0x1 << 3)));  // Version=1, Flags=EHANDLER
    rd.buf.push_back(0x00);
    rd.buf.push_back(0x00);  // CountOfCodes=0
    rd.buf.push_back(0x00);
    rd.u32(kExcTextVA);  // handler RVA：.text 入口，可执行

    IMAGE_RUNTIME_FUNCTION_ENTRY entry{};
    entry.BeginAddress = kExcTextVA;
    entry.EndAddress = kExcTextVA + 8;
    entry.UnwindData = kExcRdataVA + static_cast<uint32_t>(unwindRel);
    std::memcpy(rd.buf.data() + entryRel, &entry, sizeof(entry));

    std::vector<DirEntry> dirs = {
        {IMAGE_DIRECTORY_ENTRY_EXCEPTION, kExcRdataVA + static_cast<uint32_t>(entryRel),
         sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)}
    };
    auto lay = BuildPe(true, std::vector<uint8_t>(8, 0xCC), rd.buf, dirs, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(img && img->isValid);
    CS_TEST_CHECK(img->exceptions.entries.size() == 1);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestExceptionUnwindHandlerInvalid() {
    // Flags=UNW_FLAG_EHANDLER，但 handler RVA 指向 .rdata（不可执行）→ 拒绝。
    Writer rd;
    const size_t entryRel = rd.mark();
    rd.pad(sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY));
    const size_t unwindRel = rd.mark();
    rd.buf.push_back(static_cast<uint8_t>(0x01 | (0x1 << 3)));  // Version=1, Flags=EHANDLER
    rd.buf.push_back(0x00);
    rd.buf.push_back(0x00);  // CountOfCodes=0
    rd.buf.push_back(0x00);
    rd.u32(kExcRdataVA);  // handler RVA：.rdata 自身，不可执行

    IMAGE_RUNTIME_FUNCTION_ENTRY entry{};
    entry.BeginAddress = kExcTextVA;
    entry.EndAddress = kExcTextVA + 8;
    entry.UnwindData = kExcRdataVA + static_cast<uint32_t>(unwindRel);
    std::memcpy(rd.buf.data() + entryRel, &entry, sizeof(entry));

    std::vector<DirEntry> dirs = {
        {IMAGE_DIRECTORY_ENTRY_EXCEPTION, kExcRdataVA + static_cast<uint32_t>(entryRel),
         sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)}
    };
    auto lay = BuildPe(true, std::vector<uint8_t>(8, 0xCC), rd.buf, dirs, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(!img->isValid);
    CS_TEST_CHECK(img->exceptions.entries.empty());
    CS_TEST_CHECK(img->errorMessage.find("exception") != std::string::npos);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestExceptionUnwindChainedValid() {
    // Flags=UNW_FLAG_CHAININFO，CountOfCodes=0，尾部是一个合法的链式
    // IMAGE_RUNTIME_FUNCTION_ENTRY（Begin<End，12 字节）→ 接受。
    Writer rd;
    const size_t entryRel = rd.mark();
    rd.pad(sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY));
    const size_t unwindRel = rd.mark();
    rd.buf.push_back(static_cast<uint8_t>(0x01 | (0x4 << 3)));  // Version=1, Flags=CHAININFO
    rd.buf.push_back(0x00);
    rd.buf.push_back(0x00);  // CountOfCodes=0
    rd.buf.push_back(0x00);
    IMAGE_RUNTIME_FUNCTION_ENTRY chained{};
    chained.BeginAddress = kExcTextVA;
    chained.EndAddress = kExcTextVA + 4;
    chained.UnwindData = 0;  // 不递归校验，值本身无所谓
    rd.put(&chained, sizeof(chained));

    IMAGE_RUNTIME_FUNCTION_ENTRY entry{};
    entry.BeginAddress = kExcTextVA;
    entry.EndAddress = kExcTextVA + 8;
    entry.UnwindData = kExcRdataVA + static_cast<uint32_t>(unwindRel);
    std::memcpy(rd.buf.data() + entryRel, &entry, sizeof(entry));

    std::vector<DirEntry> dirs = {
        {IMAGE_DIRECTORY_ENTRY_EXCEPTION, kExcRdataVA + static_cast<uint32_t>(entryRel),
         sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)}
    };
    auto lay = BuildPe(true, std::vector<uint8_t>(8, 0xCC), rd.buf, dirs, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(img && img->isValid);
    CS_TEST_CHECK(img->exceptions.entries.size() == 1);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestExceptionUnwindChainedInvalid() {
    // Flags=UNW_FLAG_CHAININFO，链式 entry 的 BeginAddress >= EndAddress（畸形）→ 拒绝。
    Writer rd;
    const size_t entryRel = rd.mark();
    rd.pad(sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY));
    const size_t unwindRel = rd.mark();
    rd.buf.push_back(static_cast<uint8_t>(0x01 | (0x4 << 3)));  // Version=1, Flags=CHAININFO
    rd.buf.push_back(0x00);
    rd.buf.push_back(0x00);  // CountOfCodes=0
    rd.buf.push_back(0x00);
    IMAGE_RUNTIME_FUNCTION_ENTRY chained{};
    chained.BeginAddress = kExcTextVA + 8;
    chained.EndAddress = kExcTextVA;  // Begin >= End：畸形链式尾部
    chained.UnwindData = 0;
    rd.put(&chained, sizeof(chained));

    IMAGE_RUNTIME_FUNCTION_ENTRY entry{};
    entry.BeginAddress = kExcTextVA;
    entry.EndAddress = kExcTextVA + 8;
    entry.UnwindData = kExcRdataVA + static_cast<uint32_t>(unwindRel);
    std::memcpy(rd.buf.data() + entryRel, &entry, sizeof(entry));

    std::vector<DirEntry> dirs = {
        {IMAGE_DIRECTORY_ENTRY_EXCEPTION, kExcRdataVA + static_cast<uint32_t>(entryRel),
         sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)}
    };
    auto lay = BuildPe(true, std::vector<uint8_t>(8, 0xCC), rd.buf, dirs, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(!img->isValid);
    CS_TEST_CHECK(img->exceptions.entries.empty());
    CS_TEST_CHECK(img->errorMessage.find("exception") != std::string::npos);
    CipherShell::PEParser p; p.FreeImage(img);
}

// ============================================================================
// Delay Import
// ============================================================================

struct DelayLayout {
    std::vector<uint8_t> rdata;
    size_t descRel = 0;
};

// ModuleHandle/Bound/Unload 均为可选表：withXxx 控制是否携带该表，
// xxxBad 控制该表是否被故意构造为非法（用于对应的负面测试）。
struct DelayOptions {
    bool withModuleHandle = false;
    bool moduleHandleBad = false;  // ModuleHandleRVA 指向文件之外，无法映射
    bool withBoundTable = false;
    bool boundTableBad = false;    // Bound 表终止槽非零
    bool withUnloadTable = false;
    bool unloadTableBad = false;   // Unload 表终止槽非零
};

// 构造一个合法 RVA-based delay import descriptor（x64，2 个按名称导入 + 终止符），
// 按需附加 ModuleHandle/Bound/Unload 表。
DelayLayout BuildDelay(const DelayOptions& opt = {}) {
    Writer rd;
    const size_t descRel = rd.mark();
    // 占位 descriptor（32 字节）。
    rd.pad(sizeof(IMAGE_DELAYLOAD_DESCRIPTOR));
    // 全零终止符 descriptor（32 字节），紧跟在真实 descriptor 之后。
    // 必须真实存在且全零：目录 Size 覆盖 2 个 descriptor 槽位时，解析器会依次扫描，
    // 若第二槽不是全零就会被当成另一个（非法的）descriptor 而拒绝整个目录。
    rd.pad(sizeof(IMAGE_DELAYLOAD_DESCRIPTOR));
    // DLL 名称。
    const size_t nameRel = rd.mark();
    const char* dll = "test.dll";
    rd.put(dll, 8);
    rd.buf.push_back(0);
    // INT：2 个 hint/name 指针 + 终止符（8 字节）。
    const size_t intRel = rd.mark();
    rd.u64(0); rd.u64(0); rd.u64(0);  // 占位
    // IAT：2 + 终止符。
    const size_t iatRel = rd.mark();
    rd.u64(0); rd.u64(0); rd.u64(0);
    // hint/name 条目 1。
    const size_t hn1Rel = rd.mark();
    rd.u16(0);  // hint
    const char* f1 = "FuncA";
    rd.put(f1, 5); rd.buf.push_back(0);
    // hint/name 条目 2。
    const size_t hn2Rel = rd.mark();
    rd.u16(0);
    const char* f2 = "FuncB";
    rd.put(f2, 5); rd.buf.push_back(0);

    const uint32_t rdataVA = 0x2000;
    auto rva = [&](size_t rel) { return rdataVA + static_cast<uint32_t>(rel); };

    // ModuleHandleRVA：合法时指向一个指针宽度的占位句柄槽；非法时指向文件之外的 RVA。
    uint32_t moduleHandleRVA = 0;
    if (opt.withModuleHandle) {
        if (opt.moduleHandleBad) {
            moduleHandleRVA = 0x7FFFFFFF;  // 远超文件范围，无法映射
        } else {
            const size_t moduleHandleRel = rd.mark();
            rd.u64(0);
            moduleHandleRVA = rva(moduleHandleRel);
        }
    }

    // Bound/Unload 表：2 项占位 + 终止槽；xxxBad 时终止槽写非零值。
    uint32_t boundRVA = 0;
    if (opt.withBoundTable) {
        const size_t boundRel = rd.mark();
        rd.u64(0); rd.u64(0);
        rd.u64(opt.boundTableBad ? 0x1234ULL : 0ULL);
        boundRVA = rva(boundRel);
    }
    uint32_t unloadRVA = 0;
    if (opt.withUnloadTable) {
        const size_t unloadRel = rd.mark();
        rd.u64(0); rd.u64(0);
        rd.u64(opt.unloadTableBad ? 0x5678ULL : 0ULL);
        unloadRVA = rva(unloadRel);
    }

    IMAGE_DELAYLOAD_DESCRIPTOR desc{};
    desc.Attributes.AllAttributes = 0x1;  // RVA-based
    desc.DllNameRVA = rva(nameRel);
    desc.ModuleHandleRVA = moduleHandleRVA;
    desc.ImportAddressTableRVA = rva(iatRel);
    desc.ImportNameTableRVA = rva(intRel);
    desc.BoundImportAddressTableRVA = boundRVA;
    desc.UnloadInformationTableRVA = unloadRVA;
    desc.TimeDateStamp = 0;
    std::memcpy(rd.buf.data() + descRel, &desc, sizeof(desc));

    // 填 INT：指向 hint/name（非 ordinal）。
    uint64_t i1 = rva(hn1Rel);
    uint64_t i2 = rva(hn2Rel);
    std::memcpy(rd.buf.data() + intRel, &i1, 8);
    std::memcpy(rd.buf.data() + intRel + 8, &i2, 8);
    // iatRel+16 终止符已是 0。
    // IAT 同样写入（非终止项值不要求与 INT 相等，但终止槽必须为 0）。
    std::memcpy(rd.buf.data() + iatRel, &i1, 8);
    std::memcpy(rd.buf.data() + iatRel + 8, &i2, 8);

    return {std::move(rd.buf), descRel};
}

// 兼容旧调用点：不带任何可选表的最简合法 descriptor。
DelayLayout BuildValidDelay() { return BuildDelay({}); }

void TestDelayImportValid() {
    auto dl = BuildValidDelay();
    std::vector<DirEntry> dirs = {
        {IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, 0x2000 + static_cast<uint32_t>(dl.descRel),
         sizeof(IMAGE_DELAYLOAD_DESCRIPTOR) * 2}  // descriptor + 全零终止符
    };
    auto lay = BuildPe(true, {0xCC, 0xCC}, dl.rdata, dirs, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(img && img->isValid);
    CS_TEST_CHECK(img->delayImports.dlls.size() == 1);
    CS_TEST_CHECK(img->delayImports.dlls[0].functions.size() == 2);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestDelayImportNoTerminator() {
    auto dl = BuildValidDelay();
    // 目录只覆盖 1 个 descriptor，无全零终止项。
    std::vector<DirEntry> dirs = {
        {IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, 0x2000 + static_cast<uint32_t>(dl.descRel),
         sizeof(IMAGE_DELAYLOAD_DESCRIPTOR)}
    };
    auto lay = BuildPe(true, {0xCC, 0xCC}, dl.rdata, dirs, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(img->delayImports.dlls.empty());
    CS_TEST_CHECK(!img->isValid);
    CS_TEST_CHECK(img->errorMessage.find("delay import") != std::string::npos);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestDelayImportSizeNotMultiple() {
    auto dl = BuildValidDelay();
    std::vector<DirEntry> dirs = {
        {IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, 0x2000 + static_cast<uint32_t>(dl.descRel),
         sizeof(IMAGE_DELAYLOAD_DESCRIPTOR) + 1}  // 非 32 倍数
    };
    auto lay = BuildPe(true, {0xCC, 0xCC}, dl.rdata, dirs, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(img->delayImports.dlls.empty());
    CS_TEST_CHECK(!img->isValid);
    CS_TEST_CHECK(img->errorMessage.find("delay import") != std::string::npos);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestDelayImportVaBased() {
    auto dl = BuildValidDelay();
    // 把 attributes bit0 清零 → VA-based，明确拒绝。
    IMAGE_DELAYLOAD_DESCRIPTOR desc{};
    std::memcpy(&desc, dl.rdata.data() + dl.descRel, sizeof(desc));
    desc.Attributes.AllAttributes = 0;
    std::memcpy(dl.rdata.data() + dl.descRel, &desc, sizeof(desc));
    std::vector<DirEntry> dirs = {
        {IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, 0x2000 + static_cast<uint32_t>(dl.descRel),
         sizeof(IMAGE_DELAYLOAD_DESCRIPTOR) * 2}
    };
    auto lay = BuildPe(true, {0xCC, 0xCC}, dl.rdata, dirs, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(img->delayImports.dlls.empty());
    CS_TEST_CHECK(!img->isValid);
    CS_TEST_CHECK(img->errorMessage.find("delay import") != std::string::npos);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestDelayImportIntNotTerminated() {
    auto dl = BuildValidDelay();
    // 把 INT 终止槽改成非零：定位 INT（descriptor 中 ImportNameTableRVA），
    // 2 个非终止项后是终止槽。
    IMAGE_DELAYLOAD_DESCRIPTOR desc{};
    std::memcpy(&desc, dl.rdata.data() + dl.descRel, sizeof(desc));
    uint32_t intRVA = desc.ImportNameTableRVA;
    size_t intRel = intRVA - 0x2000;
    uint64_t bad = 0x1234;
    std::memcpy(dl.rdata.data() + intRel + 16, &bad, 8);
    std::vector<DirEntry> dirs = {
        {IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, 0x2000 + static_cast<uint32_t>(dl.descRel),
         sizeof(IMAGE_DELAYLOAD_DESCRIPTOR) * 2}
    };
    auto lay = BuildPe(true, {0xCC, 0xCC}, dl.rdata, dirs, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(img->delayImports.dlls.empty());
    CS_TEST_CHECK(!img->isValid);
    CS_TEST_CHECK(img->errorMessage.find("delay import") != std::string::npos);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestDelayImportIatNotTerminated() {
    auto dl = BuildValidDelay();
    // 把 IAT 终止槽改成非零：定位 IAT（descriptor 中 ImportAddressTableRVA），
    // 2 个非终止项后是终止槽。INT 本身保持合法且已终止，隔离出 IAT 这一项校验。
    IMAGE_DELAYLOAD_DESCRIPTOR desc{};
    std::memcpy(&desc, dl.rdata.data() + dl.descRel, sizeof(desc));
    uint32_t iatRVA = desc.ImportAddressTableRVA;
    size_t iatRel = iatRVA - 0x2000;
    uint64_t bad = 0x1234;
    std::memcpy(dl.rdata.data() + iatRel + 16, &bad, 8);
    std::vector<DirEntry> dirs = {
        {IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, 0x2000 + static_cast<uint32_t>(dl.descRel),
         sizeof(IMAGE_DELAYLOAD_DESCRIPTOR) * 2}
    };
    auto lay = BuildPe(true, {0xCC, 0xCC}, dl.rdata, dirs, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(img->delayImports.dlls.empty());
    CS_TEST_CHECK(!img->isValid);
    CS_TEST_CHECK(img->errorMessage.find("delay import") != std::string::npos);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestDelayImportModuleHandleValid() {
    // ModuleHandleRVA 指向文件内一个合法的指针宽度槽 → 正常解析。
    DelayOptions opt; opt.withModuleHandle = true; opt.moduleHandleBad = false;
    auto dl = BuildDelay(opt);
    std::vector<DirEntry> dirs = {
        {IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, 0x2000 + static_cast<uint32_t>(dl.descRel),
         sizeof(IMAGE_DELAYLOAD_DESCRIPTOR) * 2}
    };
    auto lay = BuildPe(true, {0xCC, 0xCC}, dl.rdata, dirs, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(img && img->isValid);
    CS_TEST_CHECK(img->delayImports.dlls.size() == 1);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestDelayImportModuleHandleInvalid() {
    // ModuleHandleRVA 指向文件之外 → 拒绝。其余字段与合法用例完全相同，
    // 隔离出 ModuleHandleRVA 这一项校验。
    DelayOptions opt; opt.withModuleHandle = true; opt.moduleHandleBad = true;
    auto dl = BuildDelay(opt);
    std::vector<DirEntry> dirs = {
        {IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, 0x2000 + static_cast<uint32_t>(dl.descRel),
         sizeof(IMAGE_DELAYLOAD_DESCRIPTOR) * 2}
    };
    auto lay = BuildPe(true, {0xCC, 0xCC}, dl.rdata, dirs, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(img->delayImports.dlls.empty());
    CS_TEST_CHECK(!img->isValid);
    CS_TEST_CHECK(img->errorMessage.find("delay import") != std::string::npos);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestDelayImportBoundTableValid() {
    // BoundImportAddressTableRVA 存在且终止槽为零 → 正常解析。
    DelayOptions opt; opt.withBoundTable = true; opt.boundTableBad = false;
    auto dl = BuildDelay(opt);
    std::vector<DirEntry> dirs = {
        {IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, 0x2000 + static_cast<uint32_t>(dl.descRel),
         sizeof(IMAGE_DELAYLOAD_DESCRIPTOR) * 2}
    };
    auto lay = BuildPe(true, {0xCC, 0xCC}, dl.rdata, dirs, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(img && img->isValid);
    CS_TEST_CHECK(img->delayImports.dlls.size() == 1);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestDelayImportBoundTableInvalid() {
    // Bound 表终止槽非零 → 拒绝。其余字段与合法用例完全相同，隔离出 Bound 表校验。
    DelayOptions opt; opt.withBoundTable = true; opt.boundTableBad = true;
    auto dl = BuildDelay(opt);
    std::vector<DirEntry> dirs = {
        {IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, 0x2000 + static_cast<uint32_t>(dl.descRel),
         sizeof(IMAGE_DELAYLOAD_DESCRIPTOR) * 2}
    };
    auto lay = BuildPe(true, {0xCC, 0xCC}, dl.rdata, dirs, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(img->delayImports.dlls.empty());
    CS_TEST_CHECK(!img->isValid);
    CS_TEST_CHECK(img->errorMessage.find("delay import") != std::string::npos);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestDelayImportUnloadTableValid() {
    // UnloadInformationTableRVA 存在且终止槽为零 → 正常解析。
    DelayOptions opt; opt.withUnloadTable = true; opt.unloadTableBad = false;
    auto dl = BuildDelay(opt);
    std::vector<DirEntry> dirs = {
        {IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, 0x2000 + static_cast<uint32_t>(dl.descRel),
         sizeof(IMAGE_DELAYLOAD_DESCRIPTOR) * 2}
    };
    auto lay = BuildPe(true, {0xCC, 0xCC}, dl.rdata, dirs, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(img && img->isValid);
    CS_TEST_CHECK(img->delayImports.dlls.size() == 1);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestDelayImportUnloadTableInvalid() {
    // Unload 表终止槽非零 → 拒绝。其余字段与合法用例完全相同，隔离出 Unload 表校验。
    DelayOptions opt; opt.withUnloadTable = true; opt.unloadTableBad = true;
    auto dl = BuildDelay(opt);
    std::vector<DirEntry> dirs = {
        {IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, 0x2000 + static_cast<uint32_t>(dl.descRel),
         sizeof(IMAGE_DELAYLOAD_DESCRIPTOR) * 2}
    };
    auto lay = BuildPe(true, {0xCC, 0xCC}, dl.rdata, dirs, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(img->delayImports.dlls.empty());
    CS_TEST_CHECK(!img->isValid);
    CS_TEST_CHECK(img->errorMessage.find("delay import") != std::string::npos);
    CipherShell::PEParser p; p.FreeImage(img);
}

// ============================================================================
// Resource
// ============================================================================

std::vector<uint8_t> BuildResourceCycle() {
    // 两个目录项互相指向对方 → 环。
    Writer rd;
    const size_t root = rd.mark();
    IMAGE_RESOURCE_DIRECTORY dir{};
    dir.NumberOfIdEntries = 1;
    rd.put(&dir, sizeof(dir));
    IMAGE_RESOURCE_DIRECTORY_ENTRY e1{};
    e1.Name = 1;
    e1.OffsetToData = static_cast<DWORD>((rd.mark() + sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY)) - root) | 0x80000000u;
    // 指向下一个目录。
    rd.u32(e1.Name);
    rd.u32(e1.OffsetToData);
    // 子目录 1 条目指回 root。
    const size_t sub = rd.mark();
    rd.put(&dir, sizeof(dir));
    IMAGE_RESOURCE_DIRECTORY_ENTRY e2{};
    e2.Name = 2;
    e2.OffsetToData = static_cast<DWORD>(root - root) | 0x80000000u;  // 指回 root → 环
    rd.u32(e2.Name);
    rd.u32(e2.OffsetToData);
    (void)sub;
    return std::move(rd.buf);
}

std::vector<uint8_t> BuildResourceTruncatedName() {
    Writer rd;
    const size_t root = rd.mark();
    IMAGE_RESOURCE_DIRECTORY dir{};
    dir.NumberOfNamedEntries = 1;
    rd.put(&dir, sizeof(dir));
    IMAGE_RESOURCE_DIRECTORY_ENTRY e{};
    e.Name = static_cast<DWORD>(rd.mark() + sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) - root) | 0x80000000u;
    rd.u32(e.Name);
    rd.u32(0);  // OffsetToData（指向 data entry，但名称字符串被截断）
    // 名称：长度声明为 4（8 字节 UTF-16），但不提供数据 → 截断。
    rd.u16(4);
    // 不写 UTF-16 数据。
    return std::move(rd.buf);
}

std::vector<uint8_t> BuildResourceDataOob() {
    Writer rd;
    const size_t root = rd.mark();
    IMAGE_RESOURCE_DIRECTORY dir{};
    dir.NumberOfIdEntries = 1;
    rd.put(&dir, sizeof(dir));
    IMAGE_RESOURCE_DIRECTORY_ENTRY e{};
    e.Name = 1;
    e.OffsetToData = static_cast<DWORD>(rd.mark() + sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) - root);  // 指向 data entry
    rd.u32(e.Name);
    rd.u32(e.OffsetToData);
    IMAGE_RESOURCE_DATA_ENTRY de{};
    de.OffsetToData = 0xDEADBEEF;  // 不可映射的 RVA
    de.Size = 16;
    rd.put(&de, sizeof(de));
    return std::move(rd.buf);
}

void TestResourceCycle() {
    auto rd = BuildResourceCycle();
    std::vector<DirEntry> dirs = {{IMAGE_DIRECTORY_ENTRY_RESOURCE, 0x2000, static_cast<uint32_t>(rd.size())}};
    auto lay = BuildPe(true, {0xCC}, rd, dirs, {});
    auto* img = Parse(lay);
    // 目标错误：确认整个 PE 因 resource 目录本身畸形而拒绝，而不是巧合地留空容器。
    CS_TEST_CHECK(img->resources.entries.empty());
    CS_TEST_CHECK(!img->isValid);
    CS_TEST_CHECK(img->errorMessage.find("resource") != std::string::npos);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestResourceTruncatedName() {
    auto rd = BuildResourceTruncatedName();
    std::vector<DirEntry> dirs = {{IMAGE_DIRECTORY_ENTRY_RESOURCE, 0x2000, static_cast<uint32_t>(rd.size())}};
    auto lay = BuildPe(true, {0xCC}, rd, dirs, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(img->resources.entries.empty());
    CS_TEST_CHECK(!img->isValid);
    CS_TEST_CHECK(img->errorMessage.find("resource") != std::string::npos);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestResourceDataOob() {
    auto rd = BuildResourceDataOob();
    std::vector<DirEntry> dirs = {{IMAGE_DIRECTORY_ENTRY_RESOURCE, 0x2000, static_cast<uint32_t>(rd.size())}};
    auto lay = BuildPe(true, {0xCC}, rd, dirs, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(img->resources.entries.empty());
    CS_TEST_CHECK(!img->isValid);
    CS_TEST_CHECK(img->errorMessage.find("resource") != std::string::npos);
    CipherShell::PEParser p; p.FreeImage(img);
}

// ============================================================================
// Security / WIN_CERTIFICATE
// ============================================================================

std::vector<uint8_t> BuildCertChainValid() {
    Writer w;
    // 一条 16 字节证书（dwLength=16，含 8 字节头 + 8 字节数据），8 字节对齐。
    w.u32(16);
    w.u16(0x0200);
    w.u16(0x0002);
    w.pad(8);  // 证书数据
    return std::move(w.buf);
}

void TestSecurityValid() {
    auto cert = BuildCertChainValid();
    std::vector<DirEntry> dirs = {{IMAGE_DIRECTORY_ENTRY_SECURITY, 0 /*占位*/, static_cast<uint32_t>(cert.size())}};
    // security value 是文件偏移；BuildPe 把 overlay 放在最后，cert 在 overlay 中。
    auto lay = BuildPe(true, {0xCC, 0xCC}, {0x11}, dirs, cert);
    // 修正 security 目录文件偏移为 overlay 实际偏移。
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(lay.bytes.data() + sizeof(IMAGE_DOS_HEADER));
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = lay.overlayFileOff;
    auto* img = Parse(lay);
    CS_TEST_CHECK(img && img->isValid);
    CS_TEST_CHECK(img->hasSignature);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestSecurityLengthOob() {
    Writer w;
    w.u32(0x10000);  // dwLength 远大于目录
    w.u16(0x0200); w.u16(0x0002);
    w.pad(8);
    std::vector<uint8_t> cert = std::move(w.buf);
    auto lay = BuildPe(true, {0xCC}, {0x11}, {}, cert);
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(lay.bytes.data() + sizeof(IMAGE_DOS_HEADER));
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = lay.overlayFileOff;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size = static_cast<DWORD>(cert.size());
    auto* img = Parse(lay);
    // 目标错误：确认整个 PE 因 security 目录本身畸形而拒绝，而不是巧合地留空标志位。
    CS_TEST_CHECK(!img->hasSignature);
    CS_TEST_CHECK(!img->isValid);
    CS_TEST_CHECK(img->errorMessage.find("security") != std::string::npos);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestSecurityAlignmentError() {
    // dwLength=12（非 8 对齐），对齐后 16；下一条记录 cursor 到 16，但目录末尾声明为 12 → 不精确到达。
    Writer w;
    w.u32(12);
    w.u16(0x0200); w.u16(0x0002);
    w.pad(4);  // 共 12 字节
    std::vector<uint8_t> cert = std::move(w.buf);
    auto lay = BuildPe(true, {0xCC}, {0x11}, {}, cert);
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(lay.bytes.data() + sizeof(IMAGE_DOS_HEADER));
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = lay.overlayFileOff;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size = 12;  // 12 != 对齐后 16
    auto* img = Parse(lay);
    CS_TEST_CHECK(!img->hasSignature);
    CS_TEST_CHECK(!img->isValid);
    CS_TEST_CHECK(img->errorMessage.find("security") != std::string::npos);
    CipherShell::PEParser p; p.FreeImage(img);
}

// ============================================================================
// Debug payload 越界
// ============================================================================

void TestDebugPayloadOob() {
    Writer rd;
    const size_t dirOff = rd.mark();
    IMAGE_DEBUG_DIRECTORY de{};
    de.Type = 2;
    de.SizeOfData = 16;
    de.PointerToRawData = 0x7FFFFFFF;  // 远超文件
    de.AddressOfRawData = 0;           // 不走 RVA 校验
    rd.put(&de, sizeof(de));
    std::vector<DirEntry> dirs = {{IMAGE_DIRECTORY_ENTRY_DEBUG, 0x2000 + static_cast<uint32_t>(dirOff),
                                   sizeof(IMAGE_DEBUG_DIRECTORY)}};
    auto lay = BuildPe(true, {0xCC}, rd.buf, dirs, {});
    auto* img = Parse(lay);
    // 目标错误：确认整个 PE 因 debug 目录本身畸形而拒绝，而不是巧合地留空容器。
    CS_TEST_CHECK(img->debugDir.entries.empty());
    CS_TEST_CHECK(!img->isValid);
    CS_TEST_CHECK(img->errorMessage.find("debug") != std::string::npos);
    CipherShell::PEParser p; p.FreeImage(img);
}

// ============================================================================
// PEEmitter
// ============================================================================

void TestEmitterAppendSyncsOffsets() {
    // 构造带 Security（overlay 中）、Debug（payload 在 .rdata）、overlay 的 PE。
    // 追加一个 section（headerDelta=0），验证：
    //   - overlay 移到新 section 之后（overlayOffset = overlayDestBase）
    //   - Security 文件偏移随之移动
    //   - Debug PointerToRawData（payload 在 .rdata，< lastFileEnd）保持不变
    Writer rd;
    const size_t dbgDirOff = rd.mark();
    IMAGE_DEBUG_DIRECTORY de{};
    de.Type = 2;
    de.SizeOfData = 4;
    rd.put(&de, sizeof(de));
    const size_t payloadOff = rd.mark();
    rd.u32(0xCAFEBABE);
    // Security 目录需要指向一条合法的 WIN_CERTIFICATE 记录，否则整个 PE 解析会因
    // Security 目录畸形而失败。
    auto cert = BuildCertChainValid();
    auto lay = BuildPe(true, {0xCC, 0xCC, 0xCC, 0xCC}, rd.buf,
                       {{IMAGE_DIRECTORY_ENTRY_DEBUG, 0x2000 + static_cast<uint32_t>(dbgDirOff),
                         sizeof(IMAGE_DEBUG_DIRECTORY)}}, cert);

    // 回填 debug 目录项的 PointerToRawData/AddressOfRawData，指向 .rdata 内的实际 payload
    // （BuildPe 构造时 de 尚未知道自己在整个文件中的真实位置，这里在布局确定后回填）。
    const uint32_t dbgPayloadFile = lay.rdataFileOff + static_cast<uint32_t>(payloadOff);
    const uint32_t dbgPayloadRVA = lay.rdataVA + static_cast<uint32_t>(payloadOff);
    auto* dbgEntry = reinterpret_cast<IMAGE_DEBUG_DIRECTORY*>(
        lay.bytes.data() + lay.rdataFileOff + dbgDirOff);
    dbgEntry->PointerToRawData = dbgPayloadFile;
    dbgEntry->AddressOfRawData = dbgPayloadRVA;

    // 设置 Security 目录指向 overlay（文件偏移）中的合法证书记录。
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(lay.bytes.data() + sizeof(IMAGE_DOS_HEADER));
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = lay.overlayFileOff;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size = static_cast<DWORD>(cert.size());

    auto* img = Parse(lay);
    CS_TEST_CHECK(img && img->isValid);
    const uint32_t secBefore = img->numSections;
    const uint32_t oldOverlay = img->overlayOffset;
    const uint32_t oldSecDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;

    CipherShell::PEEmitter emitter(img);
    auto res = emitter.AppendSection(".new", {0x11, 0x22, 0x33, 0x44},
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ);
    CS_TEST_CHECK(res.success);
    CS_TEST_CHECK(img->numSections == secBefore + 1);
    // overlay 移动到新 section 之后。
    CS_TEST_CHECK(img->overlayOffset > oldOverlay);
    // Security 文件偏移随之移动同样的 delta。
    auto* nt2 = reinterpret_cast<IMAGE_NT_HEADERS64*>(img->rawData + sizeof(IMAGE_DOS_HEADER));
    const uint32_t newSecDir = nt2->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
    CS_TEST_CHECK(newSecDir > oldSecDir);
    CS_TEST_CHECK(newSecDir - oldSecDir == img->overlayOffset - oldOverlay);
    // Debug PointerToRawData（payload 在 .rdata）应保持不变。
    CS_TEST_CHECK(img->debugDir.entries.size() == 1);
    CS_TEST_CHECK(img->debugDir.entries[0].pointerToRawData == dbgPayloadFile);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestEmitterConsecutiveAppend() {
    auto lay = BuildPe(true, {0xCC, 0xCC}, {0x11}, {}, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(img && img->isValid);
    CipherShell::PEEmitter emitter(img);
    auto r1 = emitter.AppendSection(".a", {0x10, 0x20, 0x30, 0x40}, IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ);
    auto r2 = emitter.AppendSection(".b", {0x50, 0x60, 0x70, 0x80}, IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ);
    CS_TEST_CHECK(r1.success && r2.success);
    // 第二个 section 的 raw offset 必须在第一个之后，无重叠/重复。
    CS_TEST_CHECK(r2.rawOffset >= r1.rawOffset + r1.rawSize);
    CS_TEST_CHECK(img->numSections >= 3);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestEmitterFailureRollback() {
    // 空数据 → AppendSection 失败，image 完全不变。
    auto lay = BuildPe(true, {0xCC, 0xCC}, {0x11}, {}, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(img && img->isValid);
    std::vector<uint8_t> snapshot(img->rawData, img->rawData + img->rawSize);
    const uint32_t numBefore = img->numSections;
    const DWORD rawSizeBefore = img->rawSize;

    CipherShell::PEEmitter emitter(img);
    auto res = emitter.AppendSection(".x", {}, IMAGE_SCN_CNT_INITIALIZED_DATA);
    CS_TEST_CHECK(!res.success);
    // image 字节、大小、section 数完全不变。
    CS_TEST_CHECK(img->numSections == numBefore);
    CS_TEST_CHECK(img->rawSize == rawSizeBefore);
    CS_TEST_CHECK(std::memcmp(img->rawData, snapshot.data(), snapshot.size()) == 0);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestEmitterHeaderRelocation() {
    // tightHeaders=true：SizeOfHeaders 与 .text 偏移设为 section table 末尾，
    // 追加一条 section header 必然触发 header relocation。
    auto lay = BuildPe(true, {0xCC, 0xCC, 0xCC, 0xCC}, {0x11}, {}, {}, true);
    auto* img = Parse(lay);
    CS_TEST_CHECK(img && img->isValid);
    const uint32_t textOffBefore = img->sections[0].PointerToRawData;
    const uint32_t numBefore = img->numSections;

    CipherShell::PEEmitter emitter(img);
    auto res = emitter.AppendSection(".r", {0x99, 0x88, 0x77, 0x66}, IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ);
    CS_TEST_CHECK(res.success);
    CS_TEST_CHECK(img->numSections == numBefore + 1);
    // .text PointerToRawData 应因头部间隙而增大。
    CS_TEST_CHECK(img->sections[0].PointerToRawData > textOffBefore);
    // 新 section 偏移应在 .text 原始数据之后。
    CS_TEST_CHECK(res.rawOffset >= img->sections[0].PointerToRawData);
    CipherShell::PEParser p; p.FreeImage(img);
}

} // namespace

int main() {
    TestLoadConfigShortNoGuardFlags();
    TestLoadConfigDeclaredSizeExceedsAvailable();
    TestLoadConfigShortNoSEHandler();
    TestSafeSEHValid();
    TestSafeSEHHandlerNotExecutable();
    TestTlsValid();
    TestTlsStartAfterEnd();
    TestTlsCrossSectionRange();
    TestTlsIndexTooSmall();
    TestTlsCallbackNotExecutable();
    TestTlsCallbackNotTerminated();
    TestTlsCallbackScanConfinedToOwnSection();
    TestExceptionValid();
    TestExceptionBeginNotLessThanEnd();
    TestExceptionRangeNotExecutable();
    TestExceptionRangeNotFileBacked();
    TestExceptionOverlappingRanges();
    TestExceptionUnwindHeaderTooShort();
    TestExceptionUnwindBadVersion();
    TestExceptionUnwindVersion2Accepted();
    TestExceptionUnwindCodeArrayTruncated();
    TestExceptionUnwindHandlerValid();
    TestExceptionUnwindHandlerInvalid();
    TestExceptionUnwindChainedValid();
    TestExceptionUnwindChainedInvalid();
    TestDelayImportValid();
    TestDelayImportNoTerminator();
    TestDelayImportSizeNotMultiple();
    TestDelayImportVaBased();
    TestDelayImportIntNotTerminated();
    TestDelayImportIatNotTerminated();
    TestDelayImportModuleHandleValid();
    TestDelayImportModuleHandleInvalid();
    TestDelayImportBoundTableValid();
    TestDelayImportBoundTableInvalid();
    TestDelayImportUnloadTableValid();
    TestDelayImportUnloadTableInvalid();
    TestResourceCycle();
    TestResourceTruncatedName();
    TestResourceDataOob();
    TestSecurityValid();
    TestSecurityLengthOob();
    TestSecurityAlignmentError();
    TestDebugPayloadOob();
    TestEmitterAppendSyncsOffsets();
    TestEmitterConsecutiveAppend();
    TestEmitterFailureRollback();
    TestEmitterHeaderRelocation();
    return 0;
}
