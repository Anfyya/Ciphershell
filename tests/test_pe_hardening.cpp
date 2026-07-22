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
//     Parser 完整接受 V1/V2、CapabilityChecker 对 V2 函数级 fail-closed；逐项校验
//     UWOP 与额外槽位、保留/冲突 Flags、V2 EPILOG 描述符；头/代码/尾部必须整体
//     位于同一 file-backed section；链式 RUNTIME_FUNCTION 递归校验并拒绝循环
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
#include "../packer/analysis/capability_checker.h"
#include "../packer/analysis/disassembler.h"
#include "../packer/transforms/vm_instruction_bridge_builder.h"
#include "../runtime/common/vm_micro_runtime_abi.h"

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
    void u8(uint8_t v) { put(&v, 1); }
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
    // declaredSize > rawAvailable（真实文件边界）→ 解析失败。
    CS_TEST_CHECK(!img->loadConfig.valid);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestLoadConfigDeclaredSizeExceedsDirectorySizeButFitsFile() {
    // 已被证实的真实 CI 场景：当前主流 MSVC/LINK.EXE 工具链下，Load Config
    // 结构体新增字段（GuardXFG/CastGuard/...）后实际变大，但 DataDirectory
    // 数组里登记的 Size 有时仍是旧版本/偏小的值，与结构体自己开头的 Size
    // 字段（declaredSize）不一致——只要 declaredSize 仍完整落在文件真实
    // 边界内，这是良性现象，不应该被当成畸形 PE 拒绝（Windows 加载器本身
    // 读取 Load Config 时也是直接信任结构体内部的 Size 字段，不会用
    // DataDirectory.Size 做二次限制）。这里复现的正是 CI 里 x86 构建实际
    // 打出的数值形状：declaredSize=0xc0 类的完整结构体，directory.Size 被
    // 故意登记成一个明显更小的 0x40。
    Writer rd;
    const size_t lcOff = rd.mark();
    const uint32_t declaredSize = sizeof(IMAGE_LOAD_CONFIG_DIRECTORY64);
    rd.u32(declaredSize);  // Size：结构体自己声明的完整大小
    rd.pad(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, SecurityCookie) - sizeof(DWORD));
    rd.u64(0xDEADBEEF12345678ULL);  // SecurityCookie
    rd.pad(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, GuardFlags) -
        (offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, SecurityCookie) + sizeof(DWORD64)));
    rd.u32(0x00004100u);  // GuardFlags：IMAGE_GUARD_CF_INSTRUMENTED 置位

    constexpr uint32_t kSmallDirectorySize = 0x40;  // 明显小于 declaredSize
    std::vector<DirEntry> dirs = {
        {IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, static_cast<uint32_t>(0x2000 + lcOff),
         kSmallDirectorySize}
    };
    auto lay = BuildPe(true, {0xCC, 0xCC, 0xCC, 0xCC}, rd.buf, dirs, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(img && img->isValid);
    CS_TEST_CHECK(img->loadConfig.valid);
    CS_TEST_CHECK(img->loadConfig.securityCookie == 0xDEADBEEF12345678ULL);
    CS_TEST_CHECK(img->loadConfig.hasCFG);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestLoadConfigDeclaredSizeCannotUseOverlay() {
    // Size DWORD 落在 .rdata 末尾，但声明的 8 字节依赖 overlay 才能凑齐。
    // 单看 rawSize-offset 会错误放行；结构必须整体位于 .rdata 内。
    Writer rd;
    rd.pad(kFileAlign - sizeof(DWORD));
    const size_t lcOff = rd.mark();
    rd.u32(8);
    std::vector<DirEntry> dirs = {
        {IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, static_cast<uint32_t>(0x2000 + lcOff), 8}
    };
    auto lay = BuildPe(true, {0xCC}, rd.buf, dirs, std::vector<uint8_t>(4, 0));
    auto* img = Parse(lay);
    CS_TEST_CHECK(img && !img->isValid);
    CS_TEST_CHECK(!img->loadConfig.valid);
    CS_TEST_CHECK(img->errorMessage.find("load config") != std::string::npos);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestLoadConfigDeclaredSizeExceedsAbsoluteStructuralBound() {
    // 反面：declaredSize 落在文件真实边界内，但大到不像任何已知版本的
    // IMAGE_LOAD_CONFIG_DIRECTORY64（超过 4x sizeof）——绝对结构上限这道
    // 关卡必须独立于 directory.Size 依然把这种离谱声明拒绝掉，不能因为放宽
    // 了 directory.Size 那条校验，就把整条防线拆空。
    Writer rd;
    const size_t lcOff = rd.mark();
    const uint32_t declaredSize =
        static_cast<uint32_t>(sizeof(IMAGE_LOAD_CONFIG_DIRECTORY64)) * 5u;  // > 4x 上限
    rd.u32(declaredSize);
    rd.pad(declaredSize - sizeof(DWORD));  // 文件里确实有这么多字节，不是越界问题
    std::vector<DirEntry> dirs = {
        {IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, static_cast<uint32_t>(0x2000 + lcOff), declaredSize}
    };
    auto lay = BuildPe(true, {0xCC, 0xCC, 0xCC, 0xCC}, rd.buf, dirs, {});
    auto* img = Parse(lay);
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
// SafeSEH 合并（PEEmitter::RebuildSafeSEHHandlerTable）
//
// 覆盖 CALL_HOST Win32 handler RVA 最终接入 PE 构建路径的核心契约：
//   - 已有真实 SafeSEH 表时合并新 handler、排序、去重，并通过独立重新解析
//     （而不仅是同一个 img 对象的内存状态）验证最终字节。
//   - 已存在的 RVA 再次提交时不重复计入。
//   - 原 PE 没有 SafeSEH 声明时是 no-op，不伪造契约。
//   - 原 PE 声明 IMAGE_DLLCHARACTERISTICS_NO_SEH 时 fail-closed。
//   - x64 image 上调用直接拒绝（x64 从不产生 Win32 SafeSEH 数据）。
// ============================================================================

CipherShell::CS_PE_IMAGE* BuildSafeSehPe(
    const std::vector<uint32_t>& existingHandlerRvas) {
    Writer rd;
    const size_t lcOff = rd.mark();
    rd.u32(sizeof(IMAGE_LOAD_CONFIG_DIRECTORY32));  // Size
    rd.pad(offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, SEHandlerTable) - sizeof(DWORD));
    const size_t sehTableRel = rd.mark();
    rd.u32(0);  // SEHandlerTable (32-bit VA) 占位
    rd.u32(static_cast<uint32_t>(existingHandlerRvas.size()));  // SEHandlerCount
    const size_t tableDataOff = rd.mark();
    for (uint32_t rva : existingHandlerRvas) rd.u32(rva);

    constexpr uint32_t imageBase = 0x10000000;
    const uint32_t tableRVA = 0x2000u + static_cast<uint32_t>(tableDataOff);
    const uint32_t tableVA = imageBase + tableRVA;
    std::memcpy(rd.buf.data() + sehTableRel, &tableVA, sizeof(uint32_t));

    std::vector<DirEntry> dirs = {
        {IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, static_cast<uint32_t>(0x2000 + lcOff),
         sizeof(IMAGE_LOAD_CONFIG_DIRECTORY32)}
    };
    // .text needs to be large enough to host every existing handler RVA plus
    // extra bytes new handler RVAs (chosen by each test) can point into.
    auto lay = BuildPe(false, std::vector<uint8_t>(0x40, 0xCCu), rd.buf, dirs, {});
    return Parse(lay);
}

void TestSafeSEHTableMergeAddsAndSortsNewHandler() {
    auto* img = BuildSafeSehPe({0x1000u, 0x1006u});
    CS_TEST_CHECK(img && img->isValid && img->loadConfig.valid);
    CS_TEST_CHECK(img->loadConfig.safeSEHHandlerRVAs.size() == 2);

    CipherShell::PEEmitter emitter(img);
    std::string error;
    // Deliberately out of order and lower than one existing entry to prove
    // the merged table is really sorted, not just appended.
    const bool ok = emitter.RebuildSafeSEHHandlerTable(
        {0x1003u}, ".tcsseh", nullptr, &error);
    CS_TEST_CHECK(ok);
    CS_TEST_CHECK(img->loadConfig.safeSEHHandlerRVAs.size() == 3);
    CS_TEST_CHECK(img->loadConfig.safeSEHHandlerRVAs[0] == 0x1000u);
    CS_TEST_CHECK(img->loadConfig.safeSEHHandlerRVAs[1] == 0x1003u);
    CS_TEST_CHECK(img->loadConfig.safeSEHHandlerRVAs[2] == 0x1006u);

    // Independent re-parse from the final raw bytes: proves the merged table
    // was really committed to the PE image, not just reflected in the
    // in-memory CS_LOAD_CONFIG the emitter itself maintains.
    BYTE* reparsedBytes = new BYTE[img->rawSize];
    std::memcpy(reparsedBytes, img->rawData, img->rawSize);
    CipherShell::PEParser reparser;
    auto* reparsed = reparser.LoadFromBuffer(reparsedBytes, img->rawSize);
    CS_TEST_CHECK(reparsed && reparsed->isValid && reparsed->loadConfig.valid);
    CS_TEST_CHECK(reparsed->loadConfig.safeSEHHandlerRVAs.size() == 3);
    CS_TEST_CHECK(reparsed->loadConfig.safeSEHHandlerRVAs[0] == 0x1000u);
    CS_TEST_CHECK(reparsed->loadConfig.safeSEHHandlerRVAs[1] == 0x1003u);
    CS_TEST_CHECK(reparsed->loadConfig.safeSEHHandlerRVAs[2] == 0x1006u);
    reparser.FreeImage(reparsed);

    CipherShell::PEParser p; p.FreeImage(img);
}

void TestSafeSEHTableMergeDedupesExistingRva() {
    auto* img = BuildSafeSehPe({0x1000u, 0x1002u});
    CS_TEST_CHECK(img && img->isValid && img->loadConfig.valid);

    CipherShell::PEEmitter emitter(img);
    std::string error;
    // 0x1000 already exists; only 0x1004 is genuinely new.
    const bool ok = emitter.RebuildSafeSEHHandlerTable(
        {0x1000u, 0x1004u}, ".tcsseh", nullptr, &error);
    CS_TEST_CHECK(ok);
    CS_TEST_CHECK(img->loadConfig.safeSEHHandlerRVAs.size() == 3);
    CS_TEST_CHECK(img->loadConfig.safeSEHHandlerRVAs[0] == 0x1000u);
    CS_TEST_CHECK(img->loadConfig.safeSEHHandlerRVAs[1] == 0x1002u);
    CS_TEST_CHECK(img->loadConfig.safeSEHHandlerRVAs[2] == 0x1004u);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestSafeSEHTableMergeNoOriginalTableIsNoOp() {
    // No LOAD_CONFIG directory at all: RebuildSafeSEHHandlerTable must not
    // fabricate a SafeSEH contract the original build never declared.
    auto lay = BuildPe(false, std::vector<uint8_t>(0x20, 0xCCu), {}, {}, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(img && img->isValid && !img->loadConfig.valid);

    CipherShell::PEEmitter emitter(img);
    std::string error;
    const bool ok = emitter.RebuildSafeSEHHandlerTable(
        {0x1000u}, ".tcsseh", nullptr, &error);
    CS_TEST_CHECK(ok);
    CS_TEST_CHECK(!img->loadConfig.valid);  // still no fabricated table
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestSafeSEHTableMergeFailsClosedOnNoSehFlag() {
    auto* img = BuildSafeSehPe({0x1000u});
    CS_TEST_CHECK(img && img->isValid && img->loadConfig.valid);
    img->ntHeaders32->OptionalHeader.DllCharacteristics |=
        IMAGE_DLLCHARACTERISTICS_NO_SEH;

    CipherShell::PEEmitter emitter(img);
    std::string error;
    const bool ok = emitter.RebuildSafeSEHHandlerTable(
        {0x1004u}, ".tcsseh", nullptr, &error);
    CS_TEST_CHECK(!ok);
    CS_TEST_CHECK(!error.empty());
    // The original two-entry table must be left completely untouched.
    CS_TEST_CHECK(img->loadConfig.safeSEHHandlerRVAs.size() == 1);
    CS_TEST_CHECK(img->loadConfig.safeSEHHandlerRVAs[0] == 0x1000u);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestSafeSEHTableMergeRejectsX64Image() {
    Writer rd;
    const size_t lcOff = rd.mark();
    rd.u32(sizeof(IMAGE_LOAD_CONFIG_DIRECTORY64));
    std::vector<DirEntry> dirs = {
        {IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, static_cast<uint32_t>(0x2000 + lcOff),
         sizeof(IMAGE_LOAD_CONFIG_DIRECTORY64)}
    };
    auto lay = BuildPe(true, {0xCC, 0xCC, 0xCC, 0xCC}, rd.buf, dirs, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(img && img->isValid);

    CipherShell::PEEmitter emitter(img);
    std::string error;
    const bool ok = emitter.RebuildSafeSEHHandlerTable(
        {0x1000u}, ".tcsseh", nullptr, &error);
    CS_TEST_CHECK(!ok);
    CS_TEST_CHECK(!error.empty());
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

CipherShell::CS_PE_IMAGE* ParseSingleExceptionWithUnwind(const std::vector<uint8_t>& unwind) {
    Writer rd;
    const size_t entryRel = rd.mark();
    rd.pad(sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY));
    const size_t unwindRel = rd.mark();
    rd.put(unwind.data(), unwind.size());

    IMAGE_RUNTIME_FUNCTION_ENTRY entry{};
    entry.BeginAddress = kExcTextVA;
    entry.EndAddress = kExcTextVA + 8;
    entry.UnwindData = kExcRdataVA + static_cast<uint32_t>(unwindRel);
    std::memcpy(rd.buf.data() + entryRel, &entry, sizeof(entry));
    auto lay = BuildPe(true, std::vector<uint8_t>(8, 0xCC), rd.buf,
        {{IMAGE_DIRECTORY_ENTRY_EXCEPTION, kExcRdataVA + static_cast<uint32_t>(entryRel),
          sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)}}, {});
    return Parse(lay);
}

void TestExceptionPushMachFrameCodeOffsetZeroAccepted() {
    // 非 CHAININFO 普通 prolog 中，PUSH_MACHFRAME 是唯一允许 CodeOffset=0
    // 的 UWOP；OpInfo=1 表示带 error code。
    auto* img = ParseSingleExceptionWithUnwind({
        0x01, 0x00, 0x01, 0x00,
        0x00, static_cast<uint8_t>(0x10 | CipherShell::PEUtils::kUwopPushMachFrame),
        0x00, 0x00  // CountOfCodes 为奇数时的 DWORD padding
    });
    CS_TEST_CHECK(img && img->isValid);
    CS_TEST_CHECK(img->exceptions.entries.size() == 1);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestExceptionPushMachFrameNonzeroOffsetRejected() {
    auto* img = ParseSingleExceptionWithUnwind({
        0x01, 0x01, 0x01, 0x00,
        0x01, CipherShell::PEUtils::kUwopPushMachFrame,
        0x00, 0x00
    });
    CS_TEST_CHECK(img && !img->isValid);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestExceptionPushMachFrameBadOpInfoRejected() {
    auto* img = ParseSingleExceptionWithUnwind({
        0x01, 0x00, 0x01, 0x00,
        0x00, static_cast<uint8_t>(0x20 | CipherShell::PEUtils::kUwopPushMachFrame),
        0x00, 0x00
    });
    CS_TEST_CHECK(img && !img->isValid);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestExceptionPushMachFrameMustBeLogicalLast() {
    // 即使后续 operation 自身编码有效，MACHFRAME 后仍不得再有正常 prolog operation。
    auto* img = ParseSingleExceptionWithUnwind({
        0x01, 0x01, 0x02, 0x00,
        0x00, CipherShell::PEUtils::kUwopPushMachFrame,
        0x01, static_cast<uint8_t>(0x30 | CipherShell::PEUtils::kUwopPushNonvol)
    });
    CS_TEST_CHECK(img && !img->isValid);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestExceptionOtherUwopCodeOffsetZeroRejected() {
    auto* img = ParseSingleExceptionWithUnwind({
        0x01, 0x00, 0x01, 0x00,
        0x00, CipherShell::PEUtils::kUwopAllocSmall,
        0x00, 0x00
    });
    CS_TEST_CHECK(img && !img->isValid);
    CipherShell::PEParser p; p.FreeImage(img);
}

CipherShell::CS_PE_IMAGE* ParseChainedExceptionWithOuterUnwind(
    uint8_t sizeOfProlog, const std::vector<uint8_t>& unwindCodes, uint8_t countOfCodes) {
    Writer rd;
    const size_t entryRel = rd.mark();
    rd.pad(sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY));
    const size_t outerUnwindRel = rd.mark();
    rd.u8(static_cast<uint8_t>(0x01 | (0x4 << 3)));  // Version=1, Flags=CHAININFO
    rd.u8(sizeOfProlog);
    rd.u8(countOfCodes);
    rd.u8(0x00);
    rd.put(unwindCodes.data(), unwindCodes.size());
    if ((countOfCodes & 1u) != 0) rd.u16(0);  // CHAININFO 尾必须 DWORD 对齐

    const size_t chainedRel = rd.mark();
    IMAGE_RUNTIME_FUNCTION_ENTRY chained{};
    chained.BeginAddress = kExcTextVA;
    chained.EndAddress = kExcTextVA + 4;
    chained.UnwindData = 0;
    rd.put(&chained, sizeof(chained));
    const size_t innerUnwindRel = rd.mark();
    auto innerUnwind = BuildUnwindInfoValid();
    rd.put(innerUnwind.data(), innerUnwind.size());
    chained.UnwindData = kExcRdataVA + static_cast<uint32_t>(innerUnwindRel);
    std::memcpy(rd.buf.data() + chainedRel, &chained, sizeof(chained));

    IMAGE_RUNTIME_FUNCTION_ENTRY entry{};
    entry.BeginAddress = kExcTextVA;
    entry.EndAddress = kExcTextVA + 8;
    entry.UnwindData = kExcRdataVA + static_cast<uint32_t>(outerUnwindRel);
    std::memcpy(rd.buf.data() + entryRel, &entry, sizeof(entry));
    return Parse(BuildPe(true, std::vector<uint8_t>(8, 0xCC), rd.buf,
        {{IMAGE_DIRECTORY_ENTRY_EXCEPTION,
          kExcRdataVA + static_cast<uint32_t>(entryRel),
          sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)}}, {}));
}

void TestExceptionZeroPrologChainedSaveNonvolAccepted() {
    // MSVC shrink-wrapped fragment：零长度 prolog 在 offset 0 保存 R15/R14/R13/RBP，
    // 完整主 prolog 由 CHAININFO 尾部的 RUNTIME_FUNCTION 描述。
    auto* img = ParseChainedExceptionWithOuterUnwind(0,
        {
            0x00, static_cast<uint8_t>(0xF0 | CipherShell::PEUtils::kUwopSaveNonvol),
            0x01, 0x00,  // R15
            0x00, static_cast<uint8_t>(0xE0 | CipherShell::PEUtils::kUwopSaveNonvol),
            0x02, 0x00,  // R14
            0x00, static_cast<uint8_t>(0xD0 | CipherShell::PEUtils::kUwopSaveNonvol),
            0x03, 0x00,  // R13
            0x00, static_cast<uint8_t>(0x50 | CipherShell::PEUtils::kUwopSaveNonvol),
            0x04, 0x00   // RBP
        }, 8);
    CS_TEST_CHECK(img && img->isValid);
    CS_TEST_CHECK(img->exceptions.entries.size() == 1);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestExceptionRootSaveNonvolCodeOffsetZeroRejected() {
    auto* img = ParseSingleExceptionWithUnwind({
        0x01, 0x00, 0x02, 0x00,
        0x00, static_cast<uint8_t>(0x30 | CipherShell::PEUtils::kUwopSaveNonvol),
        0x00, 0x00
    });
    CS_TEST_CHECK(img && !img->isValid);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestExceptionNonzeroPrologChainedSaveAtZeroRejected() {
    auto* img = ParseChainedExceptionWithOuterUnwind(1,
        {0x00, static_cast<uint8_t>(0x30 | CipherShell::PEUtils::kUwopSaveNonvol),
         0x00, 0x00}, 2);
    CS_TEST_CHECK(img && !img->isValid);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestExceptionZeroPrologChainedOtherUwopAtZeroRejected() {
    auto* img = ParseChainedExceptionWithOuterUnwind(0,
        {0x00, static_cast<uint8_t>(0x30 | CipherShell::PEUtils::kUwopPushNonvol)}, 1);
    CS_TEST_CHECK(img && !img->isValid);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestExceptionSetFpRegOpInfoMatchesFrameOffsetAccepted() {
    auto* img = ParseSingleExceptionWithUnwind({
        0x01, 0x01, 0x01, 0x55,  // FrameRegister=RBP, FrameOffset=5
        0x01, static_cast<uint8_t>(0x50 | CipherShell::PEUtils::kUwopSetFpReg),
        0x00, 0x00
    });
    CS_TEST_CHECK(img && img->isValid);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestExceptionSetFpRegReservedZeroAccepted() {
    auto* img = ParseSingleExceptionWithUnwind({
        0x01, 0x01, 0x01, 0x55,
        0x01, CipherShell::PEUtils::kUwopSetFpReg,
        0x00, 0x00
    });
    CS_TEST_CHECK(img && img->isValid);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestExceptionSetFpRegOtherOpInfoRejected() {
    auto* img = ParseSingleExceptionWithUnwind({
        0x01, 0x01, 0x01, 0x55,
        0x01, static_cast<uint8_t>(0x40 | CipherShell::PEUtils::kUwopSetFpReg),
        0x00, 0x00
    });
    CS_TEST_CHECK(img && !img->isValid);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestExceptionDuplicateSetFpRegRejected() {
    auto* img = ParseSingleExceptionWithUnwind({
        0x01, 0x02, 0x02, 0x55,
        0x02, static_cast<uint8_t>(0x50 | CipherShell::PEUtils::kUwopSetFpReg),
        0x01, CipherShell::PEUtils::kUwopSetFpReg
    });
    CS_TEST_CHECK(img && !img->isValid);
    CipherShell::PEParser p; p.FreeImage(img);
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
        rd.u8(0);
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
    rd.u8(0x03);  // Version=3：超出 Parser 支持的 [1,2]
    rd.u8(0x00);
    rd.u8(0x00);
    rd.u8(0x00);

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

void TestExceptionUnwindVersion2ParsedButVmRejected() {
    // Parser 能完整解析合法 V2；VM runtime/重建器尚未证明 V2 epilog unwind 语义，
    // CapabilityChecker 必须在函数级 fail-closed。
    Writer rd;
    const size_t entryRel = rd.mark();
    rd.pad(sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY));
    const size_t unwindRel = rd.mark();
    rd.u8(0x02);  // Version=2, Flags=0
    rd.u8(0x00);
    rd.u8(0x02);  // 长度槽 + V2 要求的偶数 epilog padding 槽
    rd.u8(0x00);
    rd.u8(0x02);  // epilog 长度=2
    rd.u8(static_cast<uint8_t>(0x10 | CipherShell::PEUtils::kUwopEpilog));
    rd.u8(0x00);  // padding EPILOG offset=0
    rd.u8(CipherShell::PEUtils::kUwopEpilog);

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

    CipherShell::Function function{};
    function.entryAddress = kExcTextVA;
    function.size = 8;
    function.boundaryTrusted = true;
    function.decodedBytes = 8;
    function.blocks.emplace_back();
    std::string reason;
    CipherShell::CapabilityChecker checker;
    CS_TEST_CHECK(!checker.IsFunctionVmSafe(img, function, reason));
    CS_TEST_CHECK(reason.find("version 2") != std::string::npos);
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestExceptionUnwindReservedFlagsRejected() {
    Writer rd;
    const size_t entryRel = rd.mark();
    rd.pad(sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY));
    const size_t unwindRel = rd.mark();
    rd.u8(static_cast<uint8_t>(0x01 | (0x08 << 3)));  // Flags bit3 保留
    rd.u8(0x00); rd.u8(0x00); rd.u8(0x00);

    IMAGE_RUNTIME_FUNCTION_ENTRY entry{};
    entry.BeginAddress = kExcTextVA;
    entry.EndAddress = kExcTextVA + 8;
    entry.UnwindData = kExcRdataVA + static_cast<uint32_t>(unwindRel);
    std::memcpy(rd.buf.data() + entryRel, &entry, sizeof(entry));
    auto lay = BuildPe(true, std::vector<uint8_t>(8, 0xCC), rd.buf,
        {{IMAGE_DIRECTORY_ENTRY_EXCEPTION, kExcRdataVA + static_cast<uint32_t>(entryRel),
          sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)}}, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(!img->isValid);
    CS_TEST_CHECK(img->exceptions.entries.empty());
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestExceptionUnwindConflictingFlagsRejected() {
    Writer rd;
    const size_t entryRel = rd.mark();
    rd.pad(sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY));
    const size_t unwindRel = rd.mark();
    rd.u8(static_cast<uint8_t>(0x01 | (0x05 << 3)));  // CHAININFO|EHANDLER
    rd.u8(0x00); rd.u8(0x00); rd.u8(0x00);
    rd.pad(sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY));

    IMAGE_RUNTIME_FUNCTION_ENTRY entry{};
    entry.BeginAddress = kExcTextVA;
    entry.EndAddress = kExcTextVA + 8;
    entry.UnwindData = kExcRdataVA + static_cast<uint32_t>(unwindRel);
    std::memcpy(rd.buf.data() + entryRel, &entry, sizeof(entry));
    auto lay = BuildPe(true, std::vector<uint8_t>(8, 0xCC), rd.buf,
        {{IMAGE_DIRECTORY_ENTRY_EXCEPTION, kExcRdataVA + static_cast<uint32_t>(entryRel),
          sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)}}, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(!img->isValid);
    CS_TEST_CHECK(img->exceptions.entries.empty());
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestExceptionUnwindVersion2MalformedEpilogRejected() {
    Writer rd;
    const size_t entryRel = rd.mark();
    rd.pad(sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY));
    const size_t unwindRel = rd.mark();
    rd.u8(0x02);  // Version=2, Flags=0
    rd.u8(0x00);
    rd.u8(0x01);  // 只有第一条 EPILOG 长度槽
    rd.u8(0x00);
    rd.u8(0x04);  // epilog 长度
    rd.u8(CipherShell::PEUtils::kUwopEpilog);  // atEnd=0，却没有显式 epilog offset
    rd.u16(0);  // DWORD 对齐 padding，不属于 CountOfCodes

    IMAGE_RUNTIME_FUNCTION_ENTRY entry{};
    entry.BeginAddress = kExcTextVA;
    entry.EndAddress = kExcTextVA + 8;
    entry.UnwindData = kExcRdataVA + static_cast<uint32_t>(unwindRel);
    std::memcpy(rd.buf.data() + entryRel, &entry, sizeof(entry));
    auto lay = BuildPe(true, std::vector<uint8_t>(8, 0xCC), rd.buf,
        {{IMAGE_DIRECTORY_ENTRY_EXCEPTION, kExcRdataVA + static_cast<uint32_t>(entryRel),
          sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)}}, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(!img->isValid);
    CS_TEST_CHECK(img->exceptions.entries.empty());
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestExceptionUnwindCrossSectionRejected() {
    // UNWIND_INFO 头位于 .text 最后 4 字节，EHANDLER 尾部物理上紧邻在 .rdata，且
    // handler 值本可指向合法 .text；整体跨 section，必须在读取尾部语义前拒绝。
    std::vector<uint8_t> text(kFileAlign, 0xCC);
    text[kFileAlign - 4] = static_cast<uint8_t>(0x01 | (0x01 << 3));
    text[kFileAlign - 3] = 0;
    text[kFileAlign - 2] = 0;
    text[kFileAlign - 1] = 0;

    Writer rd;
    const size_t entryRel = rd.mark();
    rd.pad(sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY));
    IMAGE_RUNTIME_FUNCTION_ENTRY entry{};
    entry.BeginAddress = kExcTextVA;
    entry.EndAddress = kExcTextVA + 8;
    entry.UnwindData = kExcTextVA + kFileAlign - 4;
    std::memcpy(rd.buf.data() + entryRel, &entry, sizeof(entry));

    auto lay = BuildPe(true, text, rd.buf,
        {{IMAGE_DIRECTORY_ENTRY_EXCEPTION, kExcRdataVA + static_cast<uint32_t>(entryRel),
          sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)}}, {});
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(lay.bytes.data() + sizeof(IMAGE_DOS_HEADER));
    auto* sections = reinterpret_cast<IMAGE_SECTION_HEADER*>(
        lay.bytes.data() + sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64));
    nt->OptionalHeader.SectionAlignment = kFileAlign;
    nt->OptionalHeader.SizeOfImage = kExcTextVA + 2 * kFileAlign;
    sections[1].VirtualAddress = kExcTextVA + kFileAlign;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress =
        sections[1].VirtualAddress + static_cast<uint32_t>(entryRel);

    auto* img = Parse(lay);
    CS_TEST_CHECK(!img->isValid);
    CS_TEST_CHECK(img->exceptions.entries.empty());
    CipherShell::PEParser p; p.FreeImage(img);
}

void TestExceptionUnwindCodeArrayTruncated() {
    // CountOfCodes 声明的 UNWIND_CODE 数组（每项 2 字节，奇数向上补齐到偶数）超出
    // 文件实际范围 → 拒绝。
    Writer rd;
    const size_t entryRel = rd.mark();
    rd.pad(sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY));
    const size_t unwindRel = rd.mark();
    rd.u8(0x01);  // Version=1, Flags=0
    rd.u8(0x00);  // SizeOfProlog
    rd.u8(0xFF);  // CountOfCodes=255：数组需要 255(向上补偶=256)*2=512 字节，
                              // 远超本测试实际提供的数据。
    rd.u8(0x00);  // FrameRegister/FrameOffset
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
    rd.u8(static_cast<uint8_t>(0x01 | (0x1 << 3)));  // Version=1, Flags=EHANDLER
    rd.u8(0x00);
    rd.u8(0x00);  // CountOfCodes=0
    rd.u8(0x00);
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
    rd.u8(static_cast<uint8_t>(0x01 | (0x1 << 3)));  // Version=1, Flags=EHANDLER
    rd.u8(0x00);
    rd.u8(0x00);  // CountOfCodes=0
    rd.u8(0x00);
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
    rd.u8(static_cast<uint8_t>(0x01 | (0x4 << 3)));  // Version=1, Flags=CHAININFO
    rd.u8(0x00);
    rd.u8(0x00);  // CountOfCodes=0
    rd.u8(0x00);
    const size_t chainedRel = rd.mark();
    IMAGE_RUNTIME_FUNCTION_ENTRY chained{};
    chained.BeginAddress = kExcTextVA;
    chained.EndAddress = kExcTextVA + 4;
    chained.UnwindData = 0;  // inner unwind 写入后回填
    rd.put(&chained, sizeof(chained));
    const size_t innerUnwindRel = rd.mark();
    auto innerUnwind = BuildUnwindInfoValid();
    rd.put(innerUnwind.data(), innerUnwind.size());
    chained.UnwindData = kExcRdataVA + static_cast<uint32_t>(innerUnwindRel);
    std::memcpy(rd.buf.data() + chainedRel, &chained, sizeof(chained));

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

void TestExceptionUnwindChainedZeroUnwindRejected() {
    // chained UnwindData=0 不再视为合法：即使 Begin<End，也必须 fail-closed。
    Writer rd;
    const size_t entryRel = rd.mark();
    rd.pad(sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY));
    const size_t unwindRel = rd.mark();
    rd.u8(static_cast<uint8_t>(0x01 | (0x4 << 3)));  // Version=1, Flags=CHAININFO
    rd.u8(0x00);
    rd.u8(0x00);  // CountOfCodes=0
    rd.u8(0x00);
    IMAGE_RUNTIME_FUNCTION_ENTRY chained{};
    chained.BeginAddress = kExcTextVA;
    chained.EndAddress = kExcTextVA + 4;
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

void TestExceptionUnwindChainedCycleRejected() {
    Writer rd;
    const size_t entryRel = rd.mark();
    rd.pad(sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY));
    const size_t unwindRel = rd.mark();
    rd.u8(static_cast<uint8_t>(0x01 | (0x4 << 3)));
    rd.u8(0x00); rd.u8(0x00); rd.u8(0x00);
    IMAGE_RUNTIME_FUNCTION_ENTRY chained{};
    chained.BeginAddress = kExcTextVA;
    chained.EndAddress = kExcTextVA + 4;
    chained.UnwindData = kExcRdataVA + static_cast<uint32_t>(unwindRel);  // 自环
    rd.put(&chained, sizeof(chained));

    IMAGE_RUNTIME_FUNCTION_ENTRY entry{};
    entry.BeginAddress = kExcTextVA;
    entry.EndAddress = kExcTextVA + 8;
    entry.UnwindData = kExcRdataVA + static_cast<uint32_t>(unwindRel);
    std::memcpy(rd.buf.data() + entryRel, &entry, sizeof(entry));
    auto lay = BuildPe(true, std::vector<uint8_t>(8, 0xCC), rd.buf,
        {{IMAGE_DIRECTORY_ENTRY_EXCEPTION, kExcRdataVA + static_cast<uint32_t>(entryRel),
          sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)}}, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(!img->isValid);
    CS_TEST_CHECK(img->exceptions.entries.empty());
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
    rd.u8(0);
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
    rd.put(f1, 5); rd.u8(0);
    // hint/name 条目 2。
    const size_t hn2Rel = rd.mark();
    rd.u16(0);
    const char* f2 = "FuncB";
    rd.put(f2, 5); rd.u8(0);

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

WORD GetFileCharacteristics(const CipherShell::CS_PE_IMAGE* image) {
    return image->is64Bit
        ? image->ntHeaders64->FileHeader.Characteristics
        : image->ntHeaders32->FileHeader.Characteristics;
}

WORD GetDllCharacteristics(const CipherShell::CS_PE_IMAGE* image) {
    return image->is64Bit
        ? image->ntHeaders64->OptionalHeader.DllCharacteristics
        : image->ntHeaders32->OptionalHeader.DllCharacteristics;
}

void SetFileCharacteristics(CipherShell::CS_PE_IMAGE* image, WORD value) {
    if (image->is64Bit) image->ntHeaders64->FileHeader.Characteristics = value;
    else image->ntHeaders32->FileHeader.Characteristics = value;
}

void SetDllCharacteristics(CipherShell::CS_PE_IMAGE* image, WORD value) {
    if (image->is64Bit) image->ntHeaders64->OptionalHeader.DllCharacteristics = value;
    else image->ntHeaders32->OptionalHeader.DllCharacteristics = value;
}

void VerifyDynamicBaseEmptyRelocationsGetsAnchor(bool is64) {
    auto lay = BuildPe(is64, {0xC3, 0xCC, 0xCC, 0xCC}, {}, {}, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(img && img->isValid);
    SetDllCharacteristics(img, static_cast<WORD>(
        GetDllCharacteristics(img) | IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE));
    SetFileCharacteristics(img, static_cast<WORD>(
        GetFileCharacteristics(img) | IMAGE_FILE_RELOCS_STRIPPED));

    const uint64_t preferredImageBase = CipherShell::PEUtils::ImageBase(img);
    const WORD sectionsBefore = img->numSections;
    const uint32_t pointerWidth = is64 ? 8u : 4u;
    const uint16_t expectedType = is64
        ? IMAGE_REL_BASED_DIR64
        : IMAGE_REL_BASED_HIGHLOW;
    const char relocationName[8] = {'.', 'a', 's', 'l', 'r', 'r', 'l', 0};
    CipherShell::PEAppendSectionResult appended{};
    std::string error;
    CipherShell::PEEmitter emitter(img);
    CS_TEST_CHECK(emitter.RebuildBaseRelocationDirectory(
        {}, relocationName, &appended, &error));
    CS_TEST_CHECK(appended.success);
    CS_TEST_CHECK(img->numSections == sectionsBefore + 1u);
    CS_TEST_CHECK((GetDllCharacteristics(img) &
        IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0);
    CS_TEST_CHECK((GetFileCharacteristics(img) & IMAGE_FILE_RELOCS_STRIPPED) == 0);

    // anchor 是实际 file-backed 的只读初始化数据，不可写、不可执行、不可丢弃。
    const IMAGE_SECTION_HEADER& section = img->sections[appended.sectionIndex];
    CS_TEST_CHECK((section.Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) != 0);
    CS_TEST_CHECK((section.Characteristics & IMAGE_SCN_MEM_READ) != 0);
    CS_TEST_CHECK((section.Characteristics & IMAGE_SCN_MEM_WRITE) == 0);
    CS_TEST_CHECK((section.Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0);
    CS_TEST_CHECK((section.Characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0);

    CS_TEST_CHECK(img->relocs.entries.size() == 1u);
    const CipherShell::CS_RELOC_ENTRY& anchorRelocation = img->relocs.entries[0];
    CS_TEST_CHECK(anchorRelocation.fullRVA == appended.rva);
    CS_TEST_CHECK(anchorRelocation.type == expectedType);
    CS_TEST_CHECK(anchorRelocation.pageRVA == (appended.rva & ~0xFFFu));
    CS_TEST_CHECK(anchorRelocation.offset == (appended.rva & 0x0FFFu));

    const uint32_t anchorOffset = emitter.RvaToOffset(appended.rva);
    CS_TEST_CHECK(anchorOffset != 0u);
    uint64_t storedImageBase = 0;
    std::memcpy(&storedImageBase, img->rawData + anchorOffset, pointerWidth);
    CS_TEST_CHECK(storedImageBase == preferredImageBase);

    const IMAGE_DATA_DIRECTORY directory = CipherShell::PEUtils::GetDataDirectory(
        img, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    CS_TEST_CHECK(directory.VirtualAddress == appended.rva + pointerWidth);
    CS_TEST_CHECK(directory.Size == 12u);
    const uint32_t directoryOffset = emitter.RvaToOffset(directory.VirtualAddress);
    CS_TEST_CHECK(directoryOffset != 0u);
    IMAGE_BASE_RELOCATION block{};
    std::memcpy(&block, img->rawData + directoryOffset, sizeof(block));
    CS_TEST_CHECK(block.VirtualAddress == (appended.rva & ~0xFFFu));
    CS_TEST_CHECK(block.SizeOfBlock == 12u);
    uint16_t encoded = 0;
    uint16_t padding = 0xFFFFu;
    std::memcpy(&encoded, img->rawData + directoryOffset + sizeof(block), sizeof(encoded));
    std::memcpy(&padding, img->rawData + directoryOffset + sizeof(block) + sizeof(encoded),
        sizeof(padding));
    CS_TEST_CHECK(encoded == static_cast<uint16_t>(
        (expectedType << 12u) | (appended.rva & 0x0FFFu)));
    CS_TEST_CHECK(padding == 0u);

    // 再走一次正式 parser，证明目录布局不是只在 emitter 的内存元数据中成立。
    BYTE* reparsedBytes = new BYTE[img->rawSize];
    std::memcpy(reparsedBytes, img->rawData, img->rawSize);
    CipherShell::PEParser reparsingParser;
    auto* reparsed = reparsingParser.LoadFromBuffer(reparsedBytes, img->rawSize);
    CS_TEST_CHECK(reparsed && reparsed->isValid);
    CS_TEST_CHECK(reparsed->relocs.entries.size() == 1u);
    CS_TEST_CHECK(reparsed->relocs.entries[0].fullRVA == appended.rva);
    CS_TEST_CHECK(reparsed->relocs.entries[0].type == expectedType);
    reparsingParser.FreeImage(reparsed);

    CipherShell::PEParser p;
    p.FreeImage(img);
}

void TestEmitterDynamicBaseEmptyRelocationsGetsX86Anchor() {
    VerifyDynamicBaseEmptyRelocationsGetsAnchor(false);
}

void TestEmitterDynamicBaseEmptyRelocationsGetsX64Anchor() {
    VerifyDynamicBaseEmptyRelocationsGetsAnchor(true);
}

void TestEmitterFixedBaseEmptyRelocationsMayStripDirectory() {
    auto lay = BuildPe(false, {0xC3, 0xCC, 0xCC, 0xCC}, {}, {}, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(img && img->isValid);
    SetDllCharacteristics(img, static_cast<WORD>(
        GetDllCharacteristics(img) & ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE));
    SetFileCharacteristics(img, static_cast<WORD>(
        GetFileCharacteristics(img) & ~IMAGE_FILE_RELOCS_STRIPPED));
    CipherShell::PEUtils::SetDataDirectory(
        img, IMAGE_DIRECTORY_ENTRY_BASERELOC, img->sections[0].VirtualAddress, 12u);

    const WORD sectionsBefore = img->numSections;
    const char relocationName[8] = {'.', 'f', 'i', 'x', 'r', 'l', 0, 0};
    CipherShell::PEAppendSectionResult appended{};
    std::string error;
    CipherShell::PEEmitter emitter(img);
    CS_TEST_CHECK(emitter.RebuildBaseRelocationDirectory(
        {}, relocationName, &appended, &error));
    CS_TEST_CHECK(!appended.success);
    CS_TEST_CHECK(img->numSections == sectionsBefore);
    CS_TEST_CHECK(img->relocs.entries.empty());
    const IMAGE_DATA_DIRECTORY directory = CipherShell::PEUtils::GetDataDirectory(
        img, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    CS_TEST_CHECK(directory.VirtualAddress == 0u && directory.Size == 0u);
    CS_TEST_CHECK((GetDllCharacteristics(img) &
        IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) == 0);
    CS_TEST_CHECK((GetFileCharacteristics(img) & IMAGE_FILE_RELOCS_STRIPPED) != 0);

    CipherShell::PEParser p;
    p.FreeImage(img);
}

void VerifyEmitterDynamicBaseAnchorFailureRollsBack(bool is64) {
    auto lay = BuildPe(is64, {0xC3, 0xCC, 0xCC, 0xCC}, {}, {}, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(img && img->isValid);
    SetDllCharacteristics(img, static_cast<WORD>(
        GetDllCharacteristics(img) | IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE));
    SetFileCharacteristics(img, static_cast<WORD>(
        GetFileCharacteristics(img) | IMAGE_FILE_RELOCS_STRIPPED));
    if (is64) img->ntHeaders64->OptionalHeader.SectionAlignment = 0x1800u;
    else img->ntHeaders32->OptionalHeader.SectionAlignment = 0x1800u;

    BYTE* const dataBefore = img->rawData;
    const DWORD sizeBefore = img->rawSize;
    const WORD sectionsBefore = img->numSections;
    const std::vector<uint8_t> bytesBefore(img->rawData, img->rawData + img->rawSize);
    const char relocationName[8] = {'.', 'b', 'a', 'd', 'r', 'l', 0, 0};
    std::string error;
    CipherShell::PEEmitter emitter(img);
    CS_TEST_CHECK(!emitter.RebuildBaseRelocationDirectory(
        {}, relocationName, nullptr, &error));
    CS_TEST_CHECK(error.find("anchor") != std::string::npos);
    CS_TEST_CHECK(img->rawData == dataBefore);
    CS_TEST_CHECK(img->rawSize == sizeBefore);
    CS_TEST_CHECK(img->numSections == sectionsBefore);
    CS_TEST_CHECK(std::memcmp(img->rawData, bytesBefore.data(), bytesBefore.size()) == 0);
    CS_TEST_CHECK((GetDllCharacteristics(img) &
        IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0);

    CipherShell::PEParser p;
    p.FreeImage(img);
}

void TestEmitterDynamicBaseAnchorFailureRollsBack() {
    VerifyEmitterDynamicBaseAnchorFailureRollsBack(false);
    VerifyEmitterDynamicBaseAnchorFailureRollsBack(true);
}

void TestEmitterDynamicBaseEmptyRelocationsOnRealMsvcPe(const char* fixturePath) {
    CS_TEST_CHECK(fixturePath && fixturePath[0] != '\0');
    CipherShell::PEParser parser;
    auto* img = parser.LoadFromFile(fixturePath);
    CS_TEST_CHECK(img && img->isValid);
    CS_TEST_CHECK((GetDllCharacteristics(img) &
        IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0);
    CS_TEST_CHECK(!img->relocs.entries.empty());

    // 模拟生产路径已经消费完所有原生 relocation；其余输入仍是 MSVC 正常
    // 链接出的完整 PE，不用手工 image 代替真实格式与目录布局。
    img->relocs.entries.clear();
    SetFileCharacteristics(img, static_cast<WORD>(
        GetFileCharacteristics(img) | IMAGE_FILE_RELOCS_STRIPPED));
    const WORD sectionsBefore = img->numSections;
    const char relocationName[8] = {'.', 'm', 's', 'r', 'l', 0, 0, 0};
    CipherShell::PEAppendSectionResult appended{};
    std::string error;
    CipherShell::PEEmitter emitter(img);
    CS_TEST_CHECK(emitter.RebuildBaseRelocationDirectory(
        {}, relocationName, &appended, &error));
    CS_TEST_CHECK(appended.success);
    CS_TEST_CHECK(img->numSections == sectionsBefore + 1u);
    CS_TEST_CHECK(img->relocs.entries.size() == 1u);
    CS_TEST_CHECK(img->relocs.entries[0].fullRVA == appended.rva);
    CS_TEST_CHECK((GetDllCharacteristics(img) &
        IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0);
    CS_TEST_CHECK((GetFileCharacteristics(img) & IMAGE_FILE_RELOCS_STRIPPED) == 0);

    BYTE* reparsedBytes = new BYTE[img->rawSize];
    std::memcpy(reparsedBytes, img->rawData, img->rawSize);
    CipherShell::PEParser reparsingParser;
    auto* reparsed = reparsingParser.LoadFromBuffer(reparsedBytes, img->rawSize);
    CS_TEST_CHECK(reparsed && reparsed->isValid);
    CS_TEST_CHECK(reparsed->relocs.entries.size() == 1u);
    CS_TEST_CHECK((GetDllCharacteristics(reparsed) &
        IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0);
    CS_TEST_CHECK((GetFileCharacteristics(reparsed) & IMAGE_FILE_RELOCS_STRIPPED) == 0);
    reparsingParser.FreeImage(reparsed);
    parser.FreeImage(img);
}

// ============================================================================
// VMInstructionBridgeBuilder（BRIDGE_EXTENDED 抽取指令 thunk 构造）
// ============================================================================
//
// 这条代码路径此前完全没有专门测试覆盖：test_vm_handler_synthesis.cpp 里唯一
// 的 BRIDGE_EXTENDED 执行证据绕开了 VMInstructionBridgeBuilder，直接用一个
// C++ 静态函数当 hidden-register 调用目标，验证的是 EmitX64/86BridgeExtended
// 自己的 GPR 搬运/间接调用，不是这里的 thunk 重定位 + .pdata 复制 + CFG 合并。
// 见 docs/zydis_encoder_pilot.md 独立批次 16。

constexpr uint64_t kBridgeBuilderImageBase = 0x140000000ULL;

// 用真实 Zydis 反汇编器解出待桥接指令的 InstructionIR，而不是手工猜测字段——
// 这样它与 VMInstructionBridgeBuilder::Build 自身独立反汇编校验用的是同一套
// 真实解码，不会因为手工构造的 IR 字段偷懒而制造假阳性。
CipherShell::InstructionIR DisassembleSingleInstruction(
    const std::vector<uint8_t>& bytes, uint64_t va) {
    CipherShell::Disassembler disassembler;
    CS_TEST_CHECK(disassembler.Initialize(true, kBridgeBuilderImageBase));
    const auto decoded = disassembler.Disassemble(bytes.data(),
        static_cast<uint32_t>(bytes.size()), va);
    CS_TEST_CHECK(decoded.size() == 1);
    CS_TEST_CHECK(decoded.front().length == bytes.size());
    return decoded.front();
}

// 构造一个装载了单条 BRIDGE_EXTENDED 请求的 CS_PE_IMAGE + Function +
// TranslationResult，跑真实 VMInstructionBridgeBuilder::Build，并独立
// 重新解析最终字节验证 Exception Directory 条目确实合并进了最终 PE
// （而不仅仅是构建期在内存里自证）。extractedBytes 必须是 Zydis 能真实解码
// 的单条指令；extractedOffsetInText 是它在 textData 里的偏移，必须
// >= ReadSimpleUnwind 要求的 prologSize（这里固定用 BuildUnwindInfoValid()
// 的 prologSize=0，因此任意偏移都满足）。
void VerifyInstructionBridgeBuilds(
    const std::vector<uint8_t>& textData,
    uint32_t extractedOffsetInText,
    const std::vector<uint8_t>& extractedBytes,
    uint8_t hiddenNativeRegister,
    bool usesAvx,
    bool usesX87) {
    using namespace CipherShell;

    Writer rd;
    const size_t entryRel = rd.mark();
    rd.pad(sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY));
    const size_t unwindRel = rd.mark();
    auto unwind = BuildUnwindInfoValid();
    rd.put(unwind.data(), unwind.size());

    IMAGE_RUNTIME_FUNCTION_ENTRY entry{};
    entry.BeginAddress = kExcTextVA;
    entry.EndAddress = kExcTextVA + static_cast<uint32_t>(textData.size());
    entry.UnwindData = kExcRdataVA + static_cast<uint32_t>(unwindRel);
    std::memcpy(rd.buf.data() + entryRel, &entry, sizeof(entry));

    std::vector<DirEntry> dirs = {
        {IMAGE_DIRECTORY_ENTRY_EXCEPTION, kExcRdataVA + static_cast<uint32_t>(entryRel),
         sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)}
    };
    auto lay = BuildPe(true, textData, rd.buf, dirs, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(img && img->isValid);
    CS_TEST_CHECK(img->exceptions.entries.size() == 1);

    // Disassembler::Disassemble's baseAddress parameter is an RVA (checked
    // to fit uint32_t downstream), not a full imageBase-relative VA.
    const uint64_t extractedRVA = kExcTextVA + extractedOffsetInText;
    const InstructionIR decoded = DisassembleSingleInstruction(extractedBytes, extractedRVA);

    Function function{};
    function.entryAddress = kExcTextVA;
    function.size = static_cast<uint32_t>(textData.size());

    TranslationResult translation{};
    translation.registerCount = 32;
    MicroInstruction bridgeOp{};
    bridgeOp.opcode = VM_UOP_BRIDGE_EXTENDED;
    bridgeOp.operandCount = 3;
    bridgeOp.operands[0] = 0;
    bridgeOp.operands[1] = static_cast<uint64_t>(hiddenNativeRegister) |
        (usesAvx ? VM_MICRO_BRIDGE_AVX : 0u) | (usesX87 ? VM_MICRO_BRIDGE_X87 : 0u);
    bridgeOp.operands[2] = decoded.rva;
    translation.instructions.push_back(bridgeOp);

    VMBridgeRequest request{};
    request.microOpIndex = 0;
    request.functionRVA = kExcTextVA;
    request.instruction = decoded;
    request.hiddenNativeRegister = hiddenNativeRegister;
    request.usesAvx = usesAvx;
    request.usesX87 = usesX87;
    translation.bridgeRequests.push_back(request);

    std::vector<Function> functions = {function};
    std::vector<TranslationResult> translations = {translation};

    VMInstructionBridgeBuilder builder;
    const auto result = builder.Build(img, functions, translations,
        ".vmbrdg", ".vmbrdgx", ".vmbrdgcf");
    CS_TEST_CHECK(result.success);
    CS_TEST_CHECK(result.error.empty());
    CS_TEST_CHECK(result.cfgTableVerified);
    CS_TEST_CHECK(result.unwindVerified);
    CS_TEST_CHECK(result.links.size() == 1);
    CS_TEST_CHECK(result.links[0].usesAvx == usesAvx);
    CS_TEST_CHECK(result.links[0].usesX87 == usesX87);
    CS_TEST_CHECK(result.links[0].hiddenNativeRegister == hiddenNativeRegister);
    CS_TEST_CHECK(result.links[0].nativeInstructionSize == extractedBytes.size());
    CS_TEST_CHECK(result.unwindEntries.size() == 1);
    // Build() takes `translations` by non-const reference and patches the
    // linked MicroInstruction in place; the mutation lands in translations[0]
    // (what Build() actually wrote through), not in the `translation` local
    // that was copied into the vector above.
    const MicroInstruction& patchedInstruction = translations[0].instructions[0];
    CS_TEST_CHECK(patchedInstruction.operands[0] == result.links[0].thunkRVA);
    CS_TEST_CHECK((patchedInstruction.operands[1] & VM_MICRO_BRIDGE_LINKED) != 0);
    std::string schemaError;
    CS_TEST_CHECK(VMSchema::ValidateInstruction(
        patchedInstruction, translations[0].registerCount, schemaError));

    // 独立第二条解析路径：脱离 img 内存态，重新从最终字节里 LoadFromBuffer，
    // 确认合并进最终 PE 的 Exception Directory 条目确实可以被独立解析出来，
    // 而不仅仅是构建期在内存里自证；同时用一个全新的 Disassembler 重新解码
    // 重定位后的指令字节，确认它与抽取前的语义（长度/mnemonic/instruction
    // set）完全一致——即便 VMInstructionBridgeBuilder::Build 自身已经做过一次
    // 同样的检查，这里用独立的解码器实例和独立的 image 内存复验，不复用
    // Build() 内部状态。
    BYTE* reparsedBuf = new BYTE[img->rawSize];
    std::memcpy(reparsedBuf, img->rawData, img->rawSize);
    PEParser reparser;
    auto* reparsed = reparser.LoadFromBuffer(reparsedBuf, img->rawSize);
    CS_TEST_CHECK(reparsed && reparsed->isValid);
    bool foundThunkUnwind = false;
    for (const auto& e : reparsed->exceptions.entries) {
        if (e.beginAddress == result.links[0].unwindBeginRVA) {
            foundThunkUnwind = true;
            CS_TEST_CHECK(e.endAddress == result.links[0].nativeInstructionRVA +
                result.links[0].nativeInstructionSize);
        }
    }
    CS_TEST_CHECK(foundThunkUnwind);

    const uint32_t thunkFileOffset = PEUtils::RvaToOffset(reparsed, result.links[0].nativeInstructionRVA);
    CS_TEST_CHECK(thunkFileOffset != 0 &&
        thunkFileOffset + result.links[0].nativeInstructionSize <= reparsed->rawSize);
    Disassembler independentDecoder;
    CS_TEST_CHECK(independentDecoder.Initialize(true, kBridgeBuilderImageBase));
    const auto redecoded = independentDecoder.Disassemble(
        reparsed->rawData + thunkFileOffset, result.links[0].nativeInstructionSize,
        result.links[0].nativeInstructionRVA);
    CS_TEST_CHECK(redecoded.size() == 1);
    CS_TEST_CHECK(redecoded.front().length == decoded.length);
    CS_TEST_CHECK(redecoded.front().mnemonicText == decoded.mnemonicText);
    CS_TEST_CHECK(redecoded.front().instructionSet == decoded.instructionSet);
    CS_TEST_CHECK(std::memcmp(redecoded.front().rawBytes.data(), extractedBytes.data(),
        extractedBytes.size()) == 0);

    reparser.FreeImage(reparsed);
    PEParser p; p.FreeImage(img);
}

// FABS（D9 E1）：无操作数、不读写 EFLAGS 的 x87 指令，真实覆盖
// BuildX64Thunk 的 FXRSTOR/FXSAVE（非 AVX）分支。
void TestInstructionBridgeBuilderX87Fabs() {
    const std::vector<uint8_t> textData = {0xC3, 0xD9, 0xE1, 0xC3};
    VerifyInstructionBridgeBuilds(textData, 1u, {0xD9, 0xE1},
        /*hiddenNativeRegister=*/11u, /*usesAvx=*/false, /*usesX87=*/true);
}

// ============================================================================
// VMInstructionBridgeBuilder::Build 事务保证 + 输入契约收紧（独立批次 17）
// ============================================================================
//
// 下面几个测试专门覆盖批次 17 新增的负向路径：Build() 自身的事务保证（任何
// 失败必须让 image/translations 完全回滚），以及收紧后的 hidden register /
// 指令长度输入契约。全部复用与 TestInstructionBridgeBuilderX87Fabs 相同的
// 真实 PE + 真实 Zydis 反汇编基础设施，只在这基础上有意构造非法/延迟失败的
// 输入，而不是走查代码断言"看起来对"。见 docs/zydis_encoder_pilot.md 批次 17。

struct BridgeFixture {
    CipherShell::CS_PE_IMAGE* img = nullptr;
    CipherShell::Function function{};
    CipherShell::InstructionIR decoded{};
};

// 构造与 VerifyInstructionBridgeBuilds 完全相同的最小 x64 宿主镜像（真实
// RUNTIME_FUNCTION/UNWIND_INFO，prologSize=0）与真实 Zydis 解码出的
// `instructionBytes`，但不预先构造 VMBridgeRequest —— 下面每个负向测试都
// 基于 `decoded` 独立构造自己的请求，只故意破坏自己要测的那一个字段。
BridgeFixture BuildBridgeFixtureWithInstruction(const std::vector<uint8_t>& instructionBytes) {
    using namespace CipherShell;
    std::vector<uint8_t> textData = {0xC3};
    const uint32_t instructionOffset = static_cast<uint32_t>(textData.size());
    textData.insert(textData.end(), instructionBytes.begin(), instructionBytes.end());
    textData.push_back(0xC3);
    Writer rd;
    const size_t entryRel = rd.mark();
    rd.pad(sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY));
    const size_t unwindRel = rd.mark();
    auto unwind = BuildUnwindInfoValid();
    rd.put(unwind.data(), unwind.size());

    IMAGE_RUNTIME_FUNCTION_ENTRY entry{};
    entry.BeginAddress = kExcTextVA;
    entry.EndAddress = kExcTextVA + static_cast<uint32_t>(textData.size());
    entry.UnwindData = kExcRdataVA + static_cast<uint32_t>(unwindRel);
    std::memcpy(rd.buf.data() + entryRel, &entry, sizeof(entry));

    std::vector<DirEntry> dirs = {
        {IMAGE_DIRECTORY_ENTRY_EXCEPTION, kExcRdataVA + static_cast<uint32_t>(entryRel),
         sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)}
    };
    auto lay = BuildPe(true, textData, rd.buf, dirs, {});
    auto* img = Parse(lay);
    CS_TEST_CHECK(img && img->isValid);
    CS_TEST_CHECK(img->exceptions.entries.size() == 1);

    BridgeFixture fixture;
    fixture.img = img;
    fixture.function.entryAddress = kExcTextVA;
    fixture.function.size = static_cast<uint32_t>(textData.size());
    fixture.decoded = DisassembleSingleInstruction(instructionBytes, kExcTextVA + instructionOffset);
    return fixture;
}

BridgeFixture BuildStandardBridgeFixture() {
    return BuildBridgeFixtureWithInstruction({0xD9, 0xE1}); // FABS
}

bool MicroInstructionEqual(const CipherShell::MicroInstruction& a, const CipherShell::MicroInstruction& b) {
    if (a.opcode != b.opcode || a.handlerVariant != b.handlerVariant ||
        a.operandCount != b.operandCount || a.sourceRva != b.sourceRva) return false;
    for (size_t i = 0; i < a.operands.size(); ++i) {
        if (a.operands[i] != b.operands[i]) return false;
    }
    return true;
}

// hiddenNativeRegister 必须落在该架构真实的 GPR 集合内（x64: 0..15）——这条
// 校验在 Build() 里早已存在，但在本批之前从未有专门的负向测试驱动过它
// （VerifyInstructionBridgeBuilds 系列全部只走合法寄存器）。
void TestInstructionBridgeBuilderRejectsOutOfRangeHidden() {
    using namespace CipherShell;
    BridgeFixture fixture = BuildStandardBridgeFixture();
    std::vector<uint8_t> snapshot(fixture.img->rawData, fixture.img->rawData + fixture.img->rawSize);
    const uint32_t numSectionsBefore = fixture.img->numSections;
    const DWORD rawSizeBefore = fixture.img->rawSize;

    TranslationResult translation{};
    translation.registerCount = 32;
    MicroInstruction bridgeOp{};
    bridgeOp.opcode = VM_UOP_BRIDGE_EXTENDED;
    bridgeOp.operandCount = 3;
    bridgeOp.operands[1] = 16u;
    translation.instructions.push_back(bridgeOp);

    VMBridgeRequest request{};
    request.microOpIndex = 0;
    request.functionRVA = kExcTextVA;
    request.instruction = fixture.decoded;
    request.hiddenNativeRegister = 16u; // 越过 x64 最后一个合法 GPR（0..15）
    translation.bridgeRequests.push_back(request);

    std::vector<Function> functions = {fixture.function};
    std::vector<TranslationResult> translations = {translation};
    const MicroInstruction beforeInstruction = translations[0].instructions[0];

    VMInstructionBridgeBuilder builder;
    const auto result = builder.Build(fixture.img, functions, translations,
        ".vmbrdg", ".vmbrdgx", ".vmbrdgcf");
    CS_TEST_CHECK(!result.success);
    CS_TEST_CHECK(!result.error.empty());
    CS_TEST_CHECK(fixture.img->numSections == numSectionsBefore);
    CS_TEST_CHECK(fixture.img->rawSize == rawSizeBefore);
    CS_TEST_CHECK(std::memcmp(fixture.img->rawData, snapshot.data(), snapshot.size()) == 0);
    CS_TEST_CHECK(MicroInstructionEqual(translations[0].instructions[0], beforeInstruction));

    PEParser p; p.FreeImage(fixture.img);
}

// register 4 编码 x64 的 RSP：BuildX64Thunk 把 hidden 当作贯穿整个 thunk 的
// state 指针使用，与 PushMemory/PopMemory/PushFlags/PopFlags/Ret 隐式依赖的
// 真实栈指针是两个必须保持独立的角色。收紧后 Build() 必须在生成任何字节之前
// 就 fail-closed 拒绝这个输入，而不是生成一个会在运行期破坏自己栈的 thunk。
void TestInstructionBridgeBuilderRejectsStackPointerHidden() {
    using namespace CipherShell;
    BridgeFixture fixture = BuildStandardBridgeFixture();
    std::vector<uint8_t> snapshot(fixture.img->rawData, fixture.img->rawData + fixture.img->rawSize);
    const uint32_t numSectionsBefore = fixture.img->numSections;
    const DWORD rawSizeBefore = fixture.img->rawSize;

    TranslationResult translation{};
    translation.registerCount = 32;
    MicroInstruction bridgeOp{};
    bridgeOp.opcode = VM_UOP_BRIDGE_EXTENDED;
    bridgeOp.operandCount = 3;
    bridgeOp.operands[1] = 4u;
    translation.instructions.push_back(bridgeOp);

    VMBridgeRequest request{};
    request.microOpIndex = 0;
    request.functionRVA = kExcTextVA;
    request.instruction = fixture.decoded;
    request.hiddenNativeRegister = 4u; // RSP
    translation.bridgeRequests.push_back(request);

    std::vector<Function> functions = {fixture.function};
    std::vector<TranslationResult> translations = {translation};
    const MicroInstruction beforeInstruction = translations[0].instructions[0];

    VMInstructionBridgeBuilder builder;
    const auto result = builder.Build(fixture.img, functions, translations,
        ".vmbrdg", ".vmbrdgx", ".vmbrdgcf");
    CS_TEST_CHECK(!result.success);
    CS_TEST_CHECK(!result.error.empty());
    CS_TEST_CHECK(fixture.img->numSections == numSectionsBefore);
    CS_TEST_CHECK(fixture.img->rawSize == rawSizeBefore);
    CS_TEST_CHECK(std::memcmp(fixture.img->rawData, snapshot.data(), snapshot.size()) == 0);
    CS_TEST_CHECK(MicroInstructionEqual(translations[0].instructions[0], beforeInstruction));

    PEParser p; p.FreeImage(fixture.img);
}

// instruction.length 必须真的落在 rawBytes 这个固定 15 字节 std::array 里。
// BuildX64Thunk/BuildX86Thunk 用 request.instruction.length 原样拷贝
// rawBytes.data() 出来的字节，自己不做范围检查；收紧前一个声称长度 200 的
// 请求会在 Build() 生成字节的过程中就读出 rawBytes 数组之外的内存
// （未定义行为），而不是被干净地拒绝。
void TestInstructionBridgeBuilderRejectsOversizedInstructionLength() {
    using namespace CipherShell;
    BridgeFixture fixture = BuildStandardBridgeFixture();
    std::vector<uint8_t> snapshot(fixture.img->rawData, fixture.img->rawData + fixture.img->rawSize);
    const uint32_t numSectionsBefore = fixture.img->numSections;
    const DWORD rawSizeBefore = fixture.img->rawSize;

    InstructionIR oversized = fixture.decoded;
    CS_TEST_CHECK(oversized.length <= oversized.rawBytes.size());
    oversized.length = static_cast<uint8_t>(oversized.rawBytes.size() + 1u);

    TranslationResult translation{};
    translation.registerCount = 32;
    MicroInstruction bridgeOp{};
    bridgeOp.opcode = VM_UOP_BRIDGE_EXTENDED;
    bridgeOp.operandCount = 3;
    bridgeOp.operands[1] = 11u;
    translation.instructions.push_back(bridgeOp);

    VMBridgeRequest request{};
    request.microOpIndex = 0;
    request.functionRVA = kExcTextVA;
    request.instruction = oversized;
    request.hiddenNativeRegister = 11u;
    translation.bridgeRequests.push_back(request);

    std::vector<Function> functions = {fixture.function};
    std::vector<TranslationResult> translations = {translation};
    const MicroInstruction beforeInstruction = translations[0].instructions[0];

    VMInstructionBridgeBuilder builder;
    const auto result = builder.Build(fixture.img, functions, translations,
        ".vmbrdg", ".vmbrdgx", ".vmbrdgcf");
    CS_TEST_CHECK(!result.success);
    CS_TEST_CHECK(!result.error.empty());
    CS_TEST_CHECK(fixture.img->numSections == numSectionsBefore);
    CS_TEST_CHECK(fixture.img->rawSize == rawSizeBefore);
    CS_TEST_CHECK(std::memcmp(fixture.img->rawData, snapshot.data(), snapshot.size()) == 0);
    CS_TEST_CHECK(MicroInstructionEqual(translations[0].instructions[0], beforeInstruction));

    PEParser p; p.FreeImage(fixture.img);
}

// hidden 与被桥接指令自身的操作数冲突时必须 fail-closed（批次 18 新增的
// 校验此前没有专门的负向测试直接撞它——只验证过真实 translator 管线永远不会
// 产出这样的输入，没有验证 Build() 自己在收到这样的输入时会不会真的拒绝）。
// FABS 没有任何操作数，撞不出这条校验，换用 MOV EAX,[ECX]（8B 01）：EAX 是
// 寄存器操作数（family 0，写），[ECX] 是内存操作数的 base（family 1）。
// 两个子用例分别撞寄存器操作数分支与内存 base 分支。
void TestInstructionBridgeBuilderRejectsHiddenAliasingOperand() {
    using namespace CipherShell;
    const std::vector<uint8_t> movEaxFromEcx = {0x8B, 0x01}; // mov eax,[ecx]

    for (const uint8_t hidden : std::initializer_list<uint8_t>{0u, 1u}) { // 0=EAX(寄存器操作数)，1=ECX(内存 base)
        BridgeFixture fixture = BuildBridgeFixtureWithInstruction(movEaxFromEcx);
        std::vector<uint8_t> snapshot(fixture.img->rawData, fixture.img->rawData + fixture.img->rawSize);
        const uint32_t numSectionsBefore = fixture.img->numSections;
        const DWORD rawSizeBefore = fixture.img->rawSize;

        TranslationResult translation{};
        translation.registerCount = 32;
        MicroInstruction bridgeOp{};
        bridgeOp.opcode = VM_UOP_BRIDGE_EXTENDED;
        bridgeOp.operandCount = 3;
        bridgeOp.operands[1] = hidden;
        translation.instructions.push_back(bridgeOp);

        VMBridgeRequest request{};
        request.microOpIndex = 0;
        request.functionRVA = kExcTextVA;
        request.instruction = fixture.decoded;
        request.hiddenNativeRegister = hidden;
        translation.bridgeRequests.push_back(request);

        std::vector<Function> functions = {fixture.function};
        std::vector<TranslationResult> translations = {translation};
        const MicroInstruction beforeInstruction = translations[0].instructions[0];

        VMInstructionBridgeBuilder builder;
        const auto result = builder.Build(fixture.img, functions, translations,
            ".vmbrdg", ".vmbrdgx", ".vmbrdgcf");
        CS_TEST_CHECK(!result.success);
        CS_TEST_CHECK(!result.error.empty());
        CS_TEST_CHECK(fixture.img->numSections == numSectionsBefore);
        CS_TEST_CHECK(fixture.img->rawSize == rawSizeBefore);
        CS_TEST_CHECK(std::memcmp(fixture.img->rawData, snapshot.data(), snapshot.size()) == 0);
        CS_TEST_CHECK(MicroInstructionEqual(translations[0].instructions[0], beforeInstruction));

        PEParser p; p.FreeImage(fixture.img);
    }
}

// request.usesAvx/usesX87 必须与 request.instruction 真实的扩展状态类别一致
// （批次 19 新增的校验）：FABS 是真实 x87 指令，若声称 usesX87=false/
// usesAvx=true，Build() 必须拒绝，不能顺着调用方声称的标志走进错误的
// XRSTOR/XSAVE 分支——真实 FABS 不需要、大概率也没有对应 AVX 状态可保存。
void TestInstructionBridgeBuilderRejectsMismatchedExtendedStateClass() {
    using namespace CipherShell;
    BridgeFixture fixture = BuildStandardBridgeFixture(); // FABS：真实 usesX87=true, usesAvx=false
    std::vector<uint8_t> snapshot(fixture.img->rawData, fixture.img->rawData + fixture.img->rawSize);
    const uint32_t numSectionsBefore = fixture.img->numSections;
    const DWORD rawSizeBefore = fixture.img->rawSize;

    TranslationResult translation{};
    translation.registerCount = 32;
    MicroInstruction bridgeOp{};
    bridgeOp.opcode = VM_UOP_BRIDGE_EXTENDED;
    bridgeOp.operandCount = 3;
    bridgeOp.operands[1] = 11u | VM_MICRO_BRIDGE_AVX;
    translation.instructions.push_back(bridgeOp);

    VMBridgeRequest request{};
    request.microOpIndex = 0;
    request.functionRVA = kExcTextVA;
    request.instruction = fixture.decoded;
    request.hiddenNativeRegister = 11u;
    request.usesAvx = true;   // 谎称：真实 FABS 不是 AVX 指令
    request.usesX87 = false;  // 谎称：真实 FABS 就是 x87 指令
    translation.bridgeRequests.push_back(request);

    std::vector<Function> functions = {fixture.function};
    std::vector<TranslationResult> translations = {translation};
    const MicroInstruction beforeInstruction = translations[0].instructions[0];

    VMInstructionBridgeBuilder builder;
    const auto result = builder.Build(fixture.img, functions, translations,
        ".vmbrdg", ".vmbrdgx", ".vmbrdgcf");
    CS_TEST_CHECK(!result.success);
    CS_TEST_CHECK(!result.error.empty());
    CS_TEST_CHECK(fixture.img->numSections == numSectionsBefore);
    CS_TEST_CHECK(fixture.img->rawSize == rawSizeBefore);
    CS_TEST_CHECK(std::memcmp(fixture.img->rawData, snapshot.data(), snapshot.size()) == 0);
    CS_TEST_CHECK(MicroInstructionEqual(translations[0].instructions[0], beforeInstruction));

    PEParser p; p.FreeImage(fixture.img);
}

// Build() 自身的事务保证：第一条 BRIDGE_EXTENDED 请求完全合法（会通过
// AppendSection 把 thunk 真正写进 image，也会通过第二遍逐项校验循环直到
// 暂存好它自己的 bytecode 改写），第二条引用的 micro-op 却根本不是
// VM_UOP_BRIDGE_EXTENDED —— 这个失败只会在 AppendSection 已经成功提交、且
// 第一条请求已经暂存完自己的改写之后才被发现。断言调用前后 image 逐字节相同
// （AppendSection 的提交被完全撤销）、translations 两条指令逐字段相同
// （第一条请求暂存的改写没有被提交）。"调用方失败后不保存文件所以没关系"
// 这种论证不成立：这里直接检查 Build() 返回之后、调用方还没来得及做任何事之前
// 的 image/translations 状态。
void TestInstructionBridgeBuilderRollsBackOnLateFailure() {
    using namespace CipherShell;
    BridgeFixture fixture = BuildStandardBridgeFixture();
    std::vector<uint8_t> snapshot(fixture.img->rawData, fixture.img->rawData + fixture.img->rawSize);
    const uint32_t numSectionsBefore = fixture.img->numSections;
    const DWORD rawSizeBefore = fixture.img->rawSize;

    TranslationResult translation{};
    translation.registerCount = 32;

    MicroInstruction validBridgeOp{};
    validBridgeOp.opcode = VM_UOP_BRIDGE_EXTENDED;
    validBridgeOp.operandCount = 3;
    validBridgeOp.operands[1] = 11u;
    translation.instructions.push_back(validBridgeOp); // index 0

    MicroInstruction unrelatedOp{};
    unrelatedOp.opcode = VM_UOP_RET;
    unrelatedOp.operandCount = 1;
    unrelatedOp.operands[0] = 0;
    translation.instructions.push_back(unrelatedOp); // index 1 -- 不是 BRIDGE_EXTENDED

    VMBridgeRequest firstRequest{};
    firstRequest.microOpIndex = 0;
    firstRequest.functionRVA = kExcTextVA;
    firstRequest.instruction = fixture.decoded;
    firstRequest.hiddenNativeRegister = 11u;
    translation.bridgeRequests.push_back(firstRequest);

    VMBridgeRequest secondRequest{};
    secondRequest.microOpIndex = 1; // 指向 unrelatedOp，触犯"必须引用 BRIDGE_EXTENDED"
    secondRequest.functionRVA = kExcTextVA;
    secondRequest.instruction = fixture.decoded;
    secondRequest.hiddenNativeRegister = 10u;
    translation.bridgeRequests.push_back(secondRequest);

    std::vector<Function> functions = {fixture.function};
    std::vector<TranslationResult> translations = {translation};
    const MicroInstruction beforeInstruction0 = translations[0].instructions[0];
    const MicroInstruction beforeInstruction1 = translations[0].instructions[1];

    VMInstructionBridgeBuilder builder;
    const auto result = builder.Build(fixture.img, functions, translations,
        ".vmbrdg", ".vmbrdgx", ".vmbrdgcf");
    CS_TEST_CHECK(!result.success);
    CS_TEST_CHECK(!result.error.empty());
    CS_TEST_CHECK(result.links.empty());
    // image：AppendSection 已经真实提交过一次（两条 thunk 的 blob），必须被
    // 完全撤销 —— 逐字节比较整份文件，不只是 section 计数。
    CS_TEST_CHECK(fixture.img->isValid);
    CS_TEST_CHECK(fixture.img->numSections == numSectionsBefore);
    CS_TEST_CHECK(fixture.img->rawSize == rawSizeBefore);
    CS_TEST_CHECK(std::memcmp(fixture.img->rawData, snapshot.data(), snapshot.size()) == 0);
    // translations：第一条请求已经在第二遍循环里通过了自己的全部校验、暂存好
    // 了改写，仍然不能被提交。
    CS_TEST_CHECK(MicroInstructionEqual(translations[0].instructions[0], beforeInstruction0));
    CS_TEST_CHECK(MicroInstructionEqual(translations[0].instructions[1], beforeInstruction1));

    PEParser p; p.FreeImage(fixture.img);
}

} // namespace

int main(int argc, char** argv) {
    TestLoadConfigShortNoGuardFlags();
    TestLoadConfigDeclaredSizeExceedsAvailable();
    TestLoadConfigDeclaredSizeExceedsDirectorySizeButFitsFile();
    TestLoadConfigDeclaredSizeCannotUseOverlay();
    TestLoadConfigDeclaredSizeExceedsAbsoluteStructuralBound();
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
    TestExceptionPushMachFrameCodeOffsetZeroAccepted();
    TestExceptionPushMachFrameNonzeroOffsetRejected();
    TestExceptionPushMachFrameBadOpInfoRejected();
    TestExceptionPushMachFrameMustBeLogicalLast();
    TestExceptionOtherUwopCodeOffsetZeroRejected();
    TestExceptionZeroPrologChainedSaveNonvolAccepted();
    TestExceptionRootSaveNonvolCodeOffsetZeroRejected();
    TestExceptionNonzeroPrologChainedSaveAtZeroRejected();
    TestExceptionZeroPrologChainedOtherUwopAtZeroRejected();
    TestExceptionSetFpRegOpInfoMatchesFrameOffsetAccepted();
    TestExceptionSetFpRegReservedZeroAccepted();
    TestExceptionSetFpRegOtherOpInfoRejected();
    TestExceptionDuplicateSetFpRegRejected();
    TestExceptionBeginNotLessThanEnd();
    TestExceptionRangeNotExecutable();
    TestExceptionRangeNotFileBacked();
    TestExceptionOverlappingRanges();
    TestExceptionUnwindHeaderTooShort();
    TestExceptionUnwindBadVersion();
    TestExceptionUnwindVersion2ParsedButVmRejected();
    TestExceptionUnwindReservedFlagsRejected();
    TestExceptionUnwindConflictingFlagsRejected();
    TestExceptionUnwindVersion2MalformedEpilogRejected();
    TestExceptionUnwindCrossSectionRejected();
    TestExceptionUnwindCodeArrayTruncated();
    TestExceptionUnwindHandlerValid();
    TestExceptionUnwindHandlerInvalid();
    TestExceptionUnwindChainedValid();
    TestExceptionUnwindChainedZeroUnwindRejected();
    TestExceptionUnwindChainedCycleRejected();
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
    TestEmitterDynamicBaseEmptyRelocationsGetsX86Anchor();
    TestEmitterDynamicBaseEmptyRelocationsGetsX64Anchor();
    TestEmitterFixedBaseEmptyRelocationsMayStripDirectory();
    TestEmitterDynamicBaseAnchorFailureRollsBack();
    TestSafeSEHTableMergeAddsAndSortsNewHandler();
    TestSafeSEHTableMergeDedupesExistingRva();
    TestSafeSEHTableMergeNoOriginalTableIsNoOp();
    TestSafeSEHTableMergeFailsClosedOnNoSehFlag();
    TestSafeSEHTableMergeRejectsX64Image();
    TestInstructionBridgeBuilderX87Fabs();
    TestInstructionBridgeBuilderRejectsOutOfRangeHidden();
    TestInstructionBridgeBuilderRejectsStackPointerHidden();
    TestInstructionBridgeBuilderRejectsOversizedInstructionLength();
    TestInstructionBridgeBuilderRejectsHiddenAliasingOperand();
    TestInstructionBridgeBuilderRejectsMismatchedExtendedStateClass();
    TestInstructionBridgeBuilderRollsBackOnLateFailure();
    CS_TEST_CHECK(argc == 2);
    TestEmitterDynamicBaseEmptyRelocationsOnRealMsvcPe(argv[1]);
    return 0;
}
