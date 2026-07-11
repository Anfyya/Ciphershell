#include "packer/pe_parser/pe_parser.h"

#include <cstring>
#include <iostream>
#include <memory>

namespace {

constexpr DWORD kFileSize = 0x400;
constexpr DWORD kNtOffset = 0x80;
constexpr DWORD kSectionRva = 0x1000;
constexpr DWORD kSectionOffset = 0x200;

BYTE* MakeMinimalPE() {
    auto data = std::make_unique<BYTE[]>(kFileSize);
    std::memset(data.get(), 0, kFileSize);

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(data.get());
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = kNtOffset;

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(data.get() + kNtOffset);
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nt->FileHeader.NumberOfSections = 1;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt->OptionalHeader.ImageBase = 0x140000000ull;
    nt->OptionalHeader.FileAlignment = 0x200;
    nt->OptionalHeader.SectionAlignment = 0x1000;
    nt->OptionalHeader.SizeOfHeaders = kSectionOffset;
    nt->OptionalHeader.SizeOfImage = 0x2000;
    nt->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

    auto* section = IMAGE_FIRST_SECTION(nt);
    std::memcpy(section->Name, ".test", 5);
    section->Misc.VirtualSize = 0x200;
    section->VirtualAddress = kSectionRva;
    section->SizeOfRawData = 0x200;
    section->PointerToRawData = kSectionOffset;
    section->Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
    return data.release();
}

bool Expect(bool condition, const char* name) {
    std::cout << '[' << (condition ? "PASS" : "FAIL") << "] " << name << '\n';
    return condition;
}

bool TestMinimalImage() {
    CipherShell::PEParser parser;
    CipherShell::CS_PE_IMAGE* image = parser.LoadFromBuffer(MakeMinimalPE(), kFileSize);
    const bool valid = image && image->isValid && image->is64Bit && image->numSections == 1;
    parser.FreeImage(image);
    return valid;
}

bool TestTruncatedImportDirectory() {
    BYTE* data = MakeMinimalPE();
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(data + kNtOffset);
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] = {kSectionRva, 8};

    CipherShell::PEParser parser;
    CipherShell::CS_PE_IMAGE* image = parser.LoadFromBuffer(data, kFileSize);
    const bool rejected = image && !image->isValid &&
        image->errorMessage.find("import") != std::string::npos;
    parser.FreeImage(image);
    return rejected;
}

bool TestUnterminatedImportDirectory() {
    BYTE* data = MakeMinimalPE();
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(data + kNtOffset);
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] = {
        kSectionRva, sizeof(IMAGE_IMPORT_DESCRIPTOR)};
    auto* descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(data + kSectionOffset);
    descriptor->Name = kSectionRva + sizeof(IMAGE_IMPORT_DESCRIPTOR);

    CipherShell::PEParser parser;
    CipherShell::CS_PE_IMAGE* image = parser.LoadFromBuffer(data, kFileSize);
    const bool rejected = image && !image->isValid;
    parser.FreeImage(image);
    return rejected;
}

bool TestOversizedExportTable() {
    BYTE* data = MakeMinimalPE();
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(data + kNtOffset);
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT] = {
        kSectionRva, sizeof(IMAGE_EXPORT_DIRECTORY)};
    auto* exports = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(data + kSectionOffset);
    exports->Name = kSectionRva + sizeof(IMAGE_EXPORT_DIRECTORY);
    exports->NumberOfFunctions = 0xFFFFFFFFu;

    CipherShell::PEParser parser;
    CipherShell::CS_PE_IMAGE* image = parser.LoadFromBuffer(data, kFileSize);
    const bool rejected = image && !image->isValid &&
        image->errorMessage.find("export") != std::string::npos;
    parser.FreeImage(image);
    return rejected;
}

bool TestNonexistentFile() {
    CipherShell::PEParser parser;
    return parser.LoadFromFile("this-file-must-not-exist.exe") == nullptr;
}

} // namespace

int main() {
    int failures = 0;
    failures += !Expect(TestMinimalImage(), "minimal PE32+ image");
    failures += !Expect(TestTruncatedImportDirectory(), "truncated import directory rejected");
    failures += !Expect(TestUnterminatedImportDirectory(), "unterminated import directory rejected");
    failures += !Expect(TestOversizedExportTable(), "oversized export table rejected");
    failures += !Expect(TestNonexistentFile(), "nonexistent file rejected");
    return failures == 0 ? 0 : 1;
}
