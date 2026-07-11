#include "loader_import_builder.h"
#include "../pe_parser/pe_emitter.h"
#include "../pe_parser/pe_utils.h"
#include <algorithm>
#include <cstring>
#include <limits>
#include <vector>

namespace CipherShell {
namespace {

bool NullDescriptor(const IMAGE_IMPORT_DESCRIPTOR& descriptor) {
    return descriptor.OriginalFirstThunk == 0 && descriptor.TimeDateStamp == 0 &&
        descriptor.ForwarderChain == 0 && descriptor.Name == 0 && descriptor.FirstThunk == 0;
}

void Align(std::vector<uint8_t>& data, uint32_t alignment) {
    while (alignment != 0 && data.size() % alignment != 0) data.push_back(0);
}

void AppendCString(std::vector<uint8_t>& data, const char* value) {
    while (*value) data.push_back(static_cast<uint8_t>(*value++));
    data.push_back(0);
}

} // namespace

LoaderImportBuildResult LoaderImportBuilder::Build(CS_PE_IMAGE* image, const char sectionName[8]) {
    LoaderImportBuildResult result{};
    if (!image || !image->isValid || !image->rawData) {
        result.error = "invalid PE image";
        return result;
    }

    std::vector<IMAGE_IMPORT_DESCRIPTOR> descriptors;
    const IMAGE_DATA_DIRECTORY importDirectory =
        PEUtils::GetDataDirectory(image, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (importDirectory.VirtualAddress != 0) {
        const uint32_t offset = PEUtils::RvaToOffset(image, importDirectory.VirtualAddress);
        if (offset == 0 || offset >= image->rawSize) {
            result.error = "existing import directory is outside file data";
            return result;
        }
        const uint32_t maxCount = (image->rawSize - offset) /
            static_cast<uint32_t>(sizeof(IMAGE_IMPORT_DESCRIPTOR));
        bool terminated = false;
        for (uint32_t i = 0; i < maxCount; ++i) {
            IMAGE_IMPORT_DESCRIPTOR descriptor{};
            std::memcpy(&descriptor,
                image->rawData + offset + i * sizeof(descriptor), sizeof(descriptor));
            if (NullDescriptor(descriptor)) {
                terminated = true;
                break;
            }
            // The descriptor table is relocated into a new section.  Any bound-import
            // timestamp/forwarder metadata is therefore stale and must not be reused.
            descriptor.TimeDateStamp = 0;
            descriptor.ForwarderChain = 0;
            descriptors.push_back(descriptor);
        }
        if (!terminated) {
            result.error = "existing import descriptor table has no terminator";
            return result;
        }
    }

    constexpr const char* kFunctions[] = {
        "VirtualProtect",
        "FlushInstructionCache"
    };
    constexpr uint32_t kFunctionCount = 2;
    const uint32_t descriptorCount = static_cast<uint32_t>(descriptors.size()) + 2u;
    if (descriptorCount > std::numeric_limits<uint32_t>::max() /
            static_cast<uint32_t>(sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
        result.error = "import descriptor table is too large";
        return result;
    }

    std::vector<uint8_t> section(
        descriptorCount * sizeof(IMAGE_IMPORT_DESCRIPTOR), 0);
    if (!descriptors.empty()) {
        std::memcpy(section.data(), descriptors.data(),
            descriptors.size() * sizeof(IMAGE_IMPORT_DESCRIPTOR));
    }

    const uint32_t dllNameOffset = static_cast<uint32_t>(section.size());
    AppendCString(section, "kernel32.dll");
    Align(section, 2);

    uint32_t hintNameOffsets[kFunctionCount]{};
    for (uint32_t i = 0; i < kFunctionCount; ++i) {
        hintNameOffsets[i] = static_cast<uint32_t>(section.size());
        section.push_back(0);
        section.push_back(0);
        AppendCString(section, kFunctions[i]);
        Align(section, 2);
    }

    const uint32_t thunkSize = image->is64Bit ? 8u : 4u;
    Align(section, thunkSize);
    const uint32_t iltOffset = static_cast<uint32_t>(section.size());
    section.resize(section.size() + (kFunctionCount + 1u) * thunkSize, 0);
    const uint32_t iatOffset = static_cast<uint32_t>(section.size());
    section.resize(section.size() + (kFunctionCount + 1u) * thunkSize, 0);

    PEEmitter emitter(image);
    char defaultName[8] = {'.','c','s','l','d','r',0,0};
    const char* name = sectionName ? sectionName : defaultName;
    const auto append = emitter.AppendSection(name, section,
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);
    if (!append.success) {
        result.error = "failed to append loader import section: " + append.error;
        return result;
    }

    uint8_t* emitted = image->rawData + append.rawOffset;
    IMAGE_IMPORT_DESCRIPTOR loaderDescriptor{};
    loaderDescriptor.OriginalFirstThunk = append.rva + iltOffset;
    loaderDescriptor.Name = append.rva + dllNameOffset;
    loaderDescriptor.FirstThunk = append.rva + iatOffset;
    std::memcpy(emitted + descriptors.size() * sizeof(IMAGE_IMPORT_DESCRIPTOR),
        &loaderDescriptor, sizeof(loaderDescriptor));

    for (uint32_t i = 0; i < kFunctionCount; ++i) {
        const uint64_t hintNameRVA = static_cast<uint64_t>(append.rva) + hintNameOffsets[i];
        std::memcpy(emitted + iltOffset + i * thunkSize, &hintNameRVA, thunkSize);
        std::memcpy(emitted + iatOffset + i * thunkSize, &hintNameRVA, thunkSize);
    }

    PEUtils::SetDataDirectory(image, IMAGE_DIRECTORY_ENTRY_IMPORT,
        append.rva, descriptorCount * sizeof(IMAGE_IMPORT_DESCRIPTOR));
    // Moving the descriptor table invalidates the optional bound-import directory.
    // The loader will rebuild the IAT from the unbound descriptors above.
    PEUtils::SetDataDirectory(image, IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT, 0, 0);

    CS_IMPORT_DLL loaderDll{};
    loaderDll.dllName = "kernel32.dll";
    loaderDll.originalFirstThunkRVA = loaderDescriptor.OriginalFirstThunk;
    loaderDll.firstThunkRVA = loaderDescriptor.FirstThunk;
    for (uint32_t i = 0; i < kFunctionCount; ++i) {
        CS_IMPORT_FUNCTION function{};
        function.name = kFunctions[i];
        function.thunkRVA = append.rva + iatOffset + i * thunkSize;
        loaderDll.functions.push_back(function);
    }
    image->imports.dlls.push_back(std::move(loaderDll));

    result.success = true;
    result.sectionRVA = append.rva;
    result.sectionRawOffset = append.rawOffset;
    result.sectionSize = append.rawSize;
    result.virtualProtectIatRVA = append.rva + iatOffset;
    result.flushInstructionCacheIatRVA = append.rva + iatOffset + thunkSize;
    return result;
}

} // namespace CipherShell
