#ifndef CS_DEBUG_DIRECTORY_SCRUBBER_H
#define CS_DEBUG_DIRECTORY_SCRUBBER_H

#include "pe_parser.h"
#include "pe_utils.h"

#include <cstring>
#include <string>
#include <vector>

namespace CipherShell {

struct DebugScrubRange {
    DWORD fileOffset = 0;
    DWORD size = 0;

    bool operator==(const DebugScrubRange& other) const {
        return fileOffset == other.fileOffset && size == other.size;
    }
};

inline bool CollectDebugScrubRanges(const CS_PE_IMAGE* image,
        const BYTE* rawData, DWORD rawSize,
        std::vector<DebugScrubRange>& ranges, std::string& reason) {
    ranges.clear();
    reason.clear();
    if (!image || !image->isValid || !rawData) {
        reason = "debug_scrub_invalid_image";
        return false;
    }

    const IMAGE_DATA_DIRECTORY directory =
        PEUtils::GetDataDirectory(image, IMAGE_DIRECTORY_ENTRY_DEBUG);
    if (directory.VirtualAddress == 0 && directory.Size == 0) {
        return true;
    }
    if (directory.VirtualAddress == 0 || directory.Size == 0 ||
        directory.Size % sizeof(IMAGE_DEBUG_DIRECTORY) != 0) {
        reason = "debug_scrub_malformed_directory";
        return false;
    }

    const DWORD directoryOffset =
        PEUtils::RvaToOffset(image, directory.VirtualAddress);
    if (directoryOffset == 0 || directoryOffset > rawSize ||
        directory.Size > rawSize - directoryOffset) {
        reason = "debug_scrub_directory_out_of_bounds";
        return false;
    }

    try {
        ranges.reserve(1u +
            2u * (directory.Size / sizeof(IMAGE_DEBUG_DIRECTORY)));
        ranges.push_back({directoryOffset, directory.Size});
    } catch (...) {
        reason = "debug_scrub_range_allocation_failed";
        return false;
    }

    const DWORD entryCount =
        directory.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
    for (DWORD index = 0; index < entryCount; ++index) {
        IMAGE_DEBUG_DIRECTORY entry{};
        std::memcpy(&entry,
            rawData + directoryOffset +
                index * sizeof(IMAGE_DEBUG_DIRECTORY),
            sizeof(entry));
        if (entry.SizeOfData == 0) {
            continue;
        }
        if (entry.PointerToRawData == 0 ||
            entry.PointerToRawData > rawSize ||
            entry.SizeOfData > rawSize - entry.PointerToRawData) {
            reason = "debug_scrub_payload_out_of_bounds";
            return false;
        }

        try {
            ranges.push_back(
                {entry.PointerToRawData, entry.SizeOfData});
        } catch (...) {
            reason = "debug_scrub_range_allocation_failed";
            return false;
        }

        if (entry.AddressOfRawData != 0) {
            const DWORD mappedOffset =
                PEUtils::RvaToOffset(image, entry.AddressOfRawData);
            if (mappedOffset == 0 || mappedOffset > rawSize ||
                entry.SizeOfData > rawSize - mappedOffset) {
                reason = "debug_scrub_rva_payload_out_of_bounds";
                return false;
            }
            if (mappedOffset != entry.PointerToRawData) {
                try {
                    ranges.push_back(
                        {mappedOffset, entry.SizeOfData});
                } catch (...) {
                    reason = "debug_scrub_range_allocation_failed";
                    return false;
                }
            }
        }
    }
    return true;
}

inline void ScrubDebugRanges(BYTE* rawData,
        const std::vector<DebugScrubRange>& ranges) {
    for (const DebugScrubRange& range : ranges) {
        std::memset(rawData + range.fileOffset, 0, range.size);
    }
}

inline bool VerifyDebugRangesScrubbed(const BYTE* rawData, DWORD rawSize,
        const std::vector<DebugScrubRange>& ranges, std::string& reason) {
    if (!rawData) {
        reason = "debug_scrub_verify_missing_data";
        return false;
    }
    for (const DebugScrubRange& range : ranges) {
        if (range.fileOffset > rawSize ||
            range.size > rawSize - range.fileOffset) {
            reason = "debug_scrub_verify_range_out_of_bounds";
            return false;
        }
        for (DWORD index = 0; index < range.size; ++index) {
            if (rawData[range.fileOffset + index] != 0) {
                reason = "debug_payload_not_scrubbed";
                return false;
            }
        }
    }
    return true;
}

} // namespace CipherShell

#endif // CS_DEBUG_DIRECTORY_SCRUBBER_H
