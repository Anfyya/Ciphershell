#pragma once

#include <algorithm>
#include <cwctype>
#include <filesystem>
#include <string>
#include <system_error>

namespace CipherShell {

inline bool PathsReferToSameTarget(
    const std::filesystem::path& first,
    const std::filesystem::path& second,
    bool& same,
    std::string& reason)
{
    same = false;
    reason.clear();

    std::error_code firstExistsError;
    std::error_code secondExistsError;
    const bool firstExists =
        std::filesystem::exists(first, firstExistsError);
    const bool secondExists =
        std::filesystem::exists(second, secondExistsError);
    if (firstExistsError || secondExistsError) {
        reason = "path_exists_check_failed";
        return false;
    }

    if (firstExists && secondExists) {
        std::error_code equivalentError;
        same = std::filesystem::equivalent(
            first, second, equivalentError);
        if (equivalentError) {
            reason = "path_equivalent_check_failed";
            return false;
        }
        if (same) return true;
    }

    std::error_code firstCanonicalError;
    std::error_code secondCanonicalError;
    std::filesystem::path firstNormalized =
        std::filesystem::weakly_canonical(first, firstCanonicalError)
            .lexically_normal();
    std::filesystem::path secondNormalized =
        std::filesystem::weakly_canonical(second, secondCanonicalError)
            .lexically_normal();
    if (firstCanonicalError || secondCanonicalError) {
        reason = "path_weak_canonicalization_failed";
        return false;
    }

#ifdef _WIN32
    std::wstring firstIdentity = firstNormalized.generic_wstring();
    std::wstring secondIdentity = secondNormalized.generic_wstring();
    std::transform(firstIdentity.begin(), firstIdentity.end(),
        firstIdentity.begin(), [](wchar_t value) {
            return static_cast<wchar_t>(std::towlower(value));
        });
    std::transform(secondIdentity.begin(), secondIdentity.end(),
        secondIdentity.begin(), [](wchar_t value) {
            return static_cast<wchar_t>(std::towlower(value));
        });
    same = firstIdentity == secondIdentity;
#else
    same = firstNormalized == secondNormalized;
#endif
    return true;
}

} // namespace CipherShell
