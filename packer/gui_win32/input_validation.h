#pragma once

#include <cerrno>
#include <cstdint>
#include <cwchar>
#include <limits>
#include <string>

namespace CipherShellGui {

inline bool TryParseDecimalIntInRange(
    const std::wstring& text, int minimum, int maximum, int& value)
{
    value = 0;
    if (text.empty() || minimum < 0 || maximum < minimum) return false;
    for (const wchar_t ch : text) {
        if (ch < L'0' || ch > L'9') return false;
    }

    wchar_t* end = nullptr;
    errno = 0;
    const unsigned long long parsed =
        std::wcstoull(text.c_str(), &end, 10);
    if (end == text.c_str() || *end != L'\0' || errno == ERANGE ||
        parsed < static_cast<unsigned long long>(minimum) ||
        parsed > static_cast<unsigned long long>(maximum)) {
        return false;
    }

    value = static_cast<int>(parsed);
    return true;
}

inline bool TryParseHexOrDecimalUint32(
    const std::wstring& text, uint32_t& value)
{
    value = 0;
    if (text.empty() || text[0] < L'0' || text[0] > L'9') return false;

    const bool hasHexPrefix = text.size() > 2 && text[0] == L'0' &&
        (text[1] == L'x' || text[1] == L'X');
    const int base = hasHexPrefix ? 16 : 10;
    wchar_t* end = nullptr;
    errno = 0;
    const unsigned long long parsed =
        std::wcstoull(text.c_str(), &end, base);
    if (end == text.c_str() || *end != L'\0' || errno == ERANGE ||
        parsed > (std::numeric_limits<uint32_t>::max)()) {
        return false;
    }

    value = static_cast<uint32_t>(parsed);
    return true;
}

// GUI target_rvas 的每一行都必须是完整、非零且能无损装入 uint32_t 的数值。
// 不能把无效输入静默丢成空列表，否则后端会从“精确选择”退化成“自动选择”。
inline bool TryParseTargetRva(const std::wstring& text, uint32_t& value) {
    if (!TryParseHexOrDecimalUint32(text, value) || value == 0) {
        value = 0;
        return false;
    }
    return true;
}

inline bool IsSupportedTomlStringValue(const std::wstring& text) {
    return text.find(L'"') == std::wstring::npos &&
        text.find(L'\r') == std::wstring::npos &&
        text.find(L'\n') == std::wstring::npos;
}

} // namespace CipherShellGui
