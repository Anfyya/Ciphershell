#include "win32_error.h"

#include <cstdio>

namespace CipherShellGui {
namespace {

std::wstring FormatSystemMessage(DWORD flags, DWORD code) {
    LPWSTR buffer = nullptr;
    const DWORD length = ::FormatMessageW(
        flags | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);

    std::wstring message;
    if (length != 0 && buffer != nullptr) {
        message.assign(buffer, length);
        while (!message.empty() &&
            (message.back() == L'\r' || message.back() == L'\n')) {
            message.pop_back();
        }
    }
    if (buffer) ::LocalFree(buffer);
    return message;
}

} // namespace

std::wstring FormatWin32Error(DWORD errorCode) {
    std::wstring message = FormatSystemMessage(FORMAT_MESSAGE_FROM_SYSTEM, errorCode);
    if (message.empty()) message = L"未知系统错误";

    wchar_t hex[24];
    swprintf_s(hex, L" (0x%08lX)", static_cast<unsigned long>(errorCode));
    message += hex;
    return message;
}

std::wstring FormatHResultError(HRESULT hr) {
    // 大多数系统/COM 标准 HRESULT 也能被 FormatMessage 的系统消息表识别；
    // 识别不了的就只保留十六进制码，不额外引入 comsuppw 之类的链接依赖。
    std::wstring message = FormatSystemMessage(
        FORMAT_MESSAGE_FROM_SYSTEM, static_cast<DWORD>(hr));
    if (message.empty()) message = L"未知错误";

    wchar_t hex[24];
    swprintf_s(hex, L" (0x%08lX)", static_cast<unsigned long>(hr));
    message += hex;
    return message;
}

} // namespace CipherShellGui
