#include "process_runner.h"

#include <memory>
#include <vector>

#include "text_convert.h"
#include "win32_error.h"

namespace CipherShellGui {
namespace {

HANDLE OpenNulForRead() {
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    return ::CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ, &sa,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
}

} // namespace

ProcessRunner::~ProcessRunner() {
    if (m_running) {
        // 正常流程下调用方总会先 Cancel + 等 Done + NotifyFinished；这里只是
        // 兜底，避免窗口意外销毁时泄漏句柄（后台读线程仍会自行退出、自行
        // 关闭它自己持有的那份 hProcess/hReadPipe）。
        if (m_hProcessForCancel) ::TerminateProcess(m_hProcessForCancel, 1);
    }
    if (m_hProcessForCancel) ::CloseHandle(m_hProcessForCancel);
    if (m_hThread) ::CloseHandle(m_hThread);
}

bool ProcessRunner::Start(
    const std::wstring& applicationPath,
    const std::wstring& commandLine,
    const std::wstring& workingDirectory,
    HWND notifyWindow,
    std::wstring& error)
{
    if (m_running) {
        error = L"已有保护任务在运行";
        return false;
    }

    SECURITY_ATTRIBUTES pipeAttributes{};
    pipeAttributes.nLength = sizeof(pipeAttributes);
    pipeAttributes.bInheritHandle = TRUE;

    HANDLE hReadPipe = nullptr;
    HANDLE hWritePipe = nullptr;
    if (!::CreatePipe(&hReadPipe, &hWritePipe, &pipeAttributes, 0)) {
        error = L"创建管道失败：" + FormatWin32Error(::GetLastError());
        return false;
    }
    // 读端只留给 GUI 进程自己的读线程用，绝不能被子进程继承。
    ::SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    HANDLE hNulStdin = OpenNulForRead();

    STARTUPINFOW startupInfo{};
    startupInfo.cb = sizeof(startupInfo);
    startupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    startupInfo.wShowWindow = SW_HIDE;
    startupInfo.hStdOutput = hWritePipe;
    startupInfo.hStdError = hWritePipe;
    startupInfo.hStdInput = hNulStdin;  // 可能为 INVALID_HANDLE_VALUE，CreateProcess 仍能接受。

    std::vector<wchar_t> commandLineBuffer(
        commandLine.begin(), commandLine.end());
    commandLineBuffer.push_back(L'\0');

    PROCESS_INFORMATION processInfo{};
    const BOOL created = ::CreateProcessW(
        applicationPath.c_str(),
        commandLineBuffer.data(),
        nullptr, nullptr,
        /*bInheritHandles=*/TRUE,
        CREATE_NO_WINDOW,
        nullptr,
        workingDirectory.empty() ? nullptr : workingDirectory.c_str(),
        &startupInfo,
        &processInfo);

    const DWORD createError = ::GetLastError();

    // 无论成功与否，父进程都不再需要管道写端/NUL 读端这两份句柄——
    // 成功时它们已经被子进程继承走了一份；不关掉父进程自己这份，读线程的
    // ReadFile 永远等不到 EOF（管道只要还有任何写端开着就不会返回 EOF）。
    ::CloseHandle(hWritePipe);
    if (hNulStdin && hNulStdin != INVALID_HANDLE_VALUE) ::CloseHandle(hNulStdin);

    if (!created) {
        ::CloseHandle(hReadPipe);
        error = L"启动 " + applicationPath + L" 失败：" + FormatWin32Error(createError);
        return false;
    }

    ::CloseHandle(processInfo.hThread);

    // 复制一份进程句柄专供 UI 线程的 Cancel() 使用；读线程用原始那份。
    // 两份句柄各自独立、各自负责 Close 自己那份，不会出现重复关闭。
    HANDLE hProcessForReader = processInfo.hProcess;
    HANDLE hProcessForCancel = nullptr;
    if (!::DuplicateHandle(
            ::GetCurrentProcess(), processInfo.hProcess,
            ::GetCurrentProcess(), &hProcessForCancel,
            0, FALSE, DUPLICATE_SAME_ACCESS)) {
        hProcessForCancel = nullptr;  // 复制失败不影响主流程，只是 Cancel 会失效。
    }

    auto* context = new ThreadContext{hProcessForReader, hReadPipe, notifyWindow};
    HANDLE hThread = ::CreateThread(
        nullptr, 0, &ProcessRunner::ReaderThreadProc, context, 0, nullptr);
    if (!hThread) {
        error = L"创建读取线程失败：" + FormatWin32Error(::GetLastError());
        delete context;
        ::CloseHandle(hReadPipe);
        ::TerminateProcess(hProcessForReader, 1);
        ::CloseHandle(hProcessForReader);
        if (hProcessForCancel) ::CloseHandle(hProcessForCancel);
        return false;
    }

    m_hProcessForCancel = hProcessForCancel;
    m_hThread = hThread;
    m_running = true;
    return true;
}

void ProcessRunner::Cancel() {
    if (!m_running || !m_hProcessForCancel) return;
    ::TerminateProcess(m_hProcessForCancel, 1);
}

void ProcessRunner::NotifyFinished() {
    if (m_hThread) {
        ::WaitForSingleObject(m_hThread, INFINITE);
        ::CloseHandle(m_hThread);
        m_hThread = nullptr;
    }
    if (m_hProcessForCancel) {
        ::CloseHandle(m_hProcessForCancel);
        m_hProcessForCancel = nullptr;
    }
    m_running = false;
}

DWORD WINAPI ProcessRunner::ReaderThreadProc(LPVOID param) {
    std::unique_ptr<ThreadContext> context(static_cast<ThreadContext*>(param));

    std::string pending;
    char buffer[4096];
    for (;;) {
        DWORD bytesRead = 0;
        const BOOL ok = ::ReadFile(
            context->hReadPipe, buffer, sizeof(buffer), &bytesRead, nullptr);
        if (!ok || bytesRead == 0) break;  // 管道 EOF：子进程已退出或关闭了句柄。

        pending.append(buffer, bytesRead);

        // 按行转发。'\n' 是单字节 ASCII，在 UTF-8 里绝不会作为多字节序列的
        // 一部分出现，所以在原始字节缓冲区里按它切分总是安全的，不会切断一个
        // 多字节字符——不需要额外处理"分片读取切断 UTF-8 字符"的情形。
        size_t start = 0;
        for (;;) {
            const size_t newlinePos = pending.find('\n', start);
            if (newlinePos == std::string::npos) break;
            size_t lineEnd = newlinePos;
            if (lineEnd > start && pending[lineEnd - 1] == '\r') --lineEnd;
            std::wstring* line = new std::wstring(
                Utf8ToWide(pending.substr(start, lineEnd - start)));
            ::PostMessageW(context->hNotifyWindow, kMsgProcessOutput,
                0, reinterpret_cast<LPARAM>(line));
            start = newlinePos + 1;
        }
        pending.erase(0, start);
    }

    if (!pending.empty()) {
        std::wstring* line = new std::wstring(Utf8ToWide(pending));
        ::PostMessageW(context->hNotifyWindow, kMsgProcessOutput,
            0, reinterpret_cast<LPARAM>(line));
    }

    ::WaitForSingleObject(context->hProcess, INFINITE);
    DWORD exitCode = 1;
    ::GetExitCodeProcess(context->hProcess, &exitCode);

    ::CloseHandle(context->hReadPipe);
    ::CloseHandle(context->hProcess);

    ::PostMessageW(context->hNotifyWindow, kMsgProcessDone,
        static_cast<WPARAM>(exitCode), 0);
    return 0;
}

} // namespace CipherShellGui
