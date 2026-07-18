// CipherShell GUI - 子进程运行器。
//
// 通过 CreateProcess 调用现有的 ciphershell.exe（不链接 ciphershell_packer，
// GUI 与后端逻辑完全解耦），管道捕获 stdout/stderr，后台线程异步读取、按行
// 转发给 UI 线程。后端目前没有结构化的分阶段进度回调——main.cpp 只是把
// "[1/5] ..."这类阶段说明和 FEATURE_STATUS/错误信息按行打印到 stdout/stderr。
// 这里如实转发这些真实文本，UI 侧只据此提炼一个粗粒度的"当前阶段"提示，
// 不编造任何假的百分比或分步进度。
#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <string>

namespace CipherShellGui {

// 子进程事件通过 PostMessage 投给 notify window：
//   kMsgProcessOutput：lParam = new std::wstring*，一行（已去掉行尾换行）
//                      来自子进程 stdout/stderr 的文本，UTF-8 解码后的结果。
//                      接收方处理完必须 delete。
//   kMsgProcessDone：  wParam = 退出码 (DWORD)，进程已结束（正常退出或被
//                      Cancel 终止），句柄已在后台线程内部清理完毕。
// 启动失败（CreateProcess 等）是同步的，直接由 Start() 的返回值 + error
// 参数报告，不会有对应的异步消息。
inline constexpr UINT kMsgProcessOutput = WM_APP + 1;
inline constexpr UINT kMsgProcessDone = WM_APP + 2;

class ProcessRunner {
public:
    ProcessRunner() = default;
    ~ProcessRunner();

    ProcessRunner(const ProcessRunner&) = delete;
    ProcessRunner& operator=(const ProcessRunner&) = delete;

    // applicationPath：ciphershell.exe 的完整路径（同时作为 lpApplicationName
    // 和 argv[0]，避免走 PATH 搜索的歧义）。commandLine 由 BuildCommandLine
    // 生成。notifyWindow 接收上面三种消息。
    //
    // 一次只允许一个任务在跑；已有任务运行时返回 false。
    bool Start(
        const std::wstring& applicationPath,
        const std::wstring& commandLine,
        const std::wstring& workingDirectory,
        HWND notifyWindow,
        std::wstring& error);

    // 请求终止正在运行的子进程；没有任务在跑时什么也不做。
    void Cancel();

    bool IsRunning() const { return m_running; }

    // 收到 kMsgProcessDone 或 kMsgProcessStartFailed 后必须调用，回收线程
    // 句柄、复位内部状态，之后才允许发起下一次 Start。
    void NotifyFinished();

private:
    struct ThreadContext {
        HANDLE hProcess;
        HANDLE hReadPipe;
        HWND hNotifyWindow;
    };

    static DWORD WINAPI ReaderThreadProc(LPVOID param);

    HANDLE m_hProcessForCancel = nullptr;  // Cancel() 用；与读线程里的副本各自独立、各自 Close。
    HANDLE m_hThread = nullptr;
    bool m_running = false;
};

} // namespace CipherShellGui
