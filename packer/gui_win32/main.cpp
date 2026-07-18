// CipherShell GUI - 程序入口。
//
// 只做：初始化 OLE（COM 文件对话框 IFileOpenDialog/IFileSaveDialog、拖放
// IDropTarget 都依赖它）、初始化 ComCtl32 通用控件、创建主窗口、跑消息
// 循环。所有界面/业务逻辑都在 MainWindow 里，这里不下沉任何决策。
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commctrl.h>
#include <ole2.h>

#include <memory>

#include "main_window.h"

namespace {

int RunMessageLoop(HWND mainWindow) {
    MSG msg;
    BOOL result;
    while ((result = ::GetMessageW(&msg, nullptr, 0, 0)) != 0) {
        if (result == -1) break;
        // IsDialogMessage 让 Tab/方向键之类的对话框式键盘导航在这个由
        // CreateWindowEx 手写出来的普通窗口里也能用（主窗口创建时带了
        // WS_EX_CONTROLPARENT）。
        if (!::IsDialogMessageW(mainWindow, &msg)) {
            ::TranslateMessage(&msg);
            ::DispatchMessageW(&msg);
        }
    }
    return static_cast<int>(msg.wParam);
}

} // namespace

// 用 ANSI 签名的 WinMain（不是 wWinMain）：两边工具链都无需额外的
// /ENTRY:wWinMainCRTStartup 之类的链接器设置就能识别为入口点。lpCmdLine
// 本身用不上——程序内部所有字符串/路径处理都走显式的 W 后缀 API，和入口点
// 签名是不是 Unicode 无关。
int WINAPI WinMain(HINSTANCE instance, HINSTANCE, LPSTR, int showCommand) {
    if (FAILED(::OleInitialize(nullptr))) {
        ::MessageBoxW(nullptr, L"初始化 OLE 失败，无法启动。",
            L"CipherShell 保护工具", MB_OK | MB_ICONERROR);
        return 1;
    }

    INITCOMMONCONTROLSEX commonControls{};
    commonControls.dwSize = sizeof(commonControls);
    commonControls.dwICC =
        ICC_TAB_CLASSES | ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES | ICC_BAR_CLASSES;
    ::InitCommonControlsEx(&commonControls);

    int exitCode = 1;
    if (!CipherShellGui::MainWindow::RegisterWindowClass(instance)) {
        ::MessageBoxW(nullptr, L"注册窗口类失败，无法启动。",
            L"CipherShell 保护工具", MB_OK | MB_ICONERROR);
    } else {
        std::unique_ptr<CipherShellGui::MainWindow> window(
            CipherShellGui::MainWindow::Create(instance, showCommand));
        if (!window) {
            ::MessageBoxW(nullptr, L"创建主窗口失败，无法启动。",
                L"CipherShell 保护工具", MB_OK | MB_ICONERROR);
        } else {
            exitCode = RunMessageLoop(window->GetHwnd());
        }
    }

    ::OleUninitialize();
    return exitCode;
}
