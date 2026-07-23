// CipherShell GUI - 主窗口。
//
// 单一固定大小窗口 + 一个标签控件（SysTabControl32），标签页不是独立子窗口，
// 而是把这一页需要的控件都创建成主窗口的直接子控件，切标签时整体
// 显示/隐藏（见 .cpp 里的 m_tabControls）。这样 WM_CTLCOLORSTATIC 之类的
// 消息都统一落在这一个 WndProc 里处理，不需要给每页单独写一个窗口过程。
#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <memory>
#include <string>
#include <vector>

#include "config_model.h"
#include "process_runner.h"

namespace CipherShellGui {

class MainWindow {
public:
    static bool RegisterWindowClass(HINSTANCE instance);
    static MainWindow* Create(HINSTANCE instance, int showCommand);

    // 公开給 std::unique_ptr<MainWindow> 的默认删除器调用；构造仍然只能通过
    // Create()，对象生命周期由 main.cpp 的消息循环两端持有。
    ~MainWindow();

    HWND GetHwnd() const { return m_hwnd; }

private:
    MainWindow();

    static LRESULT CALLBACK WndProcStatic(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    LRESULT WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

    void OnCreate(HWND hwnd);
    void OnDestroy();

    // --- 标签页搭建 -----------------------------------------------------
    int AddTab(const std::wstring& title);
    void TrackControl(int tabIndex, HWND hwnd);
    void SelectTab(int index);

    void BuildBasicPage(int tabIndex);
    void BuildVmPage(int tabIndex);
    void BuildControlFlowPage(int tabIndex);
    void BuildAntiDebugDumpPage(int tabIndex);
    void BuildPerformancePage(int tabIndex);
    void BuildUnavailablePage(int tabIndex);
    void BuildRunPage(int tabIndex);

    void ApplyDefaultsToControls();

    // --- 交互处理 ---------------------------------------------------------
    void OnBrowseInput();
    void OnBrowseOutput();
    void OnBrowseEvidence();
    void OnBrowseBackend();
    void OnInputFileChosen(const std::wstring& path);
    void RefreshSummaryLabel();
    void UpdateVmEnabledState();
    void UpdateEvidenceEnabledState();
    void ApplyPermanentDisabledState();

    void OnStartClicked();
    void OnCancelClicked();
    void OnOpenOutputFolderClicked();

    bool CollectConfig(AppConfig& outConfig, std::wstring& validationError);
    void SetRunningState(bool running);
    void SetStatus(const std::wstring& text, COLORREF color);
    void ResolveDefaultBackendPath();

    void HandleProcessOutputLine(const std::wstring& line);
    void HandleProcessDone(DWORD exitCode);
    void CleanupTempConfig();

    HWND m_hwnd = nullptr;
    HWND m_hwndTab = nullptr;
    int m_tabCount = 0;
    std::vector<std::vector<HWND>> m_tabControls;
    std::vector<HWND> m_permanentlyDisabledControls;
    int m_vmTabIndex = -1;
    COLORREF m_statusColor = RGB(0, 0, 0);

    // --- 基本页 ---
    HWND m_inputPathEdit = nullptr;
    HWND m_outputPathEdit = nullptr;
    HWND m_levelRadios[5] = {};
    HWND m_stripDebugCheck = nullptr;
    HWND m_stripRichCheck = nullptr;
    HWND m_stripTimestampsCheck = nullptr;
    HWND m_randomizeSectionsCheck = nullptr;
    HWND m_verboseCheck = nullptr;
    HWND m_evidenceCheck = nullptr;
    HWND m_evidencePathEdit = nullptr;
    HWND m_evidenceBrowseButton = nullptr;
    HWND m_backendPathEdit = nullptr;

    // --- VM 页 ---
    HWND m_vmEnabledCheck = nullptr;
    HWND m_vmStrengthEdit = nullptr;
    HWND m_registerCountEdit = nullptr;
    HWND m_stackSizeEdit = nullptr;
    HWND m_opcodeRandCheck = nullptr;
    HWND m_handlerMutationCheck = nullptr;
    HWND m_bytecodeEncryptionCheck = nullptr;
    HWND m_embedJunkCheck = nullptr;
    HWND m_nativeBodyCombo = nullptr;
    HWND m_x86AbiCombo = nullptr;
    HWND m_simdBridgeCheck = nullptr;
    HWND m_x87BridgeCheck = nullptr;
    HWND m_variantGroupCountEdit = nullptr;
    HWND m_variantGroupMaxEdit = nullptr;
    HWND m_variantGroupFuncPerGroupEdit = nullptr;
    HWND m_targetFunctionsEdit = nullptr;
    HWND m_targetRvasEdit = nullptr;

    // --- 控制流页 ---
    HWND m_flatteningEnabledCheck = nullptr;
    HWND m_flatteningStrengthEdit = nullptr;
    HWND m_flatteningTargetsEdit = nullptr;

    // --- 反调试 / 反Dump 页 ---
    HWND m_antiDebugChecks[8] = {};
    HWND m_antiDumpChecks[3] = {};

    // --- 性能页 ---
    HWND m_autoHotspotCheck = nullptr;
    HWND m_maxOverheadEdit = nullptr;

    // --- 运行页 ---
    HWND m_summaryLabel = nullptr;
    HWND m_startButton = nullptr;
    HWND m_cancelButton = nullptr;
    HWND m_openFolderButton = nullptr;
    HWND m_statusLabel = nullptr;
    HWND m_progressBar = nullptr;
    HWND m_logEdit = nullptr;

    std::wstring m_inputFilePath;
    std::wstring m_outputFilePath;
    bool m_outputPathManuallySet = false;
    std::wstring m_backendExePath;
    std::wstring m_lastOutputFolder;
    std::wstring m_tempConfigPath;

    // 没有单独持有 IDropTarget 指针：RegisterDragDrop 内部会自己 AddRef 一份，
    // OnCreate 里创建后立即 Release 掉本地这份初始引用，所有权完全交给 OLE，
    // RevokeDragDrop（OnDestroy 里）会释放 OLE 持有的最后一份，对象自行销毁。
    std::unique_ptr<ProcessRunner> m_processRunner;
};

} // namespace CipherShellGui
