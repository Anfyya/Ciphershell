#include "main_window.h"

#include <commctrl.h>
#include <ole2.h>
#include <shellapi.h>

#include <algorithm>
#include <cwctype>
#include <filesystem>

#include "cli_builder.h"
#include "control_ids.h"
#include "drop_target.h"
#include "file_dialogs.h"
#include "text_convert.h"
#include "toml_writer.h"
#include "ui_helpers.h"
#include "ui_metrics.h"
#include "win32_error.h"

namespace CipherShellGui {
namespace {

const wchar_t kClassName[] = L"CipherShellGuiMainWindow";
const wchar_t kWindowTitle[] = L"CipherShell 保护工具";
const wchar_t kWindowTitleDragHover[] = L"CipherShell 保护工具 — 松开鼠标以选择该文件为输入";

// 命令行 ABI 下拉框选项，索引必须和 CreateComboControl 传入的列表一一对应。
const wchar_t* const kX86CallAbiValues[] = {
    L"auto", L"cdecl", L"stdcall", L"fastcall", L"thiscall"};

} // namespace

bool MainWindow::RegisterWindowClass(HINSTANCE instance) {
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = &MainWindow::WndProcStatic;
    wc.hInstance = instance;
    wc.hIcon = ::LoadIconW(nullptr, IDI_APPLICATION);
    wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(static_cast<INT_PTR>(COLOR_BTNFACE) + 1);
    wc.lpszClassName = kClassName;
    wc.hIconSm = wc.hIcon;
    return ::RegisterClassExW(&wc) != 0;
}

MainWindow* MainWindow::Create(HINSTANCE instance, int showCommand) {
    auto* window = new MainWindow();

    RECT rect{0, 0, Metrics::kWindowWidth, Metrics::kWindowHeight};
    const DWORD style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
    ::AdjustWindowRectEx(&rect, style, FALSE, 0);

    HWND hwnd = ::CreateWindowExW(
        WS_EX_CONTROLPARENT, kClassName, kWindowTitle, style,
        CW_USEDEFAULT, CW_USEDEFAULT,
        rect.right - rect.left, rect.bottom - rect.top,
        nullptr, nullptr, instance, window);

    if (!hwnd) {
        delete window;
        return nullptr;
    }

    ::ShowWindow(hwnd, showCommand);
    ::UpdateWindow(hwnd);
    return window;
}

MainWindow::MainWindow() : m_processRunner(std::make_unique<ProcessRunner>()) {}

MainWindow::~MainWindow() = default;

LRESULT CALLBACK MainWindow::WndProcStatic(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    MainWindow* self;
    if (msg == WM_NCCREATE) {
        auto* createStruct = reinterpret_cast<CREATESTRUCTW*>(lParam);
        self = reinterpret_cast<MainWindow*>(createStruct->lpCreateParams);
        self->m_hwnd = hwnd;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
    } else {
        self = reinterpret_cast<MainWindow*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    }
    if (self) return self->WndProc(hwnd, msg, wParam, lParam);
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

LRESULT MainWindow::WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE:
            OnCreate(hwnd);
            return 0;

        case WM_COMMAND: {
            if (HIWORD(wParam) == BN_CLICKED) {
                switch (LOWORD(wParam)) {
                    case IDC_BROWSE_INPUT: OnBrowseInput(); return 0;
                    case IDC_BROWSE_OUTPUT: OnBrowseOutput(); return 0;
                    case IDC_BROWSE_EVIDENCE: OnBrowseEvidence(); return 0;
                    case IDC_BROWSE_BACKEND: OnBrowseBackend(); return 0;
                    case IDC_VM_ENABLED: UpdateVmEnabledState(); return 0;
                    case IDC_EVIDENCE_ENABLED: UpdateEvidenceEnabledState(); return 0;
                    case IDC_START: OnStartClicked(); return 0;
                    case IDC_CANCEL: OnCancelClicked(); return 0;
                    case IDC_OPEN_OUTPUT_FOLDER: OnOpenOutputFolderClicked(); return 0;
                    default: break;
                }
            }
            break;
        }

        case WM_NOTIFY: {
            const auto* header = reinterpret_cast<LPNMHDR>(lParam);
            if (header->hwndFrom == m_hwndTab && header->code == TCN_SELCHANGE) {
                SelectTab(TabCtrl_GetCurSel(m_hwndTab));
                return 0;
            }
            break;
        }

        case kMsgProcessOutput: {
            std::unique_ptr<std::wstring> line(reinterpret_cast<std::wstring*>(lParam));
            if (line) HandleProcessOutputLine(*line);
            return 0;
        }

        case kMsgProcessDone:
            HandleProcessDone(static_cast<DWORD>(wParam));
            return 0;

        case WM_CTLCOLORSTATIC: {
            HDC hdc = reinterpret_cast<HDC>(wParam);
            HWND control = reinterpret_cast<HWND>(lParam);
            ::SetBkMode(hdc, TRANSPARENT);
            ::SetTextColor(hdc, control == m_statusLabel ? m_statusColor : ::GetSysColor(COLOR_BTNTEXT));
            return reinterpret_cast<LRESULT>(::GetSysColorBrush(COLOR_BTNFACE));
        }

        case WM_CLOSE:
            ::DestroyWindow(hwnd);
            return 0;

        case WM_DESTROY:
            OnDestroy();
            ::PostQuitMessage(0);
            return 0;

        default:
            break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

void MainWindow::OnDestroy() {
    if (m_processRunner && m_processRunner->IsRunning()) {
        m_processRunner->Cancel();
    }
    ::RevokeDragDrop(m_hwnd);
    CleanupTempConfig();
}

// ============================================================================
// 标签页基础设施
// ============================================================================

int MainWindow::AddTab(const std::wstring& title) {
    std::wstring text = title;  // TCITEMW.pszText 不是 const wchar_t*，需要可写缓冲区。
    TCITEMW item{};
    item.mask = TCIF_TEXT;
    item.pszText = text.data();
    const int index = m_tabCount;
    TabCtrl_InsertItem(m_hwndTab, index, &item);
    m_tabControls.emplace_back();
    ++m_tabCount;
    return index;
}

void MainWindow::TrackControl(int tabIndex, HWND hwnd) {
    if (!hwnd) return;
    m_tabControls[static_cast<size_t>(tabIndex)].push_back(hwnd);
}

void MainWindow::SelectTab(int index) {
    for (int i = 0; i < static_cast<int>(m_tabControls.size()); ++i) {
        const int showFlag = (i == index) ? SW_SHOW : SW_HIDE;
        for (HWND hwnd : m_tabControls[static_cast<size_t>(i)]) ::ShowWindow(hwnd, showFlag);
    }
    TabCtrl_SetCurSel(m_hwndTab, index);
}

void MainWindow::OnCreate(HWND hwnd) {
    using namespace Metrics;

    m_hwndTab = CreateTabControlWidget(
        hwnd, ::GetModuleHandleW(nullptr), kTabX, kTabY, kTabWidth, kTabHeight);

    const int tabBasic = AddTab(L"基本");
    const int tabVm = AddTab(L"虚拟化 VM");
    const int tabControlFlow = AddTab(L"控制流");
    const int tabAntiDebugDump = AddTab(L"反调试 / 反Dump");
    const int tabPerformance = AddTab(L"性能");
    const int tabUnavailable = AddTab(L"不可用模块");
    const int tabRun = AddTab(L"运行");
    m_vmTabIndex = tabVm;

    BuildBasicPage(tabBasic);
    BuildVmPage(tabVm);
    BuildControlFlowPage(tabControlFlow);
    BuildAntiDebugDumpPage(tabAntiDebugDump);
    BuildPerformancePage(tabPerformance);
    BuildUnavailablePage(tabUnavailable);
    BuildRunPage(tabRun);

    ApplyDefaultsToControls();
    UpdateVmEnabledState();
    UpdateEvidenceEnabledState();
    RefreshSummaryLabel();
    SelectTab(0);

    ResolveDefaultBackendPath();

    auto* dropTarget = new InputFileDropTarget(
        [this](const std::wstring& path) { OnInputFileChosen(path); },
        [hwnd](bool hovering) {
            ::SetWindowTextW(hwnd, hovering ? kWindowTitleDragHover : kWindowTitle);
        });
    const HRESULT hr = ::RegisterDragDrop(hwnd, dropTarget);
    dropTarget->Release();  // RegisterDragDrop 成功时自己 AddRef 了一份；所有权交给 OLE。
    if (FAILED(hr)) {
        AppendLogLine(m_logEdit, L"警告：注册拖放目标失败（" + FormatHResultError(hr) +
            L"），仍可以用“浏览...”按钮选择文件。");
    }
}

// ============================================================================
// 基本页
// ============================================================================

void MainWindow::BuildBasicPage(int tabIndex) {
    using namespace Metrics;
    auto track = [&](HWND h) { TrackControl(tabIndex, h); return h; };
    int y = kPageMarginTop;
    const int x = kPageMarginLeft;
    const int editWidth = kControlWidth - kBrowseButtonWidth - 8;
    const int buttonX = kControlX + editWidth + 8;

    track(CreateSectionHeaderControl(m_hwnd, x, y, kPageWidth, kLabelHeight, L"输入 / 输出"));
    y += kRowHeight;

    track(CreateLabelControl(m_hwnd, x, y, kLabelWidth, kControlHeight, L"输入文件"));
    m_inputPathEdit = track(CreateEditControl(
        m_hwnd, kControlX, y, editWidth, kControlHeight, NextControlId(), ES_READONLY));
    track(CreateButtonControl(m_hwnd, buttonX, y, kBrowseButtonWidth, kControlHeight, L"浏览...", IDC_BROWSE_INPUT));
    y += kRowHeight;

    track(CreateLabelControl(m_hwnd, kControlX, y, kControlWidth, kLabelHeight,
        L"提示：也可以直接把 .exe / .dll 文件拖放到本窗口"));
    y += kRowHeight;

    track(CreateLabelControl(m_hwnd, x, y, kLabelWidth, kControlHeight, L"输出文件"));
    m_outputPathEdit = track(CreateEditControl(
        m_hwnd, kControlX, y, editWidth, kControlHeight, NextControlId(), ES_READONLY));
    track(CreateButtonControl(m_hwnd, buttonX, y, kBrowseButtonWidth, kControlHeight, L"另存为...", IDC_BROWSE_OUTPUT));
    y += kRowHeight + kGroupGap;

    track(CreateSectionHeaderControl(m_hwnd, x, y, kPageWidth, kLabelHeight, L"后端程序"));
    y += kRowHeight;
    track(CreateLabelControl(m_hwnd, x, y, kLabelWidth, kControlHeight, L"ciphershell.exe"));
    m_backendPathEdit = track(CreateEditControl(
        m_hwnd, kControlX, y, editWidth, kControlHeight, NextControlId(), ES_READONLY));
    track(CreateButtonControl(m_hwnd, buttonX, y, kBrowseButtonWidth, kControlHeight, L"更改...", IDC_BROWSE_BACKEND));
    y += kRowHeight + kGroupGap;

    track(CreateSectionHeaderControl(m_hwnd, x, y, kPageWidth, kLabelHeight,
        L"保护等级（global.protection_level / -l，1-5）"));
    y += kRowHeight;
    const int levelBoxHeight = kRowHeight * 5 + 10;
    track(CreateGroupBoxControl(m_hwnd, x, y, kPageWidth, levelBoxHeight, L""));
    static const wchar_t* const kLevelText[5] = {
        L"L1 (Guard)     基础加密保护       (~1.05x 性能开销)",
        L"L2 (Shield)    控制流平坦化       (~2-3x 性能开销)",
        L"L3 (Armor)     高级混淆           (~5-8x 性能开销)",
        L"L4 (Fortress)  代码虚拟化         (~15-30x 性能开销)",
        L"L5 (Citadel)   多层嵌套 VM        (~50-100x+ 性能开销)",
    };
    int radioY = y + 8;
    for (int i = 0; i < 5; ++i) {
        m_levelRadios[i] = track(CreateRadioControl(
            m_hwnd, x + 14, radioY, kPageWidth - 28, kControlHeight,
            kLevelText[i], NextControlId(), i == 0, i == 3));
        radioY += kRowHeight;
    }
    y += levelBoxHeight + kGroupGap;

    track(CreateSectionHeaderControl(m_hwnd, x, y, kPageWidth, kLabelHeight, L"全局选项 [global]"));
    y += kRowHeight;
    const int halfWidth = kPageWidth / 2 - 6;
    m_stripDebugCheck = track(CreateCheckboxControl(
        m_hwnd, x, y, halfWidth, kControlHeight, L"strip_debug_info（删除调试信息）", NextControlId(), true));
    m_stripRichCheck = track(CreateCheckboxControl(
        m_hwnd, x + halfWidth + 12, y, halfWidth, kControlHeight,
        L"strip_rich_header（删除 Rich Header）", NextControlId(), true));
    y += kRowHeight;
    m_stripTimestampsCheck = track(CreateCheckboxControl(
        m_hwnd, x, y, halfWidth, kControlHeight, L"strip_timestamps（时间戳归零）", NextControlId(), true));
    m_randomizeSectionsCheck = track(CreateCheckboxControl(
        m_hwnd, x + halfWidth + 12, y, halfWidth, kControlHeight,
        L"randomize_section_names（随机化节名）", NextControlId(), true));
    y += kRowHeight + kGroupGap;

    track(CreateSectionHeaderControl(m_hwnd, x, y, kPageWidth, kLabelHeight, L"命令行选项"));
    y += kRowHeight;
    m_verboseCheck = track(CreateCheckboxControl(
        m_hwnd, x, y, kPageWidth, kControlHeight, L"verbose（-v，输出详细信息）", NextControlId(), false));
    y += kRowHeight;
    m_evidenceCheck = track(CreateCheckboxControl(
        m_hwnd, x, y, kPageWidth, kControlHeight,
        L"导出 VM handler 明文比较证据（--vm-handler-evidence）", IDC_EVIDENCE_ENABLED, false));
    y += kRowHeight;
    track(CreateLabelControl(m_hwnd, x, y, kLabelWidth, kControlHeight, L"证据文件路径"));
    m_evidencePathEdit = track(CreateEditControl(
        m_hwnd, kControlX, y, editWidth, kControlHeight, NextControlId(), ES_READONLY));
    m_evidenceBrowseButton = track(CreateButtonControl(
        m_hwnd, buttonX, y, kBrowseButtonWidth, kControlHeight, L"另存为...", IDC_BROWSE_EVIDENCE));
    y += kRowHeight;
}

// ============================================================================
// 虚拟化 VM 页
// ============================================================================

void MainWindow::BuildVmPage(int tabIndex) {
    using namespace Metrics;
    auto track = [&](HWND h) { TrackControl(tabIndex, h); return h; };
    int y = kPageMarginTop;
    const int x = kPageMarginLeft;

    m_vmEnabledCheck = track(CreateCheckboxControl(
        m_hwnd, x, y, kPageWidth, kControlHeight, L"启用虚拟化保护 [vm].enabled", IDC_VM_ENABLED, true));
    y += kRowHeight + 4;

    track(CreateLabelControl(m_hwnd, x, y, kLabelWidth, kControlHeight, L"strength（1-100）"));
    m_vmStrengthEdit = track(CreateEditControl(
        m_hwnd, kControlX, y, kShortWidth, kControlHeight, NextControlId(), ES_NUMBER));
    y += kRowHeight;

    track(CreateLabelControl(m_hwnd, x, y, kLabelWidth, kControlHeight, L"register_count（16-32）"));
    m_registerCountEdit = track(CreateEditControl(
        m_hwnd, kControlX, y, kShortWidth, kControlHeight, NextControlId(), ES_NUMBER));
    y += kRowHeight;

    track(CreateLabelControl(m_hwnd, x, y, kLabelWidth, kControlHeight,
        L"stack_size（0x4000-0x70000，4K 对齐）"));
    m_stackSizeEdit = track(CreateEditControl(
        m_hwnd, kControlX, y, kShortWidth + 20, kControlHeight, NextControlId(), 0));
    y += kRowHeight + kGroupGap;

    track(CreateSectionHeaderControl(m_hwnd, x, y, kPageWidth, kLabelHeight, L"生成策略开关"));
    y += kRowHeight;
    const int halfWidth = kPageWidth / 2 - 6;
    m_opcodeRandCheck = track(CreateCheckboxControl(
        m_hwnd, x, y, halfWidth, kControlHeight, L"opcode_randomization", NextControlId(), true));
    m_handlerMutationCheck = track(CreateCheckboxControl(
        m_hwnd, x + halfWidth + 12, y, halfWidth, kControlHeight, L"handler_mutation", NextControlId(), true));
    y += kRowHeight;
    m_bytecodeEncryptionCheck = track(CreateCheckboxControl(
        m_hwnd, x, y, halfWidth, kControlHeight, L"bytecode_encryption", NextControlId(), true));
    m_embedJunkCheck = track(CreateCheckboxControl(
        m_hwnd, x + halfWidth + 12, y, halfWidth, kControlHeight, L"embed_junk_handlers", NextControlId(), true));
    y += kRowHeight;
    m_simdBridgeCheck = track(CreateCheckboxControl(
        m_hwnd, x, y, halfWidth, kControlHeight, L"simd_bridge", NextControlId(), true));
    m_x87BridgeCheck = track(CreateCheckboxControl(
        m_hwnd, x + halfWidth + 12, y, halfWidth, kControlHeight, L"x87_bridge", NextControlId(), true));
    y += kRowHeight;
    track(CreateLabelControl(m_hwnd, x, y, kPageWidth, kControlHeight * 2,
        L"提示：生产构建要求 opcode_randomization / handler_mutation / embed_junk_handlers /\r\n"
        L"bytecode_encryption 保持开启，否则会被拒绝（main.cpp: VM_INIT_FAIL）。"));
    y += kControlHeight * 2 + kGroupGap;

    track(CreateLabelControl(m_hwnd, x, y, kLabelWidth, kControlHeight, L"native_body_policy"));
    m_nativeBodyCombo = track(CreateComboControl(
        m_hwnd, kControlX, y, kShortWidth + 60, kControlHeight, NextControlId(), {L"destroy"}, 0, true));
    track(CreateLabelControl(m_hwnd, kControlX + kShortWidth + 70, y, 280, kControlHeight,
        L"当前后端唯一接受的取值"));
    y += kRowHeight;

    track(CreateLabelControl(m_hwnd, x, y, kLabelWidth, kControlHeight, L"x86_call_abi"));
    m_x86AbiCombo = track(CreateComboControl(
        m_hwnd, kControlX, y, kShortWidth + 60, kControlHeight, NextControlId(),
        {L"auto", L"cdecl", L"stdcall", L"fastcall", L"thiscall"}, 0, false));
    track(CreateLabelControl(m_hwnd, kControlX + kShortWidth + 70, y, 280, kControlHeight,
        L"仅影响 x86 (32-bit) 目标"));
    y += kRowHeight + kGroupGap;

    track(CreateSectionHeaderControl(m_hwnd, x, y, kPageWidth, kLabelHeight,
        L"VM Variant Group（函数级 VM 异构 / 分发去中心化）"));
    y += kRowHeight;
    const int thirdWidth = kPageWidth / 3;
    track(CreateLabelControl(m_hwnd, x, y, 46, kControlHeight, L"count"));
    m_variantGroupCountEdit = track(CreateEditControl(
        m_hwnd, x + 48, y, kShortWidth, kControlHeight, NextControlId(), ES_NUMBER));
    track(CreateLabelControl(m_hwnd, x + thirdWidth, y, 40, kControlHeight, L"max"));
    m_variantGroupMaxEdit = track(CreateEditControl(
        m_hwnd, x + thirdWidth + 42, y, kShortWidth, kControlHeight, NextControlId(), ES_NUMBER));
    track(CreateLabelControl(m_hwnd, x + 2 * thirdWidth, y, 150, kControlHeight, L"functions_per_group"));
    m_variantGroupFuncPerGroupEdit = track(CreateEditControl(
        m_hwnd, x + 2 * thirdWidth + 152, y, kShortWidth, kControlHeight, NextControlId(), ES_NUMBER));
    y += kRowHeight;
    track(CreateLabelControl(m_hwnd, x, y, kPageWidth, kControlHeight * 2,
        L"count=0 表示按候选函数数量自适应决定组数；>=1 为显式固定组数。\r\n"
        L"max / functions_per_group 只影响自适应模式（count=0）下的组数计算。"));
    y += kControlHeight * 2 + kGroupGap;

    track(CreateLabelControl(m_hwnd, x, y, kPageWidth, kControlHeight,
        L"target_functions（通配符，每行一个；留空 = 不按名称筛选）"));
    y += kRowHeight;
    m_targetFunctionsEdit = track(CreateMultilineEditControl(m_hwnd, x, y, kPageWidth, 46, NextControlId()));
    y += 46 + 6;

    track(CreateLabelControl(m_hwnd, x, y, kPageWidth, kControlHeight,
        L"target_rvas（十六进制/十进制 RVA，每行一个；留空 = 不按 RVA 筛选）"));
    y += kRowHeight;
    m_targetRvasEdit = track(CreateMultilineEditControl(m_hwnd, x, y, kPageWidth, 46, NextControlId()));
    y += 46;
}

// ============================================================================
// 控制流页
// ============================================================================

void MainWindow::BuildControlFlowPage(int tabIndex) {
    using namespace Metrics;
    auto track = [&](HWND h) { TrackControl(tabIndex, h); return h; };
    int y = kPageMarginTop;
    const int x = kPageMarginLeft;

    track(CreateSectionHeaderControl(m_hwnd, x, y, kPageWidth, kLabelHeight,
        L"控制流平坦化 [control_flow] / [control_flow.flattening]"));
    y += kRowHeight;
    track(CreateLabelControl(m_hwnd, x, y, kPageWidth, kControlHeight * 3,
        L"独立于 VM 的本地控制流保护，有完整的静态链接复验闭环（不是 fail-closed 模块）。\r\n"
        L"目标函数必须满足结构安全条件（CapabilityChecker::IsFunctionCfgSafe），否则整个构建\r\n"
        L"会失败：留空按自动跳过不安全的函数处理，显式指定了就必须每一个都满足条件。"));
    y += kControlHeight * 3 + kGroupGap;

    m_flatteningEnabledCheck = track(CreateCheckboxControl(
        m_hwnd, x, y, kPageWidth, kControlHeight,
        L"启用控制流平坦化（GUI 会让 control_flow.enabled 与此保持一致）", NextControlId(), false));
    y += kRowHeight;

    track(CreateLabelControl(m_hwnd, x, y, kLabelWidth, kControlHeight, L"strength（1-100）"));
    m_flatteningStrengthEdit = track(CreateEditControl(
        m_hwnd, kControlX, y, kShortWidth, kControlHeight, NextControlId(), ES_NUMBER));
    y += kRowHeight + kGroupGap;

    track(CreateLabelControl(m_hwnd, x, y, kPageWidth, kControlHeight,
        L"target_functions（通配符，每行一个；留空 = 所有 CFG 安全的函数）"));
    y += kRowHeight;
    m_flatteningTargetsEdit = track(CreateMultilineEditControl(m_hwnd, x, y, kPageWidth, 50, NextControlId()));
    y += 50 + kGroupGap * 2;

    track(CreateSectionHeaderControl(m_hwnd, x, y, kPageWidth, kLabelHeight,
        L"虚假控制流 [control_flow.bogus] —— 当前不可用"));
    y += kRowHeight;
    track(CreateLabelControl(m_hwnd, x, y, kPageWidth, kControlHeight * 2,
        L"CapabilityChecker 无条件拒绝 bogus.enabled=true（无法证明原函数语义保持，没有生产闭环）。\r\n"
        L"下面按 config/full_example.toml 的真实默认值只读展示，本界面不提供开关。"));
    y += kControlHeight * 2 + 4;
    track(CreateCheckboxControl(m_hwnd, x, y, 150, kControlHeight, L"enabled", NextControlId(), false, false));
    track(CreateLabelControl(m_hwnd, x + 160, y, 60, kControlHeight, L"strength"));
    HWND bogusStrength = track(CreateEditControl(
        m_hwnd, x + 224, y, kShortWidth, kControlHeight, NextControlId(), 0, false));
    SetEditInt(bogusStrength, ControlFlowOptions::kBogusStrength);
    y += kRowHeight;
}

// ============================================================================
// 反调试 / 反Dump 页
// ============================================================================

void MainWindow::BuildAntiDebugDumpPage(int tabIndex) {
    using namespace Metrics;
    auto track = [&](HWND h) { TrackControl(tabIndex, h); return h; };
    int y = kPageMarginTop;
    const int x = kPageMarginLeft;
    const int halfWidth = kPageWidth / 2 - 6;

    track(CreateSectionHeaderControl(m_hwnd, x, y, kPageWidth, kLabelHeight,
        L"反调试 [anti_debug]（CipherShell Plus，尚未实现：勾选后打包会被拒绝）"));
    y += kRowHeight;

    static const wchar_t* const kAntiDebugLabels[8] = {
        L"timing_checks（时序检测）",
        L"hardware_bp_detection（硬件断点检测）",
        L"software_bp_detection（INT3 / 0xCC 扫描）",
        L"memory_integrity（代码完整性校验）",
        L"debugger_window_scan（调试器窗口类名扫描，易被绕过）",
        L"parent_process_check（父进程检测）",
        L"thread_hiding（HideFromDebugger）",
        L"kernel_debugger_check（内核调试器检测）",
    };
    for (int i = 0; i < 8; ++i) {
        const int col = i % 2;
        const int row = i / 2;
        m_antiDebugChecks[i] = track(CreateCheckboxControl(
            m_hwnd, x + col * (halfWidth + 12), y + row * kRowHeight, halfWidth, kControlHeight,
            kAntiDebugLabels[i], NextControlId(), false));
    }
    y += 4 * kRowHeight + kGroupGap;

    track(CreateSectionHeaderControl(m_hwnd, x, y, kPageWidth, kLabelHeight,
        L"反 Dump [anti_dump]（CipherShell Plus，尚未实现：勾选后打包会被拒绝）"));
    y += kRowHeight;
    static const wchar_t* const kAntiDumpLabels[3] = {
        L"erase_pe_header（运行时擦除 PE 头）",
        L"section_permission_guard（动态权限管理）",
        L"nanomite_patches（INT3 Nanomite 技术）",
    };
    for (int i = 0; i < 3; ++i) {
        const int col = i % 2;
        const int row = i / 2;
        m_antiDumpChecks[i] = track(CreateCheckboxControl(
            m_hwnd, x + col * (halfWidth + 12), y + row * kRowHeight, halfWidth, kControlHeight,
            kAntiDumpLabels[i], NextControlId(), false));
    }
    y += 2 * kRowHeight;
}

// ============================================================================
// 性能页
// ============================================================================

void MainWindow::BuildPerformancePage(int tabIndex) {
    using namespace Metrics;
    auto track = [&](HWND h) { TrackControl(tabIndex, h); return h; };
    int y = kPageMarginTop;
    const int x = kPageMarginLeft;

    track(CreateSectionHeaderControl(m_hwnd, x, y, kPageWidth, kLabelHeight, L"性能 [performance]"));
    y += kRowHeight;
    m_autoHotspotCheck = track(CreateCheckboxControl(
        m_hwnd, x, y, kPageWidth, kControlHeight,
        L"auto_hotspot_analysis（自动分析热点函数并降低其保护等级）", NextControlId(), true));
    y += kRowHeight;

    track(CreateLabelControl(m_hwnd, x, y, kLabelWidth, kControlHeight, L"max_vm_overhead_ratio"));
    m_maxOverheadEdit = track(CreateEditControl(
        m_hwnd, kControlX, y, kShortWidth + 20, kControlHeight, NextControlId(), 0));
    track(CreateLabelControl(m_hwnd, kControlX + kShortWidth + 30, y, 420, kControlHeight,
        L"VM 执行最大允许倍率，超过则自动降级"));
    y += kRowHeight;
}

// ============================================================================
// 不可用模块页（只读展示，无可勾选开关）
// ============================================================================

void MainWindow::BuildUnavailablePage(int tabIndex) {
    using namespace Metrics;
    auto track = [&](HWND h) { TrackControl(tabIndex, h); return h; };
    int y = kPageMarginTop;
    const int x = kPageMarginLeft;

    track(CreateLabelControl(m_hwnd, x, y, kPageWidth, kControlHeight * 3,
        L"以下模块目前是 fail-closed：显式启用会被 CapabilityChecker 在任何 PE 改动之前无条件\r\n"
        L"拒绝，本界面不提供可勾选的启用开关。字段与默认值取自 config/full_example.toml 的真实\r\n"
        L"schema，仅供了解现状（勾选框/输入框均已禁用）。"));
    y += kControlHeight * 3 + kGroupGap;

    const AppConfig defaults;  // 默认构造即真实 schema 默认值。

    track(CreateSectionHeaderControl(m_hwnd, x, y, kPageWidth, kLabelHeight, L"[string_encryption]"));
    y += kRowHeight;
    track(CreateLabelControl(m_hwnd, x, y, kPageWidth, kControlHeight,
        L"原因：未认证算法 + 可恢复密钥，没有生产语义闭环"));
    y += kRowHeight;
    track(CreateCheckboxControl(m_hwnd, x, y, 110, kControlHeight, L"enabled", NextControlId(), false, false));
    track(CreateLabelControl(m_hwnd, x + 116, y, 66, kControlHeight, L"strength"));
    HWND stringStrength = track(CreateEditControl(
        m_hwnd, x + 184, y, kShortWidth, kControlHeight, NextControlId(), 0, false));
    SetEditInt(stringStrength, defaults.unavailable.stringEncryption.strength);
    track(CreateLabelControl(m_hwnd, x + 184 + kShortWidth + 12, y, 48, kControlHeight, L"mode"));
    HWND stringMode = track(CreateEditControl(
        m_hwnd, x + 184 + kShortWidth + 64, y, 100, kControlHeight, NextControlId(), 0, false));
    SetEditText(stringMode, Utf8ToWide(defaults.unavailable.stringEncryption.mode));
    y += kRowHeight;
    track(CreateCheckboxControl(m_hwnd, x, y, 90, kControlHeight, L"ascii",
        NextControlId(), defaults.unavailable.stringEncryption.ascii, false));
    track(CreateCheckboxControl(m_hwnd, x + 100, y, 90, kControlHeight, L"utf16",
        NextControlId(), defaults.unavailable.stringEncryption.utf16, false));
    track(CreateCheckboxControl(m_hwnd, x + 200, y, 130, kControlHeight, L"resources",
        NextControlId(), defaults.unavailable.stringEncryption.resources, false));
    track(CreateCheckboxControl(m_hwnd, x + 340, y, 180, kControlHeight, L"clear_after_use",
        NextControlId(), defaults.unavailable.stringEncryption.clearAfterUse, false));
    y += kRowHeight + kGroupGap;

    track(CreateSectionHeaderControl(m_hwnd, x, y, kPageWidth, kLabelHeight, L"[import_protection]"));
    y += kRowHeight;
    track(CreateLabelControl(m_hwnd, x, y, kPageWidth, kControlHeight,
        L"原因：仅追加假导入并保留真实 IAT，未改写 callsite，没有生产语义闭环"));
    y += kRowHeight;
    track(CreateCheckboxControl(m_hwnd, x, y, 110, kControlHeight, L"enabled", NextControlId(), false, false));
    track(CreateLabelControl(m_hwnd, x + 116, y, 66, kControlHeight, L"strength"));
    HWND importStrength = track(CreateEditControl(
        m_hwnd, x + 184, y, kShortWidth, kControlHeight, NextControlId(), 0, false));
    SetEditInt(importStrength, defaults.unavailable.importProtection.strength);
    y += kRowHeight + kGroupGap;

    track(CreateSectionHeaderControl(m_hwnd, x, y, kPageWidth, kLabelHeight, L"[section_encryption]"));
    y += kRowHeight;
    track(CreateLabelControl(m_hwnd, x, y, kPageWidth, kControlHeight,
        L"原因：未认证算法 + 可恢复密钥，没有生产语义闭环"));
    y += kRowHeight;
    track(CreateCheckboxControl(m_hwnd, x, y, 110, kControlHeight, L"enabled", NextControlId(), false, false));
    track(CreateLabelControl(m_hwnd, x + 116, y, 66, kControlHeight, L"strength"));
    HWND sectionStrength = track(CreateEditControl(
        m_hwnd, x + 184, y, kShortWidth, kControlHeight, NextControlId(), 0, false));
    SetEditInt(sectionStrength, defaults.unavailable.sectionEncryption.strength);
    track(CreateLabelControl(m_hwnd, x + 184 + kShortWidth + 12, y, 48, kControlHeight, L"mode"));
    HWND sectionMode = track(CreateEditControl(
        m_hwnd, x + 184 + kShortWidth + 64, y, 100, kControlHeight, NextControlId(), 0, false));
    SetEditText(sectionMode, Utf8ToWide(defaults.unavailable.sectionEncryption.mode));
    y += kRowHeight;
}

// ============================================================================
// 运行页
// ============================================================================

void MainWindow::BuildRunPage(int tabIndex) {
    using namespace Metrics;
    auto track = [&](HWND h) { TrackControl(tabIndex, h); return h; };
    int y = kPageMarginTop;
    const int x = kPageMarginLeft;

    m_summaryLabel = track(CreateLabelControl(m_hwnd, x, y, kPageWidth, kControlHeight * 2, L""));
    y += kControlHeight * 2 + kGroupGap;

    m_startButton = track(CreateButtonControl(m_hwnd, x, y, 120, 28, L"开始保护", IDC_START));
    m_cancelButton = track(CreateButtonControl(m_hwnd, x + 130, y, 110, 28, L"取消", IDC_CANCEL));
    m_openFolderButton = track(CreateButtonControl(
        m_hwnd, x + 250, y, 160, 28, L"打开输出文件夹", IDC_OPEN_OUTPUT_FOLDER));
    ::EnableWindow(m_cancelButton, FALSE);
    ::EnableWindow(m_openFolderButton, FALSE);
    y += 28 + kGroupGap;

    m_statusLabel = track(CreateLabelControl(m_hwnd, x, y, kPageWidth, kControlHeight, L"就绪"));
    y += kRowHeight;

    m_progressBar = track(CreateProgressBarControl(m_hwnd, x, y, kPageWidth, 16));
    y += 16 + kGroupGap;

    track(CreateLabelControl(m_hwnd, x, y, kPageWidth, kLabelHeight,
        L"日志（后端 stdout/stderr 原样转发；后端目前没有细粒度进度回调，不编造分步进度）"));
    y += kRowHeight;

    const int logHeight = (kPageMarginTop + kPageHeight) - y;
    m_logEdit = track(CreateReadOnlyLogControl(m_hwnd, x, y, kPageWidth, (std::max)(logHeight, 120)));
}

// ============================================================================
// 默认值填充
// ============================================================================

void MainWindow::ApplyDefaultsToControls() {
    const AppConfig defaults;

    SetCheckboxChecked(m_stripDebugCheck, defaults.global.stripDebugInfo);
    SetCheckboxChecked(m_stripRichCheck, defaults.global.stripRichHeader);
    SetCheckboxChecked(m_stripTimestampsCheck, defaults.global.stripTimestamps);
    SetCheckboxChecked(m_randomizeSectionsCheck, defaults.global.randomizeSectionNames);
    SetCheckboxChecked(m_verboseCheck, defaults.cli.verbose);
    SetCheckboxChecked(m_evidenceCheck, defaults.cli.exportVmHandlerEvidence);

    SetCheckboxChecked(m_vmEnabledCheck, defaults.vm.enabled);
    SetEditInt(m_vmStrengthEdit, defaults.vm.strength);
    SetEditInt(m_registerCountEdit, defaults.vm.registerCount);
    SetEditHex(m_stackSizeEdit, defaults.vm.stackSize);
    SetCheckboxChecked(m_opcodeRandCheck, defaults.vm.opcodeRandomization);
    SetCheckboxChecked(m_handlerMutationCheck, defaults.vm.handlerMutation);
    SetCheckboxChecked(m_bytecodeEncryptionCheck, defaults.vm.bytecodeEncryption);
    SetCheckboxChecked(m_embedJunkCheck, defaults.vm.embedJunkHandlers);
    SetCheckboxChecked(m_simdBridgeCheck, defaults.vm.simdBridge);
    SetCheckboxChecked(m_x87BridgeCheck, defaults.vm.x87Bridge);
    SetEditInt(m_variantGroupCountEdit, defaults.vm.variantGroupCount);
    SetEditInt(m_variantGroupMaxEdit, defaults.vm.variantGroupMax);
    SetEditInt(m_variantGroupFuncPerGroupEdit, defaults.vm.variantGroupFunctionsPerGroup);

    std::vector<std::wstring> targetFunctions;
    for (const auto& item : defaults.vm.targetFunctions) targetFunctions.push_back(Utf8ToWide(item));
    SetMultilineEntries(m_targetFunctionsEdit, targetFunctions);

    std::vector<std::wstring> targetRvas;
    for (uint32_t rva : defaults.vm.targetRVAs) {
        wchar_t buffer[16];
        swprintf_s(buffer, L"0x%x", rva);
        targetRvas.push_back(buffer);
    }
    SetMultilineEntries(m_targetRvasEdit, targetRvas);

    SetCheckboxChecked(m_flatteningEnabledCheck, defaults.controlFlow.flatteningEnabled);
    SetEditInt(m_flatteningStrengthEdit, defaults.controlFlow.flatteningStrength);
    std::vector<std::wstring> flatteningTargets;
    for (const auto& item : defaults.controlFlow.flatteningTargets) flatteningTargets.push_back(Utf8ToWide(item));
    SetMultilineEntries(m_flatteningTargetsEdit, flatteningTargets);

    const bool antiDebugDefaults[8] = {
        defaults.antiDebug.timingChecks, defaults.antiDebug.hardwareBpDetection,
        defaults.antiDebug.softwareBpDetection, defaults.antiDebug.memoryIntegrity,
        defaults.antiDebug.debuggerWindowScan, defaults.antiDebug.parentProcessCheck,
        defaults.antiDebug.threadHiding, defaults.antiDebug.kernelDebuggerCheck,
    };
    for (int i = 0; i < 8; ++i) SetCheckboxChecked(m_antiDebugChecks[i], antiDebugDefaults[i]);

    const bool antiDumpDefaults[3] = {
        defaults.antiDump.erasePeHeader, defaults.antiDump.sectionPermissionGuard,
        defaults.antiDump.nanomitePatches,
    };
    for (int i = 0; i < 3; ++i) SetCheckboxChecked(m_antiDumpChecks[i], antiDumpDefaults[i]);

    SetCheckboxChecked(m_autoHotspotCheck, defaults.performance.autoHotspotAnalysis);
    SetEditDouble(m_maxOverheadEdit, defaults.performance.maxVmOverheadRatio);
}

// ============================================================================
// 文件选择 / 拖放
// ============================================================================

void MainWindow::OnBrowseInput() {
    std::wstring path;
    if (ShowOpenInputFileDialog(m_hwnd, path)) OnInputFileChosen(path);
}

void MainWindow::OnInputFileChosen(const std::wstring& path) {
    m_inputFilePath = path;
    SetEditText(m_inputPathEdit, path);

    if (!m_outputPathManuallySet) {
        const std::filesystem::path inputPath(path);
        const std::filesystem::path outputPath = inputPath.parent_path() /
            (inputPath.stem().wstring() + L"_protected" + inputPath.extension().wstring());
        m_outputFilePath = outputPath.wstring();
        SetEditText(m_outputPathEdit, m_outputFilePath);
    }
    RefreshSummaryLabel();
}

void MainWindow::OnBrowseOutput() {
    std::wstring defaultFolder;
    std::wstring defaultFileName;
    if (!m_outputFilePath.empty()) {
        const std::filesystem::path current(m_outputFilePath);
        defaultFolder = current.parent_path().wstring();
        defaultFileName = current.filename().wstring();
    } else if (!m_inputFilePath.empty()) {
        const std::filesystem::path input(m_inputFilePath);
        defaultFolder = input.parent_path().wstring();
        defaultFileName = input.stem().wstring() + L"_protected" + input.extension().wstring();
    }

    std::wstring path;
    if (ShowSaveOutputFileDialog(m_hwnd, defaultFolder, defaultFileName, path)) {
        m_outputFilePath = path;
        m_outputPathManuallySet = true;
        SetEditText(m_outputPathEdit, path);
        RefreshSummaryLabel();
    }
}

void MainWindow::OnBrowseEvidence() {
    std::wstring defaultFolder;
    if (!m_outputFilePath.empty()) {
        defaultFolder = std::filesystem::path(m_outputFilePath).parent_path().wstring();
    }
    std::wstring path;
    if (ShowSaveGenericFileDialog(
            m_hwnd, L"选择 VM handler 明文比较证据的保存位置",
            defaultFolder, L"vm_handler_evidence.bin", path)) {
        SetEditText(m_evidencePathEdit, path);
    }
}

void MainWindow::OnBrowseBackend() {
    std::wstring path;
    if (ShowSelectBackendExeDialog(m_hwnd, path)) {
        m_backendExePath = path;
        SetEditText(m_backendPathEdit, path);
    }
}

void MainWindow::RefreshSummaryLabel() {
    std::wstring text = L"输入：" + (m_inputFilePath.empty() ? L"（未选择）" : m_inputFilePath);
    text += L"\r\n输出：" + (m_outputFilePath.empty() ? L"（未选择）" : m_outputFilePath);
    ::SetWindowTextW(m_summaryLabel, text.c_str());
}

void MainWindow::UpdateVmEnabledState() {
    const bool enabled = GetCheckboxChecked(m_vmEnabledCheck);
    if (m_vmTabIndex < 0) return;
    for (HWND hwnd : m_tabControls[static_cast<size_t>(m_vmTabIndex)]) {
        if (hwnd != m_vmEnabledCheck) ::EnableWindow(hwnd, enabled);
    }
}

void MainWindow::UpdateEvidenceEnabledState() {
    const bool enabled = GetCheckboxChecked(m_evidenceCheck);
    ::EnableWindow(m_evidencePathEdit, enabled);
    ::EnableWindow(m_evidenceBrowseButton, enabled);
}

void MainWindow::ResolveDefaultBackendPath() {
    wchar_t selfPath[MAX_PATH];
    const DWORD length = ::GetModuleFileNameW(nullptr, selfPath, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) return;

    const std::filesystem::path candidate =
        std::filesystem::path(selfPath).parent_path() / L"ciphershell.exe";
    std::error_code ec;
    if (std::filesystem::exists(candidate, ec) && !ec) {
        m_backendExePath = candidate.wstring();
        SetEditText(m_backendPathEdit, m_backendExePath);
    } else {
        SetEditText(m_backendPathEdit, L"（未找到，请点击“更改...”手动选择）");
    }
}

// ============================================================================
// 配置收集与校验
// ============================================================================

bool MainWindow::CollectConfig(AppConfig& outConfig, std::wstring& validationError) {
    outConfig = AppConfig{};

    if (m_inputFilePath.empty()) {
        validationError = L"请先选择要加壳的输入文件。";
        return false;
    }
    {
        std::error_code ec;
        if (!std::filesystem::exists(m_inputFilePath, ec) || ec) {
            validationError = L"输入文件不存在，请重新选择。";
            return false;
        }
    }
    if (m_outputFilePath.empty()) {
        validationError = L"请先选择输出文件路径。";
        return false;
    }
    {
        std::error_code inputEc, outputEc;
        const auto inputAbs = std::filesystem::weakly_canonical(m_inputFilePath, inputEc);
        const auto outputAbs = std::filesystem::weakly_canonical(m_outputFilePath, outputEc);
        if (!inputEc && !outputEc && inputAbs == outputAbs) {
            validationError = L"输出文件不能和输入文件是同一个路径。";
            return false;
        }
    }
    if (m_backendExePath.empty()) {
        validationError = L"未找到 ciphershell.exe，请在“基本”页点击“更改...”手动指定。";
        return false;
    }
    {
        std::error_code ec;
        if (!std::filesystem::exists(m_backendExePath, ec) || ec) {
            validationError = L"指定的 ciphershell.exe 路径不存在。";
            return false;
        }
    }

    int level = 4;
    for (int i = 0; i < 5; ++i) {
        if (GetCheckboxChecked(m_levelRadios[i])) { level = i + 1; break; }
    }
    outConfig.cli.protectionLevel = level;
    outConfig.cli.verbose = GetCheckboxChecked(m_verboseCheck);
    outConfig.cli.exportVmHandlerEvidence = GetCheckboxChecked(m_evidenceCheck);
    if (outConfig.cli.exportVmHandlerEvidence) {
        const std::wstring evidencePath = GetEditText(m_evidencePathEdit);
        if (evidencePath.empty()) {
            validationError = L"已勾选导出 VM handler 证据，但还没有选择保存路径。";
            return false;
        }
        std::error_code evidenceEc, outputEc;
        const auto evidenceAbs = std::filesystem::weakly_canonical(evidencePath, evidenceEc);
        const auto outputAbs = std::filesystem::weakly_canonical(m_outputFilePath, outputEc);
        if (!evidenceEc && !outputEc && evidenceAbs == outputAbs) {
            validationError = L"证据文件路径不能和输出文件相同。";
            return false;
        }
        outConfig.cli.vmHandlerEvidencePath = evidencePath;
    }

    outConfig.global.stripDebugInfo = GetCheckboxChecked(m_stripDebugCheck);
    outConfig.global.stripRichHeader = GetCheckboxChecked(m_stripRichCheck);
    outConfig.global.stripTimestamps = GetCheckboxChecked(m_stripTimestampsCheck);
    outConfig.global.randomizeSectionNames = GetCheckboxChecked(m_randomizeSectionsCheck);

    VmOptions& vm = outConfig.vm;
    vm.enabled = GetCheckboxChecked(m_vmEnabledCheck);
    vm.strength = std::clamp(GetEditInt(m_vmStrengthEdit, 90), 1, 100);
    vm.registerCount = GetEditInt(m_registerCountEdit, 24);
    vm.stackSize = GetEditHexOrDecimal(m_stackSizeEdit, 0x20000);
    vm.opcodeRandomization = GetCheckboxChecked(m_opcodeRandCheck);
    vm.handlerMutation = GetCheckboxChecked(m_handlerMutationCheck);
    vm.bytecodeEncryption = GetCheckboxChecked(m_bytecodeEncryptionCheck);
    vm.embedJunkHandlers = GetCheckboxChecked(m_embedJunkCheck);
    vm.simdBridge = GetCheckboxChecked(m_simdBridgeCheck);
    vm.x87Bridge = GetCheckboxChecked(m_x87BridgeCheck);
    vm.nativeBodyPolicy = WideToUtf8(GetComboText(m_nativeBodyCombo));
    {
        const int sel = GetComboSelection(m_x86AbiCombo);
        const bool validSel = sel >= 0 && sel < static_cast<int>(
            sizeof(kX86CallAbiValues) / sizeof(kX86CallAbiValues[0]));
        vm.x86CallAbi = WideToUtf8(validSel ? kX86CallAbiValues[sel] : L"auto");
    }
    vm.variantGroupCount = (std::max)(0, GetEditInt(m_variantGroupCountEdit, 0));
    vm.variantGroupMax = (std::max)(1, GetEditInt(m_variantGroupMaxEdit, 4));
    vm.variantGroupFunctionsPerGroup = (std::max)(1, GetEditInt(m_variantGroupFuncPerGroupEdit, 4));

    vm.targetFunctions.clear();
    for (const auto& item : GetMultilineEntries(m_targetFunctionsEdit)) {
        vm.targetFunctions.push_back(WideToUtf8(item));
    }
    vm.targetRVAs.clear();
    for (const auto& item : GetMultilineEntries(m_targetRvasEdit)) {
        wchar_t* end = nullptr;
        const unsigned long value = wcstoul(item.c_str(), &end, 0);
        if (end != item.c_str() && *end == L'\0' && value != 0) {
            vm.targetRVAs.push_back(static_cast<uint32_t>(value));
        }
    }

    if (vm.enabled) {
        if (vm.registerCount < 16 || vm.registerCount > 32) {
            validationError = L"register_count 必须在 16-32 之间（后端 ValidateVMRegisterMap 的硬性要求）。";
            return false;
        }
        if (vm.stackSize < 0x4000 || vm.stackSize > 0x70000 || (vm.stackSize & 0xFFFu) != 0) {
            validationError = L"stack_size 必须在 0x4000-0x70000 之间，且是 0x1000 的整数倍。";
            return false;
        }
    }

    ControlFlowOptions& cf = outConfig.controlFlow;
    cf.flatteningEnabled = GetCheckboxChecked(m_flatteningEnabledCheck);
    cf.flatteningStrength = std::clamp(GetEditInt(m_flatteningStrengthEdit, 60), 1, 100);
    cf.flatteningTargets.clear();
    for (const auto& item : GetMultilineEntries(m_flatteningTargetsEdit)) {
        cf.flatteningTargets.push_back(WideToUtf8(item));
    }

    AntiDebugOptions& antiDebug = outConfig.antiDebug;
    antiDebug.timingChecks = GetCheckboxChecked(m_antiDebugChecks[0]);
    antiDebug.hardwareBpDetection = GetCheckboxChecked(m_antiDebugChecks[1]);
    antiDebug.softwareBpDetection = GetCheckboxChecked(m_antiDebugChecks[2]);
    antiDebug.memoryIntegrity = GetCheckboxChecked(m_antiDebugChecks[3]);
    antiDebug.debuggerWindowScan = GetCheckboxChecked(m_antiDebugChecks[4]);
    antiDebug.parentProcessCheck = GetCheckboxChecked(m_antiDebugChecks[5]);
    antiDebug.threadHiding = GetCheckboxChecked(m_antiDebugChecks[6]);
    antiDebug.kernelDebuggerCheck = GetCheckboxChecked(m_antiDebugChecks[7]);

    AntiDumpOptions& antiDump = outConfig.antiDump;
    antiDump.erasePeHeader = GetCheckboxChecked(m_antiDumpChecks[0]);
    antiDump.sectionPermissionGuard = GetCheckboxChecked(m_antiDumpChecks[1]);
    antiDump.nanomitePatches = GetCheckboxChecked(m_antiDumpChecks[2]);

    outConfig.performance.autoHotspotAnalysis = GetCheckboxChecked(m_autoHotspotCheck);
    outConfig.performance.maxVmOverheadRatio = (std::max)(0.0, GetEditDouble(m_maxOverheadEdit, 15.0));

    return true;
}

// ============================================================================
// 运行 / 取消
// ============================================================================

void MainWindow::OnStartClicked() {
    if (m_processRunner->IsRunning()) return;

    AppConfig config;
    std::wstring error;
    if (!CollectConfig(config, error)) {
        ::MessageBoxW(m_hwnd, error.c_str(), L"无法开始", MB_OK | MB_ICONWARNING);
        return;
    }

    wchar_t tempDir[MAX_PATH];
    const DWORD tempDirLen = ::GetTempPathW(MAX_PATH, tempDir);
    if (tempDirLen == 0 || tempDirLen > MAX_PATH) {
        ::MessageBoxW(m_hwnd, L"无法定位系统临时目录。", L"无法开始", MB_OK | MB_ICONERROR);
        return;
    }
    wchar_t tempFile[MAX_PATH];
    if (::GetTempFileNameW(tempDir, L"csg", 0, tempFile) == 0) {
        ::MessageBoxW(m_hwnd, L"无法创建临时配置文件。", L"无法开始", MB_OK | MB_ICONERROR);
        return;
    }
    m_tempConfigPath = tempFile;

    std::wstring writeError;
    if (!WriteConfigTomlToFile(config, m_tempConfigPath, writeError)) {
        ::MessageBoxW(m_hwnd, writeError.c_str(), L"无法开始", MB_OK | MB_ICONERROR);
        CleanupTempConfig();
        return;
    }

    RunRequest request;
    request.backendExePath = m_backendExePath;
    request.inputFilePath = m_inputFilePath;
    request.outputFilePath = m_outputFilePath;
    request.tempConfigPath = m_tempConfigPath;
    const std::wstring commandLine = BuildCommandLine(request, config);
    const std::wstring workingDirectory = std::filesystem::path(m_backendExePath).parent_path().wstring();

    ::SetWindowTextW(m_logEdit, L"");
    AppendLogLine(m_logEdit, L"$ " + commandLine);
    SetStatus(L"正在处理，请稍候…", RGB(0, 0, 0));
    SetRunningState(true);
    ::EnableWindow(m_openFolderButton, FALSE);

    std::wstring startError;
    if (!m_processRunner->Start(m_backendExePath, commandLine, workingDirectory, m_hwnd, startError)) {
        SetRunningState(false);
        SetStatus(L"启动失败", RGB(180, 0, 0));
        AppendLogLine(m_logEdit, startError);
        ::MessageBoxW(m_hwnd, startError.c_str(), L"启动失败", MB_OK | MB_ICONERROR);
        CleanupTempConfig();
    }
}

void MainWindow::OnCancelClicked() {
    if (!m_processRunner->IsRunning()) return;
    m_processRunner->Cancel();
    SetStatus(L"正在取消…", RGB(150, 90, 0));
    ::EnableWindow(m_cancelButton, FALSE);
}

void MainWindow::OnOpenOutputFolderClicked() {
    if (m_lastOutputFolder.empty()) return;
    ::ShellExecuteW(m_hwnd, L"open", m_lastOutputFolder.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}

void MainWindow::SetRunningState(bool running) {
    ::EnableWindow(m_startButton, !running);
    ::EnableWindow(m_cancelButton, running);
    ::SendMessageW(m_progressBar, PBM_SETMARQUEE, running ? TRUE : FALSE, running ? 50 : 0);

    // 运行期间锁住除"运行"页以外的所有配置控件；创建顺序固定为
    // 基本(0)/虚拟化(1)/控制流(2)/反调试与反Dump(3)/性能(4)/不可用模块(5)/运行(6)。
    for (int tab = 0; tab <= 5; ++tab) {
        for (HWND hwnd : m_tabControls[static_cast<size_t>(tab)]) ::EnableWindow(hwnd, !running);
    }
    if (!running) {
        // 全部重新使能后，再按"启用开关"重新收紧一次依赖控件，
        // 不能无条件把所有控件都打开。
        UpdateVmEnabledState();
        UpdateEvidenceEnabledState();
    }
}

void MainWindow::SetStatus(const std::wstring& text, COLORREF color) {
    m_statusColor = color;
    ::SetWindowTextW(m_statusLabel, text.c_str());
    ::InvalidateRect(m_statusLabel, nullptr, TRUE);
}

void MainWindow::HandleProcessOutputLine(const std::wstring& line) {
    AppendLogLine(m_logEdit, line);

    // 后端目前没有结构化的分阶段进度回调，main.cpp 只是把 "[1/5] ..." 这样的
    // 阶段说明按行打印到 stdout。这里如实提炼这行原文当状态文案，不编造
    // 百分比或没有对应真实输出的子步骤。
    const size_t start = line.find_first_not_of(L" \t");
    if (start == std::wstring::npos || line[start] != L'[') return;
    const size_t close = line.find(L']', start);
    if (close == std::wstring::npos) return;
    const std::wstring bracket = line.substr(start + 1, close - start - 1);
    const size_t slash = bracket.find(L'/');
    if (slash == std::wstring::npos || slash == 0 || slash + 1 >= bracket.size()) return;
    if (!std::iswdigit(bracket[0]) || !std::iswdigit(bracket[slash + 1])) return;

    SetStatus(L"[" + bracket + L"]" + line.substr(close + 1), RGB(0, 90, 0));
}

void MainWindow::HandleProcessDone(DWORD exitCode) {
    m_processRunner->NotifyFinished();
    SetRunningState(false);

    if (exitCode == 0) {
        SetStatus(L"完成：保护成功（退出码 0）", RGB(0, 120, 0));
        std::error_code ec;
        const auto folder = std::filesystem::path(m_outputFilePath).parent_path();
        if (std::filesystem::exists(folder, ec) && !ec) {
            m_lastOutputFolder = folder.wstring();
            ::EnableWindow(m_openFolderButton, TRUE);
        }
    } else {
        SetStatus(L"失败：退出码 " + std::to_wstring(exitCode) + L"，详情见下方日志", RGB(180, 0, 0));
        ::EnableWindow(m_openFolderButton, FALSE);
    }
    CleanupTempConfig();
}

void MainWindow::CleanupTempConfig() {
    if (m_tempConfigPath.empty()) return;
    std::error_code ec;
    std::filesystem::remove(m_tempConfigPath, ec);
    m_tempConfigPath.clear();
}

} // namespace CipherShellGui
