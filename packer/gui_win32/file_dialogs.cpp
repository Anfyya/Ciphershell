#include "file_dialogs.h"

#include <objbase.h>
#include <shlobj.h>
#include <shobjidl.h>

namespace CipherShellGui {
namespace {

// IFileOpenDialog/IFileSaveDialog 都实现 IFileDialog，公共设置（标题、
// 默认目录、初始文件名）走这一份共用逻辑。
void ApplyCommonSettings(
    IFileDialog* dialog,
    const std::wstring& title,
    const std::wstring& defaultFolder,
    const std::wstring& defaultFileName)
{
    if (!title.empty()) {
        dialog->SetTitle(title.c_str());
    }
    if (!defaultFileName.empty()) {
        dialog->SetFileName(defaultFileName.c_str());
    }
    if (!defaultFolder.empty()) {
        IShellItem* folderItem = nullptr;
        if (SUCCEEDED(::SHCreateItemFromParsingName(
                defaultFolder.c_str(), nullptr, IID_PPV_ARGS(&folderItem)))) {
            dialog->SetFolder(folderItem);
            folderItem->Release();
        }
    }
}

bool GetResultPath(IFileDialog* dialog, std::wstring& outPath) {
    IShellItem* item = nullptr;
    if (FAILED(dialog->GetResult(&item)) || !item) return false;

    bool ok = false;
    PWSTR path = nullptr;
    if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &path)) && path) {
        outPath = path;
        ::CoTaskMemFree(path);
        ok = true;
    }
    item->Release();
    return ok;
}

bool ShowOpenDialog(
    HWND owner,
    const std::wstring& title,
    const COMDLG_FILTERSPEC* filters,
    UINT filterCount,
    DWORD extraOptions,
    std::wstring& outPath)
{
    IFileOpenDialog* dialog = nullptr;
    HRESULT hr = ::CoCreateInstance(
        CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER,
        IID_PPV_ARGS(&dialog));
    if (FAILED(hr) || !dialog) return false;

    ApplyCommonSettings(dialog, title, std::wstring(), std::wstring());
    if (filters && filterCount) {
        dialog->SetFileTypes(filterCount, filters);
        dialog->SetFileTypeIndex(1);
    }

    DWORD options = 0;
    dialog->GetOptions(&options);
    dialog->SetOptions(options | FOS_FILEMUSTEXIST | FOS_PATHMUSTEXIST | extraOptions);

    bool ok = false;
    hr = dialog->Show(owner);
    if (SUCCEEDED(hr)) {
        ok = GetResultPath(dialog, outPath);
    }
    dialog->Release();
    return ok;
}

} // namespace

bool ShowOpenInputFileDialog(HWND owner, std::wstring& outPath) {
    static const COMDLG_FILTERSPEC kFilters[] = {
        {L"可执行文件 / 动态库 (*.exe;*.dll)", L"*.exe;*.dll"},
        {L"所有文件 (*.*)", L"*.*"},
    };
    return ShowOpenDialog(
        owner, L"选择要加壳的可执行文件", kFilters, ARRAYSIZE(kFilters), 0, outPath);
}

bool ShowSelectBackendExeDialog(HWND owner, std::wstring& outPath) {
    static const COMDLG_FILTERSPEC kFilters[] = {
        {L"ciphershell.exe", L"ciphershell.exe"},
        {L"可执行文件 (*.exe)", L"*.exe"},
    };
    return ShowOpenDialog(
        owner, L"定位 ciphershell.exe（命令行加壳后端）",
        kFilters, ARRAYSIZE(kFilters), 0, outPath);
}

bool ShowSaveOutputFileDialog(
    HWND owner,
    const std::wstring& defaultFolder,
    const std::wstring& defaultFileName,
    std::wstring& outPath)
{
    static const COMDLG_FILTERSPEC kFilters[] = {
        {L"可执行文件 / 动态库 (*.exe;*.dll)", L"*.exe;*.dll"},
        {L"所有文件 (*.*)", L"*.*"},
    };

    IFileSaveDialog* dialog = nullptr;
    HRESULT hr = ::CoCreateInstance(
        CLSID_FileSaveDialog, nullptr, CLSCTX_INPROC_SERVER,
        IID_PPV_ARGS(&dialog));
    if (FAILED(hr) || !dialog) return false;

    ApplyCommonSettings(dialog, L"选择保护后输出文件的位置", defaultFolder, defaultFileName);
    dialog->SetFileTypes(ARRAYSIZE(kFilters), kFilters);
    dialog->SetFileTypeIndex(1);

    DWORD options = 0;
    dialog->GetOptions(&options);
    dialog->SetOptions(options | FOS_OVERWRITEPROMPT | FOS_PATHMUSTEXIST | FOS_NOREADONLYRETURN);

    bool ok = false;
    hr = dialog->Show(owner);
    if (SUCCEEDED(hr)) {
        ok = GetResultPath(dialog, outPath);
    }
    dialog->Release();
    return ok;
}

bool ShowSaveGenericFileDialog(
    HWND owner,
    const std::wstring& title,
    const std::wstring& defaultFolder,
    const std::wstring& defaultFileName,
    std::wstring& outPath)
{
    IFileSaveDialog* dialog = nullptr;
    HRESULT hr = ::CoCreateInstance(
        CLSID_FileSaveDialog, nullptr, CLSCTX_INPROC_SERVER,
        IID_PPV_ARGS(&dialog));
    if (FAILED(hr) || !dialog) return false;

    ApplyCommonSettings(dialog, title, defaultFolder, defaultFileName);

    DWORD options = 0;
    dialog->GetOptions(&options);
    dialog->SetOptions(options | FOS_OVERWRITEPROMPT | FOS_PATHMUSTEXIST | FOS_NOREADONLYRETURN);

    bool ok = false;
    hr = dialog->Show(owner);
    if (SUCCEEDED(hr)) {
        ok = GetResultPath(dialog, outPath);
    }
    dialog->Release();
    return ok;
}

} // namespace CipherShellGui
