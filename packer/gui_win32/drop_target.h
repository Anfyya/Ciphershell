// CipherShell GUI - 输入文件拖放（现代 COM 拖放：IDropTarget）。
//
// 按既定方案使用 IDropTarget + RegisterDragDrop，不使用旧式的
// DragAcceptFiles/WM_DROPFILES。调用方需要已经用 OleInitialize（不是单纯
// CoInitializeEx）初始化过 OLE——RegisterDragDrop 依赖它。
#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <oleidl.h>

#include <functional>
#include <string>

namespace CipherShellGui {

class InputFileDropTarget : public IDropTarget {
public:
    // onFileDropped：拖入单个文件并松手时回调，参数是文件完整路径。
    // onDragHover：拖拽悬停状态变化时回调（true = 有效拖拽正悬停在窗口上，
    //              false = 离开/结束/无效），用于给拖放区一个视觉反馈。
    InputFileDropTarget(
        std::function<void(const std::wstring&)> onFileDropped,
        std::function<void(bool)> onDragHover);

    // IUnknown/IDropTarget 都没有虚析构函数（COM 生命周期靠 AddRef/Release
    // 管理，不是靠 delete 基类指针）。Release() 里对 this 做的是"删除最终
    // 派生类"，本身是安全的，但类里有虚函数却没有虚析构函数会触发
    // -Wdelete-non-virtual-dtor / MSVC 下 /W4 的等价警告，进而在 /WX 下
    // 变成编译错误，这里显式声明一个虚析构函数堵掉它。
    virtual ~InputFileDropTarget() = default;

    // IUnknown
    HRESULT __stdcall QueryInterface(REFIID riid, void** ppvObject) override;
    ULONG __stdcall AddRef() override;
    ULONG __stdcall Release() override;

    // IDropTarget
    HRESULT __stdcall DragEnter(
        IDataObject* dataObject, DWORD keyState, POINTL point,
        DWORD* effect) override;
    HRESULT __stdcall DragOver(DWORD keyState, POINTL point, DWORD* effect) override;
    HRESULT __stdcall DragLeave() override;
    HRESULT __stdcall Drop(
        IDataObject* dataObject, DWORD keyState, POINTL point,
        DWORD* effect) override;

private:
    void ApplyCachedEffect(DWORD* effect) const;

    LONG m_refCount = 1;
    bool m_acceptableDrag = false;
    std::function<void(const std::wstring&)> m_onFileDropped;
    std::function<void(bool)> m_onDragHover;
};

} // namespace CipherShellGui
