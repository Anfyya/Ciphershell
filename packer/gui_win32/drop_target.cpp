#include "drop_target.h"

#include <shellapi.h>

namespace CipherShellGui {
namespace {

bool DataObjectHasSingleFile(IDataObject* dataObject, std::wstring* outPath) {
    FORMATETC formatEtc{
        CF_HDROP, nullptr, DVASPECT_CONTENT, -1, TYMED_HGLOBAL};
    if (dataObject->QueryGetData(&formatEtc) != S_OK) return false;

    if (!outPath) return true;  // 只是探测格式，不需要真的取数据。

    STGMEDIUM medium{};
    if (dataObject->GetData(&formatEtc, &medium) != S_OK) return false;

    bool ok = false;
    HDROP hDrop = static_cast<HDROP>(medium.hGlobal);
    const UINT fileCount = ::DragQueryFileW(hDrop, 0xFFFFFFFFu, nullptr, 0);
    if (fileCount == 1) {
        wchar_t path[MAX_PATH];
        if (::DragQueryFileW(hDrop, 0, path, ARRAYSIZE(path)) > 0) {
            *outPath = path;
            ok = true;
        }
    }
    ::ReleaseStgMedium(&medium);
    return ok;
}

} // namespace

InputFileDropTarget::InputFileDropTarget(
    std::function<void(const std::wstring&)> onFileDropped,
    std::function<void(bool)> onDragHover)
    : m_onFileDropped(std::move(onFileDropped)),
      m_onDragHover(std::move(onDragHover)) {}

HRESULT __stdcall InputFileDropTarget::QueryInterface(REFIID riid, void** ppvObject) {
    if (!ppvObject) return E_POINTER;
    if (riid == IID_IUnknown || riid == IID_IDropTarget) {
        *ppvObject = static_cast<IDropTarget*>(this);
        AddRef();
        return S_OK;
    }
    *ppvObject = nullptr;
    return E_NOINTERFACE;
}

ULONG __stdcall InputFileDropTarget::AddRef() {
    return static_cast<ULONG>(::InterlockedIncrement(&m_refCount));
}

ULONG __stdcall InputFileDropTarget::Release() {
    const LONG remaining = ::InterlockedDecrement(&m_refCount);
    if (remaining == 0) delete this;
    return static_cast<ULONG>(remaining);
}

void InputFileDropTarget::ApplyCachedEffect(DWORD* effect) const {
    *effect = m_acceptableDrag ? DROPEFFECT_COPY : DROPEFFECT_NONE;
}

HRESULT __stdcall InputFileDropTarget::DragEnter(
    IDataObject* dataObject, DWORD /*keyState*/, POINTL /*point*/, DWORD* effect)
{
    m_acceptableDrag = dataObject && DataObjectHasSingleFile(dataObject, nullptr);
    ApplyCachedEffect(effect);
    if (m_onDragHover) m_onDragHover(m_acceptableDrag);
    return S_OK;
}

HRESULT __stdcall InputFileDropTarget::DragOver(
    DWORD /*keyState*/, POINTL /*point*/, DWORD* effect)
{
    ApplyCachedEffect(effect);
    return S_OK;
}

HRESULT __stdcall InputFileDropTarget::DragLeave() {
    m_acceptableDrag = false;
    if (m_onDragHover) m_onDragHover(false);
    return S_OK;
}

HRESULT __stdcall InputFileDropTarget::Drop(
    IDataObject* dataObject, DWORD /*keyState*/, POINTL /*point*/, DWORD* effect)
{
    std::wstring path;
    const bool accepted = dataObject && DataObjectHasSingleFile(dataObject, &path);
    if (accepted && m_onFileDropped) m_onFileDropped(path);

    m_acceptableDrag = false;
    if (m_onDragHover) m_onDragHover(false);

    *effect = accepted ? DROPEFFECT_COPY : DROPEFFECT_NONE;
    return S_OK;
}

} // namespace CipherShellGui
