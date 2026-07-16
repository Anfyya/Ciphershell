// Sample target for tests/scripts/vm_per_build_similarity_gate.py.
//
// This real MSVC DLL and the companion EXE export the same eight noinline
// targets. Stable export roots let the gate prove the identical functions in
// both PE containers instead of conflating CRT entry discovery with the VM
// runtime correctness and per-build diversity properties under test.
#include <windows.h>

static int g_relocated_value = 0x13579BDF;

#if defined(_M_IX86)
// Keep the fixed public export contract while making the real Win32 target a
// genuine callee-cleanup function.  Do not add dllexport to the decorated
// implementation: that would leak a ninth `_sub2@8` export beside `sub2`.
#pragma comment(linker, "/EXPORT:sub2=_sub2@8")
#define VM_SUB2_EXPORT
#define VM_SUB2_ABI __stdcall
#else
#define VM_SUB2_EXPORT __declspec(dllexport)
#define VM_SUB2_ABI
#endif

extern "C" __declspec(dllexport) __declspec(noinline) int add(int a, int b) {
    return a + b;
}

extern "C" VM_SUB2_EXPORT __declspec(noinline) int VM_SUB2_ABI sub2(
    int a, int b) {
    return a - b;
}

extern "C" __declspec(dllexport) __declspec(noinline) int max2(int a, int b) {
    if (a > b) return a;
    return b;
}

extern "C" __declspec(dllexport) __declspec(noinline) int is_zero(int a) {
    if (a == 0) return 1;
    return 0;
}

extern "C" __declspec(dllexport) __declspec(noinline) int local1(int a) {
    int x = a + 3;
    return x;
}

// PE32 emits a HIGHLOW relocation for both the absolute immediate returned
// here and the absolute memory operand in relocated_read. These exports keep
// the per-build gate on a real MSVC PE while proving that VM bytecode rebases
// image addresses and that the destroyed native fields are removed from the
// final relocation directory.
extern "C" __declspec(dllexport) __declspec(noinline) int* relocated_ptr() {
    return &g_relocated_value;
}

extern "C" __declspec(dllexport) __declspec(noinline) int relocated_read() {
    return g_relocated_value;
}

extern "C" __declspec(dllexport) __declspec(noinline) int relocated_write(int value) {
    const int previous = g_relocated_value;
    g_relocated_value = value;
    return previous;
}

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID) {
    return TRUE;
}
