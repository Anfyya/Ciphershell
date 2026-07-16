// Sample target for tests/scripts/vm_per_build_similarity_gate.py.
//
// This is a DLL, not an EXE, specifically so the functions below are
// discoverable as VM candidates via the PE export table rather than via
// AddressOfEntryPoint. A plain console EXE's entry point is CRT startup
// code (e.g. __scrt_common_main_seh), not main() itself; recursive
// disassembly starting there can hit control flow FunctionDiscovery
// correctly refuses to trust (see the "no trusted function boundaries
// were discovered" / "branch target is not a decoded instruction
// boundary" failure this sample was introduced to work around), and on
// x86 there is no .pdata table to independently recover function
// boundaries the way there is on x64. Exporting these functions gives
// FunctionDiscovery an independent, reliable root that does not depend on
// successfully disassembling CRT startup code at all.
#include <windows.h>

extern "C" __declspec(dllexport) __declspec(noinline) int add(int a, int b) {
    return a + b;
}

extern "C" __declspec(dllexport) __declspec(noinline) int sub2(int a, int b) {
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

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID) {
    return TRUE;
}
