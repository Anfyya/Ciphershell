#include <intrin.h>

#include <cstdint>

namespace {

volatile int g_fixture_sink = 0;

} // namespace

extern "C" __declspec(noinline) int cs_derived_leaf(int value) {
    return (value * 7) ^ 0x13579BDF;
}

extern "C" __declspec(dllexport) __declspec(noinline)
int cs_plain_leaf(int value) {
    return value + 0x2468;
}

#if defined(_M_IX86)

// This is linked into a normal MSVC PE32 executable.  The reachable CFG jumps
// over nine real bytes in .text and calls a non-exported leaf outside its own
// envelope.  FunctionDiscovery must use the rejected gapped candidate only to
// derive that independent direct-call root; it must never destroy the gap.
extern "C" __declspec(dllexport) __declspec(naked)
int cs_gap_root(int) {
    __asm {
        mov eax, dword ptr [esp + 4]
        push eax
        call cs_derived_leaf
        add esp, 4
        jmp gap_done
        _emit 0xCC
        _emit 0xA5
        _emit 0x5A
        _emit 0xF1
        _emit 0x0F
        _emit 0x0B
        _emit 0xC3
        _emit 0x90
        _emit 0x7F
    gap_done:
        ret
    }
}

#else

extern "C" __declspec(dllexport) __declspec(noinline)
int cs_gap_root(int value) {
    return cs_derived_leaf(value);
}

#endif

// The discovery regression parses this real compiler-emitted function but
// never executes it.  INT3 must terminate recursive descent without treating
// the compiler's epilog/padding as a fallthrough path.
extern "C" __declspec(dllexport) __declspec(noinline)
void cs_int3_boundary() {
    __debugbreak();
}

int main(int argc, char**) {
    g_fixture_sink = cs_plain_leaf(argc);
    return g_fixture_sink == 0x7FFFFFFF ? 1 : 0;
}
