/**
 * CipherShell 反调试系统 - 实现
 */

#include "anti_debug.h"
#include <intrin.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <cstring>

#pragma comment(lib, "ntdll.lib")

namespace CipherShell {

// ============================================================================
// NT API 声明
// ============================================================================

extern "C" NTSTATUS NTAPI NtQueryInformationProcess(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

// ============================================================================
// 构造/析构
// ============================================================================

AntiDebug::AntiDebug() 
    : m_initialized(false)
    , m_lastCheckTime(0)
    , m_detectionCount(0) 
{
    memset(&m_config, 0, sizeof(m_config));
}

AntiDebug::~AntiDebug() {}

// ============================================================================
// 公共接口
// ============================================================================

bool AntiDebug::Initialize(const AntiDebugConfig& config) {
    m_config = config;
    m_initialized = true;

    // 应用主动对抗
    if (config.enabledMethods & (uint32_t)AntiDebugMethod::Active_ThreadHide) {
        HideCurrentThread();
    }

    return true;
}

AntiDebugResult AntiDebug::PerformCheck() {
    AntiDebugResult result = {0};
    result.timestamp = GetTimestamp();

    if (!m_initialized) {
        return result;
    }

    // 时序检测
    if (m_config.enabledMethods & (uint32_t)AntiDebugMethod::Timing_RDTSC) {
        if (CheckTimingRDTSC()) {
            result.detected = true;
            result.method = (uint32_t)AntiDebugMethod::Timing_RDTSC;
            result.confidence = 70;
        }
    }

    if (m_config.enabledMethods & (uint32_t)AntiDebugMethod::Timing_QPC) {
        if (CheckTimingQPC()) {
            result.detected = true;
            result.method |= (uint32_t)AntiDebugMethod::Timing_QPC;
            result.confidence = 75;
        }
    }

    // PEB 检测
    if (m_config.enabledMethods & (uint32_t)AntiDebugMethod::State_PEB_BeingDebugged) {
        if (CheckPEBBeingDebugged()) {
            result.detected = true;
            result.method |= (uint32_t)AntiDebugMethod::State_PEB_BeingDebugged;
            result.confidence = 95;
        }
    }

    if (m_config.enabledMethods & (uint32_t)AntiDebugMethod::State_PEB_NtGlobalFlag) {
        if (CheckPEBNtGlobalFlag()) {
            result.detected = true;
            result.method |= (uint32_t)AntiDebugMethod::State_PEB_NtGlobalFlag;
            result.confidence = 90;
        }
    }

    // 硬件断点检测
    if (m_config.enabledMethods & (uint32_t)AntiDebugMethod::State_HardwareBP) {
        if (CheckHardwareBreakpoints()) {
            result.detected = true;
            result.method |= (uint32_t)AntiDebugMethod::State_HardwareBP;
            result.confidence = 85;
        }
    }

    // 内核调试器检测
    if (m_config.enabledMethods & (uint32_t)AntiDebugMethod::State_KdDebugger) {
        if (CheckKdDebugger()) {
            result.detected = true;
            result.method |= (uint32_t)AntiDebugMethod::State_KdDebugger;
            result.confidence = 99;
        }
    }

    // 父进程检测
    if (m_config.enabledMethods & (uint32_t)AntiDebugMethod::Env_ParentProcess) {
        if (CheckParentProcess()) {
            result.detected = true;
            result.method |= (uint32_t)AntiDebugMethod::Env_ParentProcess;
            result.confidence = 80;
        }
    }

    // 调试器窗口检测
    if (m_config.enabledMethods & (uint32_t)AntiDebugMethod::Env_DebuggerWindow) {
        if (CheckDebuggerWindows()) {
            result.detected = true;
            result.method |= (uint32_t)AntiDebugMethod::Env_DebuggerWindow;
            result.confidence = 90;
        }
    }

    // 异常链验证
    if (m_config.enabledMethods & (uint32_t)AntiDebugMethod::Active_ExceptionChain) {
        if (!ValidateExceptionChain()) {
            result.detected = true;
            result.method |= (uint32_t)AntiDebugMethod::Active_ExceptionChain;
            result.confidence = 60;
        }
    }

    if (result.detected) {
        m_detectionCount++;
    }

    return result;
}

AntiDebugResult AntiDebug::CheckMethod(AntiDebugMethod method) {
    AntiDebugResult result = {0};
    result.timestamp = GetTimestamp();

    switch (method) {
        case AntiDebugMethod::Timing_RDTSC:
            result.detected = CheckTimingRDTSC();
            break;
        case AntiDebugMethod::Timing_QPC:
            result.detected = CheckTimingQPC();
            break;
        case AntiDebugMethod::State_PEB_BeingDebugged:
            result.detected = CheckPEBBeingDebugged();
            break;
        case AntiDebugMethod::State_PEB_NtGlobalFlag:
            result.detected = CheckPEBNtGlobalFlag();
            break;
        case AntiDebugMethod::State_HardwareBP:
            result.detected = CheckHardwareBreakpoints();
            break;
        case AntiDebugMethod::State_KdDebugger:
            result.detected = CheckKdDebugger();
            break;
        case AntiDebugMethod::Env_ParentProcess:
            result.detected = CheckParentProcess();
            break;
        case AntiDebugMethod::Env_DebuggerWindow:
            result.detected = CheckDebuggerWindows();
            break;
        default:
            break;
    }

    result.method = (uint32_t)method;
    return result;
}

void AntiDebug::ApplyImplicitResponse(const AntiDebugResult& result, void* vmContext) {
    if (!result.detected || !m_config.implicitResponse || !vmContext) {
        return;
    }

    // 隐式响应：投毒 — 污染解密密钥和执行状态
    // 不立即退出，让程序在不确定时间点产生错误行为

    // vmContext 布局约定（与 stub 运行时一致）：
    //   offset 0x00: uint8_t  decryptKey[32]
    //   offset 0x20: uint32_t poisonCountdown
    //   offset 0x24: uint32_t poisonFlags

    uint8_t* ctx = reinterpret_cast<uint8_t*>(vmContext);

    // 1. 密钥投毒 — 用检测方法做 XOR 扩散，逐字节破坏密钥
    uint32_t poison = result.method ^ 0xDEADBEEF;
    for (int i = 0; i < 32; i++) {
        poison = (poison << 7) | (poison >> 25);  // ROL 7
        poison ^= (uint32_t)ctx[i];
        ctx[i] ^= (uint8_t)(poison & 0xFF);
    }

    // 2. 设置延迟倒计时（在若干条指令后才体现异常）
    uint32_t* countdown = reinterpret_cast<uint32_t*>(ctx + 0x20);
    uint32_t* flags     = reinterpret_cast<uint32_t*>(ctx + 0x24);
    if (*countdown == 0) {
        *countdown = 500 + (result.method & 0x1FF);  // 500~1011 步延迟
    }
    *flags |= result.method;  // 累积检测标志

    m_detectionCount++;
}

// ============================================================================
// 时序检测实现
// ============================================================================

bool AntiDebug::CheckTimingRDTSC() {
    uint64_t start = __rdtsc();

    volatile int x = 0;
    for (int i = 0; i < 100; i++) {
        x += i;
    }

    uint64_t end = __rdtsc();
    uint64_t elapsed = end - start;

    return (elapsed > 100000);
}

bool AntiDebug::CheckTimingQPC() {
    LARGE_INTEGER start, end, freq;
    QueryPerformanceFrequency(&freq);

    QueryPerformanceCounter(&start);

    // 执行一些操作
    volatile int x = 0;
    for (int i = 0; i < 1000; i++) {
        x += i;
    }

    QueryPerformanceCounter(&end);

    // 计算耗时（微秒）
    int64_t elapsed_us = (end.QuadPart - start.QuadPart) * 1000000 / freq.QuadPart;

    // 正常应该 < 1000 微秒
    return (elapsed_us > 10000);
}

bool AntiDebug::CheckTimingGetTickCount() {
    DWORD start = GetTickCount();

    // 执行一些操作
    volatile int x = 0;
    for (int i = 0; i < 10000; i++) {
        x += i;
    }

    DWORD end = GetTickCount();

    // 正常应该 < 10ms
    return ((end - start) > 100);
}

// ============================================================================
// 状态检测实现
// ============================================================================

bool AntiDebug::CheckPEBBeingDebugged() {
    void* peb = GetPEB();
    if (!peb) return false;

    return *((BYTE*)peb + 2) != 0;
}

bool AntiDebug::CheckPEBNtGlobalFlag() {
    void* peb = GetPEB();
    if (!peb) return false;

    // NtGlobalFlag 偏移在不同 Windows 版本可能不同
    // 通常在 PEB + 0xBC (x86) 或 PEB + 0x118 (x64)
#ifdef _WIN64
    uint32_t ntGlobalFlag = *(uint32_t*)((BYTE*)peb + 0x118);
#else
    uint32_t ntGlobalFlag = *(uint32_t*)((BYTE*)peb + 0xBC);
#endif

    // FLG_HEAP_ENABLE_TAIL_CHECK (0x10)
    // FLG_HEAP_ENABLE_FREE_CHECK (0x20)
    // FLG_HEAP_VALIDATE_PARAMETERS (0x40)
    const uint32_t debugFlags = 0x10 | 0x20 | 0x40;
    return (ntGlobalFlag & debugFlags) != 0;
}

bool AntiDebug::CheckHeapFlags() {
    void* peb = GetPEB();
    if (!peb) return false;

    HANDLE heap = GetProcessHeap();
    if (!heap) return false;

#ifdef _WIN64
    uint32_t flags = *(uint32_t*)((BYTE*)heap + 0x70);
    uint32_t forceFlags = *(uint32_t*)((BYTE*)heap + 0x74);
#else
    uint32_t flags = *(uint32_t*)((BYTE*)heap + 0x40);
    uint32_t forceFlags = *(uint32_t*)((BYTE*)heap + 0x44);
#endif

    (void)flags;
    return (forceFlags != 0);
}

bool AntiDebug::CheckHardwareBreakpoints() {
    // x86 和 x64 统一使用 GetThreadContext，
    // 因为 Ring3 下直接 mov eax, dr0 会触发 #GP 异常
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        return (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3);
    }
    return false;
}

bool AntiDebug::CheckKdDebugger() {
    // 检查 KUSER_SHARED_DATA
    // 地址 0x7FFE02D4 (x86) 或 0x7FFE0340 (x64) 是 KdDebuggerEnabled
#ifdef _WIN64
    BYTE kdEnabled = *(BYTE*)0x7FFE0340;
#else
    BYTE kdEnabled = *(BYTE*)0x7FFE02D4;
#endif
    return kdEnabled != 0;
}

// ============================================================================
// 完整性检测实现
// ============================================================================

bool AntiDebug::CheckCodeIntegrity() {
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    FARPROC probe = kernel32 ? GetProcAddress(kernel32, "IsDebuggerPresent") : nullptr;
    if (!probe) return false;

    BYTE* funcStart = (BYTE*)probe;
    for (int i = 0; i < 100; i++) {
        if (funcStart[i] == 0xCC) {
            return true;
        }
    }
    return false;
}

bool AntiDebug::CheckAPIIntegrity() {
    // 检查关键 API 是否被 hook
    // 检查函数前几个字节是否是 jmp 指令

    FARPROC func = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    if (!func) return false;

    BYTE* funcBytes = (BYTE*)func;
    // 检查是否是 jmp 指令 (0xE9) 或其他 hook 模式
    if (funcBytes[0] == 0xE9 || funcBytes[0] == 0xEB) {
        return true;  // 被 hook
    }

    // 检查是否是 mov eax, imm32; jmp (常见 hook 模式)
    if (funcBytes[0] == 0xB8 && funcBytes[5] == 0xE9) {
        return true;
    }

    return false;
}

// ============================================================================
// 环境检测实现
// ============================================================================

bool AntiDebug::CheckParentProcess() {
    // 获取父进程 ID
    ULONG_PTR pbi[6] = {0};
    ULONG returnLength = 0;

    NTSTATUS status = NtQueryInformationProcess(
        GetCurrentProcess(),
        (PROCESSINFOCLASS)0,  // ProcessBasicInformation
        &pbi,
        sizeof(pbi),
        &returnLength
    );

    if (status != 0) return false;

    // pbi[5] 是 InheritedFromUniqueProcessId（父进程 ID）
    DWORD parentPid = (DWORD)pbi[5];

    // 获取父进程名称
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32 pe = {0};
    pe.dwSize = sizeof(pe);

    bool found = false;
    if (Process32First(snapshot, &pe)) {
        do {
            if (pe.th32ProcessID == parentPid) {
                // 检查父进程是否是 explorer.exe（正常情况）
                if (_stricmp(pe.szExeFile, "explorer.exe") != 0) {
                    // 检查是否是已知的调试器
                    if (_stricmp(pe.szExeFile, "x64dbg.exe") == 0 ||
                        _stricmp(pe.szExeFile, "ollydbg.exe") == 0 ||
                        _stricmp(pe.szExeFile, "ida.exe") == 0 ||
                        _stricmp(pe.szExeFile, "ida64.exe") == 0 ||
                        _stricmp(pe.szExeFile, "windbg.exe") == 0 ||
                        _stricmp(pe.szExeFile, "devenv.exe") == 0) {
                        found = true;
                    }
                }
                break;
            }
        } while (Process32Next(snapshot, &pe));
    }

    CloseHandle(snapshot);
    return found;
}

bool AntiDebug::CheckDebuggerWindows() {
    // 检查常见调试器窗口
    const char* debuggerWindows[] = {
        "OLLYDBG", "x64dbg", "ImmunityDebugger", "WinDbgFrameClass",
        "IDAPRO", "IDAGridWin", "IDAMainWindow",
        "Qt5QWindowIcon", "Qt6QWindowIcon",
        nullptr
    };

    for (int i = 0; debuggerWindows[i]; i++) {
        if (FindWindowA(debuggerWindows[i], nullptr)) {
            return true;
        }
    }

    return false;
}

bool AntiDebug::CheckInjectedModules() {
    // 扫描已加载模块，查找可疑的 DLL
    const char* suspiciousDLLs[] = {
        "sbiedll.dll",      // Sandboxie
        "dbghelp.dll",      // 调试器
        "frida-agent.dll",  // Frida
        "inject.dll",       // 通用注入
        nullptr
    };

    for (int i = 0; suspiciousDLLs[i]; i++) {
        if (GetModuleHandleA(suspiciousDLLs[i])) {
            return true;
        }
    }

    return false;
}

// ============================================================================
// 主动对抗实现
// ============================================================================

void AntiDebug::HideCurrentThread() {
    // 使用 NtSetInformationThread 隐藏线程
    typedef NTSTATUS(NTAPI* pNtSetInformationThread)(
        HANDLE ThreadHandle,
        THREADINFOCLASS ThreadInformationClass,
        PVOID ThreadInformation,
        ULONG ThreadInformationLength
    );

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return;

    pNtSetInformationThread NtSetInformationThread = 
        (pNtSetInformationThread)GetProcAddress(ntdll, "NtSetInformationThread");

    if (NtSetInformationThread) {
        // ThreadHideFromDebugger = 0x11
        NtSetInformationThread(GetCurrentThread(), (THREADINFOCLASS)0x11, nullptr, 0);
    }
}

bool AntiDebug::ValidateExceptionChain() {
    // 验证 SEH 链是否被篡改
#ifdef _WIN64
    // x64 使用异常表，不使用 SEH 链
    return true;
#else
    // 获取 SEH 链头
    DWORD sehHead;
    __asm {
        mov eax, fs:[0]
        mov sehHead, eax
    }

    // 验证链的完整性
    DWORD* current = (DWORD*)sehHead;
    for (int i = 0; i < 10; i++) {
        if (current == (DWORD*)-1) break;
        if (IsBadReadPtr(current, 8)) return false;
        current = (DWORD*)(*current);
    }

    return true;
#endif
}


// ============================================================================
// 辅助函数
// ============================================================================

void* AntiDebug::GetPEB() {
#ifdef _WIN32
#ifdef _WIN64
    return (void*)__readgsqword(0x60);
#else
    return (void*)__readfsdword(0x30);
#endif
#else
    return nullptr;
#endif
}

uint64_t AntiDebug::GetTimestamp() {
#ifdef _WIN32
    return __rdtsc();
#else
    uint32_t lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
#endif
}

uint32_t AntiDebug::HashFunction(const char* name) {
    uint32_t hash = 0x811C9DC5;  // FNV-1a offset basis
    while (*name) {
        // ROL5 + XOR + FNV
        hash = ((hash << 5) | (hash >> 27));
        hash ^= (uint8_t)(*name);
        hash *= 0x01000193;  // FNV prime
        name++;
    }
    return hash;
}

} // namespace CipherShell
