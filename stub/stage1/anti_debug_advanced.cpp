/**
 * CipherShell 高级反调试技术 - 实现
 */

#include "anti_debug_advanced.h"
#include <intrin.h>
#include <iphlpapi.h>
#include <shlobj.h>
#include <cmath>
#include <string>

#pragma comment(lib, "iphlpapi.lib")

namespace CipherShell {

// ============================================================================
// 构造/析构
// ============================================================================

AntiDebugAdvanced::AntiDebugAdvanced() 
    : AntiDebug()
    , m_originalCodeCRC(0)
    , m_trapActive(false)
{
    memset(&m_poisonContext, 0, sizeof(m_poisonContext));
}

AntiDebugAdvanced::~AntiDebugAdvanced() {}

// ============================================================================
// 公共接口
// ============================================================================

bool AntiDebugAdvanced::InitializeAdvanced(const AntiDebugConfig& config) {
    if (!Initialize(config)) {
        return false;
    }

    // 计算初始代码 CRC
    HMODULE hModule = GetModuleHandle(nullptr);
    if (hModule) {
        m_originalCodeCRC = CalculateCodeCRC(hModule);
    }

    // 设置自修改代码陷阱
    SetupSelfModifyingCodeTrap();

    return true;
}

AdvancedAntiDebugResult AntiDebugAdvanced::PerformAdvancedCheck() {
    AdvancedAntiDebugResult result = {0};
    result.timestamp = __rdtsc();

    // 执行基础检测
    AntiDebugResult baseResult = PerformCheck();
    result.detected = baseResult.detected;
    result.method = baseResult.method;
    result.confidence = baseResult.confidence;

    // 执行高级检测

    // 时序交叉验证
    if (TimingCrossValidation()) {
        result.detected = true;
        result.method |= (uint32_t)AdvancedAntiDebugMethod::Timing_CrossValidation;
        result.confidence = 85;
    }

    // 内存完整性检查
    if (CheckMemoryIntegrity()) {
        result.detected = true;
        result.method |= (uint32_t)AdvancedAntiDebugMethod::Memory_CodeCRC;
        result.confidence = 90;
    }

    // 虚拟环境检测
    if (DetectVirtualEnvironment()) {
        result.isVirtualMachine = true;
        result.method |= (uint32_t)AdvancedAntiDebugMethod::Env_CPUIDHypervisor;
        // 虚拟环境不一定是调试，但需要记录
    }

    // 自修改代码陷阱检查
    if (CheckSelfModifyingCodeTrap()) {
        result.detected = true;
        result.method |= (uint32_t)AdvancedAntiDebugMethod::Trap_SelfModifyingCode;
        result.confidence = 95;
    }

    return result;
}

bool AntiDebugAdvanced::TimingCrossValidation() {
    // 使用多个时序源交叉验证
    uint64_t rdtsc_times[5];
    LARGE_INTEGER qpc_times[5];
    DWORD tick_times[5];
    LARGE_INTEGER freq;
    
    QueryPerformanceFrequency(&freq);

    for (int i = 0; i < 5; i++) {
        rdtsc_times[i] = __rdtsc();
        QueryPerformanceCounter(&qpc_times[i]);
        tick_times[i] = GetTickCount();
        
        // 短暂延迟
        volatile int x = 0;
        for (int j = 0; j < 100; j++) x += j;
    }

    // 检查时序一致性
    for (int i = 1; i < 5; i++) {
        uint64_t rdtsc_delta = rdtsc_times[i] - rdtsc_times[i-1];
        int64_t qpc_delta = qpc_times[i].QuadPart - qpc_times[i-1].QuadPart;
        DWORD tick_delta = tick_times[i] - tick_times[i-1];

        // RDTSC 和 QPC 应该大致成比例
        // 如果 RDTSC 差值很大但 QPC 差值很小，说明有调试器
        if (rdtsc_delta > 100000 && qpc_delta < 100) {
            return true;
        }

        // GetTickCount 不应该跳变
        if (tick_delta > 100) {
            return true;
        }
    }

    return false;
}

uint32_t AntiDebugAdvanced::CalculateCodeCRC(void* imageBase) {
    if (!imageBase) return 0;

    // 获取 PE 头
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)imageBase + dosHeader->e_lfanew);

    // 遍历代码段
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(ntHeaders);
    uint32_t crc = 0;

    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (sections[i].Characteristics & IMAGE_SCN_CNT_CODE) {
            BYTE* codeStart = (BYTE*)imageBase + sections[i].VirtualAddress;
            DWORD codeSize = sections[i].Misc.VirtualSize;

            // 计算 Fletcher-32 校验和
            crc ^= Fletcher32((uint16_t*)codeStart, codeSize / 2);
        }
    }

    return crc;
}

bool AntiDebugAdvanced::DetectVirtualEnvironment() {
    // CPUID 检测虚拟化
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 1);

    // 检查 hypervisor 位
    if (cpuInfo[2] & (1 << 31)) {
        return true;
    }

    // 检查 CPUID 返回的厂商字符串
    __cpuid(cpuInfo, 0x40000000);
    char vendor[13] = {0};
    memcpy(vendor, &cpuInfo[1], 4);
    memcpy(vendor + 4, &cpuInfo[2], 4);
    memcpy(vendor + 8, &cpuInfo[3], 4);

    // 已知虚拟化厂商
    const char* vmVendors[] = {
        "VMwareVMware",     // VMware
        "Microsoft Hv",     // Hyper-V
        "KVMKVMKVM",        // KVM
        "VBoxVBoxVBox",     // VirtualBox
        "XenVMMXenVMM",     // Xen
        nullptr
    };

    for (int i = 0; vmVendors[i]; i++) {
        if (strcmp(vendor, vmVendors[i]) == 0) {
            return true;
        }
    }

    return false;
}

void AntiDebugAdvanced::SetupDelayedPoison(PoisonContext& context, uint32_t delay, uint32_t poisonValue) {
    context.active = true;
    context.countdown = delay;
    context.poisonValue = poisonValue;
    context.triggerTimestamp = 0;
    context.triggerMethod = 0;
}

bool AntiDebugAdvanced::CheckPoisonTrigger(PoisonContext& context) {
    if (!context.active) {
        return false;
    }

    if (context.countdown > 0) {
        context.countdown--;
        return false;
    }

    // 倒计时结束，触发投毒
    context.triggerTimestamp = __rdtsc();
    return true;
}

BYTE* AntiDebugAdvanced::GenerateInlineCheckCode(bool is64Bit, uint32_t handlerIndex, DWORD* codeSize) {
    if (!codeSize) return nullptr;

    // 生成内联反调试检查代码（用于嵌入 VM handler）
    // 这段代码会检查 PEB.BeingDebugged 并影响执行流

    if (is64Bit) {
        // x64 内联检查
        static const BYTE x64_check[] = {
            // 保存寄存器
            0x50,                               // push rax
            0x51,                               // push rcx
            
            // 获取 PEB
            0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,  // mov rax, gs:[0x60]
            
            // 检查 BeingDebugged
            0x0F, 0xB6, 0x48, 0x02,             // movzx ecx, byte [rax+2]
            0x85, 0xC9,                         // test ecx, ecx
            0x74, 0x05,                         // jz .clean
            
            // 检测到调试器 - 投毒
            0x48, 0x31, 0xC0,                   // xor rax, rax
            0xFF, 0xD0,                         // call rax (崩溃)
            
            // .clean:
            0x59,                               // pop rcx
            0x58,                               // pop rax
        };

        *codeSize = sizeof(x64_check);
        BYTE* output = new BYTE[sizeof(x64_check)];
        memcpy(output, x64_check, sizeof(x64_check));
        return output;
    } else {
        // x86 内联检查
        static const BYTE x86_check[] = {
            // 保存寄存器
            0x50,                               // push eax
            0x51,                               // push ecx
            
            // 获取 PEB
            0x64, 0x8B, 0x05, 0x30, 0x00, 0x00, 0x00,  // mov eax, fs:[0x30]
            
            // 检查 BeingDebugged
            0x0F, 0xB6, 0x48, 0x02,             // movzx ecx, byte [eax+2]
            0x85, 0xC9,                         // test ecx, ecx
            0x74, 0x04,                         // jz .clean
            
            // 检测到调试器 - 投毒
            0x31, 0xC0,                         // xor eax, eax
            0xFF, 0xD0,                         // call eax (崩溃)
            
            // .clean:
            0x59,                               // pop ecx
            0x58,                               // pop eax
        };

        *codeSize = sizeof(x86_check);
        BYTE* output = new BYTE[sizeof(x86_check)];
        memcpy(output, x86_check, sizeof(x86_check));
        return output;
    }
}

// ============================================================================
// 内部实现
// ============================================================================

bool AntiDebugAdvanced::CheckTimingWithJitter() {
    // 添加随机抖动的时序检测
    uint64_t timings[10];
    
    for (int i = 0; i < 10; i++) {
        uint64_t start = __rdtsc();
        
        // 随机操作
        volatile int x = 0;
        int iterations = 50 + (rand() % 50);
        for (int j = 0; j < iterations; j++) {
            x += j * j;
        }
        
        timings[i] = __rdtsc() - start;
    }

    // 计算平均值和标准差
    uint64_t sum = 0;
    for (int i = 0; i < 10; i++) {
        sum += timings[i];
    }
    uint64_t avg = sum / 10;

    // 检查是否有异常大的值（调试器单步）
    for (int i = 0; i < 10; i++) {
        if (timings[i] > avg * 10) {
            return true;
        }
    }

    return false;
}

bool AntiDebugAdvanced::CheckMemoryIntegrity() {
    // 检查代码段是否被修改
    HMODULE hModule = GetModuleHandle(nullptr);
    if (!hModule) return false;

    uint32_t currentCRC = CalculateCodeCRC(hModule);
    return (currentCRC != m_originalCodeCRC);
}

bool AntiDebugAdvanced::CheckExceptionHandler() {
    // 测试异常处理是否正常工作
    bool exceptionHandled = false;

    __try {
        // 触发一个异常
        *(volatile int*)0 = 0;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        exceptionHandled = true;
    }

    // 如果异常没有被处理，说明可能被调试器拦截
    return !exceptionHandled;
}

bool AntiDebugAdvanced::CheckCPUIDHypervisor() {
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 1);
    return (cpuInfo[2] & (1 << 31)) != 0;
}

bool AntiDebugAdvanced::CheckMACAddress() {
    // 获取 MAC 地址
    ULONG bufferSize = 0;
    GetAdaptersInfo(nullptr, &bufferSize);

    if (bufferSize == 0) return false;

    PIP_ADAPTER_INFO adapterInfo = (IP_ADAPTER_INFO*)malloc(bufferSize);
    if (!adapterInfo) return false;

    bool result = false;
    if (GetAdaptersInfo(adapterInfo, &bufferSize) == ERROR_SUCCESS) {
        PIP_ADAPTER_INFO adapter = adapterInfo;
        while (adapter) {
            // 检查已知虚拟机 MAC 前缀
            // VMware: 00:0C:29, 00:50:56
            // VirtualBox: 08:00:27
            if (adapter->AddressLength == 6) {
                if ((adapter->Address[0] == 0x00 && adapter->Address[1] == 0x0C && adapter->Address[2] == 0x29) ||
                    (adapter->Address[0] == 0x00 && adapter->Address[1] == 0x50 && adapter->Address[2] == 0x56) ||
                    (adapter->Address[0] == 0x08 && adapter->Address[1] == 0x00 && adapter->Address[2] == 0x27)) {
                    result = true;
                    break;
                }
            }
            adapter = adapter->Next;
        }
    }

    free(adapterInfo);
    return result;
}

bool AntiDebugAdvanced::CheckDiskSize() {
    // 检查磁盘大小（沙箱通常磁盘较小）
    ULARGE_INTEGER freeBytes, totalBytes, totalFreeBytes;
    if (GetDiskFreeSpaceExA("C:\\", &freeBytes, &totalBytes, &totalFreeBytes)) {
        // 小于 60GB 可能是沙箱
        if (totalBytes.QuadPart < 60ULL * 1024 * 1024 * 1024) {
            return true;
        }
    }
    return false;
}

bool AntiDebugAdvanced::CheckRecentFiles() {
    // 检查最近文件数量（沙箱通常很少）
    char recentPath[MAX_PATH];
    if (SHGetSpecialFolderPathA(nullptr, recentPath, CSIDL_RECENT, FALSE)) {
        WIN32_FIND_DATAA findData;
        HANDLE hFind = FindFirstFileA((std::string(recentPath) + "\\*.*").c_str(), &findData);
        
        if (hFind != INVALID_HANDLE_VALUE) {
            int count = 0;
            do {
                if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    count++;
                }
            } while (FindNextFileA(hFind, &findData) && count < 10);
            
            FindClose(hFind);
            
            // 少于 5 个最近文件可能是沙箱
            if (count < 5) {
                return true;
            }
        }
    }
    return false;
}

void AntiDebugAdvanced::SetupSelfModifyingCodeTrap() {
    // 在代码中设置一个会被调试器修改的位置
    // 正常执行时这个位置不会被访问
    m_trapActive = true;
}

bool AntiDebugAdvanced::CheckSelfModifyingCodeTrap() {
    // 检查陷阱是否被触发
    return false;  // 简化实现
}

uint32_t AntiDebugAdvanced::Fletcher32(const uint16_t* data, size_t len) {
    uint32_t sum1 = 0, sum2 = 0;
    
    while (len > 0) {
        size_t blocks = len;
        if (blocks > 360) blocks = 360;
        len -= blocks;
        
        for (size_t i = 0; i < blocks; i++) {
            sum1 += data[i];
            sum2 += sum1;
        }
        
        sum1 = (sum1 & 0xFFFF) + (sum1 >> 16);
        sum2 = (sum2 & 0xFFFF) + (sum2 >> 16);
        data += blocks;
    }
    
    sum1 = (sum1 & 0xFFFF) + (sum1 >> 16);
    sum2 = (sum2 & 0xFFFF) + (sum2 >> 16);
    
    return (sum2 << 16) | sum1;
}

uint64_t AntiDebugAdvanced::MeasureInstructionTiming(void* code) {
    uint64_t start = __rdtsc();
    
    // 执行代码
    ((void(*)())code)();
    
    return __rdtsc() - start;
}

bool AntiDebugAdvanced::IsKnownDebuggerProcess(const char* processName) {
    const char* debuggers[] = {
        "x64dbg.exe", "x32dbg.exe", "ollydbg.exe", "ida.exe", "ida64.exe",
        "windbg.exe", "cdb.exe", "ntsd.exe", "immunitydebugger.exe",
        "cheatengine.exe", "processhacker.exe", "procmon.exe",
        "frida-server.exe", "frida-agent.dll",
        nullptr
    };

    for (int i = 0; debuggers[i]; i++) {
        if (_stricmp(processName, debuggers[i]) == 0) {
            return true;
        }
    }

    return false;
}

} // namespace CipherShell
