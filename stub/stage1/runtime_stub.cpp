/**
 * CipherShell 运行时 Stub - 纯 C 实现
 * 无需汇编器，直接编译为 shellcode
 */

#include <windows.h>
#include <intrin.h>

// ============================================================================
// 类型定义
// ============================================================================

typedef HMODULE (WINAPI *pLoadLibraryA)(LPCSTR);
typedef FARPROC (WINAPI *pGetProcAddress)(HMODULE, LPCSTR);
typedef LPVOID  (WINAPI *pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL    (WINAPI *pVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL    (WINAPI *pFlushInstructionCache)(HANDLE, LPCVOID, SIZE_T);

// ============================================================================
// PEB 遍历获取 kernel32 基址
// ============================================================================

static HMODULE GetKernel32Base() {
    // 通过 PEB 获取 kernel32.dll 基址
    PEB* peb = nullptr;
#ifdef _WIN64
    peb = (PEB*)__readgsqword(0x60);
#else
    peb = (PEB*)__readfsdword(0x30);
#endif

    if (!peb || !peb->Ldr) return nullptr;

    // 遍历已加载模块
    PEB_LDR_DATA* ldr = peb->Ldr;
    LIST_ENTRY* head = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY* current = head->Flink;

    while (current != head) {
        // 获取模块基址
        // LDR_DATA_TABLE_ENTRY 结构偏移
        BYTE* entry = (BYTE*)current - sizeof(LIST_ENTRY);  // 回到结构开头
        HMODULE base = *(HMODULE*)(entry + 0x30);  // DllBase 偏移

        // 检查是否是 kernel32 (通过检查 PE 头)
        if (base) {
            IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
            if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)base + dos->e_lfanew);
                if (nt->Signature == IMAGE_NT_SIGNATURE) {
                    // 简单检查：kernel32 通常在低地址
                    if ((uintptr_t)base < 0x10000000) {
                        return base;
                    }
                }
            }
        }

        current = current->Flink;
    }

    return nullptr;
}

// ============================================================================
// 字符串哈希
// ============================================================================

static uint32_t HashString(const char* str) {
    uint32_t hash = 0x35;
    while (*str) {
        char c = *str++;
        if (c >= 'A' && c <= 'Z') c += 32;  // 转小写
        hash = ((hash << 7) | (hash >> 25)) ^ (uint8_t)c;
    }
    return hash;
}

// ============================================================================
// 通过哈希获取函数地址
// ============================================================================

static FARPROC GetFuncByHash(HMODULE module, uint32_t hash) {
    if (!module) return nullptr;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)module;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)module + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    DWORD exportRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportRva == 0) return nullptr;

    IMAGE_EXPORT_DIRECTORY* exports = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)module + exportRva);
    DWORD* functions = (DWORD*)((BYTE*)module + exports->AddressOfFunctions);
    DWORD* names = (DWORD*)((BYTE*)module + exports->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)module + exports->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        const char* name = (const char*)((BYTE*)module + names[i]);
        if (HashString(name) == hash) {
            return (FARPROC)((BYTE*)module + functions[ordinals[i]]);
        }
    }

    return nullptr;
}

// ============================================================================
// 加密数据结构
// ============================================================================

struct EncryptedSection {
    DWORD rva;              // Section RVA
    DWORD size;             // Section 大小
    BYTE  key[32];          // 解密密钥
};

struct StubData {
    DWORD           signature;          // "CS01"
    DWORD           originalEntryPoint; // 原始入口点 RVA
    DWORD           imageBase;          // 映像基址
    DWORD           sectionCount;       // 加密 section 数量
    EncryptedSection sections[16];      // 最多 16 个 section
    DWORD           importRva;          // 导入表 RVA
    DWORD           importSize;         // 导入表大小
};

// ============================================================================
// 滚动密钥解密
// ============================================================================

static void DecryptSection(BYTE* data, DWORD size, const BYTE* key) {
    uint32_t rollingKey = 0;
    for (int i = 0; i < 4; i++) {
        rollingKey |= ((uint32_t)key[i]) << (i * 8);
    }

    for (DWORD i = 0; i < size; i++) {
        uint8_t keyByte = (uint8_t)(rollingKey & 0xFF);
        data[i] ^= keyByte;
        rollingKey = (rollingKey >> 8) | (rollingKey << 24);
        rollingKey ^= (uint32_t)data[i];
    }
}

// ============================================================================
// Stub 入口点
// ============================================================================

extern "C" __declspec(dllexport) DWORD WINAPI StubEntry(LPVOID param) {
    // 获取当前模块基址
    HMODULE selfModule = GetModuleHandle(nullptr);
    if (!selfModule) return 0;

    // 获取 StubData（位于 PE 头的某个位置）
    // 简化：假设 StubData 紧跟在 stub 代码之后
    StubData* stubData = (StubData*)((BYTE*)selfModule + 0x1000);  // 假设偏移

    // 验证签名
    if (stubData->signature != 0x31534343) {  // "CS01"
        return 0;
    }

    // 获取 kernel32 基址
    HMODULE kernel32 = GetKernel32Base();
    if (!kernel32) return 0;

    // 获取必要的 API
    // kernel32!LoadLibraryA = 0xEC0E4E8E
    // kernel32!GetProcAddress = 0x7C0DFCAA
    pLoadLibraryA loadLib = (pLoadLibraryA)GetFuncByHash(kernel32, 0xEC0E4E8E);
    pGetProcAddress getProc = (pGetProcAddress)GetFuncByHash(kernel32, 0x7C0DFCAA);

    if (!loadLib || !getProc) return 0;

    // 解密所有 section
    for (DWORD i = 0; i < stubData->sectionCount && i < 16; i++) {
        EncryptedSection* sec = &stubData->sections[i];
        if (sec->size > 0) {
            BYTE* sectionData = (BYTE*)selfModule + sec->rva;
            
            // 修改内存权限
            DWORD oldProtect;
            VirtualProtect(sectionData, sec->size, PAGE_READWRITE, &oldProtect);
            
            // 解密
            DecryptSection(sectionData, sec->size, sec->key);
            
            // 恢复权限
            VirtualProtect(sectionData, sec->size, oldProtect, &oldProtect);
        }
    }

    // 刷新指令缓存
    FlushInstructionCache(GetCurrentProcess(), nullptr, 0);

    // 跳转到原始入口点
    DWORD originalEntry = stubData->originalEntryPoint;
    if (originalEntry) {
        typedef void (WINAPI *pOriginalEntry)();
        pOriginalEntry entry = (pOriginalEntry)((BYTE*)selfModule + originalEntry);
        entry();
    }

    return 1;
}
