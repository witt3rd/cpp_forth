segment .text
print:
        sub     rsp, 40
        lea     rsi, [rsp + 31]
        mov     byte [rsp + 31], 10
        mov     ecx, 1
        mov     r8, -3689348814741910323
.L1:
        mov     rax, rdi
        mul     r8
        shr     rdx, 3
        lea     eax, [rdx + rdx]
        lea     r9d, [rax + 4*rax]
        mov     eax, edi
        sub     eax, r9d
        or      al, 48
        mov     byte [rsi - 1], al
        add     rsi, -1
        add     rcx, 1
        cmp     rdi, 9
        mov     rdi, rdx
        ja      .L1
        mov     edi, 1
        mov     rdx, rcx
        mov     rax, 1
        syscall
        add     rsp, 40
        ret
global _start
_start:
addr_0:
    ;; -- push int --
    push 3
addr_1:
    ;; -- while --
addr_2:
    ;; -- dup --
    pop rax
    push rax
    push rax
addr_3:
    ;; -- push int --
    push 10
addr_4:
    ;; -- lt --
    mov rcx, 0
    mov rdx, 1
    pop rbx
    pop rax
    cmp rax, rbx
    cmovl rcx, rdx
    push rcx
addr_5:
    ;; -- do --
    pop rax
    test rax, rax
    jz addr_11
addr_6:
    ;; -- dup --
    pop rax
    push rax
    push rax
addr_7:
    ;; -- print --
    pop rdi
    call print
addr_8:
    ;; -- push int --
    push 1
addr_9:
    ;; -- plus --
    pop rbx
    pop rax
    add rax, rbx
    push rax
addr_10:
    ;; -- end --
    jmp addr_1
addr_11:
    ;; -- drop --
    pop rax
addr_12:
    ;; -- exit --
    mov rax, 60
    mov rdi, 0
    syscall
;; ---
segment .data
segment .bss
mem: resb 655360
