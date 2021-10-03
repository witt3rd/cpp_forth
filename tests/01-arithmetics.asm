segment .text
dump:
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
    ;; -- push %d --
    push 34
addr_1:
    ;; -- push %d --
    push 35
addr_2:
    ;; -- plus --
    pop rbx
    pop rax
    add rax, rbx
    push rax
addr_3:
    ;; -- dump --
    pop rdi
    call dump
addr_4:
    ;; -- push %d --
    push 500
addr_5:
    ;; -- push %d --
    push 80
addr_6:
    ;; -- minus --
    pop rbx
    pop rax
    sub rax, rbx
    push rax
addr_7:
    ;; -- dump --
    pop rdi
    call dump
addr_8:
    ;; -- push %d --
    push 10
addr_9:
    ;; -- push %d --
    push 20
addr_10:
    ;; -- plus --
    pop rbx
    pop rax
    add rax, rbx
    push rax
addr_11:
    ;; -- dump --
    pop rdi
    call dump
addr_12:
    ;; -- push %d --
    push 10
addr_13:
    ;; -- push %d --
    push 20
addr_14:
    ;; -- equal --
    mov rcx, 0
    mov rdx, 1
    pop rbx
    pop rax
    cmp rax, rbx
    cmove rcx, rdx
    push rcx
addr_15:
    ;; -- dump --
    pop rdi
    call dump
addr_16:
    ;; -- push %d --
    push 4
addr_17:
    ;; -- push %d --
    push 3
addr_18:
    ;; -- gt --
    mov rcx, 0
    mov rdx, 1
    pop rbx
    pop rax
    cmp rax, rbx
    cmovg rcx, rdx
    push rcx
addr_19:
    ;; -- dump --
    pop rdi
    call dump
addr_20:
    ;; -- push %d --
    push 3
addr_21:
    ;; -- push %d --
    push 4
addr_22:
    ;; -- lt --
    mov rcx, 0
    mov rdx, 1
    pop rbx
    pop rax
    cmp rax, rbx
    cmovl rcx, rdx
    push rcx
addr_23:
    ;; -- dump --
    pop rdi
    call dump
    ;; -- exit --
    mov rax, 60
    mov rdi, 0
    syscall
