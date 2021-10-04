#include "command.hpp"
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fmt/core.h>
#include <fmt/format.h>
#include <fstream>
#include <ios>
#include <iostream>
#include <iterator>
#include <map>
#include <string>
#include <string_view>
#include <vector>

bool is_debug = false;

static const auto MEM_CAPACITY = 640 * 1024;

#define STACK_T int64_t// simulated stack
#define MEM_T char     // simulated memory
#define ADDR_T int64_t // virtual addresses (cross-refs)

enum class op_t {
    // Stack
    PUSH,
    DUP,
    DUP2,
    DROP,
    DUMP,
    // Arithmetic
    PLUS,
    MINUS,
    EQUAL,
    GT,
    LT,
    // Bitwise
    SHR,
    SHL,
    BOR,
    BAND,
    // Conditional
    IF,
    ELSE,
    END,
    // Loop
    WHILE,
    DO,
    // Memory
    MEM,
    LOAD,
    STORE,
    // System
    SYSCALL1,
    SYSCALL2,
    SYSCALL3,
    SYSCALL4,
    SYSCALL5,
    SYSCALL6
};

std::map<op_t, std::string> op_t_names{
        // Stack
        {op_t::PUSH, "PUSH"},
        {op_t::DUP, "DUP"},
        {op_t::DUP2, "2DUP"},
        {op_t::DROP, "DROP"},
        {op_t::DUMP, "DUMP"},
        // Arithmetic
        {op_t::PLUS, "PLUS"},
        {op_t::MINUS, "MINUS"},
        {op_t::EQUAL, "EQUAL"},
        {op_t::GT, "GT"},
        {op_t::LT, "LT"},
        // Bitwise
        {op_t::SHR, "SHR"},
        {op_t::SHL, "SHL"},
        {op_t::BOR, "BOR"},
        {op_t::BAND, "BAND"},
        // Conditional
        {op_t::IF, "IF"},
        {op_t::ELSE, "ELSE"},
        {op_t::END, "END"},
        // Loop
        {op_t::WHILE, "WHILE"},
        {op_t::DO, "DO"},
        // Memory
        {op_t::MEM, "MEM"},
        {op_t::LOAD, "LOAD"},
        {op_t::STORE, "STORE"},
        // System
        {op_t::SYSCALL1, "SYSCALL1"},
        {op_t::SYSCALL2, "SYSCALL2"},
        {op_t::SYSCALL3, "SYSCALL3"},
        {op_t::SYSCALL4, "SYSCALL4"},
        {op_t::SYSCALL5, "SYSCALL5"},
        {op_t::SYSCALL6, "SYSCALL6"}};

struct loc {
    std::string file_path;
    uint64_t row;
    uint64_t col;
};

struct op {
    op_t type;
    loc loc;
    int64_t value{};
    uint64_t jmp{};
};

struct token {
    loc loc;
    std::string word;
};

std::string format_loc(const loc& loc) {
    return fmt::format("{}({:03}:{:03})", loc.file_path, loc.row, loc.col);
}

std::string format_op(const op& o) {
    return fmt::format("type: {}, loc: {}, value: {}, jmp: {}", op_t_names[o.type], format_loc(o.loc), o.value, o.jmp);
}

// Stack
op op_push(loc loc, int64_t value) { return op{.type = op_t::PUSH, .loc = loc, .value = value}; }
op op_dup(loc loc) { return op{.type = op_t::DUP, .loc = loc}; }
op op_dup2(loc loc) { return op{.type = op_t::DUP2, .loc = loc}; }
op op_drop(loc loc) { return op{.type = op_t::DROP, .loc = loc}; }
op op_dump(loc loc) { return op{.type = op_t::DUMP, .loc = loc}; }
// Arithmetic
op op_plus(loc loc) { return op{.type = op_t::PLUS, .loc = loc}; }
op op_minus(loc loc) { return op{.type = op_t::MINUS, .loc = loc}; }
op op_equal(loc loc) { return op{.type = op_t::EQUAL, .loc = loc}; }
op op_gt(loc loc) { return op{.type = op_t::GT, .loc = loc}; }
op op_lt(loc loc) { return op{.type = op_t::LT, .loc = loc}; }
// Bitwise
op op_shr(loc loc) { return op{.type = op_t::SHR, .loc = loc}; }
op op_shl(loc loc) { return op{.type = op_t::SHL, .loc = loc}; }
op op_bor(loc loc) { return op{.type = op_t::BOR, .loc = loc}; }
op op_band(loc loc) { return op{.type = op_t::BAND, .loc = loc}; }
// Conditional
op op_if(loc loc) { return op{.type = op_t::IF, .loc = loc}; }
op op_else(loc loc) { return op{.type = op_t::ELSE, .loc = loc}; }
op op_end(loc loc) { return op{.type = op_t::END, .loc = loc}; }
// Loop
op op_while(loc loc) { return op{.type = op_t::WHILE, .loc = loc}; }
op op_do(loc loc) { return op{.type = op_t::DO, .loc = loc}; }
// Memory
op op_mem(loc loc) { return op{.type = op_t::MEM, .loc = loc}; }
op op_load(loc loc) { return op{.type = op_t::LOAD, .loc = loc}; }
op op_store(loc loc) { return op{.type = op_t::STORE, .loc = loc}; }
// System
op op_syscall1(loc loc) { return op{.type = op_t::SYSCALL1, .loc = loc}; }
op op_syscall2(loc loc) { return op{.type = op_t::SYSCALL2, .loc = loc}; }
op op_syscall3(loc loc) { return op{.type = op_t::SYSCALL3, .loc = loc}; }
op op_syscall4(loc loc) { return op{.type = op_t::SYSCALL4, .loc = loc}; }
op op_syscall5(loc loc) { return op{.type = op_t::SYSCALL5, .loc = loc}; }
op op_syscall6(loc loc) { return op{.type = op_t::SYSCALL6, .loc = loc}; }

template<typename T>
inline const T pop(std::vector<T>& stack) {
    auto x = stack.back();
    stack.pop_back();
    return x;
}

template<typename T>
inline void push(std::vector<T>& stack, const T x) { stack.push_back(x); }

void simulate(std::vector<op> program) {

    // simulate the stack
    std::vector<STACK_T> stack;

    // simulate memory
    std::vector<MEM_T> mem;
    mem.reserve(MEM_CAPACITY);

    uint64_t ip{0};
    while (ip < program.size()) {
        const op& o{program[ip]};
        if (is_debug) std::cout << fmt::format("[DBG] {:03}[{:03}]: {}", ip, stack.size(), format_op(o)) << std::endl;
        ip++;// increment by default; may get overridden
        switch (o.type) {
            case op_t::PUSH: {// Stack
                if (is_debug) std::cout << fmt::format("[DBG] PUSH {}", o.value) << std::endl;
                push(stack, o.value);
                break;
            }
            case op_t::DUP: {
                auto a = pop(stack);
                if (is_debug) std::cout << fmt::format("[DBG] DUP {}", a) << std::endl;
                push(stack, a);
                push(stack, a);
                break;
            }
            case op_t::DUP2: {
                auto a = pop(stack);
                auto b = pop(stack);
                if (is_debug) std::cout << fmt::format("[DBG] 2DUP {} {}", b, a) << std::endl;
                push(stack, b);
                push(stack, a);
                push(stack, b);
                push(stack, a);
                break;
            }
            case op_t::DROP: {
                auto a = pop(stack);
                break;
            }
            case op_t::DUMP: {
                auto a = pop(stack);
                std::cout << a << std::endl;
                break;
            }
            case op_t::PLUS: {// Arithmetic
                auto b = pop(stack);
                auto a = pop(stack);
                if (is_debug) std::cout << fmt::format("[DBG] {} + {}: {}", a, b, a + b) << std::endl;
                push(stack, a + b);
                break;
            }
            case op_t::MINUS: {
                auto b = pop(stack);
                auto a = pop(stack);
                if (is_debug) std::cout << fmt::format("[DBG] {} - {}: {}", a, b, a - b) << std::endl;
                push(stack, a - b);
                break;
            }
            case op_t::EQUAL: {
                auto b = pop(stack);
                auto a = pop(stack);
                if (is_debug) std::cout << fmt::format("[DBG] {} == {}: {}", a, b, a == b) << std::endl;
                push(stack, static_cast<STACK_T>(a == b));
                break;
            }
            case op_t::GT: {
                auto b = pop(stack);
                auto a = pop(stack);
                if (is_debug) std::cout << fmt::format("[DBG] {} > {}: {}", a, b, a > b) << std::endl;
                push(stack, static_cast<STACK_T>(a > b));
                break;
            }
            case op_t::LT: {
                auto b = pop(stack);
                auto a = pop(stack);
                if (is_debug) std::cout << fmt::format("[DBG] {} < {}: {}", a, b, a < b) << std::endl;
                push(stack, static_cast<STACK_T>(a < b));
                break;
            }
            case op_t::SHR: {// Bitwise
                auto b = pop(stack);
                auto a = pop(stack);
                if (is_debug) std::cout << fmt::format("[DBG] {} >> {}: {}", a, b, a >> b) << std::endl;
                push(stack, a >> b);
                break;
            }
            case op_t::SHL: {
                auto b = pop(stack);
                auto a = pop(stack);
                if (is_debug) std::cout << fmt::format("[DBG] {} << {}: {}", a, b, a << b) << std::endl;
                push(stack, a << b);
                break;
            }
            case op_t::BOR: {
                auto b = pop(stack);
                auto a = pop(stack);
                if (is_debug) std::cout << fmt::format("[DBG] {} | {}: {}", a, b, a | b) << std::endl;
                push(stack, a | b);
                break;
            }
            case op_t::BAND: {
                auto b = pop(stack);
                auto a = pop(stack);
                if (is_debug) std::cout << fmt::format("[DBG] {} & {}: {}", a, b, a & b) << std::endl;
                push(stack, a & b);
                break;
            }
            case op_t::IF: {// Conditional
                auto a = pop(stack);
                if (is_debug) std::cout << fmt::format("[DBG] IF {} ({})", a, a != 0) << std::endl;
                if (a == 0) {
                    // failed the IF condition, jump _past_ the ELSE or END
                    ip = o.jmp;
                }
                break;
            }
            case op_t::ELSE: {
                // when we hit an ELSE (from executing the success branch of an IF), jump to the END
                ip = o.jmp;
                break;
            }
            case op_t::END: {
                // when we hit an END, jump to its saved ip
                ip = o.jmp;
                break;
            }
            case op_t::WHILE: {// Loop
                // do nothing
                break;
            }
            case op_t::DO: {
                auto a = pop(stack);
                if (is_debug) std::cout << fmt::format("[DBG] DO {} ({})", a, a != 0) << std::endl;
                if (a == 0) {
                    // failed the WHILE condition, jump _past_ the END
                    ip = o.jmp;
                }
                break;
            }
            case op_t::MEM: {// Memory
                push(stack, static_cast<STACK_T>(0));
                break;
            }
            case op_t::LOAD: {
                auto addr = pop(stack);
                auto byte = mem[addr];
                push(stack, static_cast<STACK_T>(byte));
                break;
            }
            case op_t::STORE: {
                auto byte = pop(stack);
                auto addr = pop(stack);
                mem[addr] = byte & 0xff;
                break;
            }
            case op_t::SYSCALL1: {// System
                auto syscall_number = pop(stack);
                auto arg0           = pop(stack);
                switch (syscall_number) {
                    case 60: {// exit
                        auto error_code = arg0;
                        std::exit(error_code);
                    }
                    default: {
                        std::cerr << fmt::format("[ERR] Unsupported SYSCALL1: {}", syscall_number) << std::endl;
                        std::exit(1);
                    }
                }
                break;
            }
            case op_t::SYSCALL2: {
                auto syscall_number = pop(stack);
                auto arg0           = pop(stack);
                auto arg1           = pop(stack);
                switch (syscall_number) {
                    default: {
                        std::cerr << fmt::format("[ERR] Unsupported SYSCALL2: {}", syscall_number) << std::endl;
                        std::exit(1);
                    }
                }
                break;
            }
            case op_t::SYSCALL3: {
                auto syscall_number = pop(stack);
                auto arg0           = pop(stack);
                auto arg1           = pop(stack);
                auto arg2           = pop(stack);
                switch (syscall_number) {
                    case 1: {// write
                        auto fd    = arg0;
                        auto buf   = arg1;
                        auto count = arg2;
                        auto begin = mem.begin() + buf;
                        auto end   = mem.begin() + (buf + count);
                        auto s     = std::string_view(begin, end);
                        switch (fd) {
                            case 1: {
                                std::cout << s;
                                break;
                            }
                            case 2: {
                                std::cerr << s;
                                break;
                            }
                            default: {
                                std::cerr << fmt::format("[ERR] Unknown fd {} for write syscall", fd) << std::endl;
                                std::exit(1);
                            }
                        }
                        break;
                    }
                    default: {
                        std::cerr << fmt::format("[ERR] Unsupported SYSCALL3: {}: {} {} {}", syscall_number, arg0, arg2, arg1) << std::endl;
                        std::exit(1);
                    }
                }
                break;
            }
            case op_t::SYSCALL4: {
                auto syscall_number = pop(stack);
                auto arg0           = pop(stack);
                auto arg1           = pop(stack);
                auto arg2           = pop(stack);
                auto arg3           = pop(stack);
                switch (syscall_number) {
                    default: {
                        std::cerr << fmt::format("[ERR] Unsupported SYSCALL4: {}", syscall_number) << std::endl;
                        std::exit(1);
                    }
                }
                break;
            }
            case op_t::SYSCALL5: {
                auto syscall_number = pop(stack);
                auto arg0           = pop(stack);
                auto arg1           = pop(stack);
                auto arg2           = pop(stack);
                auto arg3           = pop(stack);
                auto arg4           = pop(stack);
                switch (syscall_number) {
                    default: {
                        std::cerr << fmt::format("[ERR] Unsupported SYSCALL5: {}", syscall_number) << std::endl;
                        std::exit(1);
                    }
                }
                break;
            }
            case op_t::SYSCALL6: {
                auto syscall_number = pop(stack);
                auto arg0           = pop(stack);
                auto arg1           = pop(stack);
                auto arg2           = pop(stack);
                auto arg3           = pop(stack);
                auto arg4           = pop(stack);
                auto arg5           = pop(stack);
                switch (syscall_number) {
                    default: {
                        std::cerr << fmt::format("[ERR] Unsupported SYSCALL6: {}", syscall_number) << std::endl;
                        std::exit(1);
                    }
                }
                break;
            }
        }
    }
}

void compile(std::vector<op> program, std::string& output_path) {
    std::ofstream output(output_path);
    output << "segment .text" << std::endl;

    output << "dump:" << std::endl;
    output << "        sub     rsp, 40" << std::endl;
    output << "        lea     rsi, [rsp + 31]" << std::endl;
    output << "        mov     byte [rsp + 31], 10" << std::endl;
    output << "        mov     ecx, 1" << std::endl;
    output << "        mov     r8, -3689348814741910323" << std::endl;
    output << ".L1:" << std::endl;
    output << "        mov     rax, rdi" << std::endl;
    output << "        mul     r8" << std::endl;
    output << "        shr     rdx, 3" << std::endl;
    output << "        lea     eax, [rdx + rdx]" << std::endl;
    output << "        lea     r9d, [rax + 4*rax]" << std::endl;
    output << "        mov     eax, edi" << std::endl;
    output << "        sub     eax, r9d" << std::endl;
    output << "        or      al, 48" << std::endl;
    output << "        mov     byte [rsi - 1], al" << std::endl;
    output << "        add     rsi, -1" << std::endl;
    output << "        add     rcx, 1" << std::endl;
    output << "        cmp     rdi, 9" << std::endl;
    output << "        mov     rdi, rdx" << std::endl;
    output << "        ja      .L1" << std::endl;
    output << "        mov     edi, 1" << std::endl;
    output << "        mov     rdx, rcx" << std::endl;
    output << "        mov     rax, 1" << std::endl;
    output << "        syscall" << std::endl;
    output << "        add     rsp, 40" << std::endl;
    output << "        ret" << std::endl;

    output << "global _start" << std::endl;
    output << "_start:" << std::endl;

    ADDR_T ip{0};
    while (ip < program.size()) {
        const op& o{program[ip]};
        if (is_debug) std::cout << fmt::format("[DBG] ip={}, op={}", ip, format_op(o)) << std::endl;
        output << "addr_" << ip << ":" << std::endl;
        switch (o.type) {
            case op_t::PUSH: {// Stack
                output << "    ;; -- push %d --" << std::endl;
                output << "    push " << o.value << std::endl;
                break;
            }
            case op_t::DUP: {
                output << "    ;; -- dup --" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    push rax" << std::endl;
                output << "    push rax" << std::endl;
                break;
            }
            case op_t::DUP2: {
                output << "    ;; -- dup2 --" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    pop rbx" << std::endl;
                output << "    push rbx" << std::endl;
                output << "    push rax" << std::endl;
                output << "    push rbx" << std::endl;
                output << "    push rax" << std::endl;
                break;
            }
            case op_t::DROP: {
                output << "    ;; -- drop --" << std::endl;
                output << "    pop rax" << std::endl;
                break;
            }
            case op_t::DUMP: {
                output << "    ;; -- dump --" << std::endl;
                output << "    pop rdi" << std::endl;
                output << "    call dump" << std::endl;
                break;
            }
            case op_t::PLUS: {// Arithmetic
                output << "    ;; -- plus --" << std::endl;
                output << "    pop rbx" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    add rax, rbx" << std::endl;
                output << "    push rax" << std::endl;
                break;
            }
            case op_t::MINUS: {
                output << "    ;; -- minus --" << std::endl;
                output << "    pop rbx" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    sub rax, rbx" << std::endl;
                output << "    push rax" << std::endl;
                break;
            }
            case op_t::EQUAL: {
                output << "    ;; -- equal --" << std::endl;
                output << "    mov rcx, 0" << std::endl;
                output << "    mov rdx, 1" << std::endl;
                output << "    pop rbx" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    cmp rax, rbx" << std::endl;
                output << "    cmove rcx, rdx" << std::endl;
                output << "    push rcx" << std::endl;
                break;
            }
            case op_t::GT: {
                output << "    ;; -- gt --" << std::endl;
                output << "    mov rcx, 0" << std::endl;
                output << "    mov rdx, 1" << std::endl;
                output << "    pop rbx" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    cmp rax, rbx" << std::endl;
                output << "    cmovg rcx, rdx" << std::endl;
                output << "    push rcx" << std::endl;
                break;
            }
            case op_t::LT: {
                output << "    ;; -- lt --" << std::endl;
                output << "    mov rcx, 0" << std::endl;
                output << "    mov rdx, 1" << std::endl;
                output << "    pop rbx" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    cmp rax, rbx" << std::endl;
                output << "    cmovl rcx, rdx" << std::endl;
                output << "    push rcx" << std::endl;
                break;
            }
            case op_t::SHR: {// Bitwise
                output << "    ;; -- shr --" << std::endl;
                output << "    pop rcx" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    shr rax, cl" << std::endl;
                output << "    push rax" << std::endl;
                break;
            }
            case op_t::SHL: {
                output << "    ;; -- shl --" << std::endl;
                output << "    pop rcx" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    shl rax, cl" << std::endl;
                output << "    push rax" << std::endl;
                break;
            }
            case op_t::BOR: {
                output << "    ;; -- bor --" << std::endl;
                output << "    pop rbx" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    or rax, rbx" << std::endl;
                output << "    push rax" << std::endl;
                break;
            }
            case op_t::BAND: {
                output << "    ;; -- band --" << std::endl;
                output << "    pop rbx" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    and rax, rbx" << std::endl;
                output << "    push rax" << std::endl;
                break;
            }
            case op_t::IF: {// Conditional
                output << "    ;; -- if --" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    test rax, rax" << std::endl;
                output << "    jz addr_" << o.jmp << std::endl;
                break;
            }
            case op_t::ELSE: {
                output << "    ;; -- else --" << std::endl;
                output << "    jmp addr_" << o.jmp << std::endl;
                break;
            }
            case op_t::END: {
                output << "    ;; -- end --" << std::endl;
                if (is_debug) std::cout << fmt::format("[DBG] %END: ip={}, arg={}", ip, format_op(o)) << std::endl;
                if (ip + 1 != o.jmp) {
                    output << "    jmp addr_" << o.jmp << std::endl;
                }
                break;
            }
            case op_t::WHILE: {// Loop
                output << "    ;; -- while --" << std::endl;
                break;
            }
            case op_t::DO: {
                output << "    ;; -- do --" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    test rax, rax" << std::endl;
                output << "    jz addr_" << o.jmp << std::endl;
                break;
            }
            case op_t::MEM: {// Memory
                output << "    ;; -- mem --" << std::endl;
                output << "    push mem" << std::endl;
                break;
            }
            case op_t::LOAD: {
                output << "    ;; -- load --" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    xor rbx, rbx" << std::endl;
                output << "    mov bl, [rax]" << std::endl;
                output << "    push rbx" << std::endl;
                break;
            }
            case op_t::STORE: {
                output << "    ;; -- store --" << std::endl;
                output << "    pop rbx" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    mov [rax], bl" << std::endl;
                break;
            }
            case op_t::SYSCALL1: {// System
                output << "    ;; -- syscall1 --" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    pop rdi" << std::endl;
                output << "    syscall" << std::endl;
                break;
            }
            case op_t::SYSCALL2: {
                output << "    ;; -- syscall2 --" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    pop rdi" << std::endl;
                output << "    pop rsi" << std::endl;
                output << "    syscall" << std::endl;
                break;
            }
            case op_t::SYSCALL3: {
                output << "    ;; -- syscall3 --" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    pop rdi" << std::endl;
                output << "    pop rsi" << std::endl;
                output << "    pop rdx" << std::endl;
                output << "    syscall" << std::endl;
                break;
            }
            case op_t::SYSCALL4: {
                output << "    ;; -- syscall4 --" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    pop rdi" << std::endl;
                output << "    pop rsi" << std::endl;
                output << "    pop rdx" << std::endl;
                output << "    pop r10" << std::endl;
                output << "    syscall" << std::endl;
                break;
            }
            case op_t::SYSCALL5: {
                output << "    ;; -- syscall5 --" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    pop rdi" << std::endl;
                output << "    pop rsi" << std::endl;
                output << "    pop rdx" << std::endl;
                output << "    pop r10" << std::endl;
                output << "    pop r8" << std::endl;
                output << "    syscall" << std::endl;
                break;
            }
            case op_t::SYSCALL6: {
                output << "    ;; -- syscall5 --" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    pop rdi" << std::endl;
                output << "    pop rsi" << std::endl;
                output << "    pop rdx" << std::endl;
                output << "    pop r10" << std::endl;
                output << "    pop r8" << std::endl;
                output << "    pop r9" << std::endl;
                output << "    syscall" << std::endl;
                break;
            }
        }
        ip++;
    }

    // program exit
    output << "addr_" << ip << ":" << std::endl;
    output << "    ;; -- exit --" << std::endl;
    output << "    mov rax, 60" << std::endl;
    output << "    mov rdi, 0" << std::endl;
    output << "    syscall" << std::endl;

    // unintialized data segment
    output << ";; ---" << std::endl;
    output << "segment .bss" << std::endl;
    output << "mem: resb " << MEM_CAPACITY << std::endl;

    output.close();
}

std::vector<op>& cross_reference(std::vector<op>& program) {
    std::vector<ADDR_T> ip_stack;
    ADDR_T ip{0};
    while (ip < program.size()) {
        op& o{program[ip]};
        switch (o.type) {

            case op_t::IF: {
                push(ip_stack, ip);
                break;
            }
            case op_t::ELSE: {
                auto iff_ip = pop(ip_stack);
                op& iff_op  = program[iff_ip];
                if (is_debug) std::cout << fmt::format("[DBG] ELSE @ {} matched with {} @ {}", ip, op_t_names[iff_op.type], iff_ip) << std::endl;
                iff_op.jmp = ip + 1;// IF will jump to instruction _after_ ELSE when fail
                push(ip_stack, ip); // save the ELSE ip for END
                break;
            }
            case op_t::END: {
                // when we hit an END from:
                // - executing the success branch of an IF with no ELSE -> jump to next instruction
                // - the failure branch of an IF with an ELSE -> jump to next instruction
                // - WHILE loop -> jump back to condition
                auto block_ip = pop(ip_stack);// IF, ELSE, DO, ...
                op& block_op  = program[block_ip];
                if (is_debug) std::cout << fmt::format("[DBG] END @ {} matched with {} @ {}", ip, op_t_names[block_op.type], block_ip) << std::endl;
                if (block_op.type == op_t::IF || block_op.type == op_t::ELSE) {
                    o.jmp        = ip + 1;// Update END to jump to next instruction
                    block_op.jmp = ip;    // jump to this instruction (END)
                } else if (block_op.type == op_t::DO) {
                    o.jmp        = block_op.jmp;// END jumps to WHILE (stored in DO arg)
                    block_op.jmp = ip + 1;      // Update DO to jump _past_ END when fail
                } else {
                    std::cerr << "[ERR] `END` can only close `IF`, `ELSE`, and `DO` blocks for now" << std::endl;
                    std::exit(1);
                }
                break;
            }
            case op_t::WHILE: {
                push(ip_stack, ip);// save the WHILE ip for DO
                break;
            }
            case op_t::DO: {
                auto wile_ip = pop(ip_stack);
                op& wile_op  = program[wile_ip];
                if (is_debug) std::cout << fmt::format("[DBG] DO @ {} matched with {} @ {}", ip, op_t_names[wile_op.type], wile_ip) << std::endl;
                o.jmp = wile_ip;   // record the WHILE ip
                push(ip_stack, ip);// save the DO ip for END
                break;
            }
            default:
                break;
        }
        ip++;
    }

    if (!ip_stack.empty()) {
        std::cerr << "[ERR] Cross reference stack is non-empty (e.g., unmatched if/else/end)" << std::endl;
        std::exit(1);
    }

    return program;
}

[[noreturn]] void token_error(const token& tok, const std::string& msg) {
    std::cout << fmt::format("[ERR] {} '{}': {}", format_loc(tok.loc), tok.word, msg) << std::endl;
    std::exit(1);
}

op parse_token_as_op(const token& tok) {
    std::string kw = tok.word;
    std::transform(kw.begin(), kw.end(), kw.begin(), ::toupper);

    // Stack
    if (kw.compare("DUP") == 0) return op_dup(tok.loc);
    if (kw.compare("2DUP") == 0) return op_dup2(tok.loc);
    if (kw.compare("DROP") == 0) return op_drop(tok.loc);
    if (kw.compare("DUMP") == 0) return op_dump(tok.loc);
    // Arithmetic
    if (kw.compare("+") == 0) return op_plus(tok.loc);
    if (kw.compare("-") == 0) return op_minus(tok.loc);
    if (kw.compare("=") == 0) return op_equal(tok.loc);
    if (kw.compare(">") == 0) return op_gt(tok.loc);
    if (kw.compare("<") == 0) return op_lt(tok.loc);
    // Bitwise
    if (kw.compare("SHR") == 0) return op_shr(tok.loc);
    if (kw.compare("SHL") == 0) return op_shl(tok.loc);
    if (kw.compare("BOR") == 0) return op_bor(tok.loc);
    if (kw.compare("BAND") == 0) return op_band(tok.loc);
    // Conditional
    if (kw.compare("IF") == 0) return op_if(tok.loc);
    if (kw.compare("ELSE") == 0) return op_else(tok.loc);
    if (kw.compare("END") == 0) return op_end(tok.loc);
    // Loop
    if (kw.compare("WHILE") == 0) return op_while(tok.loc);
    if (kw.compare("DO") == 0) return op_do(tok.loc);
    // Memory
    if (kw.compare("MEM") == 0) return op_mem(tok.loc);
    if (kw.compare(",") == 0) return op_load(tok.loc);
    if (kw.compare(".") == 0) return op_store(tok.loc);
    // System
    if (kw.compare("SYSCALL1") == 0) return op_syscall1(tok.loc);
    if (kw.compare("SYSCALL2") == 0) return op_syscall2(tok.loc);
    if (kw.compare("SYSCALL3") == 0) return op_syscall3(tok.loc);
    if (kw.compare("SYSCALL4") == 0) return op_syscall4(tok.loc);
    if (kw.compare("SYSCALL5") == 0) return op_syscall5(tok.loc);
    if (kw.compare("SYSCALL6") == 0) return op_syscall6(tok.loc);

    // Default stack push
    try {
        auto value = std::stoll(tok.word);
        return op_push(tok.loc, value);
    } catch (const std::invalid_argument& e) {
        token_error(tok, "Invalid numeric value");
    } catch (const std::out_of_range& e) {
        token_error(tok, "Numeric value out of range");
    }
}

std::vector<token> lex_line(const std::string& file_path, const std::string& line, const uint64_t row) {
    std::vector<token> tokens;
    uint64_t col{0};
    bool is_word{false};
    std::string cur_word;
    uint64_t cur_word_col{};

    // remove comment (if any)
    auto no_comment = line.substr(0, line.find("//"));

    for (auto c : no_comment) {
        if (std::isspace(c)) {
            if (is_word) {
                token tok{loc{file_path, row, cur_word_col}, cur_word};
                tokens.push_back(tok);
                is_word = false;
                cur_word.clear();
            }
        } else {
            if (is_word) {
                cur_word += c;
            } else {
                cur_word     = c;
                cur_word_col = col;
                is_word      = true;
            }
        }
        col++;
    }
    if (is_word) {
        token tok{loc{file_path, row, cur_word_col}, cur_word};
        tokens.push_back(tok);
    }
    return tokens;
}

std::vector<token> lex_file(const std::string& file_path) {
    std::ifstream f(file_path);
    if (!f.is_open()) {
        std::cerr << "[ERR] Unable to open input file" << std::endl;
        std::exit(1);
    }

    std::vector<token> tokens;
    std::string line;
    uint64_t row{0};

    while (std::getline(f, line)) {
        auto line_tokens = lex_line(file_path, line, row);
        tokens.insert(tokens.cend(), line_tokens.cbegin(), line_tokens.cend());
        row++;
    }

    f.close();

    return tokens;
}

std::vector<op> load_program_from_file(const std::string& file_path) {

    auto tokens{lex_file(file_path)};

    std::vector<op> program;
    program.reserve(tokens.size());
    for (auto& tok : tokens) {
        if (is_debug) std::cout << fmt::format("[DBG] {}: {}", format_loc(tok.loc), tok.word) << std::endl;
        program.push_back(parse_token_as_op(tok));
    }

    return cross_reference(program);
}

[[noreturn]] void usage(const std::string_view& compiler_name) {
    std::cout << fmt::format("Usage: {} [OPTIONS] <SUBCOMMAND> [ARGS]", compiler_name) << std::endl;
    std::cout << "  OPTIONS:" << std::endl;
    std::cout << "    -debug                Enable debug mode." << std::endl;
    //std::cout << "    -I <path>             Add the path to the include search list" << std::endl;
    //std::cout << fmt::format("    -E <expansion-limit>  Macro and include expansion limit. (Default {})", DEFAULT_EXPANSION_LIMIT) << std::endl;
    //std::cout << "    -unsafe               Disable type checking." << std::endl;
    std::cout << "  SUBCOMMAND:" << std::endl;
    std::cout << "    sim <file>            Simulate the program" << std::endl;
    std::cout << "    com [OPTIONS] <file>  Compile the program" << std::endl;
    std::cout << "      OPTIONS:" << std::endl;
    std::cout << "        -r                  Run the program after successful compilation" << std::endl;
    //std::cout << "        -o <file|dir>       Customize the output path" << std::endl;
    //std::cout << "        -s                  Silent mode. Don't print any info about compilation phases." << std::endl;
    //std::cout << "    help                  Print this help to stdout and exit with 0 code" << std::endl;
    std::exit(1);
}

int main(int argc, char** argv) {

    auto cur_arg{0};
    const std::string compiler_name{argv[cur_arg++]};

    // options
    while (cur_arg < argc) {
        const std::string arg = argv[cur_arg];
        if (arg == "-debug") {
            is_debug = true;
            std::cout << "[DBG] Debug enabled" << std::endl;
            cur_arg++;
        } else if (arg.starts_with("-")) {
            std::cerr << fmt::format("[ERR] Unknown option: {}", arg) << std::endl;
            usage(compiler_name);
        } else {
            break;
        }
    }

    if (argc <= cur_arg) {
        std::cerr << "[ERR] Missing subcommand" << std::endl;
        usage(compiler_name);
    }

    const std::string subcommand{argv[cur_arg++]};

    if (subcommand == "sim") {
        if (argc <= cur_arg) {
            std::cerr << "[ERR] Missing input file path for simulation" << std::endl;
            usage(compiler_name);
        }
        const std::string input_file_path{argv[cur_arg++]};

        const std::vector<op> input_program = load_program_from_file(std::string{input_file_path});
        simulate(input_program);

    } else if (subcommand == "com") {
        // options
        auto is_run{false};
        while (cur_arg < argc) {
            const std::string arg = argv[cur_arg];
            if (arg == "-r") {
                is_run = true;
                if (is_debug) std::cout << "[DBG] Run enabled" << std::endl;
                cur_arg++;
            } else if (arg.starts_with("-")) {
                std::cerr << fmt::format("[ERR] Unknown option: {}", arg) << std::endl;
                usage(compiler_name);
            } else {
                break;
            }
        }

        if (argc <= cur_arg) {
            std::cerr << "[ERR] Missing input file path for compilation" << std::endl;
            usage(compiler_name);
        }
        const std::string input_file_path{argv[cur_arg++]};

        const std::vector<op> input_program = load_program_from_file(std::string{input_file_path});
        std::filesystem::path p(input_file_path);
        p.replace_extension("");
        auto output_file_path{p.string()};
        // assemble
        auto assembler_file_path = fmt::format("{}.asm", output_file_path);
        compile(input_program, assembler_file_path);
        auto assembler_command = fmt::format("nasm -felf64 {}", assembler_file_path);
        std::cout << fmt::format("[CMD] {}", assembler_command) << std::endl;
        auto res = raymii::Command::exec(assembler_command);
        if (res.exitstatus != 0) {
            std::cerr << fmt::format("[ERR] nasm exited with {}: {}", res.exitstatus, res.output) << std::endl;
            return res.exitstatus;
        }

        // link
        auto assembler_output_file_path = fmt::format("{}.o", output_file_path);
        auto linker_command             = fmt::format("ld -o {} {}", output_file_path, assembler_output_file_path);
        std::cout << fmt::format("[CMD] {}", linker_command) << std::endl;
        res = raymii::Command::exec(linker_command);
        if (res.exitstatus != 0) {
            std::cerr << fmt::format("[ERR] ld exited with {}: {}", res.exitstatus, res.output) << std::endl;
            return res.exitstatus;
        }

        // run
        if (is_run) {
            auto run_command = fmt::format("{}", output_file_path);// TODO: args
            std::cout << fmt::format("[CMD] {}", run_command) << std::endl;
            res = raymii::Command::exec(run_command);
            if (res.exitstatus != 0) {
                std::cerr << fmt::format("[ERR] program exited with {}: {}", res.exitstatus, res.output) << std::endl;
                return res.exitstatus;
            }
            std::cout << res.output;
        }
    } else {
        std::cerr << fmt::format("[ERR] Unknown subcommand: {}", subcommand) << std::endl;
        usage(compiler_name);
    }

    return 0;
}
