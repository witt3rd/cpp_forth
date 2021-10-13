#include "command.hpp"
#include "lexer.hpp"
#include "parser.hpp"
#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fmt/format.h>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <string>
#include <string_view>
#include <vector>

bool is_debug = false;

static const auto STR_CAPACITY = 640 * 1024;
static const auto MEM_CAPACITY = 640 * 1024;

#define STACK_T int64_t// simulated stack
#define MEM_T char     // simulated memory
#define ADDR_T uint64_t// virtual addresses (cross-refs)

template<typename T>
inline T pop(std::vector<T> &stack) {
    if (stack.empty()) {
        std::cerr << "[ERR] stack underflow" << std::endl;
        std::exit(1);
    }
    auto x = stack.back();
    stack.pop_back();
    return x;
}

template<typename T>
inline void push(std::vector<T> &stack, const T x) { stack.push_back(x); }

template<typename T>
std::ostream &operator<<(std::ostream &out, const std::vector<T> &stack) {
    if (!stack.empty()) {
        out << "[";
        std::ranges::copy(stack, std::ostream_iterator<T>(out, ", "));
        out << "\b\b]";
    } else {
        out << "[]";
    }
    return out;
}

void simulate(std::vector<op> program) {

    if (is_debug) std::cout << "[DBG] ***** begin simulation *****" << std::endl;

    // simulate the stack
    std::vector<STACK_T> stack;

    // simulate memory
    std::vector<MEM_T> mem;
    mem.reserve(STR_CAPACITY + MEM_CAPACITY);
    size_t str_size{0};

    uint64_t ip{0};
    while (ip < program.size()) {
        op &o{program[ip]};
        if (is_debug) std::cout << fmt::format("[DBG] IP={:03} OP={}, STACK=", ip, to_string(o)) << stack << std::endl;
        ip++;// increment by default; may get overridden
        switch (o.type) {
            case op_type::PUSH_INT: {// Stack
                push(stack, o.int_value);
                if (is_debug) std::cout << fmt::format("[DBG] PUSH_INT {}", o.int_value) << std::endl;
                break;
            }
            case op_type::PUSH_STR: {
                auto str_len = o.str_value.size();
                if (o.str_addr == -1) {
                    if (str_size + str_len >= STR_CAPACITY) {
                        std::cerr << "out of string memory" << std::endl;
                        std::exit(1);
                    }
                    o.str_addr = str_size;
                    str_size += str_len;
                    char *str = &mem[o.str_addr];
                    std::strcpy(str, o.str_value.c_str());
                }
                push(stack, (STACK_T) str_len);
                push(stack, (int64_t) o.str_addr);
                if (is_debug) std::cout << fmt::format("[DBG] PUSH_STR {}", o.str_value) << std::endl;
                break;
            }
            case op_type::DUP: {
                auto a = pop(stack);
                push(stack, a);
                push(stack, a);
                if (is_debug) std::cout << fmt::format("[DBG] DUP {}", a) << std::endl;
                break;
            }
            case op_type::DROP: {
                auto a = pop(stack);
                if (is_debug) std::cout << fmt::format("[DBG] DROP {} ", a) << std::endl;
                break;
            }
            case op_type::SWAP: {
                auto a = pop(stack);
                auto b = pop(stack);
                push(stack, a);
                push(stack, b);
                if (is_debug) std::cout << fmt::format("[DBG] SWAP {} {}", a, b) << std::endl;
                break;
            }
            case op_type::OVER: {
                auto a = pop(stack);
                auto b = pop(stack);
                push(stack, b);
                push(stack, a);
                push(stack, b);
                if (is_debug) std::cout << fmt::format("[DBG] OVER {} {}", a, b) << std::endl;
                break;
            }
            case op_type::PRINT: {
                auto a = pop(stack);
                std::cout << a << std::endl;
                if (is_debug) std::cout << fmt::format("[DBG] PRINT {}", a) << std::endl;
                break;
            }
            case op_type::PLUS: {// Arithmetic
                auto b = pop(stack);
                auto a = pop(stack);
                push(stack, a + b);
                if (is_debug) std::cout << fmt::format("[DBG] {} + {} = {}", a, b, a + b) << std::endl;
                break;
            }
            case op_type::MINUS: {
                auto b = pop(stack);
                auto a = pop(stack);
                push(stack, a - b);
                if (is_debug) std::cout << fmt::format("[DBG] {} - {} = {}", a, b, a - b) << std::endl;
                break;
            }
            case op_type::MUL: {
                auto b = pop(stack);
                auto a = pop(stack);
                push(stack, a * b);
                if (is_debug) std::cout << fmt::format("[DBG] {} * {} = {}", a, b, a * b) << std::endl;
                break;
            }
            case op_type::DIVMOD: {
                auto b = pop(stack);
                auto a = pop(stack);
                push(stack, a / b);
                push(stack, a%b);
                if (is_debug) std::cout << fmt::format("[DBG] {} / {} = {}", a, b, a / b) << std::endl;
                if (is_debug) std::cout << fmt::format("[DBG] {} % {} = {}", a, b, a % b) << std::endl;
                break;
            }
            case op_type::EQUAL: {
                auto b = pop(stack);
                auto a = pop(stack);
                push(stack, static_cast<STACK_T>(a == b));
                if (is_debug) std::cout << fmt::format("[DBG] {} == {} = {}", a, b, a == b) << std::endl;
                break;
            }
            case op_type::LT: {
                auto b = pop(stack);
                auto a = pop(stack);
                push(stack, static_cast<STACK_T>(a < b));
                if (is_debug) std::cout << fmt::format("[DBG] {} < {} = {}", a, b, a < b) << std::endl;
                break;
            }
            case op_type::LTE: {
                auto b = pop(stack);
                auto a = pop(stack);
                push(stack, static_cast<STACK_T>(a <= b));
                if (is_debug) std::cout << fmt::format("[DBG] {} <= {} = {}", a, b, a <= b) << std::endl;
                break;
            }
            case op_type::GT: {
                auto b = pop(stack);
                auto a = pop(stack);
                push(stack, static_cast<STACK_T>(a > b));
                if (is_debug) std::cout << fmt::format("[DBG] {} > {} = {}", a, b, a > b) << std::endl;
                break;
            }
            case op_type::GTE: {
                auto b = pop(stack);
                auto a = pop(stack);
                push(stack, static_cast<STACK_T>(a >= b));
                if (is_debug) std::cout << fmt::format("[DBG] {} >= {} = {}", a, b, a >= b) << std::endl;
                break;
            }
            case op_type::SHR: {// Bitwise
                auto b = pop(stack);
                auto a = pop(stack);
                push(stack, a >> b);
                if (is_debug) std::cout << fmt::format("[DBG] {} >> {} = {}", a, b, a >> b) << std::endl;
                break;
            }
            case op_type::SHL: {
                auto b = pop(stack);
                auto a = pop(stack);
                push(stack, a << b);
                if (is_debug) std::cout << fmt::format("[DBG] {} << {} = {}", a, b, a << b) << std::endl;
                break;
            }
            case op_type::BOR: {
                auto b = pop(stack);
                auto a = pop(stack);
                push(stack, a | b);
                if (is_debug) std::cout << fmt::format("[DBG] {} | {} = {}", a, b, a | b) << std::endl;
                break;
            }
            case op_type::BAND: {
                auto b = pop(stack);
                auto a = pop(stack);
                push(stack, a & b);
                if (is_debug) std::cout << fmt::format("[DBG] {} & {} = {}", a, b, a & b) << std::endl;
                break;
            }
            case op_type::IF: {// Conditional
                auto a = pop(stack);
                if (a == 0) ip = o.jmp_addr;
                if (is_debug) std::cout << fmt::format("[DBG] IF {} = {} -> {}", a, a != 0, o.jmp_addr) << std::endl;
                break;
            }
            case op_type::ELSE: {
                // when we hit an ELSE (from executing the success branch of an IF), jump to the END
                ip = o.jmp_addr;
                if (is_debug) std::cout << fmt::format("[DBG] ELSE -> {}", o.jmp_addr) << std::endl;
                break;
            }
            case op_type::END: {
                // when we hit an END, jump to its saved ip
                ip = o.jmp_addr;
                if (is_debug) std::cout << fmt::format("[DBG] END -> {}", o.jmp_addr) << std::endl;
                break;
            }
            case op_type::WHILE: {// Loop
                // do nothing
                if (is_debug) std::cout << fmt::format("[DBG] WHILE") << std::endl;
                break;
            }
            case op_type::DO: {
                auto a = pop(stack);
                if (a == 0) {
                    // failed the WHILE condition, jump _past_ the END
                    ip = o.jmp_addr;
                }
                if (is_debug) std::cout << fmt::format("[DBG] DO {} = {} -> {}", a, a != 0, o.jmp_addr) << std::endl;
                break;
            }
            case op_type::MEM: {// Memory
                push(stack, static_cast<STACK_T>(STR_CAPACITY));
                if (is_debug) std::cout << fmt::format("[DBG] MEM") << std::endl;
                break;
            }
            case op_type::LOAD: {
                auto addr = pop(stack);
                auto byte = mem[addr] & 0xff;
                push(stack, static_cast<STACK_T>(byte));
                if (is_debug) std::cout << fmt::format("[DBG] LOAD MEM[{}] -> {}", addr, byte) << std::endl;
                break;
            }
            case op_type::STORE: {
                auto byte = (uint8_t)pop(stack);
                auto addr = pop(stack);
                mem[addr] = (ADDR_T)(byte & 0xff);
                if (is_debug) std::cout << fmt::format("[DBG] STORE MEM[{}] <- {}", addr, byte & 0xff) << std::endl;
                break;
            }
            case op_type::SYSCALL1: {// System
                auto syscall_number = pop(stack);
                auto arg0           = pop(stack);
                switch (syscall_number) {
                    case 60: {// exit
                        int error_code = (int) arg0;
                        std::exit(error_code);
                    }
                    default: {
                        std::cerr << fmt::format("[ERR] unsupported SYSCALL1: {}({})", syscall_number, arg0) << std::endl;
                        std::exit(1);
                    }
                }
                break;
            }
            case op_type::SYSCALL2: {
                auto syscall_number = pop(stack);
                auto arg0           = pop(stack);
                auto arg1           = pop(stack);
                switch (syscall_number) {
                    default: {
                        std::cerr << fmt::format("[ERR] unsupported SYSCALL2: {}({},{})", syscall_number, arg0, arg1) << std::endl;
                        std::exit(1);
                    }
                }
                break;
            }
            case op_type::SYSCALL3: {
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
                                std::cerr << fmt::format("[ERR] unknown fd {} for write syscall", fd) << std::endl;
                                std::exit(1);
                            }
                        }
                        break;
                    }
                    default: {
                        std::cerr << fmt::format("[ERR] unsupported SYSCALL3: {}({}, {}, {})", syscall_number, arg0, arg1, arg2) << std::endl;
                        std::exit(1);
                    }
                }
                break;
            }
            case op_type::SYSCALL4: {
                auto syscall_number = pop(stack);
                auto arg0           = pop(stack);
                auto arg1           = pop(stack);
                auto arg2           = pop(stack);
                auto arg3           = pop(stack);
                switch (syscall_number) {
                    default: {
                        std::cerr << fmt::format("[ERR] unsupported SYSCALL4: {}({}, {}, {}, {})", syscall_number, arg0, arg1, arg2, arg3) << std::endl;
                        std::exit(1);
                    }
                }
                break;
            }
            case op_type::SYSCALL5: {
                auto syscall_number = pop(stack);
                auto arg0           = pop(stack);
                auto arg1           = pop(stack);
                auto arg2           = pop(stack);
                auto arg3           = pop(stack);
                auto arg4           = pop(stack);
                switch (syscall_number) {
                    default: {
                        std::cerr << fmt::format("[ERR] unsupported SYSCALL5: {}({},{},{},{},{})", syscall_number, arg0, arg1, arg2, arg3, arg4) << std::endl;
                        std::exit(1);
                    }
                }
                break;
            }
            case op_type::SYSCALL6: {
                auto syscall_number = pop(stack);
                auto arg0           = pop(stack);
                auto arg1           = pop(stack);
                auto arg2           = pop(stack);
                auto arg3           = pop(stack);
                auto arg4           = pop(stack);
                auto arg5           = pop(stack);
                switch (syscall_number) {
                    default: {
                        std::cerr << fmt::format("[ERR] unsupported SYSCALL6: {}({},{},{},{},{},{})", syscall_number, arg0, arg1, arg2, arg3, arg4, arg5) << std::endl;
                        std::exit(1);
                    }
                }
                break;
            }
            default:
                std::cerr << fmt::format("[ERR] unhandled op: {}", to_string(o)) << std::endl;
                std::exit(1);
        }
    }

    if (!stack.empty()) {
        std::cerr << "[WRN] program terminated with non-empty stack: " << stack << std::endl;
    }
}

void compile(std::vector<op> program, std::string &output_path) {
    std::ofstream output(output_path);
    output << "segment .text" << std::endl;

    output << "print:" << std::endl;
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

    std::map<std::string, uint64_t> strings{};

    ADDR_T ip{0};
    while (ip < program.size()) {
        const op &o{program[ip]};
        if (is_debug) std::cout << fmt::format("[DBG] ip={}, op={}", ip, to_string(o)) << std::endl;
        output << "addr_" << ip << ":" << std::endl;
        switch (o.type) {
            case op_type::PUSH_INT: {// Stack
                output << "    ;; -- push int --" << std::endl;
                output << "    push " << o.int_value << std::endl;
                break;
            }
            case op_type::PUSH_STR: {
                output << "    ;; -- push str --" << std::endl;
                output << "    mov rax, " << o.str_value.size() << std::endl;
                output << "    push rax" << std::endl;
                if (!strings.contains(o.str_value)) {
                    strings[o.str_value] = strings.size();
                }
                output << "    push str_" << strings[o.str_value] << std::endl;
                break;
            }
            case op_type::DUP: {
                output << "    ;; -- dup --" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    push rax" << std::endl;
                output << "    push rax" << std::endl;
                break;
            }
            case op_type::DROP: {
                output << "    ;; -- drop --" << std::endl;
                output << "    pop rax" << std::endl;
                break;
            }
            case op_type::SWAP: {
                output << "    ;; -- swap --" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    pop rbx" << std::endl;
                output << "    push rax" << std::endl;
                output << "    push rbx" << std::endl;
                break;
            }
            case op_type::OVER: {
                output << "    ;; -- over --" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    pop rbx" << std::endl;
                output << "    push rbx" << std::endl;
                output << "    push rax" << std::endl;
                output << "    push rbx" << std::endl;
                break;
            }
            case op_type::PRINT: {
                output << "    ;; -- print --" << std::endl;
                output << "    pop rdi" << std::endl;
                output << "    call print" << std::endl;
                break;
            }
            case op_type::PLUS: {// Arithmetic
                output << "    ;; -- plus --" << std::endl;
                output << "    pop rbx" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    add rax, rbx" << std::endl;
                output << "    push rax" << std::endl;
                break;
            }
            case op_type::MINUS: {
                output << "    ;; -- minus --" << std::endl;
                output << "    pop rbx" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    sub rax, rbx" << std::endl;
                output << "    push rax" << std::endl;
                break;
            }
            case op_type::MUL: {
                output << "    ;; -- mul --" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    pop rbx" << std::endl;
                output << "    mul rbx" << std::endl;
                output << "    push rax" << std::endl;
                break;
            }
            case op_type::DIVMOD: {
                output << "    ;; -- div --" << std::endl;
                output << "    xor rdx, rdx" << std::endl;
                output << "    pop rbx" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    div rbx" << std::endl;
                output << "    push rax" << std::endl;
                output << "    push rdx" << std::endl;
                break;
            }
            case op_type::EQUAL: {
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
            case op_type::LT: {
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
            case op_type::LTE: {
                output << "    ;; -- lte --" << std::endl;
                output << "    mov rcx, 0" << std::endl;
                output << "    mov rdx, 1" << std::endl;
                output << "    pop rbx" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    cmp rax, rbx" << std::endl;
                output << "    cmovle rcx, rdx" << std::endl;
                output << "    push rcx" << std::endl;
                break;
            }
            case op_type::GT: {
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
            case op_type::GTE: {
                output << "    ;; -- gte --" << std::endl;
                output << "    mov rcx, 0" << std::endl;
                output << "    mov rdx, 1" << std::endl;
                output << "    pop rbx" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    cmp rax, rbx" << std::endl;
                output << "    cmovge rcx, rdx" << std::endl;
                output << "    push rcx" << std::endl;
                break;
            }
            case op_type::SHR: {// Bitwise
                output << "    ;; -- shr --" << std::endl;
                output << "    pop rcx" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    shr rax, cl" << std::endl;
                output << "    push rax" << std::endl;
                break;
            }
            case op_type::SHL: {
                output << "    ;; -- shl --" << std::endl;
                output << "    pop rcx" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    shl rax, cl" << std::endl;
                output << "    push rax" << std::endl;
                break;
            }
            case op_type::BOR: {
                output << "    ;; -- bor --" << std::endl;
                output << "    pop rbx" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    or rax, rbx" << std::endl;
                output << "    push rax" << std::endl;
                break;
            }
            case op_type::BAND: {
                output << "    ;; -- band --" << std::endl;
                output << "    pop rbx" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    and rax, rbx" << std::endl;
                output << "    push rax" << std::endl;
                break;
            }
            case op_type::IF: {// Conditional
                output << "    ;; -- if --" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    test rax, rax" << std::endl;
                output << "    jz addr_" << o.jmp_addr << std::endl;
                break;
            }
            case op_type::ELSE: {
                output << "    ;; -- else --" << std::endl;
                output << "    jmp addr_" << o.jmp_addr << std::endl;
                break;
            }
            case op_type::END: {
                output << "    ;; -- end --" << std::endl;
                if (is_debug) std::cout << fmt::format("[DBG] %END: ip={}, arg={}", ip, to_string(o)) << std::endl;
                if (ip + 1 != o.jmp_addr) {
                    output << "    jmp addr_" << o.jmp_addr << std::endl;
                }
                break;
            }
            case op_type::WHILE: {// Loop
                output << "    ;; -- while --" << std::endl;
                break;
            }
            case op_type::DO: {
                output << "    ;; -- do --" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    test rax, rax" << std::endl;
                output << "    jz addr_" << o.jmp_addr << std::endl;
                break;
            }
            case op_type::MEM: {// Memory
                output << "    ;; -- mem --" << std::endl;
                output << "    push mem" << std::endl;
                break;
            }
            case op_type::LOAD: {
                output << "    ;; -- load --" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    xor rbx, rbx" << std::endl;
                output << "    mov bl, [rax]" << std::endl;
                output << "    push rbx" << std::endl;
                break;
            }
            case op_type::STORE: {
                output << "    ;; -- store --" << std::endl;
                output << "    pop rbx" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    mov [rax], bl" << std::endl;
                break;
            }
            case op_type::SYSCALL1: {// System
                output << "    ;; -- syscall1 --" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    pop rdi" << std::endl;
                output << "    syscall" << std::endl;
                break;
            }
            case op_type::SYSCALL2: {
                output << "    ;; -- syscall2 --" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    pop rdi" << std::endl;
                output << "    pop rsi" << std::endl;
                output << "    syscall" << std::endl;
                break;
            }
            case op_type::SYSCALL3: {
                output << "    ;; -- syscall3 --" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    pop rdi" << std::endl;
                output << "    pop rsi" << std::endl;
                output << "    pop rdx" << std::endl;
                output << "    syscall" << std::endl;
                break;
            }
            case op_type::SYSCALL4: {
                output << "    ;; -- syscall4 --" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    pop rdi" << std::endl;
                output << "    pop rsi" << std::endl;
                output << "    pop rdx" << std::endl;
                output << "    pop r10" << std::endl;
                output << "    syscall" << std::endl;
                break;
            }
            case op_type::SYSCALL5: {
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
            case op_type::SYSCALL6: {
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
            default:
                std::cerr << fmt::format("[ERR] unhandled op: {}", to_string(o)) << std::endl;
                std::exit(1);
        }
        ip++;
    }

    // program exit
    output << "addr_" << ip << ":" << std::endl;
    output << "    ;; -- exit --" << std::endl;
    output << "    mov rax, 60" << std::endl;
    output << "    mov rdi, 0" << std::endl;
    output << "    syscall" << std::endl;

    // uninitialized data segment
    output << ";; ---" << std::endl;
    output << "segment .data" << std::endl;
    for (auto e : strings) {
        output << "str_" << e.second << ":" << std::endl;
        output << "    db ";
        for (auto ch : e.first) {
            output << int(ch) << ", ";
        }
        output << "0" << std::endl;
    }
    output << "segment .bss" << std::endl;
    output << "mem: resb " << MEM_CAPACITY << std::endl;

    output.close();
}

std::vector<op> &cross_reference(std::vector<op> &program) {
    if (is_debug) std::cout << "***** generating cross references *****" << std::endl;
    std::vector<ADDR_T> ip_stack;
    ADDR_T ip{0};
    while (ip < program.size()) {
        op &o{program[ip]};
        switch (o.type) {

            case op_type::IF: {
                push(ip_stack, ip);
                break;
            }
            case op_type::ELSE: {
                auto iff_ip = pop(ip_stack);
                op &iff_op  = program[iff_ip];
                if (is_debug) std::cout << fmt::format("[DBG] ELSE @ {} matched with {} @ {}", ip, to_string(iff_op.type), iff_ip) << std::endl;
                iff_op.jmp_addr = ip + 1;// IF will jump to instruction _after_ ELSE when fail
                push(ip_stack, ip);      // save the ELSE ip for END
                break;
            }
            case op_type::END: {
                // when we hit an END from:
                // - executing the success branch of an IF with no ELSE -> jump to next instruction
                // - the failure branch of an IF with an ELSE -> jump to next instruction
                // - WHILE loop -> jump back to condition
                auto block_ip = pop(ip_stack);// IF, ELSE, DO, ...
                op &block_op  = program[block_ip];
                if (is_debug) std::cout << fmt::format("[DBG] END @ {} matched with {} @ {}", ip, to_string(block_op.type), block_ip) << std::endl;
                if (block_op.type == op_type::IF || block_op.type == op_type::ELSE) {
                    o.jmp_addr        = ip + 1;// Update END to jump to next instruction
                    block_op.jmp_addr = ip;    // jump to this instruction (END)
                } else if (block_op.type == op_type::DO) {
                    o.jmp_addr        = block_op.jmp_addr;// END jumps to WHILE (stored in DO arg)
                    block_op.jmp_addr = ip + 1;           // Update DO to jump _past_ END when fail
                } else {
                    std::cerr << "[ERR] `END` can only close `IF`, `ELSE`, and `DO` blocks for now" << std::endl;
                    std::exit(1);
                }
                break;
            }
            case op_type::WHILE: {
                push(ip_stack, ip);// save the WHILE ip for DO
                break;
            }
            case op_type::DO: {
                auto wile_ip = pop(ip_stack);
                op &wile_op  = program[wile_ip];
                if (is_debug) std::cout << fmt::format("[DBG] DO @ {} matched with {} @ {}", ip, to_string(wile_op.type), wile_ip) << std::endl;
                o.jmp_addr = wile_ip;// record the WHILE ip
                push(ip_stack, ip);  // save the DO ip for END
                break;
            }
            default:
                break;
        }
        ip++;
    }

    if (!ip_stack.empty()) {
        std::cerr << "[ERR] cross reference stack is non-empty (e.g., unmatched if/else/end)" << std::endl;
        std::exit(1);
    }

    return program;
}

std::vector<op> load_program_from_file(std::string const &file_path) {
    auto tokens{lex_file(file_path)};
    std::map<std::string, macro> macros{};
    auto program{parse(tokens, macros)};
    return cross_reference(program);
}

[[noreturn]] void usage(const std::string_view &compiler_name) {
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

int main(int argc, char **argv) {

    auto cur_arg{0};
    const std::string compiler_name{argv[cur_arg++]};

    // options
    while (cur_arg < argc) {
        const std::string arg = argv[cur_arg];
        if (arg == "-debug") {
            is_debug = true;
            std::cout << "[DBG] debug enabled" << std::endl;
            cur_arg++;
        } else if (arg.starts_with("-")) {
            std::cerr << fmt::format("[ERR] unknown option: {}", arg) << std::endl;
            usage(compiler_name);
        } else {
            break;
        }
    }

    if (argc <= cur_arg) {
        std::cerr << "[ERR] missing subcommand" << std::endl;
        usage(compiler_name);
    }

    const std::string subcommand{argv[cur_arg++]};

    if (subcommand == "sim") {
        if (argc <= cur_arg) {
            std::cerr << "[ERR] missing input file path for simulation" << std::endl;
            usage(compiler_name);
        }
        const std::string input_file_path{argv[cur_arg++]};

        const std::vector<op> input_program = load_program_from_file(std::string{input_file_path});

        if (input_program.size() == 0) {
            std::cerr << "[ERR] no operations to perform" << std::endl;
            std::exit(1);
        }

        simulate(input_program);

    } else if (subcommand == "com") {
        // options
        auto is_run{false};
        while (cur_arg < argc) {
            const std::string arg = argv[cur_arg];
            if (arg == "-r") {
                is_run = true;
                if (is_debug) std::cout << "[DBG] run enabled" << std::endl;
                cur_arg++;
            } else if (arg.starts_with("-")) {
                std::cerr << fmt::format("[ERR] unknown option: {}", arg) << std::endl;
                usage(compiler_name);
            } else {
                break;
            }
        }

        if (argc <= cur_arg) {
            std::cerr << "[ERR] missing input file path for compilation" << std::endl;
            usage(compiler_name);
        }
        const std::string input_file_path{argv[cur_arg++]};

        const std::vector<op> input_program = load_program_from_file(std::string{input_file_path});

        if (input_program.size() == 0) {
            std::cerr << "[ERR] invalid program" << std::endl;
            std::exit(1);
        }

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
        std::cerr << fmt::format("[ERR] unknown subcommand: {}", subcommand) << std::endl;
        usage(compiler_name);
    }
    return 0;
}
