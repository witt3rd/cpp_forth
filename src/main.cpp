#include "command.hpp"
#include <filesystem>
#include <fmt/core.h>
#include <fmt/format.h>
#include <fstream>
#include <ios>
#include <iostream>
#include <map>
#include <string_view>
#include <vector>

enum class op_t { push,
                  plus,
                  minus,
                  dump };

std::map<op_t, std::string> op_t_names{{op_t::push, "PUSH"},
                                       {op_t::plus, "PLUS"},
                                       {op_t::minus, "MINUS"},
                                       {op_t::dump, "DUMP"}};

struct op {
    op_t type;
    uint64_t arg;
};

void dump(op o) {
    std::cout << fmt::format("{} {}", op_t_names[o.type], o.arg) << std::endl;
}

op push(uint64_t x) { return op{op_t::push, x}; }
op plus() { return op{op_t::plus}; }
op minus() { return op{op_t::minus}; }
op dump() { return op{op_t::dump}; }

inline const uint64_t pop(std::vector<uint64_t>& stack) {
    auto x = stack.back();
    stack.pop_back();
    return x;
}

inline void push(std::vector<uint64_t>& stack, const uint64_t x) { stack.push_back(x); }

void simulate(std::vector<op> program) {
    std::vector<uint64_t> stack;
    for (op& o : program) {
        // dump(o);
        switch (o.type) {
            case op_t::push:
                push(stack, o.arg);
                break;
            case op_t::plus: {
                auto a = pop(stack);
                auto b = pop(stack);
                push(stack, a + b);
                break;
            }
            case op_t::minus: {
                auto a = pop(stack);
                auto b = pop(stack);
                push(stack, b - a);
                break;
            }
            case op_t::dump:
                auto a = pop(stack);
                std::cout << a << std::endl;
                break;
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
    for (op& o : program) {
        //dump(o);
        switch (o.type) {
            case op_t::push:
                output << "    ;; -- push %d --" << std::endl;
                output << "    push " << o.arg << std::endl;
                break;
            case op_t::plus: {
                output << "    ;; -- plus --" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    pop rbx" << std::endl;
                output << "    add rax, rbx" << std::endl;
                output << "    push rax" << std::endl;
                break;
            }
            case op_t::minus: {
                output << "    ;; -- minus --" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    pop rbx" << std::endl;
                output << "    sub rbx, rax" << std::endl;
                output << "    push rbx" << std::endl;
                break;
            }
            case op_t::dump:
                output << "    ;; -- dump --" << std::endl;
                output << "    pop rdi" << std::endl;
                output << "    call dump" << std::endl;
                break;
        }
    }

    output << "    ;; -- exit --" << std::endl;
    output << "    mov rax, 60" << std::endl;
    output << "    mov rdi, 0" << std::endl;
    output << "    syscall" << std::endl;

    output.close();
}

std::vector<op> load_program(const std::string_view& input_file_path) {
    std::vector<op> program{push(42), push(27), plus(), dump(),
                            push(500), push(80), minus(), dump()};

    return program;
}

[[noreturn]] void usage(const std::string_view& forth_name) {
    std::cout << fmt::format("Usage: {} <SUBCOMMAND> <INPUT FILE PATH> [ARGS]", forth_name) << std::endl;
    std::cout << "SUBCOMMANDS: " << std::endl;
    std::cout << "    sim      Simulate the program" << std::endl;
    std::cout << "    com      Compile the program" << std::endl;
    std::exit(1);
}

int main(int argc, char** argv) {

    auto cur_arg{0};
    const std::string_view forth_name{argv[cur_arg++]};

    if (argc <= cur_arg) {
        std::cerr << ">>> Missing subcommand" << std::endl;
        usage(forth_name);
    }
    const std::string_view subcommand{argv[cur_arg++]};

    if (argc <= cur_arg) {
        std::cerr << ">>> Missing input file path" << std::endl;
        usage(forth_name);
    }
    const std::string_view input_file_path{argv[cur_arg++]};

    const std::vector<op> input_program = load_program(input_file_path);

    if (subcommand == "sim") {
        simulate(input_program);
    } else if (subcommand == "com") {
        std::filesystem::path p = input_file_path;
        p.replace_extension("");
        const std::string_view output_file_path{p.string()};

        // assemble
        auto assembler_file_path = fmt::format("{}.asm", output_file_path);
        compile(input_program, assembler_file_path);
        auto assembler_command = fmt::format("nasm -felf64 {}", assembler_file_path);
        std::cout << assembler_command << std::endl;
        auto res = raymii::Command::exec(assembler_command);
        if (res.exitstatus != 0) {
            std::cout << fmt::format("nasm exited with {}: {}", res.exitstatus, res.output) << std::endl;
            return res.exitstatus;
        }

        // link
        auto assembler_output_file_path = fmt::format("{}.o", output_file_path);
        auto linker_command             = fmt::format("ld -o {} {}", output_file_path, assembler_output_file_path);
        std::cout << linker_command << std::endl;
        res = raymii::Command::exec(linker_command);
        if (res.exitstatus != 0) {
            std::cout << fmt::format("ld exited with {}: {}", res.exitstatus, res.output) << std::endl;
            return res.exitstatus;
        }
    } else {
        std::cerr << fmt::format(">>> Unknown subcommand: {}", subcommand) << std::endl;
        usage(forth_name);
    }

    return 0;
}
