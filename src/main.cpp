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

enum class op_t { push,
                  plus,
                  minus,
                  equal,
                  gt,
                  lt,
                  iff,
                  elze,
                  end,
                  dup,
                  wile,
                  doo,
                  dump };

std::map<op_t, std::string> op_t_names{{op_t::push, "PUSH"},
                                       {op_t::plus, "PLUS"},
                                       {op_t::minus, "MINUS"},
                                       {op_t::equal, "EQUAL"},
                                       {op_t::gt, "GT"},
                                       {op_t::lt, "LT"},
                                       {op_t::iff, "IF"},
                                       {op_t::elze, "ELSE"},
                                       {op_t::end, "END"},
                                       {op_t::dup, "DUP"},
                                       {op_t::wile, "WHILE"},
                                       {op_t::doo, "DO"},
                                       {op_t::dump, "DUMP"}};

struct op {
    op_t type;
    uint64_t arg;
};

struct token {
    std::string file_path;
    uint64_t row;
    uint64_t col;
    std::string word;
};

std::string format_op(op o) {
    return fmt::format("{} {}", op_t_names[o.type], o.arg);
}

op push(uint64_t x) { return op{op_t::push, x}; }
op plus() { return op{op_t::plus}; }
op minus() { return op{op_t::minus}; }
op equal() { return op{op_t::equal}; }
op gt() { return op{op_t::gt}; }
op lt() { return op{op_t::lt}; }
op iff() { return op{op_t::iff}; }
op elze() { return op{op_t::elze}; }
op end() { return op{op_t::end}; }
op dup() { return op{op_t::dup}; }
op wile() { return op{op_t::wile}; }
op doo() { return op{op_t::doo}; }
op dump() { return op{op_t::dump}; }

inline const int64_t pop(std::vector<int64_t>& stack) {
    auto x = stack.back();
    stack.pop_back();
    return x;
}

inline void push(std::vector<int64_t>& stack, const int64_t x) { stack.push_back(x); }

void simulate(std::vector<op> program) {
    auto is_trace{false};
    std::vector<int64_t> stack;
    uint64_t ip{0};
    while (ip < program.size()) {
        const op& o{program[ip]};
        if (is_trace) std::cout << fmt::format("{:03}[{:03}]: {}", ip, stack.size(), format_op(o)) << std::endl;
        ip++;
        switch (o.type) {
            case op_t::push:
                if (is_trace) std::cout << fmt::format("$ PUSH {}", o.arg) << std::endl;
                push(stack, o.arg);
                break;
            case op_t::plus: {
                auto b = pop(stack);
                auto a = pop(stack);
                if (is_trace) std::cout << fmt::format("$ {} + {}: {}", a, b, a + b) << std::endl;
                push(stack, a + b);
                break;
            }
            case op_t::minus: {
                auto b = pop(stack);
                auto a = pop(stack);
                if (is_trace) std::cout << fmt::format("$ {} - {}: {}", a, b, a - b) << std::endl;
                push(stack, a - b);
                break;
            }
            case op_t::equal: {
                auto b = pop(stack);
                auto a = pop(stack);
                if (is_trace) std::cout << fmt::format("$ {} == {}: {}", a, b, a == b) << std::endl;
                push(stack, a == b);
                break;
            }
            case op_t::gt: {
                auto b = pop(stack);
                auto a = pop(stack);
                if (is_trace) std::cout << fmt::format("$ {} > {}: {}", a, b, a > b) << std::endl;
                push(stack, a > b);
                break;
            }
            case op_t::lt: {
                auto b = pop(stack);
                auto a = pop(stack);
                if (is_trace) std::cout << fmt::format("$ {} < {}: {}", a, b, a < b) << std::endl;
                push(stack, a < b);
                break;
            }
            case op_t::iff: {
                auto a = pop(stack);
                if (is_trace) std::cout << fmt::format("$ IF {} ({})", a, a != 0) << std::endl;
                if (a == 0) {
                    // failed the IF condition, jump _past_ the ELSE or END
                    ip = o.arg;
                }
                break;
            }
            case op_t::elze: {
                // when we hit an ELSE (from executing the success branch of an IF), jump to the END
                ip = o.arg;
                break;
            }
            case op_t::end: {
                // when we hit an END, jump to its saved ip
                ip = o.arg;
                break;
            }
            case op_t::wile: {
                // do nothing
                break;
            }
            case op_t::doo: {
                auto a = pop(stack);
                if (is_trace) std::cout << fmt::format("$ DO {} ({})", a, a != 0) << std::endl;
                if (a == 0) {
                    // failed the WHILE condition, jump _past_ the END
                    ip = o.arg;
                }
                break;
            }
            case op_t::dup: {
                auto a = pop(stack);
                if (is_trace) std::cout << fmt::format("$ DUP {}", a) << std::endl;
                push(stack, a);
                push(stack, a);
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

    uint64_t ip{0};
    while (ip < program.size()) {
        const op& o{program[ip]};
        //std::cout << fmt::format("{}: {}", ip, format_op(o)) << std::endl;
        output << "addr_" << ip << ":" << std::endl;
        ip++;
        switch (o.type) {
            case op_t::push:
                output << "    ;; -- push %d --" << std::endl;
                output << "    push " << o.arg << std::endl;
                break;
            case op_t::plus: {
                output << "    ;; -- plus --" << std::endl;
                output << "    pop rbx" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    add rax, rbx" << std::endl;
                output << "    push rax" << std::endl;
                break;
            }
            case op_t::minus: {
                output << "    ;; -- minus --" << std::endl;
                output << "    pop rbx" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    sub rax, rbx" << std::endl;
                output << "    push rax" << std::endl;
                break;
            }
            case op_t::equal: {
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
            case op_t::gt: {
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
            case op_t::lt: {
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
            case op_t::iff: {
                output << "    ;; -- if --" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    test rax, rax" << std::endl;
                output << "    jz addr_" << o.arg << std::endl;
                break;
            }
            case op_t::elze: {
                output << "    ;; -- else --" << std::endl;
                output << "    jmp addr_" << o.arg << std::endl;
                break;
            }
            case op_t::end: {
                output << "    ;; -- end --" << std::endl;
                if (ip + 1 != o.arg) {
                    output << "    jmp addr_" << o.arg << std::endl;
                }
                break;
            }
            case op_t::wile: {
                output << "    ;; -- while --" << std::endl;
                break;
            }
            case op_t::doo: {
                output << "    ;; -- do --" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    test rax, rax" << std::endl;
                output << "    jz addr_" << o.arg << std::endl;
                break;
            }
            case op_t::dup: {
                output << "    ;; -- dup --" << std::endl;
                output << "    pop rax" << std::endl;
                output << "    push rax" << std::endl;
                output << "    push rax" << std::endl;
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

std::vector<op>& cross_reference(std::vector<op>& program) {
    auto is_trace{false};
    std::vector<uint64_t> ip_stack;
    uint64_t ip{0};
    while (ip < program.size()) {
        op& o{program[ip]};
        switch (o.type) {

            case op_t::iff: {
                ip_stack.push_back(ip);
                break;
            }
            case op_t::elze: {
                auto iff_ip = ip_stack.back();
                ip_stack.pop_back();
                op& iff_op = program[iff_ip];
                if (is_trace) std::cout << fmt::format("ELSE @ {} matched with {} @ {}", ip, op_t_names[iff_op.type], iff_ip) << std::endl;
                iff_op.arg = ip + 1;   // IF will jump to instruction _after_ ELSE when fail
                ip_stack.push_back(ip);// save the ELSE ip for END
                break;
            }
            case op_t::end: {
                // when we hit an END from:
                // - executing the success branch of an IF with no ELSE -> jump to next instruction
                // - the failure branch of an IF with an ELSE -> jump to next instruction
                // - WHILE loop -> jump back to condition
                auto block_ip = ip_stack.back();
                ip_stack.pop_back();
                op& block_op = program[block_ip];
                if (is_trace) std::cout << fmt::format("END @ {} matched with {} @ {}", ip, op_t_names[block_op.type], block_ip) << std::endl;
                if (block_op.type == op_t::iff || block_op.type == op_t::elze) {
                    block_op.arg = ip + 1;// jump to instruction _after_ END
                } else if (block_op.type == op_t::doo) {
                    o.arg        = block_op.arg;// END jumps to WHILE (stored in DO arg)
                    block_op.arg = ip + 1;      // Update DO to jump _past_ END when fail
                } else {
                    std::cerr << "`END` can only close `IF`, `ELSE`, and `DO` blocks for now" << std::endl;
                    std::exit(1);
                }
                break;
            }
            case op_t::wile: {
                ip_stack.push_back(ip);// save the WHILE ip for DO
                break;
            }
            case op_t::doo: {
                auto wile_ip = ip_stack.back();
                ip_stack.pop_back();
                op& wile_op = program[wile_ip];
                if (is_trace) std::cout << fmt::format("DO @ {} matched with {} @ {}", ip, op_t_names[wile_op.type], wile_ip) << std::endl;
                o.arg = wile_ip;       // record the WHILE ip
                ip_stack.push_back(ip);// save the DO ip for END
                break;
            }
            default:
                break;
        }
        ip++;
    }

    if (!ip_stack.empty()) {
        std::cerr << "Cross reference stack is non-empty (e.g., unmatched if/else/end)" << std::endl;
        std::exit(1);
    }

    return program;
}

[[noreturn]] void token_error(const token& tok, const std::string& msg) {
    std::cout << fmt::format("[ERR] {} ({},{}): '{}': {}", tok.file_path, tok.row, tok.col, tok.word, msg) << std::endl;
    std::exit(1);
}

op parse_token_as_op(const token& tok) {
    std::string kw = tok.word;
    std::transform(kw.begin(), kw.end(), kw.begin(), ::toupper);
    if (kw.compare("+") == 0) {
        return plus();
    } else if (kw.compare("-") == 0) {
        return minus();
    } else if (kw.compare("=") == 0) {
        return equal();
    } else if (kw.compare(">") == 0) {
        return gt();
    } else if (kw.compare("<") == 0) {
        return lt();
    } else if (kw.compare("IF") == 0) {
        return iff();
    } else if (kw.compare("ELSE") == 0) {
        return elze();
    } else if (kw.compare("END") == 0) {
        return end();
    } else if (kw.compare("WHILE") == 0) {
        return wile();
    } else if (kw.compare("DO") == 0) {
        return doo();
    } else if (kw.compare("DUP") == 0) {
        return dup();
    } else if (kw.compare(".") == 0) {
        return dump();
    }

    try {
        auto value = std::stoll(tok.word);
        return push(value);
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
    token cur_token{.file_path = file_path, .row = row};

    for (auto c : line) {
        if (std::isspace(c)) {
            if (is_word) {
                tokens.push_back(cur_token);
                is_word = false;
            }
        } else {
            if (is_word) {
                cur_token.word += c;
            } else {
                cur_token.col  = col;
                cur_token.word = c;
                is_word        = true;
            }
        }
        col++;
    }
    if (is_word) {
        tokens.push_back(cur_token);
    }
    return tokens;
}

std::vector<token> lex_file(const std::string& file_path) {
    std::ifstream f(file_path);
    if (!f.is_open()) {
        std::cerr << "Unable to open input file" << std::endl;
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
        //std::cout << fmt::format("{}({:03},{:03}): {}", tok.file_path, tok.row, tok.col, tok.word) << std::endl;
        program.push_back(parse_token_as_op(tok));
    }

    return cross_reference(program);
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
    const std::string forth_name{argv[cur_arg++]};

    if (argc <= cur_arg) {
        std::cerr << ">>> Missing subcommand" << std::endl;
        usage(forth_name);
    }
    const std::string subcommand{argv[cur_arg++]};

    if (argc <= cur_arg) {
        std::cerr << ">>> Missing input file path" << std::endl;
        usage(forth_name);
    }
    const std::string input_file_path{argv[cur_arg++]};

    const std::vector<op> input_program = load_program_from_file(std::string{input_file_path});

    if (subcommand == "sim") {
        simulate(input_program);
    } else if (subcommand == "com") {
        std::filesystem::path p(input_file_path);
        p.replace_extension("");
        auto output_file_path{p.string()};
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
