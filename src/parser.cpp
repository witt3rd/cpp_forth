#include "parser.hpp"
#include "lexer.hpp"
#include <iostream>
#include <map>

bimap<op_type, std::string> const &get_op_bimap() {
    static bimap<op_type, std::string> const op_bimap{
            // Stack
            {op_type::PUSH_INT, "push_int"},
            {op_type::PUSH_STR, "push_str"},
            {op_type::DUP, "dup"},
            {op_type::DROP, "drop"},
            {op_type::SWAP, "swap"},
            {op_type::OVER, "over"},
            {op_type::PRINT, "print"},
            // Arithmetic
            {op_type::PLUS, "+"},
            {op_type::MINUS, "-"},
            {op_type::MUL, "*"},
            {op_type::DIVMOD, "divmod"},
            {op_type::EQUAL, "="},
            {op_type::LT, "<"},
            {op_type::LTE, "<="},
            {op_type::GT, ">"},
            {op_type::GTE, ">="},
            // Bitwise
            {op_type::SHR, "shr"},
            {op_type::SHL, "shl"},
            {op_type::BOR, "bor"},
            {op_type::BAND, "band"},
            // Conditional
            {op_type::IF, "if"},
            {op_type::ELSE, "else"},
            {op_type::END, "end"},
            // Loop
            {op_type::WHILE, "while"},
            {op_type::DO, "do"},
            // Memory
            {op_type::MEM, "mem"},
            {op_type::LOAD, ","},
            {op_type::STORE, "."},
            // System
            {op_type::SYSCALL1, "syscall1"},
            {op_type::SYSCALL2, "syscall2"},
            {op_type::SYSCALL3, "syscall3"},
            {op_type::SYSCALL4, "syscall4"},
            {op_type::SYSCALL5, "syscall5"},
            {op_type::SYSCALL6, "syscall6"}};
    return op_bimap;
}

static op parse_token_as_op(token const &token) {
    switch (token.type) {
        case token_type::IDENTIFIER:
            try {
                return op{.type = to_op_type(token.text), .token = token, .str_value = token.text};
            } catch (std::out_of_range &e) {
                std::cerr << fmt::format("[ERR] {}: invalid identifier", to_string(token)) << std::endl;
                std::exit(1);
            }
        case token_type::INTEGER_LITERAL:
            return op{.type = op_type::PUSH_INT, .token = token, .int_value = std::stoll(token.text)};
        case token_type::FLOAT_LITERAL:
            std::cerr << "FLOAT_LITERAL not implemented" << std::endl;
            std::exit(1);
        case token_type::CHAR_LITERAL:
            return op{.type = op_type::PUSH_INT, .token = token, .int_value = (int64_t) *token.text.c_str()};
        case token_type::STRING_LITERAL:
            return op{.type = op_type::PUSH_STR, .token = token, .str_value = token.text, .str_addr = static_cast<uint64_t>(-1)};
        case token_type::DOT:
            return op{.type = op_type::STORE, .token = token};
        case token_type::COMMA:
            return op{.type = op_type::LOAD, .token = token};
        case token_type::PLUS:
            return op{.type = op_type::PLUS, .token = token};
        case token_type::MINUS:
            return op{.type = op_type::MINUS, .token = token};
        case token_type::STAR:
            return op{.type = op_type::MUL, .token = token};
        case token_type::LT:
            return op{.type = op_type::LT, .token = token};
        case token_type::LTE:
            return op{.type = op_type::LTE, .token = token};
        case token_type::GT:
            return op{.type = op_type::GT, .token = token};
        case token_type::GTE:
            return op{.type = op_type::GTE, .token = token};
        case token_type::EQUAL:
            return op{.type = op_type::EQUAL, .token = token};
        default:
            std::cerr << fmt::format("[INF] unsupported token: {}", to_string(token.type)) << std::endl;
            std::exit(1);
    }
}

std::vector<op> parse(std::vector<token> &tokens, std::map<std::string, macro> &macros) {
    std::vector<op> program;
    size_t i{0};
    while (i < tokens.size()) {
        auto tok = tokens[i++];
        //std::cout << fmt::format("[DBG] parsing token: {}", to_string(tok)) << std::endl;

        // expand macros
        if (auto it = macros.find(tok.text); it != macros.end()) {
            auto m           = it->second;
            auto sub_program = parse(m.body_tokens, macros);
            program.insert(program.end(), sub_program.begin(), sub_program.end());
            continue;
        }

        if (tok.text == "macro") {
            if (i >= tokens.size()) {
                std::cerr << fmt::format("[ERR] incomplete macro definition: {}", to_string(tok)) << std::endl;
                std::exit(1);
            }
            auto name = tokens[i++];
            if (name.type != token_type::IDENTIFIER) {
                std::cerr << fmt::format("[ERR] macro name must be an identifier: {}", to_string(name)) << std::endl;
                std::exit(1);
            }
            if (macros.contains(name.text)) {
                std::cerr << fmt::format("[ERR] macro already defined: {}", to_string(name)) << std::endl;
                std::cerr << fmt::format("[INF] original macro: {}", to_string(macros[name.text].macro_token)) << std::endl;
                std::exit(1);
            }
            macro m{.macro_token = tok};
            auto blocks{0};
            auto complete{false};
            while (i < tokens.size()) {
                tok = tokens[i++];
                if (tok.type == token_type::IDENTIFIER) {
                    if (tok.text == "if" || tok.text == "while") blocks++;
                    if (tok.text == "end") {
                        if (blocks) blocks--;
                        else {
                            complete = true;
                            break;
                        }
                    }
                }
                m.body_tokens.push_back(tok);
            }
            if (!complete || m.body_tokens.empty()) {
                std::cerr << fmt::format("[ERR] incomplete macro definition: {}", to_string(m.macro_token)) << std::endl;
                std::exit(1);
            }
            macros[name.text] = m;
        } else if (tok.text == "include") {
            if (i >= tokens.size()) {
                std::cerr << fmt::format("[ERR] incomplete include definition: {}", to_string(tok)) << std::endl;
                std::exit(1);
            }
            auto file_name = tokens[i++];
            if (file_name.type != token_type::STRING_LITERAL) {
                std::cerr << fmt::format("[ERR] include file name must be a string: {}", to_string(file_name)) << std::endl;
                std::exit(1);
            }
            auto included_tokens = lex_file(file_name.text);
            //            std::cout << fmt::format("[DBG] including {} tokens from {}", included_tokens.size(), file_name.text) << std::endl;
            auto it = tokens.begin() + (long) i;
            tokens.insert(it, included_tokens.begin(), included_tokens.end());
        } else {
            auto op = parse_token_as_op(tok);
            program.push_back(op);
        }
    }
    return program;
}

std::string to_string(op_type t) {
    return get_op_bimap().b(t);
}

op_type to_op_type(std::string const &s) {
    return get_op_bimap().a(s);
}

bool is_op(std::string const &s) {
    return get_op_bimap().has_b(s);
}
std::string to_string(op const &o) {
    return fmt::format("type: {}, token: {{}}, str_value: {}, int/jmp/str: {}", to_string(o.type), to_string(o.token), o.str_value, o.int_value);
}
