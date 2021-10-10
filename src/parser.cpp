#include "parser.hpp"
#include <iostream>

bimap<op_type, std::string> const op_bimap{
        // Stack
        {op_type::PUSH_INT, "PUSH_INT"},
        {op_type::PUSH_STR, "PUSH_STR"},
        {op_type::DUP, "DUP"},
        {op_type::DUP2, "2DUP"},
        {op_type::DROP, "DROP"},
        {op_type::SWAP, "SWAP"},
        {op_type::OVER, "OVER"},
        {op_type::DUMP, "DUMP"},
        // Arithmetic
        {op_type::PLUS, "+"},
        {op_type::MINUS, "-"},
        {op_type::EQUAL, "="},
        {op_type::GT, ">"},
        {op_type::LT, "<"},
        // Bitwise
        {op_type::SHR, "SHR"},
        {op_type::SHL, "SHL"},
        {op_type::BOR, "BOR"},
        {op_type::BAND, "BAND"},
        // Conditional
        {op_type::IF, "IF"},
        {op_type::ELSE, "ELSE"},
        {op_type::END, "END"},
        // Loop
        {op_type::WHILE, "WHILE"},
        {op_type::DO, "DO"},
        // Memory
        {op_type::MEM, "MEM"},
        {op_type::LOAD, ","},
        {op_type::STORE, "."},
        // System
        {op_type::SYSCALL1, "SYSCALL1"},
        {op_type::SYSCALL2, "SYSCALL2"},
        {op_type::SYSCALL3, "SYSCALL3"},
        {op_type::SYSCALL4, "SYSCALL4"},
        {op_type::SYSCALL5, "SYSCALL5"},
        {op_type::SYSCALL6, "SYSCALL6"}};

static op parse_token_as_op(token const &token) {
    switch (token.type) {
        case token_type::IDENTIFIER: {
            return op{.type = to_op_type(token.text), .token = token};
        }
        case token_type::INTEGER_LITERAL: {
            return op{.type = op_type::PUSH_INT, .token = token, .int_value = std::stoll(token.text)};
        }
        case token_type::STRING_LITERAL: {
            return op{.type = op_type::PUSH_STR, .token = token, .str_value = token.text};
        }
        case token_type::WHITESPACE:
        case token_type::OPERATOR:
        case token_type::FLOAT_LITERAL: {
            std::cerr << fmt::format("[INF] Unsupported token: {}", to_string(token.type)) << std::endl;
            std::exit(1);
        }
    }
}

std::vector<op> parse(std::vector<token> const &tokens) {
    std::vector<op> program;
    program.reserve(tokens.size());
    for (auto &tok : tokens) {
        std::cout << fmt::format("[DBG] parsing token: {}", to_string(tok)) << std::endl;
        program.push_back(parse_token_as_op(tok));
    }
    return program;
}

std::string to_string(op_type t) {
    return op_bimap.b(t);
}
op_type to_op_type(std::string const &s) {
    return op_bimap.a(s);
}
bool is_op(std::string const &s) {
    return op_bimap.has_b(s);
}
std::string to_string(op const &o) {
    return fmt::format("type: {}, token: {{}}, int_value: {}, str_value: {}, jmp: {}", to_string(o.type), to_string(o.token), o.int_value, o.str_value, o.jmp);
}

