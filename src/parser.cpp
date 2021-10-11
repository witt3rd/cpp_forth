#include "parser.hpp"
#include <iostream>

bimap<op_type, std::string> const &get_op_bimap() {
    static bimap<op_type, std::string> const op_bimap{
            {op_type::NOP, "NOP"},
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
    return op_bimap;
}

static op parse_token_as_op(token const &token) {
    op op{.type = op_type::NOP, .token = token, .str_value = token.text};
    switch (token.type) {
        case token_type::IDENTIFIER:
            op.type = to_op_type(token.text);
            break;
        case token_type::INTEGER_LITERAL:
            op.type      = op_type::PUSH_INT;
            op.int_value = std::stoll(token.text);
            break;
        case token_type::FLOAT_LITERAL:
            break;
        case token_type::STRING_LITERAL:
            op.type = op_type::PUSH_STR;
            op.str_value = token.text;
            op.str_addr = -1;
            break;
        case token_type::DOT:
            op.type = op_type::STORE;
            break;
        case token_type::COMMA:
            op.type = op_type::LOAD;
            break;
        case token_type::PLUS:
            op.type = op_type::PLUS;
            break;
        case token_type::MINUS:
            op.type = op_type::MINUS;
            break;
        case token_type::LESS_THAN:
            op.type = op_type::LT;
            break;
        case token_type::GREATER_THAN:
            op.type = op_type::GT;
            break;
        case token_type::EQUAL:
            op.type = op_type::EQUAL;
            break;
        default:
            std::cerr << fmt::format("[INF] Unsupported token: {}", to_string(token.type)) << std::endl;
            std::exit(1);
    }
    return op;
}

std::vector<op> parse(std::vector<token> const &tokens) {
    std::vector<op> program;
    program.reserve(tokens.size());
    for (auto &tok : tokens) {
        //std::cout << fmt::format("[DBG] parsing token: {}", to_string(tok)) << std::endl;
        auto op = parse_token_as_op(tok);
        if (op.type != op_type::NOP) program.push_back(op);
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
