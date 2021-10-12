#include "parser.hpp"
#include <iostream>
#include <map>

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
            // Macros
            {op_type::MACRO, "MACRO"},
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
            try {
                op.type = to_op_type(token.text);
            } catch (std::out_of_range &e) {
                std::cerr << fmt::format("[ERR] {}: invalid identifier", to_string(token)) << std::endl;
                std::exit(1);
            }
            break;
        case token_type::INTEGER_LITERAL:
            op.type      = op_type::PUSH_INT;
            op.int_value = std::stoll(token.text);
            break;
        case token_type::FLOAT_LITERAL:
            break;
        case token_type::STRING_LITERAL:
            op.type      = op_type::PUSH_STR;
            op.str_value = token.text;
            op.str_addr  = -1;
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
            std::cerr << fmt::format("[INF] unsupported token: {}", to_string(token.type)) << std::endl;
            std::exit(1);
    }
    return op;
}

std::vector<op> parse(std::vector<token> const &tokens) {
    std::vector<op> program;
    std::map<std::string, macro> macros;
    size_t i{0};
    while (i < tokens.size()) {
        auto tok = tokens[i++];
//        std::cout << fmt::format("[DBG] parsing token: {}", to_string(tok)) << std::endl;
        if (macros.contains(tok.text)) {
            auto m = macros[tok.text];
            for (auto const &t : m.body_tokens) {
                program.push_back(parse_token_as_op(t));
            }
            continue;
        }
        auto op = parse_token_as_op(tok);
        if (op.type == op_type::MACRO) {
            if (i >= tokens.size()) {
                std::cerr << fmt::format("[ERR] incomplete macro definition: {}", to_string(tok)) << std::endl;
                std::exit(1);
            }
            auto name = tokens[i++];
            if (name.type != token_type::IDENTIFIER) {
                std::cerr << fmt::format("[ERR] token name must be identifier: {}", to_string(name)) << std::endl;
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
                    if (tok.text == "IF" || tok.text == "WHILE") blocks++;
                    if (tok.text == "END") {
                        if (blocks) blocks--;
                        else {
                            complete = true;
                            break;
                        }
                    }
                }
                m.body_tokens.push_back(tok);
            }
            if (!complete || m.body_tokens.size() == 0) {
                std::cerr << fmt::format("[ERR] incomplete macro definition: {}", to_string(m.macro_token)) << std::endl;
                std::exit(1);
            }
            macros[name.text] = m;
        } else if (op.type != op_type::NOP) {
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
