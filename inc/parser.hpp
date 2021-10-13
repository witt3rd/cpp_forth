#pragma once
#include "bimap.hpp"
#include "lexer.hpp"
#include <fmt/format.h>
#include <string>
#include <utility>
#include <vector>

enum class op_type {
    // Stack
    PUSH_INT,
    PUSH_STR,
    DUP,
    DROP,
    SWAP,
    OVER,
    PRINT,
    // Arithmetic
    PLUS,
    MINUS,
    MUL,
    DIVMOD,
    EQUAL,
    LT,
    LTE,
    GT,
    GTE,
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

struct op {
    op_type type;
    token token;
    std::string str_value{};
    union {
        int64_t int_value{};
        uint64_t jmp_addr;
        uint64_t str_addr;
    };
};

struct macro {
    token macro_token;
    std::vector<token> body_tokens;
};

std::vector<op> parse(std::vector<token> &tokens, std::map<std::string, macro> &macros);

std::string to_string(op_type t);
op_type to_op_type(std::string const &s);
bool is_op(std::string const &s);
std::string to_string(op const &o);

