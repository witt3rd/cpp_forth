#pragma once
#include "lexer.hpp"
#include <fmt/format.h>
#include <map>
#include <string>

enum class op_t {
    // Stack
    PUSH_INT,
    PUSH_STR,
    DUP,
    DUP2,
    DROP,
    SWAP,
    OVER,
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

std::string to_string(op_t const t);
op_t to_op_t(std::string const& s);
bool is_op(std::string const& s);

struct op {
    op_t type;
    loc loc;
    int64_t int_value{};
    std::string str_value{};
    uint64_t jmp{};
};

std::string to_string(op const& op);
