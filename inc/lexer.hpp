#pragma once

#include "bimap.hpp"
#include <fmt/format.h>
#include <string>
#include <vector>

enum class token_type {
    WHITESPACE,
    IDENTIFIER,
    STRING_LITERAL,
    INTEGER_LITERAL,
    FLOAT_LITERAL,
    DOT,
    COMMA,
    PLUS,
    MINUS,
    LESS_THAN,
    GREATER_THAN,
    EQUAL,
    SLASH,
    BACKSLASH,
    STAR,
    COMMENT,
};

struct token {
    token_type type{token_type::WHITESPACE};
    std::string file_path{};
    std::string text{};
    std::size_t line{1};
    std::size_t column{1};
};

std::vector<token> lex_file(std::string const &file_path);

std::string to_string(token_type t);
token_type to_token_type(std::string const &s);
std::string to_string(token const &t);