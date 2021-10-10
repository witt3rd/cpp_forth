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
    OPERATOR,
};

struct token {
    token_type type{token_type::WHITESPACE};
    std::string file_path{};
    std::string text{};
    std::size_t row{0};
    std::size_t column{0};
};

std::vector<token> lex_file(std::string const &file_path);
std::vector<token> lex_stream(std::istream &in_stream);

std::string to_string(token_type t);
token_type to_token_type(std::string const &s);
std::string to_string(token const &t);