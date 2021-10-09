#pragma once

#include <fmt/format.h>
#include <string>
#include <vector>

struct loc {
    std::string file_path;
    uint64_t row;
    uint64_t col;
    std::string to_string() const {
        return fmt::format("{}({:03}:{:03})", file_path, row, col);
    }
};

enum class tok_t {
    WORD,
    INT,
    STRING,
};

struct tok {
    tok_t type;
    loc loc;
    std::string raw_text;
    std::int64_t integer;
    std::string text;
};

struct lexer {
    tok lex_word(loc const& loc, std::string const& word);
    std::vector<tok> lex_line(std::string const& file_path, uint64_t const row, std::string const& line);
    std::vector<tok> lex_file(std::string const& file_path);
};
