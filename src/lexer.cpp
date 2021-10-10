#include "lexer.hpp"
#include <cstddef>
#include <fstream>
#include <iostream>

bimap<token_type, std::string> const &get_token_bimap() {
    static bimap<token_type, std::string> const token_bimap{
            {token_type::WHITESPACE, "WHITESPACE"},
            {token_type::IDENTIFIER, "IDENTIFIER"},
            {token_type::OPERATOR, "OPERATOR"},
            {token_type::STRING_LITERAL, "STRING_LITERAL"},
            {token_type::INTEGER_LITERAL, "INTEGER_LITERAL"},
            {token_type::FLOAT_LITERAL, "FLOAT_LITERAL"}};
    return token_bimap;
}

std::vector<token> lex_stream(std::istream &in_stream) {
    std::vector<token> tokens{};
    std::size_t cur_row{0};
    std::size_t cur_col{0};
    token cur_tok{};

    char ch;
    while (in_stream.get(ch) && !in_stream.eof()) {
        cur_col++;
        std::cout.put(ch);
        switch (ch) {
            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9': {
                if (cur_tok.type == token_type::WHITESPACE) {
                    cur_tok.type = token_type::INTEGER_LITERAL;
                    cur_tok.text += ch;
                } else {
                    cur_tok.text += ch;
                }
                break;
            }
            case '.': {
                break;
            }
            case ' ':
            case '\t':
            case '\r': {
                break;
            }
            case '\n': {
                cur_row++;
                cur_col = 0;
            }
            default: {
            }
        }
    }
    return tokens;
}

std::vector<token> lex_file(std::string const &file_path) {
    std::cout << "***** lexing file *****" << std::endl;

    std::ifstream f{file_path};
    if (!f.is_open()) {
        std::cerr << "[ERR] Unable to open input file" << std::endl;
        std::exit(1);
    }

    auto tokens = lex_stream(f);

    f.close();

    return tokens;
}

std::string to_string(token_type t) {
    return get_token_bimap().b(t);
}
token_type to_token_type(std::string const &s) {
    return get_token_bimap().a(s);
}
std::string to_string(token const &t) {
    return fmt::format("{}:{}:{} {}:\"{}\"", t.file_path, t.row, t.column, to_string(t.type), t.text);
}