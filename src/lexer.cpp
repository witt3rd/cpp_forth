#include "lexer.hpp"
#include <fstream>
#include <iostream>
#include <filesystem>

static bimap<token_type, std::string> const &get_token_bimap() {
    static bimap<token_type, std::string> const token_bimap{
            {token_type::WHITESPACE, "WHITESPACE"},
            {token_type::IDENTIFIER, "IDENTIFIER"},
            {token_type::CHAR_LITERAL, "CHAR_LITERAL"},
            {token_type::STRING_LITERAL, "STRING_LITERAL"},
            {token_type::INTEGER_LITERAL, "INTEGER_LITERAL"},
            {token_type::FLOAT_LITERAL, "FLOAT_LITERAL"},
            {token_type::DOT, "DOT"},
            {token_type::COMMA, "COMMA"},
            {token_type::PLUS, "PLUS"},
            {token_type::MINUS, "MINUS"},
            {token_type::LESS_THAN, "LESS_THAN"},
            {token_type::GREATER_THAN, "GREATER_THAN"},
            {token_type::EQUAL, "EQUAL"},
            {token_type::SLASH, "SLASH"},
            {token_type::BACKSLASH, "BACKSLASH"},
            {token_type::STAR, "STAR"},
            {token_type::COMMENT, "COMMENT"},
    };
    return token_bimap;
}

static void end_token(std::vector<token> &tokens, token &token) {
    if (!(token.type == token_type::WHITESPACE || token.type == token_type::COMMENT)) {
        tokens.push_back(token);
    }
    token.type = token_type::WHITESPACE;
    token.text.clear();
}

static std::vector<token> lex_stream(std::string const &file_path, std::istream &in_stream) {
    std::vector<token> tokens{};
    token cur_token{.file_path = file_path};
    size_t column = 1;
    char ch;
    bool is_escaped{false};
    while (in_stream.get(ch) && !in_stream.eof()) {
//        std::cout << fmt::format("{:03}) [{:03}] {}", column, int(ch), ch) << std::endl;
        if (cur_token.type == token_type::COMMENT) {
            if (ch == '\n') {
                end_token(tokens, cur_token);
                cur_token.line++;
                column = 1;
                continue;
            } else {
                cur_token.text += ch;
            }
        } else if (cur_token.type == token_type::STRING_LITERAL || cur_token.type == token_type::CHAR_LITERAL) {
            if (ch == '\\' && !is_escaped) {
                is_escaped = true;
            } else if ((ch == '\"' || ch == '\'') && !is_escaped) {
                end_token(tokens, cur_token);
            } else {
                if (is_escaped) {
                    switch (ch) {
                        case 0:
                            ch = '\0';
                            break;
                        case 'a':
                            ch = '\a';
                            break;
                        case 'b':
                            ch = '\b';
                            break;
                        case 'f':
                            ch = '\f';
                            break;
                        case 'n':
                            ch = '\n';
                            break;
                        case 'r':
                            ch = '\r';
                            break;
                        case 't':
                            ch = '\t';
                            break;
                        case 'v':
                            ch = '\v';
                            break;
                        case '\\':
                            ch = '\\';
                            break;
                        case '\'':
                            ch = '\'';
                            break;
                        case '"':
                            ch = '\"';
                            break;
                        case '?':
                            ch = '\?';
                            break;
                        default:
                            std::cerr << "[ERR] unsupported escape sequence: " << int(ch) << std::endl;
                            std::exit(1);
                    }
                    is_escaped = false;
                }
                cur_token.text += ch;
            }
        } else {
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
                case '9':
                    if (cur_token.type == token_type::WHITESPACE) {
                        cur_token.type   = token_type::INTEGER_LITERAL;
                        cur_token.text   = ch;
                        cur_token.column = column;
                    } else {
                        cur_token.text += ch;
                    }
                    break;
                case '\'':
                    end_token(tokens, cur_token);
                    cur_token.type   = token_type::CHAR_LITERAL;
                    cur_token.column = column;
                    break;
                case '\"':
                    end_token(tokens, cur_token);
                    cur_token.type   = token_type::STRING_LITERAL;
                    cur_token.column = column;
                    break;
                case '.':
                    if (cur_token.type == token_type::INTEGER_LITERAL) {
                        cur_token.type = token_type::FLOAT_LITERAL;
                        cur_token.text += ch;
                    } else {
                        cur_token.type   = token_type::DOT;
                        cur_token.column = column;
                    }
                    break;
                case ',':
                    cur_token.type   = token_type::COMMA;
                    cur_token.column = column;
                    break;
                case '+':
                    cur_token.type   = token_type::PLUS;
                    cur_token.column = column;
                    break;
                case '-':
                    cur_token.type   = token_type::MINUS;
                    cur_token.column = column;
                    break;
                case '<':
                    cur_token.type   = token_type::LESS_THAN;
                    cur_token.column = column;
                    break;
                case '>':
                    cur_token.type   = token_type::GREATER_THAN;
                    cur_token.column = column;
                    break;
                case '=':
                    cur_token.type   = token_type::EQUAL;
                    cur_token.column = column;
                    break;
                case ' ':
                case '\t':
                case '\r':
                    end_token(tokens, cur_token);
                    break;

                case '\n':
                    end_token(tokens, cur_token);
                    cur_token.line++;
                    column = 1;
                    continue;

                case '/':
                    if (cur_token.type == token_type::WHITESPACE) {
                        cur_token.type = token_type::SLASH;
                    } else if (cur_token.type == token_type::SLASH) {
                        cur_token.type = token_type::COMMENT;
                    } else {
                        end_token(tokens, cur_token);
                        cur_token.type = token_type::SLASH;
                    }
                    cur_token.column = column;
                    break;

                default:
                    // allow identifiers to start with an integer (e.g., "2dup")
                    if (cur_token.type == token_type::WHITESPACE || cur_token.type == token_type::INTEGER_LITERAL) {
                        cur_token.type = token_type::IDENTIFIER;
                        cur_token.column = column;
                    }
                    cur_token.text += (char) toupper(ch);
                    break;
            }
        }
        column++;
    }
    end_token(tokens, cur_token);
    return tokens;
}

std::vector<token> lex_file(std::string const &file_path) {
    std::cout << fmt::format("[INF] lexing file: {}", file_path) << std::endl;

    std::ifstream f{file_path};
    if (!f.is_open()) {
        auto cwd = std::filesystem::current_path();
        std::cerr << fmt::format("[ERR] unable to open input file: {}, cwd: {}", file_path, cwd.c_str()) << std::endl;
        std::exit(1);
    }

    auto tokens = lex_stream(file_path, f);

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
    return fmt::format("{}:{}:{} {}: {}", t.file_path, t.line, t.column, to_string(t.type), t.text);
}