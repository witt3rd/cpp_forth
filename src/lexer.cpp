#include "lexer.hpp"
#include "op.hpp"
#include <fstream>
#include <iostream>

[[noreturn]] void token_error(const loc& loc, const std::string& raw_text, const std::string& msg) {
    std::cout << fmt::format("[ERR] {} '{}': {}", loc.to_string(), raw_text, msg) << std::endl;
    std::exit(1);
}

tok lexer::lex_word(loc const& loc, std::string const& word) {
    std::string kw = word;
    std::transform(kw.begin(), kw.end(), kw.begin(), ::toupper);
    std::cout << fmt::format("==> {}", kw) << std::endl;
    if (is_op(kw)) {
        return tok{.type = tok_t::WORD, .loc = loc, .raw_text = word, .text = kw};
    }

    try {
        return tok{.type = tok_t::INT, .loc = loc, .raw_text = word, .integer = std::stoll(word)};
    } catch (std::out_of_range const& e) {
        token_error(loc, word, "Numeric value out of range");
    } catch (std::invalid_argument const& e) {
        std::cerr << "[ERR] Unsupported word: " << word << std::endl;
        std::exit(1);
    }
}

std::vector<tok> lexer::lex_line(std::string const& file_path, uint64_t const row, std::string const& line) {
    std::vector<tok> tokens;
    uint64_t col{0};
    bool is_word{false};
    std::string cur_word;
    uint64_t cur_word_col{};

    // remove comment (if any)
    auto no_comment = line.substr(0, line.find("//"));

    for (auto c : no_comment) {
        if (std::isspace(c)) {
            if (is_word) {
                loc loc{file_path, row + 1, cur_word_col};// 1-based row numbering
                tokens.push_back(lex_word(loc, cur_word));
                is_word = false;
                cur_word.clear();
            }
        } else {
            if (is_word) {
                cur_word += c;
            } else {
                cur_word     = c;
                cur_word_col = col;
                is_word      = true;
            }
        }
        col++;
    }

    // left over
    if (is_word) {
        loc loc{file_path, row + 1, cur_word_col};// 1-based row numbering fs
        tokens.push_back(lex_word(loc, cur_word));
    }
    return tokens;
}

std::vector<tok> lexer::lex_file(std::string const& file_path) {
    //    if (is_debug) std::cout << "***** lexing file *****" << std::endl;
    std::ifstream f(file_path);
    if (!f.is_open()) {
        std::cerr << "[ERR] Unable to open input file" << std::endl;
        std::exit(1);
    }

    std::vector<tok> tokens;
    std::string line;
    uint64_t row{0};

    while (std::getline(f, line)) {
        auto line_tokens = lex_line(file_path, row, line);
        tokens.insert(tokens.cend(), line_tokens.cbegin(), line_tokens.cend());
        row++;
    }

    f.close();

    return tokens;
}
