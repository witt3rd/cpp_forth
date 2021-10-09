#include "op.hpp"

std::map<op_t, std::string> const _op_words{
        // Stack
        {op_t::PUSH_INT, "PUSH_INT"},
        {op_t::PUSH_STR, "PUSH_STR"},
        {op_t::DUP, "DUP"},
        {op_t::DUP2, "2DUP"},
        {op_t::DROP, "DROP"},
        {op_t::SWAP, "SWAP"},
        {op_t::OVER, "OVER"},
        {op_t::DUMP, "DUMP"},
        // Arithmetic
        {op_t::PLUS, "+"},
        {op_t::MINUS, "-"},
        {op_t::EQUAL, "="},
        {op_t::GT, ">"},
        {op_t::LT, "<"},
        // Bitwise
        {op_t::SHR, "SHR"},
        {op_t::SHL, "SHL"},
        {op_t::BOR, "BOR"},
        {op_t::BAND, "BAND"},
        // Conditional
        {op_t::IF, "IF"},
        {op_t::ELSE, "ELSE"},
        {op_t::END, "END"},
        // Loop
        {op_t::WHILE, "WHILE"},
        {op_t::DO, "DO"},
        // Memory
        {op_t::MEM, "MEM"},
        {op_t::LOAD, ","},
        {op_t::STORE, "."},
        // System
        {op_t::SYSCALL1, "SYSCALL1"},
        {op_t::SYSCALL2, "SYSCALL2"},
        {op_t::SYSCALL3, "SYSCALL3"},
        {op_t::SYSCALL4, "SYSCALL4"},
        {op_t::SYSCALL5, "SYSCALL5"},
        {op_t::SYSCALL6, "SYSCALL6"}};

std::map<std::string, op_t> _word_ops;// generated from op_words

std::string to_string(op_t const t) {
    return _op_words.at(t);
}

std::map<std::string, op_t> const& get_word_ops() {
    if (_word_ops.empty()) {
        // generate lookup table
        auto it = _op_words.cbegin();
        while (it != _op_words.cend()) {
            _word_ops[it->second] = it->first;
            it++;
        }
    }
    return _word_ops;
}

op_t to_op_t(std::string const& s) {
    return get_word_ops().at(s);
}

bool is_op(std::string const& s) {
    return get_word_ops().contains(s);
}

std::string to_string(op const& o) {
    return fmt::format("type: {}, loc: {}, int_value: {}, str_value: {}, jmp: {}", to_string(o.type), o.loc.to_string(), o.int_value, o.str_value, o.jmp);
}
