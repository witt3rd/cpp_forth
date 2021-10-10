#pragma once
#include <iostream>
#include <map>

template<typename A, typename B>
class bimap {
public:
    bimap(std::initializer_list<std::pair<A, B>> init) noexcept {
        try {
            auto it = init.begin();
            while (it != init.end()) {
                _a_b[it->first]  = it->second;
                _b_a[it->second] = it->first;
                it++;
            }
        } catch (std::exception const &e) {
            std::cerr << "[ERR] Exception: " << e.what() << std::endl;
            std::exit(1);
        }
    }

    A const &a(B const &b) const {
        return _b_a.at(b);
    };
    B const &b(const A &a) const {
        return _a_b.at(a);
    };

    bool has_a(A const &a) const { return _b_a.contains(a); }
    bool has_b(B const &b) const { return _b_a.contains(b); }

private:
    std::map<A, B> _a_b;
    std::map<B, A> _b_a;
};
