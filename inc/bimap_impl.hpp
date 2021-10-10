#include "bimap.hpp"

template<typename A, typename B>
bimap<A, B>::bimap(std::initializer_list<std::pair<A, B>> init) : _a_b(init) {
    auto it = init.begin();
    while (it != init.end()) {
        _b_a[it->second] = it->first;
        it++;
    }
}

template<typename A, typename B>
A &bimap<A, B>::a(B const &b) const {
    return _b_a.at(b);
}

template<typename A, typename B>
B &bimap<A, B>::b(A const &a) const {
    return _a_b.at(a);
}

template<typename A, typename B>
bool bimap<A, B>::has_a(A const &a) const {
    return _b_a.contains(a);
}

template<typename A, typename B>
bool bimap<A, B>::has_b(B const &b) const {
    return _b_a.contains(b);
}
