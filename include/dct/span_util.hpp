#ifndef SPAN_UTIL_HPP
#define SPAN_UTIL_HPP

// methods that should be in std::span (from https://en.cppreference.com/w/cpp/container/span)

#include <algorithm>
#include <span>
 
template<class T, std::size_t N> [[nodiscard]]
constexpr auto s_slide(std::span<T,N> s, std::size_t offset, std::size_t width) {
    return s.subspan(offset, offset + width <= s.size() ? width : 0U);
}
 
template<class T, std::size_t N, std::size_t M> [[nodiscard]]
constexpr bool s_starts_with(std::span<T,N> data, std::span<T,M> prefix) {
    return data.size() >= prefix.size() 
        && std::equal(prefix.begin(), prefix.end(), data.begin());
}
 
template<class T, std::size_t N, std::size_t M> [[nodiscard]]
constexpr bool s_ends_with(std::span<T,N> data, std::span<T,M> suffix) {
    return data.size() >= suffix.size() 
        && std::equal(data.end() - suffix.size(), data.end(), suffix.end() - suffix.size());
}
 
template<class T, std::size_t N, std::size_t M> [[nodiscard]]
constexpr bool s_contains(std::span<T,N> span, std::span<T,M> sub) {
    return std::search(span.begin(), span.end(), sub.begin(), sub.end()) != span.end();
}

#endif // SPAN_UTIL_HPP
