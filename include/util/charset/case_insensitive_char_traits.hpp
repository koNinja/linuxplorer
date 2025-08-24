#ifndef LINUXPLORER_CASE_INSENSITIVE_CHAR_TRAITS_HPP_
#define LINUXPLORER_CASE_INSENSITIVE_CHAR_TRAITS_HPP_

#include <string>

namespace linuxplorer::util::charset {
	template <class T>
	class case_insensitive_char_traits : std::char_traits<T> {
		using base_traits = std::char_traits<T>;
	public:
		using char_type = T;
		using int_type = int;
		using off_type = std::streamoff;
		using pos_type = std::streampos;
		using state_type = std::mbstate_t;
		using comparison_category = std::weak_ordering;

		static constexpr void assign(char_type& c1, const char_type& c2) noexcept {
			base_traits::assign(c1, c2);
		}

		static constexpr bool eq(char_type c1, char_type c2) noexcept {
			return base_traits::eq(std::tolower(c1), std::tolower(c2));
		}

		static constexpr bool lt(char_type c1, char_type c2) noexcept {
			return base_traits::lt(std::tolower(c1), std::tolower(c2));
		}

		static constexpr int compare(const char_type* s1, const char_type* s2, size_t n) {
			auto order = std::lexicographical_compare_three_way(s1, s1 + n, s2, s2 + n,
				[](char_type c1, char_type c2) -> std::weak_ordering {
					return std::tolower(c1) <=> std::tolower(c2);
				});
			return order == std::weak_ordering::equivalent ? 0 :
				order == std::weak_ordering::greater ? 1 :
				-1;
		}

		static constexpr size_t length(const char_type* s) {
			return base_traits::length(s);
		}

		static constexpr const char_type* find(const char_type* s, size_t n,
			const char_type& a) {
			return std::find_if(s, s + n, [a](char_type c) {
				return std::tolower(c) == a;
				});
		}

		static constexpr char_type* move(char_type* s1, const char_type* s2, size_t n) {
			return base_traits::move(s1, s2, n);
		}

		static constexpr char_type* copy(char_type* s1, const char_type* s2, size_t n) {
			return base_traits::copy(s1, s2, n);
		}

		static constexpr char_type* assign(char_type* s, size_t n, char_type a) {
			return base_traits::assign(s, n, a);
		}
	};
}

#endif // LINUXPLORER_CASE_INSENSITIVE_CHAR_TRAITS_HPP_