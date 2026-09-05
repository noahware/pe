#pragma once
#include <cstddef>
#include <cstdint>

#if defined(PE_DEPS_HDR)
#	include PE_DEPS_HDR
#else
#	include <charconv>
#	include <ranges>
#	include <vector>
#	include <span>
#	include <string_view>

// the only place in the library that names std:: containers and range adaptors

namespace pe
{
	template <class T>
	using span_t = std::span<T>;

	template <class T>
	using vector_t = std::vector<T>;

	using string_view_t = std::string_view;

	// bounded by an end pointer, unlike the strto* family which read as far as the digits go
	using std::from_chars;

	namespace ranges
	{
		using std::ranges::find;
	}

	namespace views
	{
		using std::views::filter;
		using std::views::iota;
		using std::views::join;
		using std::views::take_while;
		using std::views::transform;
	}
}
#endif
