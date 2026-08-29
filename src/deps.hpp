#pragma once
#include <cstddef>
#include <cstdint>
#include <optional>
#include <ranges>
#include <span>
#include <string_view>

// the only place in the library that names std:: containers and range adaptors

namespace pe
{
	template <class T>
	using span_t = std::span<T>;

	template <class T>
	using optional_t = std::optional<T>;

	using string_view_t = std::string_view;

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
