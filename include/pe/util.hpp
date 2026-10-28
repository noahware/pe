#pragma once
#include "deps.hpp"

namespace pe
{
	// string literal wrapper so a string can be a template argument
	template <std::size_t N>
	struct fixed_string
	{
		char str[N]{};

		constexpr fixed_string(const char (&s)[N]) noexcept
		{
			for (std::size_t i = 0; i < N; i++)
				str[i] = s[i];
		}

		[[nodiscard]] constexpr string_view_t view() const noexcept
		{
			return { str, N - 1 };
		}
	};
}
