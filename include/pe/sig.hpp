#pragma once
#include "util.hpp"
#include "image.hpp"

// definitions of image's sig_scan members, takes IDA format signatures (e.g. "E8 ? ? ? ? E9")

namespace pe
{
	namespace sig_detail
	{
		using bytes_t = vector_t<std::int16_t>; // -1 = wildcard
		using bytes_view_t = span_t<const std::int16_t>;

		[[nodiscard]] constexpr int hex_value(const char c) noexcept
		{
			if (c >= '0' && c <= '9')
				return c - '0';

			if (c >= 'a' && c <= 'f')
				return c - 'a' + 10;

			if (c >= 'A' && c <= 'F')
				return c - 'A' + 10;

			return -1;
		}

		// emits -1 for a wildcard, returns false on a malformed signature
		template <class F>
		[[nodiscard]] constexpr bool walk(const string_view_t s, F&& emit) noexcept(noexcept(emit(std::int16_t{})))
		{
			for (std::size_t i = 0; i < s.size();)
			{
				if (s[i] == ' ')
				{
					i++;
					continue;
				}

				if (s[i] == '?')
				{
					emit(std::int16_t{ -1 });

					// for sigs that have double wild card format (e.g. "E8 ?? ?? ?? ?? E9")
					i += i + 1 < s.size() && s[i + 1] == '?' ? 2 : 1;
					continue;
				}

				// two hex digits at a time, so "E8FF" stays two bytes rather than one value
				const int hi = hex_value(s[i]);
				const int lo = i + 1 < s.size() ? hex_value(s[i + 1]) : -1;

				if (hi < 0 || lo < 0)
					return false;

				emit(static_cast<std::int16_t>(hi << 4 | lo));
				i += 2;
			}

			return true;
		}

		[[nodiscard]] inline bytes_t parse(const string_view_t str)
		{
			bytes_t bytes;
			bytes.reserve(str.size() / 3);

			if (!walk(str, [&bytes](const std::int16_t b) { bytes.push_back(b); }))
				return {};

			return bytes;
		}

		// compile time parse, a malformed or empty signature fails to compile
		template <fixed_string Sig>
		[[nodiscard]] constexpr auto parse() noexcept
		{
			constexpr auto count = []
			{
				std::size_t n = 0;
				const bool ok = walk(Sig.view(), [&n](std::int16_t) { n++; });

				return ok ? n : 0;
			}();

			static_assert(count > 0, "malformed or empty signature");

			array_t<std::int16_t, count> bytes{};
			std::size_t i = 0;

			(void)walk(Sig.view(), [&](const std::int16_t b) { bytes[i++] = b; });

			return bytes;
		}

		[[nodiscard]] inline const std::uint8_t* scan(const bytes_view_t bytes, const std::uint8_t* const start,
		                                              const std::uint8_t* const end) noexcept
		{
			for (auto curr = start; curr < end - bytes.size(); curr++)
			{
				bool found = true;

				for (std::size_t i = 0; i < bytes.size(); i++)
				{
					const auto byte = bytes[i];

					if (byte != -1 && byte != *(curr + i))
					{
						found = false;
						break;
					}
				}

				if (found)
				{
					return curr;
				}
			}

			return nullptr;
		}

		[[nodiscard]] inline const std::uint8_t* scan(const image& img, const bytes_view_t bytes,
		                                              const bool skip_pageable, const bool skip_data) noexcept
		{
			if (bytes.empty())
			{
				return nullptr;
			}

			for (const auto& seg : img.sections())
			{
				if (skip_data && !seg.characteristics.cnt_code)
					continue;

				if (skip_pageable && !seg.characteristics.mem_not_paged)
					continue;

				const auto start = img.as() + seg.virtual_address;
				const auto end = start + seg.virtual_size;

				if (const auto found = scan(bytes, start, end))
					return found;
			}

			return nullptr;
		}
	}

	template <class T>
	T image::sig_scan(const string_view_t str, const bool skip_pageable, const bool skip_data) noexcept
	{
		const auto& self = *this;

		return reinterpret_cast<T>(const_cast<std::uint8_t*>(self.sig_scan<const std::uint8_t*>(str, skip_pageable, skip_data)));
	}

	template <class T>
	T image::sig_scan(const string_view_t str, const bool skip_pageable, const bool skip_data) const noexcept
	{
		const auto bytes = sig_detail::parse(str);

		return reinterpret_cast<T>(sig_detail::scan(*this, bytes, skip_pageable, skip_data));
	}

	template <class T>
	T image::sig_scan(const string_view_t str, const std::uint8_t* const begin, const std::uint8_t* const end) noexcept
	{
		const auto bytes = sig_detail::parse(str);
		const auto found = const_cast<std::uint8_t*>(sig_detail::scan(bytes, begin, end));

		return reinterpret_cast<T>(found);
	}

	template <fixed_string Sig, class T>
	T image::sig_scan(const bool skip_pageable, const bool skip_data) noexcept
	{
		const auto& self = *this;

		return reinterpret_cast<T>(const_cast<std::uint8_t*>(self.sig_scan<Sig, const std::uint8_t*>(skip_pageable, skip_data)));
	}

	template <fixed_string Sig, class T>
	T image::sig_scan(const bool skip_pageable, const bool skip_data) const noexcept
	{
		static constexpr auto bytes = sig_detail::parse<Sig>();

		return reinterpret_cast<T>(sig_detail::scan(*this, sig_detail::bytes_view_t{ bytes }, skip_pageable, skip_data));
	}

	template <fixed_string Sig, class T>
	T image::sig_scan(const std::uint8_t* const begin, const std::uint8_t* const end) noexcept
	{
		static constexpr auto bytes = sig_detail::parse<Sig>();
		const auto found = const_cast<std::uint8_t*>(sig_detail::scan(sig_detail::bytes_view_t{ bytes }, begin, end));

		return reinterpret_cast<T>(found);
	}
}
