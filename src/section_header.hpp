#pragma once
#include "deps.hpp"

namespace pe
{
	struct section_header
	{
		static constexpr std::size_t short_name_length = 8;

		char short_name[short_name_length];
		std::uint32_t virtual_size;
		std::uint32_t virtual_address;
		std::uint32_t size_of_raw_data;
		std::uint32_t pointer_to_raw_data;
		std::uint32_t pointer_to_relocations;
		std::uint32_t pointer_to_linenumbers;
		std::uint16_t number_of_relocations;
		std::uint16_t number_of_linenumbers;
		std::uint32_t characteristics;

		[[nodiscard]] string_view_t name() const noexcept
		{
			const auto view = string_view_t{ short_name, short_name_length };

			return view.substr(0, view.find('\0'));
		}
	};

	static_assert(sizeof(section_header) == 0x28);
}
