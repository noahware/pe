#pragma once
#include <cstdint>
#include "deps.hpp"
#include "addr.hpp"

namespace pe
{
	struct export_info
	{
		bool is_ordinal;
		std::uint32_t ordinal;
		string_view_t name;
		const_bin_addr loc;
	};

	struct export_directory
	{
		std::uint32_t characteristics;
		std::uint32_t time_date_stamp;
		std::uint16_t major_version;
		std::uint16_t minor_version;
		std::uint32_t name;
		std::uint32_t base;
		std::uint32_t number_of_functions;
		std::uint32_t number_of_names;
		std::uint32_t address_of_functions;
		std::uint32_t address_of_names;
		std::uint32_t address_of_name_ordinals;
	};

	static_assert(sizeof(export_directory) == 0x28);
}
