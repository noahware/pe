#pragma once
#include "deps.hpp"

namespace pe
{
	enum class debug_directory_type : std::uint32_t
	{
		unknown = 0,
		coff = 1,
		codeview = 2,
		fpo = 3,
		misc = 4,
		exception = 5,
		fixup = 6,
		omap_to_src = 7,
		omap_from_src = 8,
		borland = 9,
		reserved_10 = 10,
		clsid = 11,
		vc_feature = 12,
		pogo = 13,
		iltcg = 14,
		mpx = 15,
		repro = 16,
		undefined_17 = 17,
		reserved_18 = 18,
		undefined_19 = 19,
		ex_dll_characteristics = 20
	};

	struct debug_directory
	{
		std::uint32_t characteristics;
		std::uint32_t time_date_stamp;
		std::uint16_t major_version;
		std::uint16_t minor_version;
		debug_directory_type type;
		std::uint32_t size_of_data;
		std::uint32_t address_of_raw_data;
		std::uint32_t pointer_to_raw_data;
	};

	static_assert(sizeof(debug_directory) == 0x1C);
}
