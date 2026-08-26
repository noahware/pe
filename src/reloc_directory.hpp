#pragma once
#include "addr.hpp"
#include "deps.hpp"

namespace pe
{
	enum class reloc_type : std::uint16_t
	{
		absolute = 0,
		high = 1,
		low = 2,
		highlow = 3,
		highadj = 4,
		machine_specific_5 = 5,
		reserved = 6,
		machine_specific_7 = 7,
		machine_specific_8 = 8,
		machine_specific_9 = 9,
		dir64 = 10
	};

	union reloc_entry
	{
		std::uint16_t raw;

		struct
		{
			std::uint16_t offset : 12;
			reloc_type type : 4;
		};
	};

	static_assert(sizeof(reloc_entry) == 0x2);

	struct reloc_block
	{
		std::uint32_t virtual_address;
		std::uint32_t size_of_block;
	};

	static_assert(sizeof(reloc_block) == 0x8);

	struct reloc_info
	{
		reloc_type type;
		const_bin_addr loc;
	};
}
