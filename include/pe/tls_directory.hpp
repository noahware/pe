#pragma once
#include "deps.hpp"

namespace pe
{
	union tls_characteristics_t
	{
		struct
		{
			std::uint32_t _pad0 : 20;
			// stored as a log2 exponent biased by one, so 0 means unspecified
			std::uint32_t alignment : 4;
			std::uint32_t _pad1 : 8;
		};

		std::uint32_t flags;
	};

	static_assert(sizeof(tls_characteristics_t) == 0x4);

	struct tls_directory
	{
		// only 64 bit supported for now, x86 uses std::uint32_t
		using value_type = std::uint64_t;

		// every address in here is a va, not an rva
		value_type start_address_of_raw_data;
		value_type end_address_of_raw_data;
		value_type address_of_index;
		value_type address_of_call_backs;
		std::uint32_t size_of_zero_fill;
		tls_characteristics_t characteristics;
	};

	static_assert(offsetof(tls_directory, address_of_call_backs) == 0x18);
	static_assert(sizeof(tls_directory) == 0x28);
}
