#pragma once
#include "addr.hpp"
#include "deps.hpp"

namespace pe
{
	struct import_info
	{
		bool is_ordinal;
		std::uint32_t ordinal;
		string_view_t name;
		const_bin_addr iat_slot;
	};

	struct import_by_name
	{
		std::uint16_t hint;
		char name[1];

		[[nodiscard]] string_view_t str() const noexcept
		{
			return name;
		}
	};

	static_assert(sizeof(import_by_name) == 0x4);

	struct thunk_data
	{
		union
		{
			std::uint64_t raw;

			struct
			{
				std::uint64_t ordinal : 16;
				std::uint64_t : 47;
				std::uint64_t is_ordinal : 1;
			};

			struct
			{
				std::uint64_t address_of_data : 31;
				std::uint64_t : 33;
			};
		};

		[[nodiscard]] bool used() const noexcept
		{
			return raw != 0;
		}
	};

	static_assert(sizeof(thunk_data) == 0x8);

	struct import_directory
	{
		std::uint32_t original_first_thunk;
		std::uint32_t time_date_stamp;
		std::uint32_t forwarder_chain;
		std::uint32_t name;
		std::uint32_t first_thunk;
	};

	static_assert(sizeof(import_directory) == 0x14);
}
