#pragma once
#include "addr.hpp"
#include "deps.hpp"

namespace pe
{
	struct import_info
	{
		string_view_t module_name;
		string_view_t import_name;
		bool is_ordinal;
		std::uint32_t ordinal;
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

	union thunk_data
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

	// the delayed table has the same thunk layout, only its rvas are found through a different descriptor
	[[nodiscard]] inline auto import_thunks(const std::uint8_t* const base, const std::uint32_t name_rva,
		const std::uint32_t lookup_rva, const std::uint32_t iat_rva) noexcept
	{
		const auto* thunks = reinterpret_cast<const thunk_data*>(base + lookup_rva);

		const auto module_name = name_rva
			? string_view_t{ reinterpret_cast<const char*>(base + name_rva) }
			: string_view_t{};

		return views::iota(0u)
			| views::take_while([thunks](const std::uint32_t t) { return thunks[t].used(); })
			| views::transform([base, thunks, iat_rva, module_name](const std::uint32_t t) -> import_info
				{
					const auto& thunk = thunks[t];

					auto import_name = string_view_t{};
					auto ordinal = std::uint32_t{};

					if (thunk.is_ordinal)
					{
						ordinal = static_cast<std::uint32_t>(thunk.ordinal);
					}
					else
					{
						import_name = reinterpret_cast<const import_by_name*>(base + thunk.address_of_data)->str();
					}

					const auto slot_rva = iat_rva + static_cast<std::uint32_t>(t * sizeof(thunk_data));

					return import_info{ module_name, import_name, thunk.is_ordinal != 0, ordinal, const_bin_addr{ base, slot_rva } };
				});
	}
}
