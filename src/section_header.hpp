#pragma once
#include "deps.hpp"

namespace pe
{
	union section_characteristics_t
	{
		struct
		{
			std::uint32_t _pad0 : 5;
			std::uint32_t cnt_code : 1;
			std::uint32_t cnt_init_data : 1;
			std::uint32_t cnt_uninit_data : 1;
			std::uint32_t _pad1 : 1;
			std::uint32_t lnk_info : 1;
			std::uint32_t _pad2 : 1;
			std::uint32_t lnk_remove : 1;
			std::uint32_t lnk_comdat : 1;
			std::uint32_t _pad3 : 1;
			std::uint32_t no_defer_spec_exc : 1;
			std::uint32_t mem_far : 1;
			std::uint32_t _pad4 : 1;
			std::uint32_t mem_purgeable : 1;
			std::uint32_t mem_locked : 1;
			std::uint32_t mem_preload : 1;
			std::uint32_t alignment : 4;
			std::uint32_t lnk_nreloc_ovfl : 1;
			std::uint32_t mem_discardable : 1;
			std::uint32_t mem_not_cached : 1;
			std::uint32_t mem_not_paged : 1;
			std::uint32_t mem_shared : 1;
			std::uint32_t mem_execute : 1;
			std::uint32_t mem_read : 1;
			std::uint32_t mem_write : 1;
		};

		std::uint32_t flags;
	};

	static_assert(sizeof(section_characteristics_t) == 0x4);

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
		section_characteristics_t characteristics;

		[[nodiscard]] string_view_t name() const noexcept
		{
			const auto view = string_view_t{ short_name, short_name_length };

			return view.substr(0, view.find('\0'));
		}
	};

	static_assert(sizeof(section_header) == 0x28);
}
