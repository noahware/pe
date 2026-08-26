#pragma once
#include "deps.hpp"

namespace pe
{
	union delay_load_attributes_t
	{
		struct
		{
			std::uint32_t rva_based : 1;
			std::uint32_t reserved : 31;
		};

		std::uint32_t flags;
	};

	static_assert(sizeof(delay_load_attributes_t) == 0x4);

	struct delay_load_descriptor
	{
		// the fields below are vas rather than rvas when rva_based is not set
		delay_load_attributes_t attributes;
		std::uint32_t dll_name_rva;
		std::uint32_t module_handle_rva;
		std::uint32_t import_address_table_rva;
		std::uint32_t import_name_table_rva;
		std::uint32_t bound_import_address_table_rva;
		std::uint32_t unload_information_table_rva;
		std::uint32_t time_date_stamp;
	};

	static_assert(sizeof(delay_load_descriptor) == 0x20);
}
