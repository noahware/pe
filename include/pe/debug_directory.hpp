#pragma once
#include "deps.hpp"

#include <cstring>

namespace pe
{
	struct guid
	{
		std::uint32_t data1;
		std::uint16_t data2;
		std::uint16_t data3;
		std::uint8_t data4[8];
	};

	static_assert(sizeof(guid) == 0x10);

	struct codeview_rsds
	{
		static constexpr std::uint32_t rsds_signature = 0x53445352;

		std::uint32_t signature;
		guid guid;
		std::uint32_t age;
		char pdb_file_name[1];

		[[nodiscard]] bool ok() const noexcept { return signature == rsds_signature; }
		[[nodiscard]] explicit operator bool() const noexcept { return ok(); }

		[[nodiscard]] string_view_t pdb_path() const noexcept
		{
			return pdb_file_name;
		}
	};

	static_assert(offsetof(codeview_rsds, pdb_file_name) == 0x18);
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
