#pragma once
#include <cstdint>

#include "data_directory.hpp"
#include "section_header.hpp"

namespace pe
{
	struct file_header
	{
		std::uint16_t machine;
		std::uint16_t number_of_sections;
		std::uint32_t time_date_stamp;
		std::uint32_t pointer_to_symbol_table;
		std::uint32_t number_of_symbols;
		std::uint16_t size_of_optional_header;
		std::uint16_t characteristics;
	};

	static_assert(sizeof(file_header) == 0x14);

	struct optional_header64
	{
		// only 64 bit supported for now
		static constexpr std::uint16_t hdr64_magic = 0x20b;

		std::uint16_t magic;
		std::uint8_t major_linker_version;
		std::uint8_t minor_linker_version;
		std::uint32_t size_of_code;
		std::uint32_t size_of_initialized_data;
		std::uint32_t size_of_uninitialized_data;
		std::uint32_t address_of_entry_point;
		std::uint32_t base_of_code;
		std::uint64_t image_base;
		std::uint32_t section_alignment;
		std::uint32_t file_alignment;
		std::uint16_t major_operating_system_version;
		std::uint16_t minor_operating_system_version;
		std::uint16_t major_image_version;
		std::uint16_t minor_image_version;
		std::uint16_t major_subsystem_version;
		std::uint16_t minor_subsystem_version;
		std::uint32_t win32_version_value;
		std::uint32_t size_of_image;
		std::uint32_t size_of_headers;
		std::uint32_t check_sum;
		std::uint16_t subsystem;
		std::uint16_t dll_characteristics;
		std::uint64_t size_of_stack_reserve;
		std::uint64_t size_of_stack_commit;
		std::uint64_t size_of_heap_reserve;
		std::uint64_t size_of_heap_commit;
		std::uint32_t loader_flags;
		std::uint32_t number_of_rva_and_sizes;
		data_directories data_dirs;

		[[nodiscard]] bool ok() const noexcept
		{
			return magic == hdr64_magic;
		}

		[[nodiscard]] explicit operator bool() const noexcept
		{
			return ok();
		}
	};

	static_assert(sizeof(optional_header64) == 0xf0);

	struct nt_headers
	{
		static constexpr std::uint32_t nt_signature = 0x00004550;

		std::uint32_t signature;
		file_header file_hdr;
		optional_header64 optional_hdr;

		[[nodiscard]] section_header* first_section_hdr() noexcept
		{
			const auto& self = *this;

			return const_cast<section_header*>(self.first_section_hdr());
		}

		[[nodiscard]] const section_header* first_section_hdr() const noexcept
		{
			return reinterpret_cast<const section_header*>(reinterpret_cast<const std::uint8_t*>(&optional_hdr) + file_hdr.size_of_optional_header);
		}

		[[nodiscard]] std::uint16_t num_sections() const noexcept
		{
			return file_hdr.number_of_sections;
		}

		[[nodiscard]] bool ok() const noexcept
		{
			return signature == nt_signature && optional_hdr.ok();
		}

		[[nodiscard]] explicit operator bool() const noexcept
		{
			return ok();
		}
	};

	static_assert(sizeof(nt_headers) == 0x108);
}
