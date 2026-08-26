#pragma once
#include <cstdint>
#include <cstddef>

namespace pe
{
	struct data_directory
	{
		static constexpr std::size_t count = 16;

		std::uint32_t virtual_address;
		std::uint32_t size;

		[[nodiscard]] bool used() const noexcept
		{
			return size != 0;
		}

		[[nodiscard]] explicit operator bool() const noexcept
		{
			return used();
		}
	};

	static_assert(sizeof(data_directory) == 0x8);

	union data_directories
	{
		struct
		{
			data_directory exports;
			data_directory imports;
			data_directory resource;
			data_directory exception;
			data_directory security;
			data_directory basereloc;
			data_directory debug;
			data_directory architecture;
			data_directory globalptr;
			data_directory tls;
			data_directory load_config;
			data_directory bound_import;
			data_directory iat;
			data_directory delay_import;
			data_directory com_descriptor;
			data_directory reserved;
		};

		data_directory entries[data_directory::count];
	};

	static_assert(sizeof(data_directories) == 0x80);
}
