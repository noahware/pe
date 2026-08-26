#pragma once
#include <cstdint>

namespace pe
{
	struct data_directory
	{
		static constexpr std::uint32_t count = 16;

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
}
