#pragma once
#include <cstdint>

namespace pe
{
	class bin_addr
	{
	public:
		bin_addr() noexcept = default;

		explicit bin_addr(std::uint8_t* const base, const std::uint32_t rva)
			:	base_(base),
				rva_(rva) { }

		[[nodiscard]] std::uint32_t rva() const noexcept
		{
			return rva_;
		}

		template <class T = std::uint8_t*>
		[[nodiscard]] T addr() const noexcept
		{
			return reinterpret_cast<T>(base_ + rva_);
		}

	protected:
		std::uint8_t* base_;
		std::uint32_t rva_;
	};
}
