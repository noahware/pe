#pragma once
#include "deps.hpp"

namespace pe
{
	template <class Byte>
	class base_bin_addr
	{
	public:
		base_bin_addr() noexcept = default;

		explicit base_bin_addr(Byte* const base, const std::uint32_t rva)
			:	base_(base),
				rva_(rva) { }

		[[nodiscard]] std::uint32_t rva() const noexcept
		{
			return rva_;
		}

		template <class T = Byte*>
		[[nodiscard]] T addr() const noexcept
		{
			return reinterpret_cast<T>(base_ + rva_);
		}

	protected:
		Byte* base_;
		std::uint32_t rva_;
	};

	using bin_addr = base_bin_addr<std::uint8_t>;
	using const_bin_addr = base_bin_addr<const std::uint8_t>;
}
