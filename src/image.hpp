#pragma once
#include "dos_header.hpp"

namespace pe
{
	class image
	{
	public:
		[[nodiscard]] dos_header* dos_hdr() noexcept
		{
			return &dos_hdr_;
		}

		[[nodiscard]] const auto* dos_hdr() const noexcept
		{
			return &dos_hdr_;
		}

	protected:
		dos_header dos_hdr_;
	};
}
