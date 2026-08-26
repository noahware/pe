#pragma once
#include "deps.hpp"
#include "dos_header.hpp"

namespace pe
{
	struct section_header;

	class image
	{
	public:
		image() noexcept = default;

		[[nodiscard]] dos_header* dos_hdr() noexcept
		{
			return &dos_hdr_;
		}

		[[nodiscard]] const dos_header* dos_hdr() const noexcept
		{
			return &dos_hdr_;
		}

		[[nodiscard]] nt_headers* nt_hdrs() noexcept
		{
			return dos_hdr_.nt_hdrs();
		}

		[[nodiscard]] const nt_headers* nt_hdrs() const noexcept
		{
			return dos_hdr_.nt_hdrs();
		}

		[[nodiscard]] span_t<section_header> sections() noexcept;
		[[nodiscard]] span_t<const section_header> sections() const noexcept;

	protected:
		dos_header dos_hdr_;
	};
}
