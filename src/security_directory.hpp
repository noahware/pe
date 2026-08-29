#pragma once
#include "deps.hpp"

namespace pe
{
	enum class certificate_revision : std::uint16_t
	{
		v1_0 = 0x0100,
		v2_0 = 0x0200
	};

	enum class certificate_type : std::uint16_t
	{
		x509 = 0x0001,
		pkcs_signed_data = 0x0002,
		reserved_1 = 0x0003,
		ts_stack_signed = 0x0004,
		pkcs1_sign = 0x0009
	};

	struct certificate_info
	{
		certificate_revision revision;
		certificate_type type;
		span_t<const std::uint8_t> data;
	};

	struct win_certificate
	{
		std::uint32_t length; // includes this struct in size
		certificate_revision revision;
		certificate_type type;

		[[nodiscard]] span_t<const std::uint8_t> data() const noexcept
		{
			return { reinterpret_cast<const std::uint8_t*>(this + 1), length - sizeof(win_certificate) };
		}
	};

	static_assert(sizeof(win_certificate) == 0x8);
}
