#pragma once
#include <cstdint>

namespace pe
{
	struct nt_headers;

	struct dos_header
	{
		static constexpr std::uint16_t dos_magic = 0x5a4d;

		std::uint16_t magic;
		std::uint16_t cblp;
		std::uint16_t cp;
		std::uint16_t crlc;
		std::uint16_t cparhdr;
		std::uint16_t minalloc;
		std::uint16_t maxalloc;
		std::uint16_t ss;
		std::uint16_t sp;
		std::uint16_t csum;
		std::uint16_t ip;
		std::uint16_t cs;
		std::uint16_t lfarlc;
		std::uint16_t ovno;
		std::uint16_t res[4];
		std::uint16_t oemid;
		std::uint16_t oeminfo;
		std::uint16_t res2[10];
		std::int32_t lfanew;

		[[nodiscard]] nt_headers* nt_hdrs() noexcept
		{
			return const_cast<nt_headers*>(std::as_const(*this).nt_hdrs());
		}

		[[nodiscard]] const nt_headers* nt_hdrs() const noexcept
		{
			return reinterpret_cast<const nt_headers*>(reinterpret_cast<const std::uint8_t*>(this) + lfanew);
		}

		[[nodiscard]] bool ok() const noexcept
		{
			return magic == dos_magic;
		}

		[[nodiscard]] explicit operator bool() const noexcept
		{
			return ok();
		}
	};

	static_assert(sizeof(dos_header) == 0x40);
}
