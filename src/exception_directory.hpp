#pragma once
#include "addr.hpp"
#include "deps.hpp"

namespace pe
{
	union unwind_code
	{
		// the wider ops spill into the following slots and read them as a plain value
		std::uint16_t frame_offset;

		struct
		{
			std::uint8_t offset;
			std::uint8_t code : 4;
			std::uint8_t info : 4;
		};
	};

	static_assert(sizeof(unwind_code) == 0x2);

	struct unwind_info
	{
		union
		{
			struct
			{
				std::uint8_t version : 3;
				std::uint8_t flags : 5;
			};

			struct
			{
				std::uint8_t : 3;
				std::uint8_t exception_handler : 1;
				std::uint8_t unwind_handler : 1;
				// the codes are followed by another runtime function instead of a handler
				std::uint8_t chain_info : 1;
				std::uint8_t : 2;
			};
		};

		std::uint8_t size_of_prolog;
		std::uint8_t unwind_code_count;
		std::uint8_t frame_register : 4;
		std::uint8_t frame_offset : 4;
		// the handler rva or the chained runtime function follows the codes, padded to an even count
		unwind_code codes[1];

		[[nodiscard]] span_t<const unwind_code> code_list() const noexcept
		{
			return { codes, unwind_code_count };
		}
	};

	static_assert(sizeof(unwind_info) == 0x6);
	static_assert(offsetof(unwind_info, codes) == 0x4);

	struct runtime_function
	{
		std::uint32_t begin_address;
		std::uint32_t end_address;
		std::uint32_t unwind_info_rva;
	};

	static_assert(sizeof(runtime_function) == 0xC);

	struct runtime_function_info
	{
		const_bin_addr begin;
		const_bin_addr end;
		const unwind_info* info;
	};
}
