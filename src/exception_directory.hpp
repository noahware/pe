#pragma once
#include "addr.hpp"
#include "deps.hpp"

namespace pe
{
	enum class unwind_opcode_x64 : std::uint8_t
	{
		push_nonvol = 0,
		alloc_large = 1,
		alloc_small = 2,
		set_fpreg = 3,
		save_nonvol = 4,
		save_nonvol_far = 5,
		epilog = 6,
		spare = 7,
		save_xmm128 = 8,
		save_xmm128_far = 9,
		push_machframe = 10
	};

	enum class unwind_register_x64 : std::uint8_t
	{
		rax = 0,
		rcx = 1,
		rdx = 2,
		rbx = 3,
		rsp = 4,
		rbp = 5,
		rsi = 6,
		rdi = 7,
		r8 = 8,
		r9 = 9,
		r10 = 10,
		r11 = 11,
		r12 = 12,
		r13 = 13,
		r14 = 14,
		r15 = 15
	};

	union unwind_code_x64
	{
		// the wider ops spill into the following slots and read them as a plain value
		std::uint16_t frame_offset;

		struct
		{
			std::uint8_t offset;
			unwind_opcode_x64 code : 4;
			std::uint8_t info : 4;
		};
	};

	static_assert(sizeof(unwind_code_x64) == 0x2);

	struct unwind_info_x64
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
		unwind_register_x64 frame_register : 4;
		std::uint8_t frame_offset : 4;
		// the handler rva or the chained runtime function follows the codes, padded to an even count
		unwind_code_x64 codes[1];

		[[nodiscard]] span_t<const unwind_code_x64> code_list() const noexcept
		{
			return { codes, unwind_code_count };
		}
	};

	static_assert(sizeof(unwind_info_x64) == 0x6);
	static_assert(offsetof(unwind_info_x64, codes) == 0x4);

	struct runtime_function_x64
	{
		std::uint32_t begin_address;
		std::uint32_t end_address;
		std::uint32_t unwind_info_rva;
	};

	static_assert(sizeof(runtime_function_x64) == 0xC);

	struct runtime_function_info_x64
	{
		const_bin_addr begin;
		const_bin_addr end;
		const unwind_info_x64* info;
	};

	enum class unwind_opcode_arm64 : std::uint8_t
	{
		alloc_s = 0,
		save_r19r20_x = 1,
		save_fplr = 2,
		save_fplr_x = 3,
		alloc_m = 4,
		save_regp = 5,
		save_regp_x = 6,
		save_reg = 7,
		save_reg_x = 8,
		save_lrpair = 9,
		save_fregp = 10,
		save_fregp_x = 11,
		save_freg = 12,
		save_freg_x = 13,
		alloc_l = 14,
		set_fp = 15,
		add_fp = 16,
		nop = 17,
		end = 18,
		end_c = 19,
		save_next = 20,
		trap_frame = 21,
		context = 22,
		clear_unwound_to_call = 23,
		pac_sign_lr = 24
	};

	enum class unwind_register_arm64 : std::uint8_t
	{
		x0 = 0,
		x1 = 1,
		x2 = 2,
		x3 = 3,
		x4 = 4,
		x5 = 5,
		x6 = 6,
		x7 = 7,
		x8 = 8,
		x9 = 9,
		x10 = 10,
		x11 = 11,
		x12 = 12,
		x13 = 13,
		x14 = 14,
		x15 = 15,
		x16 = 16,
		x17 = 17,
		x18 = 18,
		x19 = 19,
		x20 = 20,
		x21 = 21,
		x22 = 22,
		x23 = 23,
		x24 = 24,
		x25 = 25,
		x26 = 26,
		x27 = 27,
		x28 = 28,
		fp = 29,
		lr = 30
	};

	struct epilog_scope_arm64
	{
		std::uint32_t epilog_start_offset : 18;
		std::uint32_t _reserved : 4;
		std::uint32_t epilog_start_index : 10;
	};

	static_assert(sizeof(epilog_scope_arm64) == 0x4);

	struct unwind_info_arm64
	{
		std::uint32_t function_length : 18;
		std::uint32_t version : 2;
		std::uint32_t exception_data_present : 1;
		std::uint32_t epilog_in_header : 1;
		std::uint32_t epilog_count : 5;
		std::uint32_t code_words : 5;

		[[nodiscard]] span_t<const epilog_scope_arm64> epilog_scopes() const noexcept
		{
			if (epilog_in_header)
				return {};
			return { reinterpret_cast<const epilog_scope_arm64*>(this + 1), epilog_count };
		}

		[[nodiscard]] span_t<const std::uint8_t> code_data() const noexcept
		{
			const auto* start = reinterpret_cast<const std::uint8_t*>(this + 1);
			if (!epilog_in_header)
				start += epilog_count * sizeof(epilog_scope_arm64);
			return { start, code_words * 4u };
		}
	};

	static_assert(sizeof(unwind_info_arm64) == 0x4);

	struct runtime_function_arm64
	{
		std::uint32_t begin_address;

		union
		{
			std::uint32_t unwind_data;

			struct
			{
				std::uint32_t flag : 1;
				std::uint32_t cr : 2;
				std::uint32_t h : 1;
				std::uint32_t reg_i : 4;
				std::uint32_t reg_f : 3;
				std::uint32_t frame_size : 10;
				std::uint32_t function_length : 11;
			};
		};

		[[nodiscard]] bool is_packed() const noexcept { return flag; }
	};

	static_assert(sizeof(runtime_function_arm64) == 0x8);

	struct runtime_function_info_arm64
	{
		const_bin_addr begin;
		const runtime_function_arm64* func;
		const unwind_info_arm64* info;
	};
}
