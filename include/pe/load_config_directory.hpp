#pragma once
#include "deps.hpp"

namespace pe
{
	union load_config_guard_flags_t
	{
		struct
		{
			std::uint32_t _pad0 : 8;
			std::uint32_t cf_instrumented : 1;
			std::uint32_t cfw_instrumented : 1;
			std::uint32_t cf_function_table_present : 1;
			std::uint32_t security_cookie_unused : 1;
			std::uint32_t protect_delayload_iat : 1;
			std::uint32_t delayload_iat_in_its_own_section : 1;
			std::uint32_t cf_export_suppression_info_present : 1;
			std::uint32_t cf_enable_export_suppression : 1;
			std::uint32_t cf_longjump_table_present : 1;
			std::uint32_t rf_instrumented : 1;
			std::uint32_t rf_enable : 1;
			std::uint32_t rf_strict : 1;
			std::uint32_t retpoline_present : 1;
			std::uint32_t _pad1 : 1;
			std::uint32_t eh_continuation_table_present : 1;
			std::uint32_t xfg_enabled : 1;
			std::uint32_t castguard_present : 1;
			std::uint32_t memcpy_present : 1;
			std::uint32_t _pad2 : 2;
			// the stride of the entries in guard_cf_function_table, minus the four byte rva
			std::uint32_t cf_function_table_size : 4;
		};

		std::uint32_t flags;
	};

	static_assert(sizeof(load_config_guard_flags_t) == 0x4);

	struct load_config_code_integrity
	{
		std::uint16_t flags;
		std::uint16_t catalog;
		std::uint32_t catalog_rva;
		std::uint32_t reserved;
	};

	static_assert(sizeof(load_config_code_integrity) == 0xC);

	struct load_config_directory
	{
		// only 64 bit supported for now, x86 uses std::uint32_t
		using value_type = std::uint64_t;

		struct table
		{
			value_type virtual_address;
			value_type size;
		};

		// the layout grows with every sdk, so anything past what size covers is not really present
		std::uint32_t size;
		std::uint32_t time_date_stamp;
		std::uint16_t major_version;
		std::uint16_t minor_version;
		std::uint32_t global_flags_clear;
		std::uint32_t global_flags_set;
		std::uint32_t critical_section_default_timeout;
		value_type de_commit_free_block_threshold;
		value_type de_commit_total_free_threshold;
		value_type lock_prefix_table;
		value_type maximum_allocation_size;
		value_type virtual_memory_threshold;
		value_type process_affinity_mask;
		std::uint32_t process_heap_flags;
		std::uint16_t csd_version;
		std::uint16_t dependent_load_flags;
		value_type reserved;
		value_type security_cookie;
		table se_handler_table;
		value_type guard_cf_check_function_pointer;
		value_type guard_cf_dispatch_function_pointer;
		table guard_cf_function_table;
		load_config_guard_flags_t guard_flags;
		load_config_code_integrity code_integrity;
		table guard_address_taken_iat_entry_table;
		table guard_long_jump_target_table;
		value_type dynamic_value_reloc_table;
		value_type chpe_metadata_pointer;
		value_type guard_rf_failure_routine;
		value_type guard_rf_failure_routine_function_pointer;
		std::uint32_t dynamic_value_reloc_table_rva;
		std::uint16_t dynamic_value_reloc_table_section;
		std::uint16_t reserved2;
		value_type guard_rf_verify_stack_pointer_function_pointer;
		std::uint32_t hot_patch_table_rva;
		std::uint32_t reserved3;
		value_type enclave_configuration_pointer;
		value_type volatile_metadata_pointer;
		table guard_eh_continuation_table;
		value_type guard_xfg_check_function_pointer;
		value_type guard_xfg_dispatch_function_pointer;
		value_type guard_xfg_table_dispatch_function_pointer;
		value_type cast_guard_os_determined_failure_mode;
		value_type guard_memcpy_function_pointer;
		value_type uma_function_pointers;
	};

	// there is no sizeof assert here on purpose, the struct is versioned by its own size field
	static_assert(offsetof(load_config_directory, security_cookie) == 0x58);
	static_assert(offsetof(load_config_directory, guard_cf_function_table) == 0x80);
	static_assert(offsetof(load_config_directory, guard_flags) == 0x90);
}
