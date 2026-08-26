#pragma once
#include "deps.hpp"
#include "dos_header.hpp"
#include "nt_headers.hpp"
#include "export_directory.hpp"
#include "import_directory.hpp"
#include "debug_directory.hpp"
#include "reloc_directory.hpp"
#include "tls_directory.hpp"

namespace pe
{
	class image
	{
	public:
		image() noexcept = default;

		template <class T>
		[[nodiscard]] T as() const noexcept
		{
			return reinterpret_cast<T>(this);
		}

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

		[[nodiscard]] std::uint32_t entry_point() const noexcept
		{
			return nt_hdrs()->optional_hdr.address_of_entry_point;
		}

		[[nodiscard]] std::uint64_t base_addr() const noexcept
		{
			return nt_hdrs()->optional_hdr.image_base;
		}

		[[nodiscard]] std::uint32_t size() const noexcept
		{
			return nt_hdrs()->optional_hdr.size_of_image;
		}

		[[nodiscard]] auto exports() const noexcept
		{
			const auto* const base = as<const std::uint8_t*>();
			const auto& dir = nt_hdrs()->optional_hdr.data_dirs.exports;

			const auto* exp_dir = dir.virtual_address && dir.used()
				? reinterpret_cast<const export_directory*>(base + dir.virtual_address)
				: nullptr;

			const auto num_funcs = exp_dir ? exp_dir->number_of_functions : 0u;
			const auto num_names = exp_dir ? exp_dir->number_of_names : 0u;
			const auto ord_base = exp_dir ? exp_dir->base : 0u;

			const auto* funcs = exp_dir ? reinterpret_cast<const std::uint32_t*>(base + exp_dir->address_of_functions) : nullptr;
			const auto* names = exp_dir ? reinterpret_cast<const std::uint32_t*>(base + exp_dir->address_of_names) : nullptr;
			const auto* name_ords = exp_dir ? reinterpret_cast<const std::uint16_t*>(base + exp_dir->address_of_name_ordinals) : nullptr;

			return views::iota(0u, num_funcs)
				| views::filter([funcs](const std::uint32_t i) { return funcs[i] != 0; })
				| views::transform([base, funcs, names, name_ords, num_names, ord_base](const std::uint32_t i) -> export_info
					{
						auto name = string_view_t{};

						for (std::uint32_t k = 0; k < num_names; ++k)
						{
							if (name_ords[k] != i)
							{
								continue;
							}

							name = reinterpret_cast<const char*>(base + names[k]);

							break;
						}

						return export_info{ name.empty(), ord_base + i, name, const_bin_addr{ base, funcs[i] } };
					});
		}

		[[nodiscard]] auto imports() const noexcept
		{
			const auto* const base = as<const std::uint8_t*>();
			const auto& dir = nt_hdrs()->optional_hdr.data_dirs.imports;

			const auto* descs = dir.virtual_address && dir.used()
				? reinterpret_cast<const import_directory*>(base + dir.virtual_address)
				: nullptr;

			// the descriptor array is null terminated, so there is no count to iterate to
			return views::iota(0u)
				| views::take_while([descs](const std::uint32_t d)
					{
						return descs && (descs[d].original_first_thunk || descs[d].first_thunk);
					})
				| views::transform([base, descs](const std::uint32_t d)
					{
						// bound imports overwrite the IAT, so prefer the untouched lookup table
						const auto lookup_rva = descs[d].original_first_thunk
							? descs[d].original_first_thunk
							: descs[d].first_thunk;

						const auto* thunks = reinterpret_cast<const thunk_data*>(base + lookup_rva);
						const auto iat_rva = descs[d].first_thunk;

						const auto module_name = descs[d].name
							? string_view_t{ reinterpret_cast<const char*>(base + descs[d].name) }
							: string_view_t{};

						return views::iota(0u)
							| views::take_while([thunks](const std::uint32_t t) { return thunks[t].used(); })
							| views::transform([base, thunks, iat_rva, module_name](const std::uint32_t t) -> import_info
								{
									const auto& thunk = thunks[t];

									auto import_name = string_view_t{};
									auto ordinal = std::uint32_t{};

									if (thunk.is_ordinal)
									{
										ordinal = static_cast<std::uint32_t>(thunk.ordinal);
									}
									else
									{
										import_name = reinterpret_cast<const import_by_name*>(base + thunk.address_of_data)->str();
									}

									const auto slot_rva = iat_rva + static_cast<std::uint32_t>(t * sizeof(thunk_data));

									return import_info{ module_name, import_name, thunk.is_ordinal != 0, ordinal, const_bin_addr{ base, slot_rva } };
								});
					})
				| views::join;
		}

		// unlike the other directories this one is a plain array, sized by the data dir
		[[nodiscard]] span_t<const debug_directory> debug_dirs() const noexcept
		{
			const auto* const base = as<const std::uint8_t*>();
			const auto& dir = nt_hdrs()->optional_hdr.data_dirs.debug;

			if (!dir.virtual_address || !dir.used())
				return {};

			return { reinterpret_cast<const debug_directory*>(base + dir.virtual_address), dir.size / sizeof(debug_directory) };
		}

		[[nodiscard]] const tls_directory* tls() const noexcept
		{
			const auto* const base = as<const std::uint8_t*>();
			const auto& dir = nt_hdrs()->optional_hdr.data_dirs.tls;

			return dir.virtual_address && dir.used()
				? reinterpret_cast<const tls_directory*>(base + dir.virtual_address)
				: nullptr;
		}

		[[nodiscard]] auto tls_callbacks() const noexcept
		{
			const auto* const base = as<const std::uint8_t*>();
			const auto* const dir = tls();
			const auto img_base = base_addr();

			// the callback table is pointed to by a va, and holds vas, terminated by a null one
			const auto* callbacks = dir && dir->address_of_call_backs
				? reinterpret_cast<const tls_directory::value_type*>(base + (dir->address_of_call_backs - img_base))
				: nullptr;

			return views::iota(0u)
				| views::take_while([callbacks](const std::uint32_t c) { return callbacks && callbacks[c]; })
				| views::transform([base, callbacks, img_base](const std::uint32_t c) -> const_bin_addr
					{
						return const_bin_addr{ base, static_cast<std::uint32_t>(callbacks[c] - img_base) };
					});
		}

		[[nodiscard]] auto relocs() const noexcept
		{
			const auto* const base = as<const std::uint8_t*>();
			const auto& dir = nt_hdrs()->optional_hdr.data_dirs.basereloc;

			const auto dir_rva = dir.virtual_address && dir.used() ? dir.virtual_address : 0u;
			const auto dir_size = dir_rva ? dir.size : 0u;

			// blocks are variable length, so the nth one can only be found by walking from the first
			const auto block_at = [base, dir_rva, dir_size](const std::uint32_t index) -> const reloc_block*
			{
				std::uint32_t walked = 0;

				for (std::uint32_t i = 0; walked < dir_size; ++i)
				{
					const auto* block = reinterpret_cast<const reloc_block*>(base + dir_rva + walked);

					if (block->size_of_block < sizeof(reloc_block))
						break;

					if (i == index)
						return block;

					walked += block->size_of_block;
				}

				return nullptr;
			};

			return views::iota(0u)
				| views::take_while([block_at](const std::uint32_t b) { return block_at(b) != nullptr; })
				| views::transform([base, block_at](const std::uint32_t b)
					{
						const auto* block = block_at(b);
						const auto* entries = reinterpret_cast<const reloc_entry*>(block + 1);

						const auto page_rva = block->virtual_address;
						const auto count = static_cast<std::uint32_t>(
							(block->size_of_block - sizeof(reloc_block)) / sizeof(reloc_entry));

						return views::iota(0u, count)
							// absolute entries are padding to keep blocks 4 byte aligned
							| views::filter([entries](const std::uint32_t e) { return entries[e].type != reloc_type::absolute; })
							| views::transform([base, entries, page_rva](const std::uint32_t e) -> reloc_info
								{
									return { entries[e].type, const_bin_addr{ base, page_rva + entries[e].offset } };
								});
					})
				| views::join;
		}

		[[nodiscard]] span_t<section_header> sections() noexcept
		{
			const auto& self = *this;
			const auto sec = self.sections();

			return { const_cast<section_header*>(sec.data()), sec.size() };
		}

		[[nodiscard]] span_t<const section_header> sections() const noexcept
		{
			const auto nt = nt_hdrs();

			return span_t{ nt->first_section_hdr(), nt->num_sections() };
		}

	protected:
		dos_header dos_hdr_;
	};
}
