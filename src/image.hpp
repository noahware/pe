#pragma once
#include "deps.hpp"
#include "dos_header.hpp"
#include "nt_headers.hpp"
#include "export_directory.hpp"
#include "import_directory.hpp"

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

						return views::iota(0u)
							| views::take_while([thunks](const std::uint32_t t) { return thunks[t].used(); })
							| views::transform([base, thunks, iat_rva](const std::uint32_t t) -> import_info
								{
									const auto& thunk = thunks[t];

									auto name = string_view_t{};
									auto ordinal = std::uint32_t{};

									if (thunk.is_ordinal)
									{
										ordinal = static_cast<std::uint32_t>(thunk.ordinal);
									}
									else
									{
										name = reinterpret_cast<const import_by_name*>(base + thunk.address_of_data)->str();
									}

									const auto slot_rva = iat_rva + static_cast<std::uint32_t>(t * sizeof(thunk_data));

									return import_info{ thunk.is_ordinal != 0, ordinal, name, const_bin_addr{ base, slot_rva } };
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
