#pragma once
#include "deps.hpp"
#include "dos_header.hpp"
#include "nt_headers.hpp"
#include "export_directory.hpp"

namespace pe
{
	struct section_header;

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

		[[nodiscard]] std::uint32_t size() const noexcept;

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

			return std::views::iota(0u, num_funcs)
				| std::views::filter([funcs](const std::uint32_t i) { return funcs[i] != 0; })
				| std::views::transform([base, funcs, names, name_ords, num_names, ord_base](const std::uint32_t i) -> export_info
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

		[[nodiscard]] span_t<section_header> sections() noexcept;
		[[nodiscard]] span_t<const section_header> sections() const noexcept;

	protected:
		dos_header dos_hdr_;
	};
}
