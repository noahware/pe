#include <format>
#include <print>
#include <ranges>
#include <Windows.h>

#include "pe.hpp"

namespace
{
	// only the first few entries of the big directories are printed, they run into the thousands
	constexpr std::size_t preview_count = 5;

	void print_sections(const pe::image& img)
	{
		std::println("sections ({})", img.sections().size());

		for (const auto& sec : img.sections())
		{
			std::println("\t{} rva {} size {} {}{}{}", sec.name(), sec.virtual_address, sec.virtual_size,
				sec.characteristics.mem_read ? 'r' : '-', sec.characteristics.mem_write ? 'w' : '-',
				sec.characteristics.mem_execute ? 'x' : '-');
		}
	}

	void print_exports(const pe::image& img)
	{
		std::println("exports ({})", std::ranges::distance(img.exports()));

		for (const auto& exp : img.exports() | std::views::take(preview_count))
		{
			std::println("\t{} {} {}", exp.ordinal, exp.is_ordinal ? "<no name>" : exp.name, exp.loc.addr<const void*>());
		}
	}

	void print_find_export(const pe::image& img)
	{
		const auto message_box = img.find_export<std::uintptr_t>("MessageBoxA");

		std::println("MessageBoxA address (found by export): 0x{:X}", message_box);
	}

	void print_sig_scan(const pe::image& img)
	{
		const auto sig = img.sig_scan<std::uintptr_t>("C3 ? CC");

		std::println("signature \"C3 ? CC\" address: 0x{:X}", sig);
	}

	void print_imports(const pe::image& img)
	{
		std::println("imports ({})", std::ranges::distance(img.imports()));

		for (const auto& imp : img.imports() | std::views::take(preview_count))
		{
			std::println("\t{} {} iat {}", imp.module_name, imp.is_ordinal ? "<by ordinal>" : imp.import_name,
				imp.iat_slot.addr<const void*>());
		}
	}
}

int main()
{
	const auto module = LoadLibraryA("user32.dll");

	if (!module)
	{
		std::println("failed to load user32.dll: {}", GetLastError());

		return 1;
	}

	const auto& img = *reinterpret_cast<const pe::image*>(module);

	print_sections(img);
	print_exports(img);
	print_imports(img);
	print_find_export(img);
	print_sig_scan(img);

	return 0;
}
