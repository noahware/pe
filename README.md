# pe

Modern C++ library that parses the portable executable file format. The library **does not** rely on Windows specific headers. C++ standard library usage is *abstracted* in deps.hpp so it can be switched out with a custom implementation. It makes use of string views to not create any unnecessary allocations too. The tests/ app is built for Windows targets. The library requires at least C++ 20.

# Building tests

To build the test app, run the following commands:

```
cmake -B build
cmake --build build --config Release
```

# Examples

## Getting an instance

```cpp
const auto mod = LoadLibraryA("kernel32.dll");
const auto& img = *reinterpret_cast<const pe::image*>(module);
```

## Signature scan

```c++
const auto sig = img.sig_scan<std::uintptr_t>("C3 ? CC");
std::println("addr: 0x{:X}", sig);
```

## Sections iteration

```c++
for (const auto& sec : img.sections())
{
	std::println("{} rva {} size {} {}{}{}", sec.name(), sec.virtual_address, sec.virtual_size,
		sec.characteristics.mem_read ? 'r' : '-', sec.characteristics.mem_write ? 'w' : '-',
		sec.characteristics.mem_execute ? 'x' : '-');
}
```

## Exports iteration

```c++
for (const auto& exp : img.exports())
{
	std::println("ordinal {} {} {}", exp.ordinal, exp.name, exp.loc.rva());
}
```

### Direct export lookup

```c++
const auto message_box = img.find_export<std::uintptr_t>("MessageBoxA");
std::println("address: 0x{:X}", message_box);
```

## Imports iteration

```c++
for (const auto& imp : img.imports())
{
	std::println("{} {} iat {}", imp.module_name,
		imp.is_ordinal ? std::format("ordinal {}", imp.ordinal) : std::string{ imp.import_name },
		imp.iat_slot.rva());
}
```

## Delay imports iteration

```c++
for (const auto& imp : img.delay_imports())
{
	std::println("{} {} iat {}", imp.module_name,
		imp.is_ordinal ? std::format("ordinal {}", imp.ordinal) : std::string{ imp.import_name },
		imp.iat_slot.rva());
}
```

## Runtime functions iteration

```c++
for (const auto& func : img.runtime_funcs())
{
	// version is a bit field, so it cannot bind to the forwarding ref println takes
	std::println("{} - {} version {} codes {} prolog {}{}{}{}", func.begin.rva(), func.end.rva(),
		static_cast<std::uint32_t>(func.info->version),
		static_cast<std::uint32_t>(func.info->unwind_code_count),
		static_cast<std::uint32_t>(func.info->size_of_prolog),
		func.info->exception_handler ? " exception" : "", func.info->unwind_handler ? " unwind" : "",
		func.info->chain_info ? " chained" : "");
}
```

### Unwind codes iteration

```c++
for (const auto& code : func.info->code_list())
{
	std::println("offset {} code {} info {}", static_cast<std::uint32_t>(code.offset),
		static_cast<std::uint32_t>(code.code), static_cast<std::uint32_t>(code.info));
}
```

## Relocs iteration

```c++
for (const auto& rel : img.relocs())
{
	std::println("type {} at {}", static_cast<std::uint32_t>(rel.type), rel.loc.rva());
}
```

## TLS callbacks iteration

```c++
for (const auto& callback : img.tls_callbacks())
{
	std::println("{}", callback.rva());
}
```

## Debug directories iteration

```c++
for (const auto& dbg : img.debug_dirs())
{
	std::println("type {} size {} rva {}", static_cast<std::uint32_t>(dbg.type), dbg.size_of_data,
		dbg.address_of_raw_data);
}
```

## Certificates iteration

This must be done on the raw file mapping, not one that has already been virtually mapped as the security directory is destroyed when virtually mapped.

```c++
for (const auto& cert : img.certificates())
{
	LOG("revision 0x{:X} type {} data {} bytes", static_cast<std::uint16_t>(cert.revision),
		static_cast<std::uint16_t>(cert.type), cert.data.size());
}
```

# License

The project uses the Apache-2.0 license.
