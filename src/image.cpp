#include "image.hpp"

#include "nt_headers.hpp"
#include "section_header.hpp"

std::uint32_t pe::image::size() const noexcept
{
	return nt_hdrs()->optional_hdr.size_of_image;
}

span_t<pe::section_header> pe::image::sections() noexcept
{
	const auto& self = *this;
	const auto sec = self.sections();

	return { const_cast<section_header*>(sec.data()), sec.size() };
}

span_t<const pe::section_header> pe::image::sections() const noexcept
{
	const auto nt = nt_hdrs();

	return span_t{ nt->first_section_hdr(), nt->num_sections() };
}
