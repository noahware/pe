#include "image.hpp"

#include "nt_headers.hpp"
#include "section_header.hpp"

span_t<pe::section_header> pe::image::sections() noexcept
{
	const auto& self = *this;
	const auto sec = self.sections();

	return { const_cast<pe::section_header*>(sec.data()), sec.size() };
}

span_t<const pe::section_header> pe::image::sections() const noexcept
{
	const auto nt = nt_hdrs();

	return span_t{ nt->first_section_hdr(), nt->num_sections() };
}
