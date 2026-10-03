#pragma once
#include "image.hpp"

namespace pe
{
	class raw_image
	{
	public:
		explicit raw_image(const image* const img)
		{
			buf_.resize(img->size(), 0);

			const auto hdrs_size = img->nt_hdrs()->optional_hdr.size_of_headers;
			pe::memcpy(buf_.data(), img->as(), hdrs_size);

			for (const auto& sec : img->sections())
			{
				const auto dest = buf_.data() + sec.virtual_address;
				const auto src = img->as() + sec.pointer_to_raw_data;

				pe::memcpy(dest, src, sec.size_of_raw_data);
			}
		}

		explicit raw_image(const span_t<const std::uint8_t> buf)
			:	raw_image(reinterpret_cast<const image*>(buf.data())) { }

		[[nodiscard]] image* virt_img() noexcept
		{
			return reinterpret_cast<image*>(buf_.data());
		}

		[[nodiscard]] const image* virt_img() const noexcept
		{
			return reinterpret_cast<const image*>(buf_.data());
		}

		[[nodiscard]] std::span<std::uint8_t> virt_buffer() noexcept
		{
			return buf_;
		}

		[[nodiscard]] std::span<const std::uint8_t> virt_buffer() const noexcept
		{
			return buf_;
		}

	protected:
		vector_t<std::uint8_t> buf_;
	};
}
