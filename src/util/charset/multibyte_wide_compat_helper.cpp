#include <util/charset/multibyte_wide_compat_helper.hpp>

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <stringapiset.h>

#include <system_error>
#include <memory>

namespace linuxplorer::util::charset {
	std::wstring multibyte_wide_compat_helper::convert_multibyte_to_wide(std::string_view source) {
		std::size_t src_len = source.size();
		int dst_len = ::MultiByteToWideChar(CP_ACP, 9, source.data(), src_len, nullptr, 0);

		auto str = std::make_unique<wchar_t[]>(dst_len + 1);

		auto ec = ::MultiByteToWideChar(CP_ACP, 0, source.data(), src_len * sizeof(char), str.get(), (dst_len + 1) * sizeof(wchar_t));
		if (ec <= 0) {
			std::error_code ec(::GetLastError(), std::system_category());
			throw std::system_error(ec, "Failed to convert multibyte type to wide type.");
		}

		return std::wstring(str.get());
	}

	std::string multibyte_wide_compat_helper::convert_wide_to_multibyte(std::wstring_view source) {
		std::size_t src_len = source.size();
		int dst_len = ::WideCharToMultiByte(CP_ACP, 0, source.data(), src_len * sizeof(wchar_t), nullptr, 0, nullptr, nullptr);
		
		auto str = std::make_unique<char[]>(dst_len + 1);

		auto ec = ::WideCharToMultiByte(CP_ACP, 0, source.data(), src_len * sizeof(wchar_t), str.get(), (dst_len + 1) * sizeof(char), nullptr, nullptr);
		if (ec <= 0) {
			std::error_code ec(::GetLastError(), std::system_category());
			throw std::system_error(ec, "Failed to convert multibyte type to wide type.");
		}

		return std::string(str.get());
	}
}