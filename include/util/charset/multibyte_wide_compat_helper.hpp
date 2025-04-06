#ifndef MULTIBYTE_WIDE_COMPAT_HELPER_HPP
#define MULTIBYTE_WIDE_COMPAT_HELPER_HPP

#include <string>

namespace linuxplorer::util::charset {
	class multibyte_wide_compat_helper {
	public:
		static std::wstring convert_multibyte_to_wide(std::string_view source);
		static std::string convert_wide_to_multibyte(std::wstring_view source);
	};
}

#endif // MULTIBYTE_WIDE_COMPAT_HELPER_HPP