#ifndef LINUXPLORER_MULTIBYTE_WIDE_COMPAT_HELPER_HPP_
#define LINUXPLORER_MULTIBYTE_WIDE_COMPAT_HELPER_HPP_

#include <string>

namespace linuxplorer::util::charset {
	class multibyte_wide_compat_helper {
	public:
		static std::wstring convert_multibyte_to_wide(std::string_view source);
		static std::string convert_wide_to_multibyte(std::wstring_view source);
	};
}

#endif // LINUXPLORER_MULTIBYTE_WIDE_COMPAT_HELPER_HPP_