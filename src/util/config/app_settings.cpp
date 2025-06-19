#include <util/config/app_settings.hpp>
#include <system_error>
#include <windows.h>

namespace linuxplorer::util::config {
	std::wstring get_config_path() {
		constexpr std::size_t path_len = MAX_PATH;
		wchar_t path[path_len];
		auto rc = ::GetEnvironmentVariableW(L"USERPROFILE", path, path_len);
		if (!rc) {
			std::error_code ec(::GetLastError(), std::system_category());
			throw std::system_error(ec, "Failed to get the environment variable: USERPROFILE");
		}

		std::wstring result = path;
		result += L"\\.linuxplorer\\config.json";

		return result;
	}
}