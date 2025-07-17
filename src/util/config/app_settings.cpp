#include <util/config/app_settings.hpp>
#include <system_error>
#include <windows.h>

#define TO_STRING(x)	#x

namespace linuxplorer::util::config {
	std::string get_config_path() {
		constexpr std::size_t path_len = MAX_PATH;
		char path[path_len];
		auto rc = ::GetEnvironmentVariableA("USERPROFILE", path, path_len);
		if (!rc) {
			std::error_code ec(::GetLastError(), std::system_category());
			throw std::system_error(ec, "Failed to get the environment variable: USERPROFILE");
		}

		std::string result = path;
		result += "\\.linuxplorer\\config.json";

		return result;
	}

	std::string get_install_path() {
		return TO_STRING(PROJECT_INSTALL_DIR);
	}
}