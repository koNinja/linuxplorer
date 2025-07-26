#include <util/config/app_settings.hpp>
#include <system_error>
#include <windows.h>
#include <Shlwapi.h>

#define TO_STRING(x)	#x
#define STRINGIFY(x)	TO_STRING(x)

namespace linuxplorer::util::config {
	std::string configuration_manager::get_config_path() {
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

	std::string configuration_manager::get_install_path() {
		return STRINGIFY(PROJECT_INSTALL_DIR);
	}

	void configuration_manager::initialize() {
		try {
				std::ofstream ofs;
				ofs.exceptions(std::ios_base::badbit | std::ios_base::failbit);
				ofs.open(get_config_path());
				
				ofs << "{}" << std::endl;
			}
			catch (const std::ios_base::failure& e) {
				std::stringstream error;
				error << "File stream failed: " << e.code().message();
				throw config_io_exception(error.str());
			}
	}
}