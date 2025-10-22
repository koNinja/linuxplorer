#include <util/config/app_settings.hpp>
#include <system_error>
#include <windows.h>
#include <Shlwapi.h>

#define TO_STRING(x)	#x
#define STRINGIFY(x)	TO_STRING(x)

namespace linuxplorer::util::config {
	static std::wstring get_userprofile_path() {
		constexpr std::size_t path_len = MAX_PATH;
		wchar_t path[path_len];
		auto rc = ::GetEnvironmentVariableW(L"USERPROFILE", path, path_len);
		if (!rc) {
			std::error_code ec(::GetLastError(), std::system_category());
			throw config_system_error(ec, "Failed to get the environment variable: USERPROFILE");
		}

		return path;
	}

	std::wstring configuration_manager::get_root_path() {
		std::wstring result = get_userprofile_path();
		result += L"\\.linuxplorer";

		return result;
	}

	std::wstring configuration_manager::get_config_path() {
		return get_root_path() + L"\\config.json";
	}

	std::wstring configuration_manager::get_install_path() {
		constexpr std::size_t path_len = MAX_PATH;
		wchar_t module_file_path[path_len];
		auto rc = ::GetModuleFileNameW(nullptr, module_file_path, path_len);
		if (!rc) {
			std::error_code ec(::GetLastError(), std::system_category());
			throw config_system_error(ec, "Failed to retrieve the path for the current process executable.");
		}

		std::wstring_view view(module_file_path, rc);

		return std::wstring(view.substr(0, view.find_last_of(L'\\')));
	}

	std::wstring configuration_manager::get_log_path() {
		return get_root_path() + L"\\logs\\service.log";
	}

	void configuration_manager::initialize() {
		try {
			std::ofstream ofs;
			ofs.exceptions(std::ios_base::badbit | std::ios_base::failbit);
			ofs.open(get_config_path());
			
			ofs << "{}" << std::endl;
			ofs.flush();
		}
		catch (const std::ios_base::failure& e) {
			std::stringstream error;
			error << "File stream failed: " << e.code().message();
			throw config_io_exception(error.str());
		}
	}
}