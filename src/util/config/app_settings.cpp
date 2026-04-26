#include <util/config/app_settings.hpp>
#include <filesystem>
#include <system_error>
#include <windows.h>
#include <Shlwapi.h>

#define TO_STRING(x)	#x
#define STRINGIFY(x)	TO_STRING(x)

namespace linuxplorer::util::config {
	static std::filesystem::path get_userprofile_path() {
		constexpr std::size_t path_len = MAX_PATH;
		wchar_t path[path_len];
		auto rc = ::GetEnvironmentVariableW(L"USERPROFILE", path, path_len);
		if (!rc) {
			std::error_code ec(::GetLastError(), std::system_category());
			throw config_system_error(ec, "Failed to get the environment variable: USERPROFILE");
		}

		return path;
	}

	std::filesystem::path configuration_manager::get_root_path() {
		return get_userprofile_path() / L".Linuxplorer";
	}

	std::filesystem::path configuration_manager::get_config_path() {
		return get_root_path() / L"config.json";
	}

	std::filesystem::path configuration_manager::get_install_path() {
		constexpr std::size_t path_len = MAX_PATH;
		wchar_t module_file_path[path_len];
		auto rc = ::GetModuleFileNameW(nullptr, module_file_path, path_len);
		if (!rc) {
			std::error_code ec(::GetLastError(), std::system_category());
			throw config_system_error(ec, "Failed to retrieve the path for the current process executable.");
		}

		return std::filesystem::path(std::wstring_view(module_file_path, rc)).parent_path();
	}

	std::filesystem::path configuration_manager::get_log_path() {
		return get_root_path() / L"logs";
	}

	void configuration_manager::initialize() {
		try {
			std::filesystem::create_directories(get_root_path());

			std::ofstream ofs;
			ofs.exceptions(std::ios_base::badbit | std::ios_base::failbit);
			ofs.open(get_config_path());
			ofs << "{}" << std::endl;
			ofs.flush();
			ofs.close();
		}
		catch (const std::ios_base::failure& e) {
			std::stringstream error;
			error << "File stream failed: " << e.what() << " (" << e.code().message() << "(" << e.code().value() << "))";
			throw config_io_exception(error.str());
		}
		catch (const std::filesystem::filesystem_error& e) {
			std::stringstream error;
			error << "File system operation failed: " << e.what() << " (" << e.code().message() << "(" << e.code().value() << "))";
			throw config_io_exception(error.str());
		}
	}
}