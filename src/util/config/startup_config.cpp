#include <util/config/startup_config.hpp>
#include <util/charset/multibyte_wide_compat_helper.hpp>
#include <util/charset/case_insensitive_char_traits.hpp>

#include <filesystem>

#include <windows.h>

#include <objbase.h>
#include <atlbase.h>
#include <shobjidl.h>
#include <shlguid.h>
#include <shlwapi.h>

#define TO_STRING(x)	#x
#define STRINGIFY(x)	TO_STRING(x)

namespace linuxplorer::util::config {
	startup_config::startup_config() {}

	long startup_config::create_link_without_co_initialization(const std::wstring& src, const std::wstring& link) noexcept {
		::HRESULT hResult;

		::CComPtr<::IShellLinkW> lpShellLink = nullptr;
		hResult = ::CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_IShellLinkW, reinterpret_cast<void**>(&lpShellLink));
		if (FAILED(hResult)) {
			return hResult;
		}

		lpShellLink->SetPath(src.c_str());

		::CComPtr<::IPersistFile> lpPersistFile = nullptr;
		hResult = lpShellLink->QueryInterface(IID_IPersistFile, reinterpret_cast<void**>(&lpPersistFile));
		if (FAILED(hResult)) {
			return hResult;
		}

		hResult = lpPersistFile->Save(link.c_str(), true);

		return hResult;
	}

	std::wstring startup_config::get_startup_file_path() {
		wchar_t appdata_path[MAX_PATH];

		bool succeeded = ::GetEnvironmentVariableW(L"APPDATA", appdata_path, MAX_PATH);
		if (!succeeded) {
			std::error_code ec(::GetLastError(), std::system_category());
			throw std::system_error(ec, "Failed to get the environment variable: APPDATA");
		}
		std::wstring startup_path(appdata_path);
		startup_path += L"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\linuxplorer.lnk";

		return startup_path;
	}

	void startup_config::xload(const json_data_type& data) {
		bool exists = ::PathFileExistsW(startup_config::get_startup_file_path().c_str());
		if (exists != data) {
			throw startup_inconsistency_exception("The configuration data is inconsistent with the startup file.");
		}

		this->m_enabled = data;
	}

	startup_config::json_data_type startup_config::xsave() const {
		auto path = get_startup_file_path();
		if (this->m_enabled) {	
			if (!::PathFileExistsW(path.c_str())) {
				using chichar_traits = linuxplorer::util::charset::case_insensitive_char_traits<char>;

				auto install_dir = configuration_manager::get_install_path();
				std::filesystem::recursive_directory_iterator itr(install_dir);
				std::filesystem::path src_path;

				std::string app_name = STRINGIFY(LINUXPLORER_APP_SERVICE_NAME);
				app_name += ".exe";

				for (const auto& p : itr) {
					auto stem = p.path().filename().string();

					if (chichar_traits::compare(stem.c_str(), app_name.c_str(), std::min(stem.size(), app_name.size())) == 0) 
						src_path = p;
				}
				if (src_path.empty()) {
					std::error_code ec(static_cast<int>(std::errc::no_such_file_or_directory), std::generic_category());
					throw std::system_error(ec, "No service executable.");
				}

				::HRESULT hResult = ::CoInitialize(nullptr);
				if (FAILED(hResult)) {
					std::error_code ec(hResult, std::system_category());
					throw std::system_error(ec, "Failed to initialize COM component on this thread.");
				}

				hResult = startup_config::create_link_without_co_initialization(src_path.wstring(), path);

				if (FAILED(hResult)) {
					std::error_code ec(hResult, std::system_category());
					throw std::system_error(ec, "Failed to create a startup file.");
				}
			}
		}
		else {
			if (::PathFileExistsW(path.c_str())) {
				bool succeeded = ::DeleteFileW(path.c_str());
				if (!succeeded) {
					std::error_code ec(::GetLastError(), std::system_category());
					throw std::system_error(ec, "Failed to delete a startup file.");
				}
			}
		}

		return this->m_enabled;
	}

	startup_config::data_type startup_config::xget() const {
		return this->m_enabled;
	}

	void startup_config::xset(const startup_config::data_type& data) {
		this->m_enabled = data;
	}
}