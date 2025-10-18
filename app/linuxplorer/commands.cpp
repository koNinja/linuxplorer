#include "commands.hpp"

#include <windows.h>
#include <winternl.h>
#include <Shlwapi.h>
#include <TlHelp32.h>
#include <winreg.h>
#include <sddl.h>
#include <shell/filesystem/cloud_provider_registrar.hpp>

#include <ssh/ssh_address.hpp>
#include <util/charset/case_insensitive_char_traits.hpp>
#include <util/config/profiles.hpp>
#include <util/config/startup_config.hpp>

#include <boost/program_options.hpp>
#include <iostream>
#include <string>
#include <cwctype>
#include <algorithm>
#include <optional>

#define TO_WSTRING(x)	L#x
#define WSTRINGIFY(x)	TO_WSTRING(x)

namespace linuxplorer::app::linuxplorer {
	using unique_key_ptr = std::unique_ptr<std::remove_pointer_t<::HKEY>, decltype([](::HKEY ptr) -> void { ::RegCloseKey(ptr); })>;

	template <class T>
	using unique_hlocal_ptr = std::unique_ptr<T, decltype([](T* ptr) -> void { ::LocalFree(ptr); })>;

	static std::optional<std::wstring> get_string_current_user_sid() noexcept {
		::HANDLE token;
		bool succeeded = ::OpenProcessToken(
			::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, ::GetCurrentProcessId()),
			TOKEN_QUERY,
			&token
		);
		if (!succeeded) {
			return std::nullopt;
		}

		::DWORD bytes_returned_token_user;
		::GetTokenInformation(
			token,
			::TOKEN_INFORMATION_CLASS::TokenUser,
			nullptr,
			0,
			&bytes_returned_token_user
		);

		unique_hlocal_ptr<::TOKEN_USER> token_user(static_cast<::TOKEN_USER*>(::LocalAlloc(LPTR, bytes_returned_token_user)));

		succeeded = ::GetTokenInformation(
			token,
			::TOKEN_INFORMATION_CLASS::TokenUser,
			token_user.get(),
			bytes_returned_token_user,
			&bytes_returned_token_user
		);
		if (!succeeded) {
			::DWORD last_error = ::GetLastError();
			return std::nullopt;
		}

		::LPWSTR nt_sid_str;
		succeeded = ::ConvertSidToStringSidW(token_user->User.Sid, &nt_sid_str);
		if (!succeeded) {
			return std::nullopt;
		}
		unique_hlocal_ptr<wchar_t> sid_str(nt_sid_str);

		return sid_str.get();
	}

	static ::LSTATUS open_key_in_hklm(unique_key_ptr& ptr, const std::wstring& relative_key_path) noexcept {
		::LSTATUS rc;
		::HKEY nt_key;
		rc = ::RegCreateKeyExW(
			HKEY_LOCAL_MACHINE,
			relative_key_path.c_str(),
			0,
			nullptr,
			REG_OPTION_NON_VOLATILE,
			KEY_READ | KEY_WRITE | KEY_QUERY_VALUE | KEY_SET_VALUE,
			nullptr,
			&nt_key,
			nullptr
		);

		ptr = unique_key_ptr(nt_key);
		return rc;
	}

	static ::LSTATUS set_reg_value(const unique_key_ptr& ptr, const std::wstring& value_name, const std::wstring& value) noexcept {
		return ::RegSetValueExW(
			ptr.get(),
			value_name.c_str(),
			0,
			REG_SZ,
			reinterpret_cast<const ::BYTE*>(value.c_str()),
			sizeof(wchar_t) * value.size()
		);
	}

	static ::LSTATUS set_reg_value(const unique_key_ptr& ptr, const std::wstring& value_name, ::DWORD value) noexcept {
		return ::RegSetValueExW(
			ptr.get(),
			value_name.c_str(),
			0,
			REG_DWORD,
			reinterpret_cast<const ::BYTE*>(&value),
			sizeof(::DWORD)
		);
	}

	static ::LSTATUS delete_in_hklm(const std::wstring& relative_path) noexcept {
		return ::RegDeleteTreeW(HKEY_LOCAL_MACHINE, relative_path.c_str());
	}

	constexpr const wchar_t* syncroot_key_prefix = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SyncRootManager";

	int compare(std::wstring_view l, std::wstring_view r) {
		if (l.length() == r.length()) return util::charset::case_insensitive_char_traits<basic_string_char_t<std::wstring_view>>::compare(l.data(), r.data(), std::min(l.length(), r.length()));
		else return 1;
	}

	int compare(std::string_view l, std::string_view r) {
		if (l.length() == r.length()) return util::charset::case_insensitive_char_traits<basic_string_char_t<std::string_view>>::compare(l.data(), r.data(), std::min(l.length(), r.length()));
		else return 1;
	}

	int option_handler(int argc, char** argv) {
		boost::program_options::options_description description("");
		description.add_options()
		("help,h", "")
		("config,c", boost::program_options::wvalue<std::wstring>()->implicit_value(L"", ""), "")
		("initialize", "")
		("initiate,i", "")
		("terminate,t", "")
		("status,s", "")
		("profile,p",  "")
		("create", boost::program_options::wvalue<std::wstring>()->implicit_value(L"", ""), "")
		("remove", boost::program_options::wvalue<std::wstring>()->implicit_value(L"", ""), "")
		("list", "")
		("version", "");
		
		boost::program_options::variables_map options;

		try {
			boost::program_options::store(
				boost::program_options::parse_command_line(argc, argv, description),
				options
			);
			boost::program_options::notify(options);
		}
		catch (const boost::program_options::error& e) {
			std::wcerr << L"Failed to parse command line arguments: " << e.what() << std::endl;
			return 1;
		}

		if (options.count("version")) {
			std::wcout << L"linuxplorer version: " << WSTRINGIFY(LINUXPLORER_VERSION) << std::endl;
			return 0;
		}
		else if (options.count("config")) {
			if (options.count("help")) {
				return commands::help_config_option();
			}
			if (options.count("initialize")) {
				return commands::initialize_config_option();
			}
			else {
				const auto& param = options["config"].as<std::wstring>();
				auto name_value_offset = param.find('@') != param.npos ? param.find('@') + 1 : param.npos;
				auto profile_name = name_value_offset != param.npos ? param.substr(0, name_value_offset - 1) : L"";

				auto value_offset = param.find(L'=') != param.npos ? param.find('=') + 1 : param.npos;
				if (value_offset != param.npos) {
					return commands::set_config_option(profile_name, param.substr(name_value_offset, value_offset - 1 - name_value_offset), param.substr(value_offset));
				}
				// no value
				else {
					std::size_t name_offset = name_value_offset != param.npos ? name_value_offset /* specified with a profile */ : 0 /* specified a setting name only */ ;
					return commands::get_config_option(profile_name, param.substr(name_offset));
				}
			}
		}
		else if (options.count("status")) {
			return commands::status_option();
		}
		else if (options.count("initiate")) {
			return commands::initiate_option();
		}
		else if (options.count("terminate")) {
			return commands::terminate_option();
		}
		else if (options.count("profile")) {
			if (options.count("create")) {
				auto profile_name = options["create"].as<std::wstring>();
				return commands::create_profile_option(profile_name);
			}
			else if (options.count("remove")) {
				auto profile_name = options["remove"].as<std::wstring>();
				return commands::remove_profile_option(profile_name);
			}
			else if (options.count("list")) {
				return commands::enumerate_profile_option();
			}
			else {
				std::wcerr << L"Error: Please specify any of the '--create', '--remove' or '--list' option." << std::endl;
				return 1;
			}
		}
		else {
			return commands::no_options();
		}
	}

	std::optional<std::uint32_t> try_get_service_pid() {
		std::wstring app_service_name = WSTRINGIFY(LINUXPLORER_APP_SERVICE_NAME);
			app_service_name += L".exe";

		::HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (!snapshot) {
			std::error_code ec(::GetLastError(), std::system_category());
			throw std::system_error(ec, "Failed to create a snapshot of the process list.");
		}

		::PROCESSENTRY32W entry{};
		entry.dwSize = sizeof(::PROCESSENTRY32W);
		if (!::Process32FirstW(snapshot, &entry)) {
			std::error_code ec(::GetLastError(), std::system_category());
			::CloseHandle(snapshot);
			throw std::system_error(ec, "Failed to get the first process in the snapshot.");
		}

		std::uint32_t pid = 0;
		bool found = false;
		
		do {
			if (compare(app_service_name, entry.szExeFile) == 0) {
				found = true;
				pid = entry.th32ProcessID;
				break;
			}
		} while (::Process32NextW(snapshot, &entry));

		::CloseHandle(snapshot);

		return found ? std::make_optional(pid) : std::nullopt;
	}

	namespace commands {
		int no_options() {
			std::wcout <<
				L"Usage: linuxplorer [-h | --help] [--version] [-p | --profile [[[--create] or [--remove]] <profile>] or --list] [-c | --config [[<profile>@]<name>[=<value>] or [--initialize]]] [-i | --initiate] [-t | --terminate]" << std::endl << std::endl <<
				L"Allowed options:" << std::endl <<
				L"\t" << L"-h | --help: Produce help message. Help for each option can also be shown by combining it with this option." << std::endl <<
				L"\t" << L"--version: Display version info about linuxplorer." << std::endl << 
				L"\t" << L"-p | --profile: Create and remove a profile." << std::endl <<
				L"\t" << L"-c | --config: Get and set app settings." << std::endl <<
				L"\t" << L"-i | --initiate: Initiate the linuxplorer session." << std::endl <<
				L"\t" << L"-t | --terminate: Stop the linuxplorer session." << std::endl <<
				L"\t" << L"-s | --status: Show status of the linuxplorer session." << std::endl;
			return 0;
		}

		int help_config_option() {
			std::wcout <<
				L"--config option: Get and set app settings." << std::endl << 
				L"Usage: linuxplorer -c | --config [<profile>@<name>[=<value>] or [--initialize]]" << std::endl << std::endl <<
				L"Options:" << std::endl <<
				L"\t" << L"<profile>: Profile name" << std::endl <<
				L"\t" << L"<name>: Setting name" << std::endl <<
				L"\t" << L"<value>: Setting value" << std::endl <<
				L"\t" << L"--initialize: Reset all setting data" << std::endl << std::endl <<
				L"Gets the specified settings when only \'<name>\' field is provided. Otherwise, if \'<value>\' field is also specified, sets the settings." << std::endl << std::endl <<
				L"Allowed <name> and <value> patterns:" << std::endl <<
				L"\t" << L"<profile>@credential[=[<xxx.xxx.xxx.xxx> or <xxxx:xxxx:xxxx:...>],<username>,<password>]: Server address, username, and password for the SSH connection." << std::endl <<
				L"\t" << L"<profile>@syncroot[=<path>]: The mount point for the SFTP directory." << std::endl <<
				L"\t" << L"<profile>@port[=<port>]: The port number for the SSH connection." << std::endl <<
				L"\t" << L"startup[=[on] or [off]]: If the app starts at startup." << std::endl;
				
			return 0;
		}

		int get_config_option(std::wstring_view profile_name, std::wstring_view name) {
			if (name.empty()) {
				std::wcerr << L"Error: Plase specify at least one setting." << std::endl;
				return 1;
			}
			else if (compare(name, L"credential") == 0) {
				try {
					auto result = util::config::profile_manager::get(profile_name);

					std::wcout << L"The credential is as follows:" << std::endl <<
						L"\t" << L"Address: " << result.get_credential().get_host() << std::endl <<
						L"\t" << L"Username: " << result.get_credential().get_username() << std::endl <<
						L"\t" << L"Password: ";
					
					for (int i = 0; i < result.get_credential().get_password().length(); i++) {
						std::wcout << L"*";
					}
					std::wcout << std::endl;

					return 0;
				}
				catch (const util::config::config_exception& e) {
					std::wcerr << L"Configuration loading error: " << e.what() << std::endl;
					return 1;
				}
			}
			else if (compare(name, L"syncroot") == 0) {
				try {
					auto result = util::config::profile_manager::get(profile_name);

					std::wcout << L"The SFTP mount point is: \'" << result.get_syncroot() << L"\'." << std::endl;

					return 0;
				}
				catch (const util::config::config_exception& e) {
					std::wcerr << L"Configuration loading error: " << e.what() << std::endl;
					return 1;
				}
			}
			else if (compare(name, L"port") == 0) {
				try {
					auto result = util::config::profile_manager::get(profile_name);

					std::wcout << L"The port number for the SSH connection is: " << result.get_port() << std::endl;
					
					return 0;
				}
				catch (const util::config::config_exception& e) {
					std::wcerr << L"Configuration loading error: " << e.what() << std::endl;
					return 1;
				}
			}
			else if (compare(name, L"startup") == 0) {
				try {
					util::config::startup_config config;
					config.load();
					std::wcout << L"Startup is " << (config.get() ? L"enabled" : L"disabled") << std::endl;
				}
				catch (const util::config::config_exception& e) {
					std::wcerr << L"Configuration loading error: " << e.what() << std::endl;
					return 1;
				}

				return 0;
			}
			else {
				std::wcerr << L"Error: Cannot recongnize the setting name: " << L"\'" << name << L"\'" << std::endl;
				return 1;
			}
		}

		int set_config_option(std::wstring_view profile_name, std::wstring_view name, std::wstring_view value) {
			std::wstring v(value);

			if (compare(name, L"credential") == 0) {
				if (profile_name.empty()) {
					std::wcerr << "Error: Please specify a profile." << std::endl;
					return 1;
				}

				v.erase(std::remove_if(v.begin(), v.end(), [](wchar_t c) -> bool { return std::iswspace(c);}), v.end());

				std::size_t pos = 0, prev_pos = 0;
				int i = 0;
				std::wstring address, username, password;

				while ((pos = v.find(L',', prev_pos)) != std::wstring_view::npos || prev_pos < v.length()) {
					if (pos == std::wstring_view::npos) {
						pos = v.length();
					}
					auto token = v.substr(prev_pos, pos - prev_pos);

					switch (i) {
						case 0:
							try {
								ssh::ssh_address address(token);
							}
							catch (const ssh::invalid_address_format_exception& e) {
								std::wcerr << L"Error: Invalid address format: " << e.what() << std::endl;
								return 1;
							}

							address = token;
							break;
						case 1:
							username = token;
							break;
						case 2:
							password = token;
							break;
						default:
							std::wcerr << L"Error: Too many arguments for the setting: " << L"\'" << token << L"\'" << std::endl;
							return 1;
					}
					
					prev_pos = pos + 1;
					i++;
				}

				if (i < 2) {
					std::wcerr << L"Error: Not enough arguments for the setting: " << L"\'" << v << L"\'" << std::endl;
					return 1;
				}

				try {
					auto& profile = util::config::profile_manager::get(profile_name);
					profile.set_credential(util::config::credential(address, username, password));
					util::config::profile_manager::flush();
				}
				catch (const util::config::config_exception& e) {
					std::wcerr << L"Configuration saving error: " << e.what() << std::endl;
					return 1;
				}
			}
			else if (compare(name, L"syncroot") == 0) {
				if (profile_name.empty()) {
					std::wcerr << "Error: Please specify a profile." << std::endl;
					return 1;
				}
				try {
					auto& result = util::config::profile_manager::get(profile_name);
					if (!::PathFileExistsW(v.c_str())) {
						std::wcout << L"Error: The specified directory: \'" << value << "\' can't be used for the mount point." << std::endl;
						return 1;
					}

					std::wstring old_syncroot(result.get_syncroot());

					result.set_syncroot(v);
					util::config::profile_manager::flush();

					auto sid = get_string_current_user_sid();
					if (!sid) {
						std::wcerr << L"Failed to get the current user sid." << std::endl;
						return 1;
					}

					std::wstring reg_path;
					reg_path.append(syncroot_key_prefix).append(L"\\").append(WSTRINGIFY(LINUXPLORER_CLOUD_PROVIDER_NAME))
						.append(L"!").append(*sid).append(L"!").append(profile_name).append(L"\\").append(L"UserSyncRoots");

					unique_key_ptr key;
					::LSTATUS rc = open_key_in_hklm(key, reg_path);
					if (rc != ERROR_SUCCESS) {
						std::error_code ec(rc, std::system_category());
						std::wcerr << L"Failed to open the registry key 'HKEY_LOCAL_MACHINE\\" << reg_path << L"' (From Win32: " << ec.message().c_str() << L"(" << ec.value() << L"))" << std::endl;
						return 1;
					}

					rc = set_reg_value(key, sid->c_str(), v);
					if (rc != ERROR_SUCCESS) {
						std::wcerr << L"Failed to set data of the registry value." << std::endl;
						return 1;
					}

					try {
						shell::filesystem::cloud_provider_registrar::unregister_provider(old_syncroot);
					} catch (...) {}

					shell::filesystem::cloud_provider_registrar::register_provider(v, WSTRINGIFY(LINUXPLORER_CLOUD_PROVIDER_NAME), WSTRINGIFY(LINUXPLORER_VERSION));
				}
				catch (const util::config::config_exception& e) {
					std::wcerr << L"Configuration loading error: " << e.what() << std::endl;
					return 1;
				}
				catch (const shell::cloud_provider_system_error& e) {
					std::wcerr << L"Error: " << e.what() << L"(From Win32: " << e.code().message().c_str() << L"(" << e.code().value() << L"))" << std::endl;
					return 1;
				}
			}
			else if (compare(name, L"port") == 0) {
				if (profile_name.empty()) {
					std::wcerr << "Error: Please specify a profile." << std::endl;
					return 1;
				}
				try {
					auto& result = util::config::profile_manager::get(profile_name);

					if (std::count_if(v.begin(), v.end(), [](wchar_t ch) { return !std::iswdigit(ch); })) {
						std::wcout << L"Error: Please specify numbers only." << std::endl;
						return 1;
					}

					auto port = std::stoul(v);
					if (port > std::numeric_limits<unsigned short>::max()) {
						std::wcout << L"Error: Maximum port number exceeded." << std::endl;
						return 1;
					}

					result.set_port(port);
					util::config::profile_manager::flush();
				}
				catch (const util::config::config_exception& e) {
					std::wcerr << L"Configuration loading error: " << e.what() << std::endl;
					return 1;
				}
			}
			else if (compare(name, L"startup") == 0) {
				try {
					util::config::startup_config config;
					bool is_on;
					if (compare(v, L"on") == 0){
						is_on = true;
					}
					else if (compare(v, L"off") == 0) {
						is_on = false;
					}
					else {
						std::wcerr << L"Error: Invalid value for the setting: " << L"\'" << v << L"\'" << std::endl;
						return 1;
					}
					::CoInitializeEx(nullptr, ::COINIT::COINIT_APARTMENTTHREADED);
					config.set(is_on);
					config.save();
					::CoUninitialize();
				}
				catch (const util::config::config_exception& e) {
					std::wcerr << L"Configuration saving error: " << e.what() << std::endl;
					return 1;
				}
				catch (const std::system_error& e) {
					std::wcerr << L"Error: " << e.what() << std::endl;
					return 1;
				}
			}
			else {
				std::wcerr << L"Error: Cannot recongnize the setting name: " << L"\'" << name << L"\'" << std::endl;
				return 1;
			}

			std::wcout << L"The setting has been updated successfully." << std::endl;
			return 0;
		}

		int initialize_config_option() {
			try {
				std::vector<std::wstring> profile_names;
				for (const auto& profile : util::config::profile_manager::enumerate()) {
					profile_names.push_back(std::wstring(profile.get_name()));
				}

				for (const auto& profile_name : profile_names) {
					remove_profile_option(profile_name);
				}

				util::config::configuration_manager::initialize();
			}
			catch (const util::config::config_exception& e) {
				std::wcerr << L"Configuration initialization error: " << e.what() << std::endl;
				return 1;
			}
			std::wcout << L"Configuration has been initialized." << std::endl;
			return 0;
		}

		int status_option() {
			try {
				auto result = try_get_service_pid();
				std::wcout << "Status: linuxplorer service is " << (result.has_value() ? L"running." : L"not running.") << std::endl;
				return 0;
			}
			catch (const std::system_error& e) {
				std::wcerr << L"Error: " << e.what() << std::endl;
				return 1;
			}
			catch (const std::exception& e) {
				std::wcerr << L"Unexpected error: " << e.what() << std::endl;
				return 1;
			}
		}

		int initiate_option() {
			std::filesystem::path exe_path;
			try {
				std::filesystem::recursive_directory_iterator itr(util::config::configuration_manager::get_install_path());
				for (const auto& p : itr) {
					auto stem = p.path().stem().wstring();
					if (compare(stem, WSTRINGIFY(LINUXPLORER_APP_SERVICE_NAME)) == 0) exe_path = p;
				}
			}
			catch (const std::filesystem::filesystem_error& e) {
				std::wcerr << L"Filesystem error: " << e.what() << std::endl;
				return 1;
			}
			if (exe_path.empty()) {
				std::wcerr << L"Error: No service executable found." << std::endl;

				return 1;
			}

			STARTUPINFOW si{};
			si.cb = sizeof(si);
			PROCESS_INFORMATION pi{};

			bool succeeded = ::CreateProcessW(
				exe_path.wstring().c_str(),
				nullptr,
				nullptr,
				nullptr,
				false,
				0,
				nullptr,
				nullptr,
				&si,
				&pi
			);
			if (!succeeded) {
				std::error_code ec(::GetLastError(), std::system_category());
				std::wcerr << L"Failed to initiate the linuxplorer service: " << ec.message().c_str() << std::endl;
				return 1;
			}

			::CloseHandle(pi.hThread);
			::CloseHandle(pi.hProcess);

			std::wcout << L"linuxplorer service has been initiated successfully." << std::endl;

			return 0;
		}

		int terminate_option() {
			uint32_t pid;
			try {
				auto pid_nullable = try_get_service_pid();
				if (!pid_nullable.has_value()) {
					std::wcerr << L"Error: linuxplorer service is not running." << std::endl;
					return 1;
				}

				pid = pid_nullable.value();
			}
			catch (const std::system_error& e) {
				std::wcerr << L"Error: " << e.what() << std::endl;
				return 1;
			}
			catch (const std::exception& e) {
				std::wcerr << L"Unexpected error: " << e.what() << std::endl;
				return 1;
			}

			::HANDLE process = ::OpenProcess(PROCESS_QUERY_INFORMATION | SYNCHRONIZE, false, pid);
			if (!process) {
				std::error_code ec(::GetLastError(), std::system_category());
				std::wcerr << L"Failed to open the linuxplorer service process: " << ec.message().c_str() << std::endl;
				return 1;
			}

			::HANDLE event = ::OpenEventW(EVENT_MODIFY_STATE, false, WSTRINGIFY(LINUXPLORER_APP_SERVICE_TERMINATE_EVENT_NAME));
			if (!event) {
				std::error_code ec(::GetLastError(), std::system_category());
				std::wcerr << L"Failed to open the terminate event: " << ec.message().c_str() << std::endl;
				return 1;
			}

			bool succeeded = ::SetEvent(event);
			if (!succeeded) {
				std::error_code ec(::GetLastError(), std::system_category());
				std::wcerr << L"Failed to set the terminate event: " << ec.message().c_str() << std::endl;
				::CloseHandle(event);
				return 1;
			}

			std::wcout << L"Waiting for the linuxplorer service to terminate..." << std::endl;
			::WaitForSingleObject(process, INFINITE);

			::CloseHandle(event);
			::CloseHandle(process);

			std::wcout << L"linuxplorer service has been terminated successfully." << std::endl;
			return 0;
		}

		int remove_profile_option(std::wstring_view profile_name) {
			try {
				auto profile = util::config::profile_manager::get(profile_name);
				std::wstring old_syncroot(profile.get_syncroot());

				util::config::profile_manager::remove(profile_name);
				util::config::profile_manager::flush();

				auto sid = get_string_current_user_sid();
				if (!sid) {
					std::wcerr << L"Failed to get the current user sid." << std::endl;
					return 1;
				}

				std::wstring reg_path;
				reg_path.append(syncroot_key_prefix).append(L"\\").append(WSTRINGIFY(LINUXPLORER_CLOUD_PROVIDER_NAME))
						.append(L"!").append(*sid).append(L"!").append(profile_name);

				unique_key_ptr key;
				::LSTATUS rc = open_key_in_hklm(key, reg_path);
				if (rc != ERROR_SUCCESS) {
					std::error_code ec(rc, std::system_category());
					std::wcerr << L"Failed to open the registry key 'HKEY_LOCAL_MACHINE\\" << reg_path << L"' (From Win32: " << ec.message().c_str() << L"(" << ec.value() << L"))" << std::endl;
					return 1;
				}

				rc = delete_in_hklm(reg_path);
				if (rc != ERROR_SUCCESS) {
					std::error_code ec(rc, std::system_category());
					std::wcerr << L"Failed to delete the registry key 'HKEY_LOCAL_MACHINE\\" << reg_path << L"' (From Win32: " << ec.message().c_str() << L"(" << ec.value() << L"))" << std::endl;
					return 1;
				}

				try {
					shell::filesystem::cloud_provider_registrar::unregister_provider(old_syncroot);
				} catch (...) {}

				std::wcout << L"The profile \'" << profile_name << L"\' has been unregistered successfully." << std::endl;
				return 0;
			}
			catch (const util::config::config_exception& e) {
				std::wcerr << L"Error: " << e.what() << std::endl;
				return 1;
			}
			catch (const shell::cloud_provider_system_error& e) {
				std::wcerr << L"Error: " << e.what() << L"(From Win32: " << e.code().message().c_str() << L"(" << e.code().value() << L"))" << std::endl;
				return 1;
			}
		}

		int create_profile_option(std::wstring_view profile_name) {
			try {
				util::config::credential credential(L"", L"", L"");
				util::config::profile profile(profile_name, L"", 22, credential);
				util::config::profile_manager::add(profile);
				util::config::profile_manager::flush();
				
				auto sid = get_string_current_user_sid();
				if (!sid) {
					std::wcerr << L"Failed to get the current user sid." << std::endl;
					return 1;
				}

				std::wstring reg_path;
				reg_path.append(syncroot_key_prefix).append(L"\\").append(WSTRINGIFY(LINUXPLORER_CLOUD_PROVIDER_NAME))
						.append(L"!").append(*sid).append(L"!").append(profile_name);

				unique_key_ptr key;
				::LSTATUS rc = open_key_in_hklm(key, reg_path);
				if (rc != ERROR_SUCCESS) {
					std::error_code ec(rc, std::system_category());
					std::wcerr << L"Failed to open the registry key 'HKEY_LOCAL_MACHINE\\" << reg_path << L"' (From Win32: " << ec.message().c_str() << L"(" << ec.value() << L"))" << std::endl;
					return 1;
				}

				bool failed_once = false;
				rc = set_reg_value(key, L"DisplayNameResource", std::wstring(profile_name));
				if (rc != ERROR_SUCCESS) failed_once = true;

				constexpr ::DWORD flags_value = 0x422;
				rc = set_reg_value(key, L"Flags", flags_value);
				if (rc != ERROR_SUCCESS) failed_once = true;

				rc = set_reg_value(key, L"IconResource", L"C:\\Windows\\system32\\shell.dll,-7");
				if (rc != ERROR_SUCCESS || failed_once) {
					std::wcerr << L"Failed to set data of registry values." << std::endl;
					return 1;
				}
				
				std::wcout << L"The profile \'" << profile_name << L"\' has been registered successfully." << std::endl;
				return 0;
			}
			catch (const util::config::config_exception& e) {
				std::wcerr << L"Error: " << e.what() << std::endl;
				return 1;
			}
		}

		int enumerate_profile_option() {
			try {
				const auto& profiles = util::config::profile_manager::enumerate();
				std::wcout << L"Registered profiles are as follows:" << std::endl;
				for (const auto& profile : profiles) {
					std::wcout << profile.get_name() << std::endl;
				}
				return 0;
			}
			catch (const util::config::config_exception& e) {
				std::wcerr << L"Error: " << e.what() << std::endl;
				return 1;
			}
		}
	}
}