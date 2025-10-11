#include "commands.hpp"

#include <windows.h>
#include <Shlwapi.h>
#include <TlHelp32.h>

#include <ssh/ssh_address.hpp>
#include <util/charset/case_insensitive_char_traits.hpp>
#include <util/config/profiles.hpp>
#include <util/config/startup_config.hpp>

#include <boost/program_options.hpp>
#include <iostream>
#include <string>
#include <cctype>
#include <algorithm>
#include <optional>

#define TO_WSTRING(x)	L#x
#define WSTRINGIFY(x)	TO_WSTRING(x)

namespace linuxplorer::app::linuxplorer {
	int compare(std::wstring_view l, std::wstring_view r) {
		return util::charset::case_insensitive_char_traits<basic_string_char_t<std::wstring_view>>::compare(l.data(), r.data(), std::min(l.length(), r.length()));
	}

	int compare(std::string_view l, std::string_view r) {
		return util::charset::case_insensitive_char_traits<basic_string_char_t<std::string_view>>::compare(l.data(), r.data(), std::min(l.length(), r.length()));
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
				if (param == L"") {
					std::wcerr << L"Error: Plase specify at least one setting." << std::endl;
					return 1;
				}
				auto offset = param.find('@');
				auto profile_name = offset != param.npos ? param.substr(0, offset) : L"";

				auto pos = param.find(L'=');
				if (pos != param.npos) {
					return commands::set_config_option(profile_name, param.substr(offset + 1, pos), param.substr(pos + 1));
				}
				else {
					return commands::get_config_option(profile_name, param.substr(offset + 1));
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
			if (compare(name, L"credential") == 0) {
				try {
					auto result = util::config::profile_manager::get(profile_name);

					std::wcout << L"The credential is as follows below:" << std::endl <<
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
			v.erase(std::remove_if(v.begin(), v.end(), [](wchar_t c) -> bool { return std::isspace(c);}), v.end());

			if (compare(name, L"credential") == 0) {
				if (profile_name == L"") {
					std::wcerr << "Error: Please specify a profile." << std::endl;
					return 1;
				}

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
							catch (const std::invalid_argument& e) {
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
				try {
					auto& result = util::config::profile_manager::get(profile_name);
					if (!::PathFileExistsW(v.c_str())) {
						std::wcout << L"Error: The specified directory: \'" << value << "\' can't be used for the mount point." << std::endl;
						return 1;
					}

					result.set_syncroot(v);
					util::config::profile_manager::flush();
					
					return 0;
				}
				catch (const util::config::config_exception& e) {
					std::wcerr << L"Configuration loading error: " << e.what() << std::endl;
					return 1;
				}
			}
			else if (compare(name, L"port") == 0) {
				try {
					auto& result = util::config::profile_manager::get(profile_name);

					if (std::count_if(v.begin(), v.end(), [](wchar_t ch) { return std::isdigit(ch); })) {
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

			return 0;
		}

		int initialize_config_option() {
			try {
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
				util::config::profile_manager::remove(profile_name);
				util::config::profile_manager::flush();
				std::wcout << L"The profile \'" << profile_name << L"\' is unregistered successfully." << std::endl;
				return 0;
			}
			catch (const util::config::config_exception& e) {
				std::wcerr << L"Error: " << e.what() << std::endl;
				return 1;
			}
		}

		int create_profile_option(std::wstring_view profile_name) {
			try {
				util::config::credential credential(L"", L"", L"");
				util::config::profile profile(profile_name, L"", 22, credential);
				util::config::profile_manager::add(profile);
				util::config::profile_manager::flush();
				std::wcout << L"The profile \'" << profile_name << L"\' is registered successfully." << std::endl;
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
				std::wcout << L"Registered profiles are as follows below:" << std::endl;
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