#ifndef COMMANDS_HPP
#define COMMANDS_HPP

#include <string_view>

namespace linuxplorer::app::linuxplorer {
	template <class T>
	using basic_string_char_t = T::traits_type::char_type;

	int compare(std::wstring_view l, std::wstring_view r);
	int compare(std::string_view l, std::string_view r);

	int option_handler(int argc, char** argv);

	namespace commands {
		int no_options();

		int help_config_option();
		int get_config_option(std::wstring_view name);
		int set_config_option(std::wstring_view name, std::wstring_view value);
		int initialize_config_option();
		int initiate_option();
		int terminate_option();
		int status_option();
	}
}

#endif // COMMANDS_HPP