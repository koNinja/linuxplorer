#pragma once

#include <shell/functional/cloud_provider_callback.hpp>

using namespace linuxplorer;

inline shell::models::chunked_callback_generator<shell::functional::fetch_data_operation_info> on_fetch_data(const shell::functional::fetch_data_callback_parameters&) {
	co_return;
}

inline shell::functional::fetch_placeholders_operation_info on_fetch_placeholders(const shell::functional::callback_parameters&) {
	return {};
}