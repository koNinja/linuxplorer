#include "session.hpp"

#include <util/charset/multibyte_wide_compat_helper.hpp>
#include <util/config/app_settings.hpp>

#include <quill/Backend.h>
#include <quill/Frontend.h>
#include <quill/LogMacros.h>
#include <quill/sinks/FileSink.h>

#define TO_STRING(x)	#x
#define STRINGIFY(x)	TO_STRING(x)

namespace linuxplorer::app::lxpsvc {
	bool session::initialize_logger_if() noexcept {
		using chcvt = util::charset::multibyte_wide_compat_helper;

		if (s_logger) {
			return false;
		}

		try {
			std::unique_lock lock(s_logger_mutex);

			quill::Backend::start();

			auto sink = quill::Frontend::create_or_get_sink<quill::FileSink>(
				chcvt::convert_wide_to_multibyte(util::config::configuration_manager::get_log_path()),
				[]() {
					quill::FileSinkConfig cfg;
					cfg.set_open_mode('w');
					cfg.set_filename_append_option(quill::FilenameAppendOption::StartDateTime);
					return cfg;
				}(),
				quill::FileEventNotifier{}
			);

			s_logger = quill::Frontend::create_or_get_logger(STRINGIFY(LINUXPLORER_APP_SERVICE_NAME), std::move(sink));

			return true;
		}
		catch (...) { return false; }
	}

	session::session(std::wstring_view profile_name) noexcept : m_profile_name(profile_name), m_session_id(++s_session_id_prefix) {
		initialize_logger_if();

		LOG_INFO(s_logger, "Session #{} created.", this->m_session_id);
	}

	std::int32_t session::get_exit_code() const noexcept {
		return this->m_exit_code;
	}

	std::uint32_t session::get_session_id() const noexcept {
		return this->m_session_id;
	}

	session::~session() {}
}