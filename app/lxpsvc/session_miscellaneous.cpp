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
	bool session::initialize_logger_if() {
		if (s_logger) {
			return false;
		}

		quill::Backend::start();

		auto sink = quill::Frontend::create_or_get_sink<quill::FileSink>(
			util::config::configuration_manager::get_log_path(),
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

	std::optional<std::reference_wrapper<session>> session::get_session_from_connection_key(const ::CF_CONNECTION_KEY& key) {
		auto itr = std::find_if(
			s_sessions.cbegin(),
			s_sessions.cend(),
			[&](session* sess) -> bool {
				return sess->get_cloud_session().has_value() ?
					sess->get_cloud_session()->get_connection_key().Internal == key.Internal :
					false;
			}
		);
		
		return (itr != s_sessions.cend()) ? std::make_optional(std::ref(**itr)) : std::nullopt;
	}

	session::session() : m_session_id(++s_session_count) {
		initialize_logger_if();

		s_sessions.push_back(this);
		LOG_INFO(s_logger, "Session #{} created.", this->m_session_id);
	}

	std::int32_t session::get_exit_code() const noexcept {
		return this->m_exit_code;
	}

	std::uint32_t session::get_session_id() const noexcept {
		return this->m_session_id;
	}

	const std::optional<ssh::ssh_session>& session::get_ssh_session() const noexcept {
		return this->m_ssh_session;
	}

	const std::optional<shell::cloud_provider_session>& session::get_cloud_session() const noexcept {
		return this->m_cloud_session;
	}

	const std::optional<ssh::sftp::sftp_session>& session::get_sftp_session() const noexcept {
		return this->m_sftp_session;
	}

	session::~session() {}
}