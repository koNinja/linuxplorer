#include "session.hpp"

#include <util/charset/multibyte_wide_compat_helper.hpp>
#include <util/charset/case_insensitive_char_traits.hpp>
#include <util/config/app_settings.hpp>

#include <Shlwapi.h>

#include <quill/Backend.h>
#include <quill/Frontend.h>
#include <quill/LogMacros.h>
#include <quill/sinks/FileSink.h>

#define TO_STRING(x)	#x
#define STRINGIFY(x)	TO_STRING(x)

namespace linuxplorer::app::lxpsvc {
	bool session::initialize_logger_if() noexcept {
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

	std::wstring session::relative_path_from_syncroot(const std::wstring& absolute_path) const noexcept {
		auto compare = [](std::wstring_view l, std::wstring_view r) -> int {
			if (l.length() == r.length()) return util::charset::case_insensitive_char_traits<wchar_t>::compare(l.data(), r.data(), std::min(l.length(), r.length()));
			else return 1;
		};

		if (compare(this->m_syncroot_dir, absolute_path) != 0) {
			return absolute_path.substr(this->m_syncroot_dir.length() + 1);
		}
		else {
			return {};
		}
	}

	std::wstring session::server_path_from_relative_path(std::wstring_view relative_path) const noexcept {
		std::wstring result;
		result.append(L"/").append(relative_path);
		std::replace(result.begin(), result.end(), L'\\', L'/');

		return result;
	}

	std::wstring session::build_absolute_path_from(std::wstring_view relative_path) const noexcept {
		std::wstring result = this->m_syncroot_dir;
		if (result.size() <= 0) return result; 
		result.append(L"\\").append(relative_path);
		return result;
	}

	std::wstring session::extract_parent_path(std::wstring_view path) const noexcept {
		std::wstring result;
		auto last_separator_pos = path.find_last_of(L'\\');
		if (last_separator_pos != std::wstring_view::npos) result = path.substr(0, last_separator_pos);

		return result;
	}

	session::~session() {}
}