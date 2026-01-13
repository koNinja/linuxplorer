#include "session.hpp"

#include <util/config/profiles.hpp>

#include <quill/LogMacros.h>

namespace linuxplorer::app::lxpsvc {
	void session::watch_ssh_sessions() noexcept {
		int seconds_to_wait = 0;
		while (true) {
			auto response = ::WaitForSingleObject(this->m_death_event.get(), seconds_to_wait * 1000);
			if (response == WAIT_FAILED || response == WAIT_OBJECT_0 || response == WAIT_ABANDONED) return;

			std::unique_lock ssh_lock(this->m_ssh_mutex);
			int rc = ::libssh2_keepalive_send(this->m_ssh_session->get_session(), &seconds_to_wait);
			// The mutex will remain occupied and will cause a deadlock in build_ssh_sftp_sessions() unless it is not unlocked.
			ssh_lock.unlock();

			if (rc < 0) {
				LOG_WARNING(s_logger, "Couldn't transmit or receive a keep-alive packet from the server in session #{}.", this->m_session_id);

				LOG_INFO(s_logger, "Try rebuild SSH and SFTP sessions in session #{}.", this->m_session_id);

				try {
					LOG_INFO(
						s_logger,
						"Loading the profile '{}' for session #{}.",
						this->m_session_id, 
						util::charset::multibyte_wide_compat_helper::convert_wide_to_multibyte(this->m_profile_name)
					);
					const auto& profile = util::config::profile_manager::get(this->m_profile_name);

					this->build_ssh_sftp_sessions(profile.get_port(), profile.get_credential().get_host(), profile.get_credential().get_username(), profile.get_credential().get_password());
				}
				catch (const util::config::config_exception& e) {
					LOG_CRITICAL(
						s_logger,
						"Failed to load the profile '{}' for this session #{}.",
						util::charset::multibyte_wide_compat_helper::convert_wide_to_multibyte(this->m_profile_name),
						this->m_session_id
					);
					::SetEvent(this->m_death_event.get());
					return;
				}
				catch (const ssh::ssh_exception& e) {
					LOG_CRITICAL(s_logger, "Failed to rebuild the SSH and SFTP session in session #{}.", this->m_session_id);
					::SetEvent(this->m_death_event.get());
					return;
				}
			}
		}
	}
}