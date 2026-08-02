#include <engine/resilience/session_keepalive.hpp>

#include <ssh/ssh_exception.hpp>

namespace linuxplorer::engine::resilience {
	session_keeper::session_keeper(
		std::chrono::seconds duration,
		ssh::ssh_session& ssh_session,
		ssh::sftp::sftp_session& sftp_session,
		contexts::execution_context& execution_context,
		std::mutex& session_mutex
	) : m_duration(duration), m_ssh_session(ssh_session), m_sftp_session(sftp_session), m_termination_requested(false),
		m_execution_context(execution_context), m_session_mutex(session_mutex), m_state(session_keeper_state::pending)
	{}

	session_keeper::~session_keeper() {
		this->request_stop();
		this->wait();
	}

	void session_keeper::start() {
		this->m_keeper_thread = std::thread(&session_keeper::keep_alive, this);
	}

	void session_keeper::keep_alive() {
		this->m_state = session_keeper_state::running;

		int raw_seconds_to_wait = 0;
		while (true) {
			auto seconds_to_wait = std::min(this->m_duration, std::chrono::seconds(raw_seconds_to_wait));

			while (true) {
				std::unique_lock flag_lock(this->m_termination_flag_mutex);
				if (this->m_termination_requested) {
					this->m_state = session_keeper_state::stopped;
					return;
				}

				auto stat = this->m_cv.wait_for(flag_lock, seconds_to_wait);
				if (stat == std::cv_status::timeout) break;
			}

			{
				std::unique_lock ssh_lock(this->m_session_mutex);
				int rc = ::libssh2_keepalive_send(this->m_ssh_session.get_session(), &raw_seconds_to_wait);
				if (rc < 0) {
					std::error_code ec(rc, ssh::libssh2_category(this->m_ssh_session));
					this->m_execution_context.enqueue_error(exceptions::fatal_runtime_exception(
						exceptions::runtime_error_domain::keeper,
						"Failed to transmit and receive a keep-alive packet with the server. (libssh2: {}({}))",
						ec.message(),
						ec.value()
					));

					this->m_state = session_keeper_state::stopped;
					return;
				}
			}
		}
	}

	void session_keeper::request_stop() noexcept {
		{
			std::unique_lock lock(this->m_termination_flag_mutex);
			this->m_termination_requested = true;
		}
		this->m_cv.notify_one();
	}

	void session_keeper::wait() noexcept {
		if (this->m_keeper_thread.joinable()) {
			this->m_keeper_thread.join();
		}
	}
	
	session_keeper_state session_keeper::get_state() const noexcept {
		return this->m_state;
	}
}