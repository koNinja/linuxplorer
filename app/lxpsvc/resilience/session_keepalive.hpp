#ifndef LINUXPLORER_LXPSVC_SESSION_KEEPALIVE_HPP_
#define LINUXPLORER_LXPSVC_SESSION_KEEPALIVE_HPP_

#include <thread>
#include <condition_variable>
#include <mutex>
#include <atomic>

#include <ssh/ssh_session.hpp>
#include <ssh/sftp/sftp_session.hpp>

#include "../contexts/execution_context.hpp"

namespace linuxplorer::lxpsvc::resilience {
	enum class session_keeper_state {
		pending,
		running,
		stopped
	};

	class session_keeper {
	private:
		const std::chrono::seconds m_duration;

		std::thread m_keeper_thread;
		void keep_alive();
		std::condition_variable m_cv;
		std::mutex m_termination_flag_mutex;
		bool m_termination_requested;
		std::atomic<session_keeper_state> m_state;

		contexts::execution_context& m_execution_context;
		ssh::ssh_session& m_ssh_session;
		ssh::sftp::sftp_session& m_sftp_session;
		std::mutex& m_session_mutex;
	public:
		session_keeper(
			std::chrono::seconds duration,
			ssh::ssh_session& ssh_session,
			ssh::sftp::sftp_session& sftp_session,
			contexts::execution_context& execution_context,
			std::mutex& session_mutex
		);
		virtual ~session_keeper();

		void request_stop() noexcept;
		void wait() noexcept;
		
		session_keeper_state get_state() const noexcept;
	};
}

#endif // LINUXPLORER_LXPSVC_SESSION_KEEPALIVE_HPP_