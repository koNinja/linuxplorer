#include <ssh/sftp/sftp_session.hpp>
#include <ssh/ssh_exception.hpp>

namespace linuxplorer::ssh::sftp {
	sftp_session::sftp_session(const ssh_session& session) {
		auto ss_id = session.get_id();

		if (s_sessions.contains(ss_id) && !s_sessions[ss_id].expired()) {
			this->m_session = s_sessions[ss_id].lock();
		}
		else {
			::LIBSSH2_SFTP* sftp = ::libssh2_sftp_init(session.get_session());
			if (!sftp) {
				throw ssh_libssh2_exception(::libssh2_session_last_errno(session.get_session()), "Failed to initialize a SFTP session.");
			}

			this->m_session = internal::build_sftp_from(sftp, session);

			s_sessions[ss_id] = internal::weak_sftp_session_ptr(this->m_session);
		}
	}

	sftp_session::operator bool() const noexcept {
		return this->m_session != nullptr;
	}

	::LIBSSH2_SFTP* sftp_session::get_session() const noexcept {
		return this->m_session->ptr();
	}

	internal::weak_sftp_session_ptr sftp_session::get_weak() const noexcept {
		return this->m_session;
	}

	int sftp_session::get_last_errno() const noexcept {
		return ::libssh2_sftp_last_error(this->m_session->ptr());
	}

	sftp_handle::sftp_handle(const sftp_session& session, ::LIBSSH2_SFTP_HANDLE* handle) {
		if (!handle) {
			throw std::invalid_argument("null handle.");
		}
		this->m_handle = internal::unqiue_sftp_handle_ptr(new internal::internal_sftp_handle_ptr_t(handle, session.get_weak()));
	}

	sftp_handle::operator bool() const noexcept {
		return this->m_handle != nullptr;
	}

	::LIBSSH2_SFTP_HANDLE* sftp_handle::get_handle() const noexcept {
		return this->m_handle->ptr();
	}
}