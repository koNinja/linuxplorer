#ifndef SFTP_SESSION_HPP
#define SFTP_SESSION_HPP

#include <ssh/ssh_session.hpp>
#include <unordered_map>
#include <libssh2_sftp.h>

namespace linuxplorer::ssh::sftp {
	namespace internal {
		struct internal_sftp_session_ptr_t {
		private:
			ssh::internal::shared_ssh_session_ptr m_dependency;
			::LIBSSH2_SFTP* m_ptr;
		public:
			internal_sftp_session_ptr_t(::LIBSSH2_SFTP* ptr, ssh::internal::weak_ssh_session_ptr wref) noexcept {
				this->m_dependency = wref.lock();
				this->m_ptr = ptr;
			}
			internal_sftp_session_ptr_t(const internal_sftp_session_ptr_t&) = default;
			internal_sftp_session_ptr_t(internal_sftp_session_ptr_t&&) = default;
			internal_sftp_session_ptr_t& operator=(const internal_sftp_session_ptr_t&) = default;
			internal_sftp_session_ptr_t& operator=(internal_sftp_session_ptr_t&&) = default;
			
			inline ::LIBSSH2_SFTP* ptr() const noexcept {
				return this->m_ptr;
			}
		};

		using shared_sftp_session_ptr = std::shared_ptr<internal_sftp_session_ptr_t>;
		using weak_sftp_session_ptr = std::weak_ptr<internal_sftp_session_ptr_t>;	

		struct sftp_session_delete {
		public:
			inline void operator()(internal_sftp_session_ptr_t* ptr) {
				::libssh2_sftp_shutdown(ptr->ptr());
				delete ptr;
			}
		};

		inline shared_sftp_session_ptr build_sftp_from(::LIBSSH2_SFTP* src, const ssh_session& session) noexcept {
			return shared_sftp_session_ptr(new internal_sftp_session_ptr_t(src, session.get_weak()), sftp_session_delete());
		}

		struct internal_sftp_handle_ptr_t {
		private:
			shared_sftp_session_ptr m_dependency;
			::LIBSSH2_SFTP_HANDLE* m_ptr;
		public:
			internal_sftp_handle_ptr_t(::LIBSSH2_SFTP_HANDLE* ptr, weak_sftp_session_ptr wref) noexcept {
				this->m_dependency = wref.lock();
				this->m_ptr = ptr;
			}
			internal_sftp_handle_ptr_t(const internal_sftp_handle_ptr_t&) = default;
			internal_sftp_handle_ptr_t(internal_sftp_handle_ptr_t&&) = default;
			internal_sftp_handle_ptr_t& operator=(const internal_sftp_handle_ptr_t&) = default;
			internal_sftp_handle_ptr_t& operator=(internal_sftp_handle_ptr_t&&) = default;
			
			inline ::LIBSSH2_SFTP_HANDLE* ptr() const noexcept {
				return this->m_ptr;
			}
		};
		
		struct sftp_handle_delete {
			public:
			void operator()(internal_sftp_handle_ptr_t* ptr) {
				::libssh2_sftp_close_handle(ptr->ptr());
				delete ptr;
			}
		};

		using unqiue_sftp_handle_ptr = std::unique_ptr<internal_sftp_handle_ptr_t, sftp_handle_delete>;
	}
	
	class sftp_session {
	private:
		inline static std::unordered_map<boost::uuids::uuid, internal::weak_sftp_session_ptr> s_sessions {};

		internal::shared_sftp_session_ptr m_session;
	public:
		sftp_session(const ssh_session& session);
		sftp_session(const sftp_session&) = default;
		sftp_session(sftp_session&&) = default;

		internal::weak_sftp_session_ptr get_weak() const noexcept;
		::LIBSSH2_SFTP* get_session() const noexcept;
	};

	
	class sftp_handle {
	private:
		internal::unqiue_sftp_handle_ptr m_handle;
	public:
		sftp_handle(const sftp_session& session, ::LIBSSH2_SFTP_HANDLE* handle);
		sftp_handle(const sftp_handle&) = delete;
		sftp_handle(sftp_handle&&) = default;

		::LIBSSH2_SFTP_HANDLE* get_handle() const noexcept;
	};
}

#endif // SFTP_SESSION_HPP