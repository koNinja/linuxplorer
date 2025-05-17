#ifndef SSH_SESSION_HPP
#define SSH_SESSION_HPP

#include <boost/uuid.hpp>
#include <winsock2.h>
#include <ws2ipdef.h>

#include <libssh2.h>

#include <cstdint>
#include <string>
#include <string_view>
#include <variant>
#include <memory>

#include <ssh/ssh_address.hpp>

namespace linuxplorer::ssh {
	namespace internal {
		struct internal_ssh_session_ptr_t {
		private:
			::LIBSSH2_SESSION* m_ptr;
		public:
			internal_ssh_session_ptr_t(::LIBSSH2_SESSION* ptr) noexcept {
				this->m_ptr = ptr;
			}
			internal_ssh_session_ptr_t(const internal_ssh_session_ptr_t&) = default;
			internal_ssh_session_ptr_t(internal_ssh_session_ptr_t&&) = default;
			internal_ssh_session_ptr_t& operator=(const internal_ssh_session_ptr_t&) = default;
			internal_ssh_session_ptr_t& operator=(internal_ssh_session_ptr_t&&) = default;
			
			inline ::LIBSSH2_SESSION* ptr() const noexcept {
				return this->m_ptr;
			}
		};

		using shared_ssh_session_ptr = std::shared_ptr<internal_ssh_session_ptr_t>;
		using weak_ssh_session_ptr = std::weak_ptr<internal_ssh_session_ptr_t>;	
		struct ssh_session_delete {
		public:
			inline void operator()(internal_ssh_session_ptr_t* ptr) {
				::libssh2_session_free(ptr->ptr());
				delete ptr;
			}
		};

		inline shared_ssh_session_ptr build_session_from(::LIBSSH2_SESSION* src) noexcept {
			return shared_ssh_session_ptr(new internal_ssh_session_ptr_t(src), ssh_session_delete());
		}
	}

	enum class ssh_session_state {
		connectable,
		need_to_authenticate,
		connected,
		disconnected
	};

	constexpr std::uint16_t default_ssh_port = 22;

	class ssh_session {
		internal::shared_ssh_session_ptr m_session;

		::libssh2_socket_t m_socket;
		std::variant<::sockaddr_in, ::sockaddr_in6> m_socket_addr;

		ssh_address m_host;
		std::wstring m_username;
		ssh_session_state m_state;

		boost::uuids::uuid m_id;

		const ::sockaddr* get_sockaddr_ptr() const noexcept;
		std::size_t get_sockaddr_length() const noexcept;		
	public:
		ssh_session(const ssh_address& host, std::uint16_t port = default_ssh_port);
		ssh_session(const ssh_session&) = delete;
		ssh_session(ssh_session&& rhs) = default;

		void connect();
		void authenticate(std::wstring_view username, std::wstring_view password);
		void disconnect(std::wstring_view description = L"");

		std::uint16_t get_port() const noexcept;
		const ssh_address& get_host() const noexcept;
		::LIBSSH2_SESSION* get_session() const noexcept;
		internal::weak_ssh_session_ptr get_weak() const noexcept;
		ssh_session_state get_state() const noexcept;
		const boost::uuids::uuid& get_id() const noexcept;

		virtual ~ssh_session();
	};
}

#endif // SSH_SESSION_HPP