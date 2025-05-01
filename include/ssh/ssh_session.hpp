#ifndef SSH_SESSION_HPP
#define SSH_SESSION_HPP

#include <winsock2.h>
#include <ws2ipdef.h>
#include <libssh2.h>

#include <cstdint>
#include <string>
#include <string_view>
#include <variant>

#include <ssh/ssh_address.hpp>

namespace linuxplorer::ssh {
	enum class ssh_session_state {
		connectable,
		need_to_authenticate,
		connected,
		disconnected
	};

	constexpr std::uint16_t default_ssh_port = 22;

	class ssh_session {
		::LIBSSH2_SESSION* m_session;

		::libssh2_socket_t m_socket;
		std::variant<::sockaddr_in, ::sockaddr_in6> m_socket_addr;

		ssh_address m_host;
		std::wstring m_username;
		ssh_session_state m_state;

		const ::sockaddr* get_sockaddr_ptr() const noexcept;
		std::size_t get_sockaddr_length() const noexcept;
	public:
		ssh_session(const ssh_address& host, std::uint16_t port = default_ssh_port);
		ssh_session(const ssh_session&) = delete;
		ssh_session(ssh_session&& right);

		void connect(bool ignore_known_hosts = false);
		void authenticate(std::wstring_view username, std::wstring_view password);
		void disconnect(std::wstring_view description = L"");

		std::uint16_t get_port() const noexcept;
		const ssh_address& get_host() const noexcept;
		::LIBSSH2_SESSION* get_session() const noexcept;

		virtual ~ssh_session();
	};
}

#endif // SSH_SESSION_HPP