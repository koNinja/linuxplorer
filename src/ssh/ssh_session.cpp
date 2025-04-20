#define USE_SSH_INTERNAL_LIBRARIES

#include <ssh/ssh_session.hpp>
#include <ssh/auth/ssh_knownhosts.hpp>
#include <ssh/ssh_exception.hpp>
#include <ssh/internal/ssh_library_resource_manager.hpp>

namespace linuxplorer::ssh {
	const ::sockaddr* ssh_session::get_sockaddr_ptr() const noexcept {
		switch (this->m_host.get_type()) {
			case ssh_address_type::ipv4:
				return reinterpret_cast<const ::sockaddr*>(&std::get<::sockaddr_in>(this->m_socket_addr));

			case ssh_address_type::ipv6:
				return reinterpret_cast<const ::sockaddr*>(&std::get<::sockaddr_in6>(this->m_socket_addr));
			default:
				return nullptr;
		}
	}

	std::size_t ssh_session::get_sockaddr_length() const noexcept {
		switch (this->m_host.get_type()) {
			case ssh_address_type::ipv4:
				return sizeof(::sockaddr_in);

			case ssh_address_type::ipv6:
				return sizeof(::sockaddr_in6);
			default:
				return 0;
		}
	}

	ssh_session::ssh_session(const ssh_address& host, std::uint16_t port) : m_host(host) {
		if (!internal::ssh_library_resource_manager::is_wsa_initiated()) {
			int errc = internal::ssh_library_resource_manager::try_initiate_wsa();
			if (errc != 0) {
				throw ssh_wsa_exception(errc, "Failed to initiate use of the Winsock DLL by the process.");
			}
		}
		if (!internal::ssh_library_resource_manager::is_libssh2_initiated()) {
			int errc = internal::ssh_library_resource_manager::is_libssh2_initiated();
			if (errc != 0) {
				throw ssh_libssh2_exception(errc, "Failed to initiate use of the libssh2 by the process.");
			}
		}

		this->m_socket = ::socket(this->m_host.get_type() == ssh_address_type::ipv4 ? AF_INET : AF_INET6, SOCK_STREAM, 0);
		if (this->m_socket == LIBSSH2_INVALID_SOCKET) throw ssh_wsa_exception(::WSAGetLastError(), "Failed to create a socket.");

		switch (this->m_host.get_type()) {
			case linuxplorer::ssh::ssh_address_type::ipv4:
				::sockaddr_in sin;
				sin.sin_family = AF_INET;
				sin.sin_port = ::htons(port);
				sin.sin_addr = this->m_host.try_get_address_ipv4().value();
				this->m_socket_addr = sin;
				break;
			default:
				::sockaddr_in6 sin6;
				sin6.sin6_family = AF_INET6;
				sin6.sin6_port = ::htons(port);
				sin6.sin6_addr = this->m_host.try_get_address_ipv6().value();
				this->m_socket_addr = sin6;
				break;
		}

		this->m_state = ssh_session_state::connectable;
	}

	void ssh_session::connect(bool ignore_known_hosts) {
		if (this->m_state != ssh_session_state::connectable) {
			throw std::runtime_error("Session is not in a state to connect.");
		}

		int result = ::connect(this->m_socket, this->get_sockaddr_ptr(), this->get_sockaddr_length());
		if (result == SOCKET_ERROR) {
			throw ssh_wsa_exception(::WSAGetLastError(), "Failed to connect to the SSH server.");
		}

		this->m_session = ::libssh2_session_init();
		if (this->m_session == nullptr) {
			throw ssh_libssh2_exception(-1, "Failed to initialize an SSH session object.");
		}
		
		::libssh2_session_set_blocking(this->m_session, true);
		
		result = ::libssh2_session_handshake(this->m_session, this->m_socket);
		if (result < 0) {
			throw ssh_libssh2_exception(result, "Failed to perform the SSH handshake.");
		}

		if (!ignore_known_hosts) {
			auth::ssh_knownhosts knownhosts(*this);
			auto result = knownhosts.check();

			switch (result) {
				case auth::ssh_knownhosts_check_result::matched:
					break;
				case auth::ssh_knownhosts_check_result::mismatch:
					throw auth::ssh_knownhost_exception(auth::ssh_knownhosts_check_result::mismatch, "Host was found, but the keys didn't match.");
				case auth::ssh_knownhosts_check_result::missing:
					throw auth::ssh_knownhost_exception(auth::ssh_knownhosts_check_result::missing, "Host was not found in the known hosts.");
				default:
					throw std::logic_error("Unknown known hosts check result.");
			}
		}

		this->m_state = ssh_session_state::need_to_authenticate;
	}

	void ssh_session::authenticate(std::string_view username, std::string_view password) {
		if (this->m_state != ssh_session_state::need_to_authenticate) {
			throw std::runtime_error("Session is not in a state to authenticate.");
		}

		this->m_username = username.data();

		int result = libssh2_userauth_password(this->m_session, username.data(), password.data());
		if (result != 0) {
			throw ssh_libssh2_exception(result, "Failed to authenticate.");
		}

		this->m_state = ssh_session_state::connected;
	}

	void ssh_session::disconnect(std::string_view description) {
		if (this->m_state == ssh_session_state::connected) {
			throw std::runtime_error("Session is not in a state to disconnect.");
		}

		::libssh2_session_disconnect(this->m_session, description.data());
		::libssh2_session_free(this->m_session);

		this->m_state = ssh_session_state::disconnected;
	}

	std::uint16_t ssh_session::get_port() const noexcept {
		std::uint16_t netshort = 0;

		switch (this->m_host.get_type()) {
			case ssh_address_type::ipv4:
				netshort = std::get<::sockaddr_in>(this->m_socket_addr).sin_port;
				break;
			default:
				netshort = std::get<::sockaddr_in6>(this->m_socket_addr).sin6_port;
				break;
		}

		return ::ntohs(netshort);
	}

	const ssh_address& ssh_session::get_host() const noexcept {
		return this->m_host;
	}

	::LIBSSH2_SESSION* ssh_session::get_session() const noexcept {
		return this->m_session;
	}

	ssh_session::~ssh_session() {
		::shutdown(this->m_socket, SD_BOTH);
		::closesocket(this->m_socket);
	}
}