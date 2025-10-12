#define USE_SSH_INTERNAL_LIBRARIES

#include <ssh/ssh_session.hpp>
#include <ssh/ssh_exception.hpp>
#include <ssh/internal/ssh_library_resource_manager.hpp>
#include <util/charset/multibyte_wide_compat_helper.hpp>

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
				throw ssh_wsa_exception(std::error_code(errc, std::system_category()), "Failed to initiate use of the Winsock DLL by the process.");
			}
		}
		if (!internal::ssh_library_resource_manager::is_libssh2_initiated()) {
			int errc = internal::ssh_library_resource_manager::is_libssh2_initiated();
			if (errc != 0) {
				throw ssh_libssh2_exception(std::error_code(errc, libssh2_category(*this)), "Failed to initiate use of the libssh2 by the process.");
			}
		}

		this->m_id = boost::uuids::random_generator()();

		this->m_socket = ::socket(this->m_host.get_type() == ssh_address_type::ipv4 ? AF_INET : AF_INET6, SOCK_STREAM, 0);
		if (this->m_socket == LIBSSH2_INVALID_SOCKET) throw ssh_wsa_exception(std::error_code(::WSAGetLastError(), std::system_category()), "Failed to create a socket.");

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

		this->m_session = internal::build_session_from(::libssh2_session_init());
		if (this->m_session == nullptr) {
			throw ssh_libssh2_exception(std::error_code(0, libssh2_category(*this)), "Failed to initialize an SSH session object.");
		}
		
		::libssh2_session_set_blocking(this->m_session->ptr(), true);

		this->m_state = ssh_session_state::connectable;
	}

	void ssh_session::connect() {
		if (this->m_state != ssh_session_state::connectable) {
			throw ssh_invalid_state_operation("Session is not in a state to connect.");
		}

		int result = ::connect(this->m_socket, this->get_sockaddr_ptr(), this->get_sockaddr_length());
		if (result == SOCKET_ERROR) {
			throw ssh_wsa_exception(std::error_code(::WSAGetLastError(), std::system_category()), "Failed to connect to the SSH server.");
		}

		result = ::libssh2_session_handshake(this->m_session->ptr(), this->m_socket);
		if (result < 0) {
			throw ssh_libssh2_exception(std::error_code(result, libssh2_category(*this)), "Failed to perform the SSH handshake.");
		}

		this->m_state = ssh_session_state::need_to_authenticate;
	}

	void ssh_session::authenticate(std::wstring_view username, std::wstring_view password) {
		using charset_helper = linuxplorer::util::charset::multibyte_wide_compat_helper;

		if (this->m_state != ssh_session_state::need_to_authenticate) {
			throw ssh_invalid_state_operation("Session is not in a state to authenticate.");
		}

		this->m_username = username.data();

		int result = libssh2_userauth_password(this->m_session->ptr(), charset_helper::convert_wide_to_multibyte(username).c_str(), charset_helper::convert_wide_to_multibyte(password).c_str());
		if (result != 0) {
			throw ssh_libssh2_exception(std::error_code(result, libssh2_category(*this)), "Failed to authenticate.");
		}

		this->m_state = ssh_session_state::connected;
	}

	void ssh_session::disconnect(std::wstring_view description) {
		using charset_helper = linuxplorer::util::charset::multibyte_wide_compat_helper;

		if (this->m_state != ssh_session_state::connected) {
			throw ssh_invalid_state_operation("Session is not in a state to disconnect.");
		}

		::libssh2_session_disconnect(this->m_session->ptr(), charset_helper::convert_wide_to_multibyte(description).c_str());

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
		return this->m_session->ptr();
	}

	internal::weak_ssh_session_ptr ssh_session::get_weak() const noexcept {
		return this->m_session;
	}

	ssh_session_state ssh_session::get_state() const noexcept {
		return this->m_state;
	}

	const boost::uuids::uuid& ssh_session::get_id() const noexcept {
		return this->m_id;
	}

	int ssh_session::get_last_errno() const noexcept {
		return ::libssh2_session_last_errno(this->m_session->ptr());
	}

	ssh_session::~ssh_session() {
		if (this->m_state == ssh_session_state::connected) {
			this->disconnect();
		}
		
		::shutdown(this->m_socket, SD_BOTH);
		::closesocket(this->m_socket);
	}
}