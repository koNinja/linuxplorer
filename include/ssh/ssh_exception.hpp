#ifndef SSH_EXCEPTION_HPP
#define SSH_EXCEPTION_HPP

#include <stdexcept>
#include <cstdint>

namespace linuxplorer::ssh {
	class ssh_exception : public std::runtime_error {
	public:
		ssh_exception(const std::string& what) : std::runtime_error(what) {}
		ssh_exception(const char* what) : std::runtime_error(what) {}
	};

	class ssh_libssh2_exception : public ssh_exception {
	protected:
		int m_errc;
	public:
		ssh_libssh2_exception(int errc, const std::string& what) : ssh_exception(what), m_errc(errc) {}
		ssh_libssh2_exception(int errc, const char* what) : ssh_exception(what), m_errc(errc) {}

		inline int code() const noexcept { 
			return this->m_errc;
		}
	};

	class ssh_invalid_state_operation : public ssh_exception {
	public:
		ssh_invalid_state_operation(const std::string& what) : ssh_exception(what) {}
		ssh_invalid_state_operation(const char* what) : ssh_exception(what) {}
	};

	class ssh_libssh2_sftp_exception : public ssh_libssh2_exception {
	public:
		ssh_libssh2_sftp_exception(int errc, const std::string& what) : ssh_libssh2_exception(errc, what) {}
		ssh_libssh2_sftp_exception(int errc, const char* what) : ssh_libssh2_exception(errc, what) {}
	};

	class ssh_wsa_exception : public ssh_exception {
	protected:
		std::int32_t m_errc;
	public:
		ssh_wsa_exception(std::int32_t errc, const std::string& what) : ssh_exception(what), m_errc(errc) {};
		ssh_wsa_exception(std::int32_t errc, const char* what) : ssh_exception(what), m_errc(errc) {};

		inline std::int32_t code() const noexcept { 
			return this->m_errc;
		}
	};
}

#endif // SSH_EXCEPTION_HPP