#ifndef LINUXPLORER_SSH_EXCEPTION_HPP_
#define LINUXPLORER_SSH_EXCEPTION_HPP_

#include <ssh/sshfwd.hpp>
#include <stdexcept>
#include <system_error>
#include <functional>

namespace linuxplorer::ssh {
	class ssh_exception : public std::runtime_error {
	public:
		explicit ssh_exception(const std::string& what) : std::runtime_error(what) {}
		explicit ssh_exception(const char* what) : std::runtime_error(what) {}
		virtual ~ssh_exception() noexcept = default;
	};

	class ssh_libssh2_exception : public ssh_exception {
	private:
		std::error_code m_errc;
	public:
		explicit ssh_libssh2_exception(const std::error_code& errc, const std::string& what) : ssh_exception(what), m_errc(errc) {}
		explicit ssh_libssh2_exception(const std::error_code& errc, const char* what) : ssh_exception(what), m_errc(errc) {}
		virtual ~ssh_libssh2_exception() noexcept = default;

		inline const std::error_code& code() const noexcept { 
			return this->m_errc;
		}
	};

	class ssh_libssh2_sftp_exception : public ssh_libssh2_exception {
	public:
		ssh_libssh2_sftp_exception(const std::error_code& errc, const std::string& what) : ssh_libssh2_exception(errc, what) {}
		ssh_libssh2_sftp_exception(const std::error_code& errc, const char* what) : ssh_libssh2_exception(errc, what) {}
		virtual ~ssh_libssh2_sftp_exception() noexcept = default;
	};

	class ssh_system_error : public ssh_exception {
	private:
		std::error_code m_errc;
	public:
		explicit ssh_system_error(const std::error_code& errc, const std::string& what) : ssh_exception(what), m_errc(errc) {}
		explicit ssh_system_error(const std::error_code& errc, const char* what) : ssh_exception(what), m_errc(errc) {}
		virtual ~ssh_system_error() noexcept = default;

		inline const std::error_code& code() const noexcept { 
			return this->m_errc;
		}
	};

	class ssh_wsa_exception : public ssh_system_error {
	public:
		explicit ssh_wsa_exception(const std::error_code& errc, const std::string& what) : ssh_system_error(errc, what) {}
		explicit ssh_wsa_exception(const std::error_code& errc, const char* what) : ssh_system_error(errc, what) {}
		virtual ~ssh_wsa_exception() noexcept = default;
	};

	class ssh_session;
	class LINUXPLORER_SSH_API libssh2_category : public std::error_category {
	private:
		std::reference_wrapper<const ssh_session> m_session_ref;
	public:
		libssh2_category(const ssh_session& session);
		virtual ~libssh2_category() noexcept = default;
	
		virtual const char* name() const noexcept override;
		virtual std::string message(int ev) const override;
	};

	class libssh2_sftp_category : public std::error_category {
	public:
		virtual const char* name() const noexcept override { return ""; }
		virtual std::string message(int ev) const noexcept override { return ""; }
	};

	class ssh_invalid_operation_exception : public ssh_exception {
	public:
		explicit ssh_invalid_operation_exception(const char* what) : ssh_exception(what) {}
		explicit ssh_invalid_operation_exception(const std::string& what) : ssh_exception(what) {}
		virtual ~ssh_invalid_operation_exception() noexcept = default;
	};
}

#endif // LINUXPLORER_SSH_EXCEPTION_HPP_