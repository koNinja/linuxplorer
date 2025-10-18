#ifndef LINUXPLORER_CONFIG_EXCEPTION_HPP_
#define LINUXPLORER_CONFIG_EXCEPTION_HPP_

#include <util/config/configfwd.hpp>
#include <stdexcept>
#include <system_error>

namespace linuxplorer::util::config {
	class config_exception : public std::runtime_error {
	public:
		explicit config_exception(const char* what) : std::runtime_error(what) {}
		explicit config_exception(const std::string& what) : std::runtime_error(what) {}
		virtual ~config_exception() noexcept = default;
	};

	class config_io_exception : public config_exception {
	public:
		explicit config_io_exception(const char* what) : config_exception(what) {}
		explicit config_io_exception(const std::string& what) : config_exception(what) {}
		virtual ~config_io_exception() noexcept = default;
	};

	class config_json_exception : public config_io_exception {
	private:
		std::exception_ptr m_exptr;
	public:
		explicit config_json_exception(const char* what) : config_io_exception(what) {}
		explicit config_json_exception(const std::string& what) : config_io_exception(what) {}
		explicit config_json_exception(std::exception_ptr inner, const char* what) : config_io_exception(what), m_exptr(inner) {}
		explicit config_json_exception(std::exception_ptr inner, const std::string& what) : config_io_exception(what), m_exptr(inner) {}
		virtual ~config_json_exception() noexcept = default;

		std::exception_ptr inner_exception() const noexcept { return this->m_exptr; }
	};

	class config_system_error : public config_exception {
	private:
		std::error_code m_errc;
	public:
		explicit config_system_error(const std::error_code& errc, const char* what) : m_errc(errc), config_exception(what) {}
		explicit config_system_error(const std::error_code& errc, const std::string& what) : m_errc(errc), config_exception(what) {}
		virtual ~config_system_error() noexcept = default;

		const std::error_code& code() const noexcept { return this->m_errc; }
	};
}

#endif // LINUXPLORER_CONFIG_EXCEPTION_HPP_