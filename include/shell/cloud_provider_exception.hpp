#ifndef LINUXPLORER_CLOUD_PROVIDER_EXCEPTION_HPP_
#define LINUXPLORER_CLOUD_PROVIDER_EXCEPTION_HPP_

#include <stdexcept>
#include <winerror.h>
#include <system_error>

namespace linuxplorer::shell {
	class cloud_provider_runtime_exception : public std::runtime_error {
	public:
		explicit cloud_provider_runtime_exception(const char* message) : std::runtime_error(message) {}
		explicit cloud_provider_runtime_exception(const std::string& message) : std::runtime_error(message) {}
		virtual ~cloud_provider_runtime_exception() noexcept = default;
	};

	class cloud_provider_system_error : public cloud_provider_runtime_exception {
	private:
		std::error_code m_error_code;
	public:
		explicit cloud_provider_system_error(const std::error_code& ec, const std::string& message) : m_error_code(ec), cloud_provider_runtime_exception(message) {}
		explicit cloud_provider_system_error(const std::error_code& ec, const char* message) : m_error_code(ec), cloud_provider_runtime_exception(message) {}
		virtual ~cloud_provider_system_error() noexcept = default;

		inline const std::error_code& code() const noexcept { return this->m_error_code; }
	};
}

#endif // LINUXPLORER_CLOUD_PROVIDER_EXCEPTION_HPP_