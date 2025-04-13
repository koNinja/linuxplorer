#ifndef CLOUD_PROVIDER_EXCEPTION_H
#define CLOUD_PROVIDER_EXCEPTION_H

#include <stdexcept>
#include <winerror.h>

namespace linuxplorer::shell {
	class cloud_provider_exception : public std::runtime_error {
	protected:
		::HRESULT m_hresult;
	public:
		explicit cloud_provider_exception(const char* message, ::HRESULT hresult) : std::runtime_error(message) {}
		explicit cloud_provider_exception(const std::string& message, ::HRESULT hresult) : std::runtime_error(message) {}
		virtual ~cloud_provider_exception() noexcept = default;
	};
}

#endif // CLOUD_PROVIDER_EXCEPTION_H