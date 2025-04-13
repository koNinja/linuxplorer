#ifndef CLOUD_PROVIDER_EXCEPTION_H
#define CLOUD_PROVIDER_EXCEPTION_H

#include <stdexcept>
#include <winerror.h>

namespace linuxplorer::shell {
	class cloud_provider_runtime_exception : public std::runtime_error {
	protected:
	public:
		explicit cloud_provider_runtime_exception(const char* message) : std::runtime_error(message) {}
		explicit cloud_provider_runtime_exception(const std::string& message) : std::runtime_error(message) {}
		virtual ~cloud_provider_runtime_exception() noexcept = default;
	};
}

#endif // CLOUD_PROVIDER_EXCEPTION_H