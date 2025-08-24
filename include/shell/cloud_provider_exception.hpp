#ifndef LINUXPLORER_CLOUD_PROVIDER_EXCEPTION_HPP_
#define LINUXPLORER_CLOUD_PROVIDER_EXCEPTION_HPP_

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

#endif // LINUXPLORER_CLOUD_PROVIDER_EXCEPTION_HPP_