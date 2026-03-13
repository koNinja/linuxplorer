#ifndef LINUXPLORER_LXPSVC_ABNORMAL_SYSTEMS_HPP_
#define LINUXPLORER_LXPSVC_ABNORMAL_SYSTEMS_HPP_

#include <stdexcept>
#include <format>

namespace linuxplorer::app::lxpsvc::exceptions {
	enum class runtime_error_domain {
		watcher,
		executor,
		context
	};

	class fatal_runtime_exception : std::runtime_error {
	private:
		runtime_error_domain m_domain;
	public:
		template <class... Args>
		explicit fatal_runtime_exception(runtime_error_domain domain, std::format_string<Args...> format, Args&&... args) 
			: std::runtime_error(std::format(format, std::forward<Args>(args)...)), m_domain(domain)
		{}

		inline runtime_error_domain get_domain() const noexcept {
			return this->m_domain;
		}
	};
}

#endif // LINUXPLORER_LXPSVC_ABNORMAL_SYSTEMS_HPP_