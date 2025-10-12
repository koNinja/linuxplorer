#include <ssh/ssh_exception.hpp>
#include <ssh/ssh_session.hpp>

#include <libssh2.h>

namespace linuxplorer::ssh {
	libssh2_category::libssh2_category(const ssh_session& session) : m_session_ref(std::ref(session)) {}

	const char* libssh2_category::name() const noexcept {
		return "libssh2_category";
	}
	std::string libssh2_category::message(int ev) const {
		char* result;
		::libssh2_session_last_error(this->m_session_ref.get().get_session(), &result, nullptr, true);
		return std::string(result);
	}
}