#include <ssh/internal/ssh_library_resource_manager.hpp>

#include <libssh2.h>

namespace linuxplorer::ssh::internal {
	int ssh_library_resource_manager::try_initiate_wsa() noexcept {
		if (is_wsa_initiated()) return 0;

		int result = ::WSAStartup(MAKEWORD(2, 0), &s_wsa_data);

		s_is_wsa_initiated = result == 0;

		return result;
	}
	int ssh_library_resource_manager::try_initiate_libssh2() noexcept {
		if (is_libssh2_initiated()) return 0;

		int result = ::libssh2_init(0);

		s_is_libssh2_initiated = result == 0;

		return result;
	}
	bool ssh_library_resource_manager::is_libssh2_initiated() noexcept {
		return s_is_libssh2_initiated;
	}
	bool ssh_library_resource_manager::is_wsa_initiated() noexcept {
		return s_is_wsa_initiated;
	}
}