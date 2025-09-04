#ifndef LINUXPLORER_SSH_LIBRARY_RESOURCE_MANAGER_HPP_
#define LINUXPLORER_SSH_LIBRARY_RESOURCE_MANAGER_HPP_

#ifndef LINUXPLORER_SSH_API_IMPLEMENTATION
#ifdef __GNUC__
#pragma GCC warning "This header file is used only in the implementation of the library."
#elif _MSC_VER
#pragma message("This header file is used only in the implementation of the library.")
#endif
#endif

#include <winsock2.h>

namespace linuxplorer::ssh::internal {
	class ssh_library_resource_manager final {
		inline static bool s_is_wsa_initiated = false;
		inline static bool s_is_libssh2_initiated = false;
		inline static ::WSADATA s_wsa_data;
	public:
		static int try_initiate_wsa() noexcept;
		static int try_initiate_libssh2() noexcept;

		static bool is_wsa_initiated() noexcept;
		static bool is_libssh2_initiated() noexcept;
		static bool is_libssh2_sftp_initiated() noexcept;
	};
}

#endif // LINUXPLORER_SSH_LIBRARY_RESOURCE_MANAGER_HPP_