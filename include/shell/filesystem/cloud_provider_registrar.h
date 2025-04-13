#ifndef CLOUD_PROVIDER_REGISTRAR_H
#define CLOUD_PROVIDER_REGISTRAR_H

#include <shell/cloud_provider_session.h>
#include <string_view>

namespace linuxplorer::shell::filesystem {
	class cloud_provider_registrar {
	public:
		cloud_provider_registrar() = delete;
		cloud_provider_registrar(const cloud_provider_registrar&) = delete;
		cloud_provider_registrar(cloud_provider_registrar&&) = delete;
		~cloud_provider_registrar() = delete;

		static cloud_provider_session register_provider(
			std::wstring_view sync_root_dir,
			std::wstring_view provider_name,
			std::wstring_view provider_version
		);

		static void unregister_provider(std::wstring_view sync_root_dir);
	};
}

#endif // CLOUD_PROVIDER_REGISTRAR_H