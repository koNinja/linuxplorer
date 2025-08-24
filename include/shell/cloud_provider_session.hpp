#ifndef LINUXPLORER_CLOUD_PROVIDER_SESSION_HPP_
#define LINUXPLORER_CLOUD_PROVIDER_SESSION_HPP_

#include <shell/shellfwd.hpp>
#include <shell/cloud_provider_callback.hpp>

#include <string>
#include <string_view>
#include <vector>

namespace linuxplorer::shell {
	class LINUXPLORER_SHELL_API cloud_provider_session {
		std::wstring m_sync_root_dir;
		std::vector<cloud_provider_callback> m_callbacks;

		::CF_CONNECTION_KEY m_connection_key;

		bool m_is_connected;
	public:
		cloud_provider_session(std::wstring_view sync_root_dir);
		cloud_provider_session(const cloud_provider_session&) = delete;
		cloud_provider_session(cloud_provider_session&& right);
		cloud_provider_session& operator=(const cloud_provider_session&) = delete;
		cloud_provider_session& operator=(cloud_provider_session&& right);
		virtual ~cloud_provider_session() noexcept;

		void register_callback(const cloud_provider_callback& callback) noexcept;
		void register_callbacks(const std::vector<cloud_provider_callback>& callbacks) noexcept;

		void connect();
		void disconnect();

		std::wstring_view get_sync_root_dir() const noexcept;
		const ::CF_CONNECTION_KEY& get_connection_key() const noexcept;
	};
}

#endif // LINUXPLORER_CLOUD_PROVIDER_SESSION_HPP_