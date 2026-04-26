#ifndef LINUXPLORER_CLOUD_PROVIDER_SESSION_HPP_
#define LINUXPLORER_CLOUD_PROVIDER_SESSION_HPP_

#include <shell/shellfwd.hpp>
#include <shell/functional/cloud_provider_callback.hpp>

#include <filesystem>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <vector>

namespace linuxplorer::shell {
	class LINUXPLORER_SHELL_API cloud_provider_session {
	private:
		using this_t = cloud_provider_session;

		static ::CF_CALLBACK get_typed_caller_from_type(functional::cloud_provider_callback_type type) noexcept;

		template <functional::cloud_provider_callback_type T>
		static void typed_internal_caller(const ::CF_CALLBACK_INFO* info, const ::CF_CALLBACK_PARAMETERS* parameters);
		inline static std::mutex s_callback_table_mutex;
		inline static std::unordered_map<cloud_provider_session_token, std::vector<std::unique_ptr<functional::cloud_provider_callback>>> s_callbacks;
	private:
		std::filesystem::path m_sync_root_dir;
		cloud_provider_session_token m_connection_key;
		std::vector<std::unique_ptr<functional::cloud_provider_callback>> m_temporary_callback_table;

		bool m_is_connected;
	public:
		cloud_provider_session(const std::filesystem::path& sync_root_dir);
		cloud_provider_session(const cloud_provider_session& lhs) = delete;
		cloud_provider_session(cloud_provider_session&& rhs);
		cloud_provider_session& operator=(const cloud_provider_session& lhs) = delete;
		cloud_provider_session& operator=(cloud_provider_session&& rhs);
		virtual ~cloud_provider_session() noexcept;

		template <functional::cloud_provider_callback_type T, class C>
		requires std::same_as<std::remove_cvref_t<C>, functional::specialized_cloud_provider_callback<T>>
		void register_callback(C&& callback) {
			this->register_callback(std::make_unique<functional::specialized_cloud_provider_callback<T>>(std::forward<C>(callback)));
		}

		void register_callback(std::unique_ptr<functional::cloud_provider_callback> callback);

		void connect();
		void disconnect();

		const std::filesystem::path& get_sync_root_dir() const noexcept;
		cloud_provider_session_token get_connection_key() const noexcept;
	};
}

#endif // LINUXPLORER_CLOUD_PROVIDER_SESSION_HPP_