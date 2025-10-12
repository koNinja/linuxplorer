#ifndef LINUXPLORER_CLOUD_PROVIDER_SESSION_HPP_
#define LINUXPLORER_CLOUD_PROVIDER_SESSION_HPP_

#include <shell/shellfwd.hpp>
#include <shell/functional/cloud_provider_callback.hpp>

#include <string>
#include <string_view>
#include <unordered_map>
#include <memory>
#include <vector>

namespace linuxplorer::shell {
	class LINUXPLORER_SHELL_API cloud_provider_session {
	private:
		using this_t = cloud_provider_session;

		static ::CF_CALLBACK get_typed_caller_from_type(functional::cloud_provider_callback_type type) noexcept;

		template <functional::cloud_provider_callback_type T>
		static void typed_internal_caller(const ::CF_CALLBACK_INFO* info, const ::CF_CALLBACK_PARAMETERS* parameters);
		inline static std::unordered_map<cloud_provider_session_token, std::vector<std::unique_ptr<functional::cloud_provider_callback>>> s_callbacks;
	private:
		std::wstring m_sync_root_dir;
		cloud_provider_session_token m_connection_key;
		std::vector<std::unique_ptr<functional::cloud_provider_callback>> m_temporary_callback_table;

		bool m_is_connected;
	public:
		cloud_provider_session(std::wstring_view sync_root_dir);
		cloud_provider_session(const cloud_provider_session&) = delete;
		cloud_provider_session(cloud_provider_session&& right);
		cloud_provider_session& operator=(const cloud_provider_session&) = delete;
		cloud_provider_session& operator=(cloud_provider_session&& right);
		virtual ~cloud_provider_session() noexcept;

		template <functional::cloud_provider_callback_type T>
		void register_callback(const functional::specialized_cloud_provider_callback<T>& callback) {
			auto type = callback.get_type();
			auto xitr = std::find_if(this->m_temporary_callback_table.begin(), this->m_temporary_callback_table.end(), [type](const decltype(this->m_temporary_callback_table)::value_type& ptr) {
				return ptr->get_type() == type;
			});
			if (xitr != this->m_temporary_callback_table.end()) {
				throw functional::callback_duplication_exception(callback.get_type(), "The callback for the specified type has been already registered.");
			}

			this->m_temporary_callback_table.push_back(std::make_unique<functional::specialized_cloud_provider_callback<T>>(callback));
		}

		void connect();
		void disconnect();

		std::wstring_view get_sync_root_dir() const noexcept;
		cloud_provider_session_token get_connection_key() const noexcept;
	};
}

#endif // LINUXPLORER_CLOUD_PROVIDER_SESSION_HPP_