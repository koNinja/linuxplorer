#ifndef LINUXPLORER_SESSION_HPP_
#define LINUXPLORER_SESSION_HPP_

#include <optional>
#include <mutex>

#include <ssh/ssh_address.hpp>
#include <ssh/ssh_session.hpp>
#include <ssh/sftp/sftp_session.hpp>

#include <shell/cloud_provider_session.hpp>
#include <shell/functional/cloud_provider_callback.hpp>

#include <util/config/profiles.hpp>

#include <quill/Logger.h>

#define TO_WSTRING(x)	L#x
#define WSTRINGIFY(x)	TO_WSTRING(x)

namespace linuxplorer::app::lxpsvc {
	class session {
	private:
		inline static constexpr const wchar_t* s_provider_name = WSTRINGIFY(LINUXPLORER_CLOUD_PROVIDER_NAME);
		inline static constexpr const wchar_t* s_provider_version = WSTRINGIFY(LINUXPLORER_VERSION);

		inline static quill::Logger* s_logger = nullptr;
		inline static std::uint32_t s_session_id_prefix = 0;
		inline static std::mutex s_logger_mutex;
		static bool initialize_logger_if() noexcept;

		struct nthandle_delete {
		public:
			void operator()(::HANDLE handle) {
				::CloseHandle(handle);
			}
		};

		using unique_nthandle = std::unique_ptr<std::remove_pointer_t<::HANDLE>, nthandle_delete>;
	private:
		const std::wstring m_profile_name;
		const std::uint32_t m_session_id;
		std::wstring m_syncroot_dir;

		std::optional<ssh::ssh_session> m_ssh_session;
		std::optional<ssh::sftp::sftp_session> m_sftp_session;
		std::optional<shell::cloud_provider_session> m_cloud_session;
		
		std::int32_t m_exit_code;
		
		std::mutex m_sftp_mutex;
		std::shared_mutex m_this_session_mutex;
		
		int main();
		void stop() noexcept;

		void on_change_read(std::span<::std::byte> bytes_notify_info);
		shell::models::chunked_callback_generator<shell::functional::fetch_data_operation_info> on_fetch_data(const shell::functional::fetch_data_callback_parameters& parameters);
		shell::functional::fetch_placeholders_operation_info on_fetch_placeholders(const shell::functional::callback_parameters& parameters);
	public:
		session(std::wstring_view profile_name) noexcept;
		session(const session& lhs) = delete;
		session(session&& rhs) = delete;

		void start() noexcept;

		std::int32_t get_exit_code() const noexcept;
		std::uint32_t get_session_id() const noexcept;

		virtual ~session();
	};
}

#endif