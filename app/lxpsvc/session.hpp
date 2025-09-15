#ifndef LINUXPLORER_SESSION_HPP_
#define LINUXPLORER_SESSION_HPP_

#include <optional>
#include <list>
#include <functional>

#include <ssh/ssh_address.hpp>
#include <ssh/ssh_session.hpp>
#include <ssh/sftp/sftp_session.hpp>

#include <shell/cloud_provider_session.hpp>

#include <quill/Logger.h>

#include <mutex>

#define TO_WSTRING(x)	L#x
#define WSTRINGIFY(x)	TO_WSTRING(x)

namespace linuxplorer::app::lxpsvc {
	class session {
	private:
		inline static quill::Logger* s_logger = nullptr;
		inline static std::uint32_t s_session_count = 0;
		static bool initialize_logger_if();

		static std::optional<std::reference_wrapper<session>> get_session_from_connection_key(const ::CF_CONNECTION_KEY& key);
		inline static std::list<session*> s_sessions;

		struct cloud_providing_callbacks {
			static shell::models::chunked_callback_generator<shell::functional::fetch_data_operation_info> on_fetch_data(
				const shell::functional::fetch_data_callback_parameters& parameters
			);

			static shell::functional::fetch_placeholders_operation_info on_fetch_placeholders(
				const shell::functional::callback_parameters& parameters
			);
		};

		struct nthandle_delete {
		public:
			void operator()(::HANDLE handle) {
				::CloseHandle(handle);
			}
		};

		using unique_nthandle = std::unique_ptr<std::remove_pointer_t<::HANDLE>, nthandle_delete>;

		private:
		const wchar_t* m_syncroot_dir = L"C:\\Users\\koNinja\\Desktop\\client";
		const wchar_t* m_provider_name = L"LinuxplorerCloudProvider";
		const wchar_t* m_provider_version = WSTRINGIFY(LINUXPLORER_VERSION);

		const std::uint32_t m_session_id;
		std::optional<ssh::ssh_session> m_ssh_session;
		std::optional<ssh::sftp::sftp_session> m_sftp_session;
		std::optional<shell::cloud_provider_session> m_cloud_session;
		
		std::int32_t m_exit_code;
		
		std::mutex m_sftp_mutex;
		
		int main();
		void on_change_read(std::span<::std::byte> bytes_notify_info);
		
		::DWORD registered;
	public:
		session();

		void start();
		void stop();

		std::int32_t get_exit_code() const noexcept;
		std::uint32_t get_session_id() const noexcept;

		const std::optional<ssh::ssh_session>& get_ssh_session() const noexcept;
		const std::optional<shell::cloud_provider_session>& get_cloud_session() const noexcept;
		const std::optional<ssh::sftp::sftp_session>& get_sftp_session() const noexcept;

		virtual ~session();
	};
}

#endif