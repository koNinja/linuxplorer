#ifndef LINUXPLORER_SESSION_HPP_
#define LINUXPLORER_SESSION_HPP_

#include <optional>
#include <mutex>
#include <shared_mutex>
#include <atomic>
#include <unordered_map>

#include <ssh/ssh_address.hpp>
#include <ssh/ssh_session.hpp>
#include <ssh/sftp/sftp_session.hpp>

#include <shell/cloud_provider_session.hpp>
#include <shell/functional/cloud_provider_callback.hpp>
#include <shell/filesystem/cloud_filter_placeholder.hpp>

#include <util/charset/multibyte_wide_compat_helper.hpp>

#include <quill/Logger.h>

#define TO_WSTRING(x)	L#x
#define WSTRINGIFY(x)	TO_WSTRING(x)

namespace std {
	template <>
	struct hash<::FILE_ID_128> {
		size_t operator()(const ::FILE_ID_128& key) const noexcept {
            static_assert(sizeof(size_t) == 8, "This hash requires 64-bit size_t.");

            uint64_t high, low;
            std::memcpy(&high, key.Identifier, 8);
            std::memcpy(&low, key.Identifier + 8, 8);

            return high ^ (low * 0x9e3779b97f4a7c15ull);
        }
	};
}

inline bool operator==(const ::FILE_ID_128& lhs, const ::FILE_ID_128& rhs) noexcept {
	return std::memcmp(lhs.Identifier, rhs.Identifier, sizeof(lhs.Identifier)) == 0;
}

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
				if (handle && handle != INVALID_HANDLE_VALUE)
				::CloseHandle(handle);
			}
		};

		using unique_nthandle = std::unique_ptr<std::remove_pointer_t<::HANDLE>, nthandle_delete>;

		using usn_journal_data_t = ::USN_JOURNAL_DATA_V2;
		using read_usn_journal_data_t = ::READ_USN_JOURNAL_DATA_V1;
		using usn_record_t = ::USN_RECORD_V3;

		inline static constexpr std::chrono::seconds s_refetch_period = std::chrono::seconds(300);
	private:
		using chcvt = util::charset::multibyte_wide_compat_helper;

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
		
		shell::models::chunked_callback_generator<shell::functional::fetch_data_operation_info> on_fetch_data(const shell::functional::fetch_data_callback_parameters& parameters);
		shell::functional::fetch_placeholders_operation_info on_fetch_placeholders(const shell::functional::callback_parameters& parameters);
		void on_cancel_fetch_data(const shell::functional::cancel_fetch_data_callback_parameters& parameters);
		shell::functional::delete_operation_info on_delete(const shell::functional::delete_callback_parameters& parameters);
		shell::functional::operation_info on_rename(const shell::functional::rename_callback_parameters& parameters);
		void on_rename_completion(const shell::functional::rename_completion_callback_parameters& parameters);
		
		::USN on_change_read(const unique_nthandle& device, ::DWORDLONG journal_id, ::USN read_starts_at, std::span<std::byte> bytes_notify_info);
		void on_created_new(std::wstring_view client_path, std::wstring_view relative_client_path, std::wstring_view server_path);
		void on_attribute_changed(std::wstring_view absolute_client_path, std::wstring_view relative_client_path, std::wstring_view server_path);
		void on_content_changed(std::wstring_view absolute_client_path, std::wstring_view relative_client_path, std::wstring_view server_path);

		void internal_transform_children_recursive(const std::filesystem::path& absolute_client_path, const std::filesystem::path& relative_client_path, const std::filesystem::path& server_path);
		void on_moved_from_external(std::wstring_view absolute_client_path, std::wstring_view relative_client_path, std::wstring_view server_path);

		std::unordered_map<std::uint64_t, std::atomic<bool>> m_fetch_cancel_tokens;

		std::wstring relative_path_from_syncroot(const std::wstring& absolute_path) const noexcept;
		std::wstring build_absolute_path_from(std::wstring_view relative_path) const noexcept;
		std::wstring server_path_from_relative_path(std::wstring_view relative_path) const noexcept;
		std::wstring extract_parent_path(std::wstring_view path) const noexcept;

		std::unordered_map<::FILE_ID_128, std::chrono::sys_seconds> m_placeholder_last_fetched;
		std::mutex m_placeholder_last_fetched_mutex;
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