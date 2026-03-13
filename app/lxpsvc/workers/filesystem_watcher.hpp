#ifndef LINUXPLORER_LXPSVC_FILESYSTEM_WATCHER_HPP_
#define LINUXPLORER_LXPSVC_FILESYSTEM_WATCHER_HPP_

#include "../win32/handle.hpp"
#include "../contexts/execution_context.hpp"

#include <filesystem>
#include <thread>
#include <span>

#include <quill/Logger.h>

#include <winioctl.h>

namespace linuxplorer::app::lxpsvc::workers {
	enum class filesystem_watcher_state {
		pending,
		running,
		stopped
	};

	class filesystem_watcher {
	private:
		using usn_journal_data_t = ::USN_JOURNAL_DATA_V2;
		using read_usn_journal_data_t = ::READ_USN_JOURNAL_DATA_V1;
		using usn_record_t = ::USN_RECORD_V3;

		inline static constexpr std::uint32_t s_supported_file_changes_at_once = 500;
		inline static constexpr std::uint32_t s_notify_filter = FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_CREATION | FILE_NOTIFY_CHANGE_ATTRIBUTES | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_FILE_NAME;
		inline static constexpr std::uint32_t s_usn_reason_mask = USN_REASON_BASIC_INFO_CHANGE | USN_REASON_DATA_OVERWRITE | USN_REASON_DATA_EXTEND | USN_REASON_FILE_CREATE | USN_REASON_DATA_TRUNCATION | USN_REASON_RENAME_NEW_NAME | USN_REASON_RENAME_OLD_NAME | USN_REASON_FILE_DELETE;
	private:
		std::atomic<filesystem_watcher_state> m_watcher_state;
		std::thread m_watcher_thread;
		void watch_actions();
		win32::unique_event_handle m_termination_event;
		
		contexts::execution_context& m_execution_context;
		
		win32::unique_event_handle m_changes_detection_event;
		win32::unique_file_handle m_directory_handle;
		win32::unique_file_handle m_device_handle;

		quill::Logger* m_logger;

		::USN parse_and_request_changes(
			::DWORDLONG journal_id,
			::USN read_start_at,
			std::optional<::USN> read_until,
			std::span<std::byte> bytes_notify_info
		);

		void on_created(const std::filesystem::path& absolute_client_path);
		void on_data_modified(const std::filesystem::path& absolute_client_path);
		void on_attribute_changed(const std::filesystem::path& absolute_client_path);
		void on_newly_imported(const std::filesystem::path& absolute_client_path);

		std::filesystem::path m_absolute_watching_path;
	public:
		filesystem_watcher(const std::filesystem::path& absolute_path_to_watch, contexts::execution_context& execution_context, quill::Logger* logger);
		virtual ~filesystem_watcher();

		void request_stop() noexcept;
		void wait() noexcept;
		
		filesystem_watcher_state get_state() const noexcept;
	};
}

#endif // LINUXPLORER_LXPSVC_FILESYSTEM_WATCHER_HPP_
