#ifndef LINUXPLORER_ENGINE_FILESYSTEM_WATCHER_HPP_
#define LINUXPLORER_ENGINE_FILESYSTEM_WATCHER_HPP_

#include <engine/enginefwd.hpp>

#include <engine/win32/handle.hpp>
#include <engine/win32/ntfs.hpp>
#include <engine/win32/overlapped.hpp>
#include <engine/contexts/execution_context.hpp>
#include <engine/models/usn/usn_normalizer.hpp>

#include <filesystem>
#include <thread>
#include <optional>
#include <span>
#include <unordered_map>

#include <quill/Logger.h>

#include <winioctl.h>

namespace linuxplorer::engine::workers {
	enum class filesystem_watcher_state {
		pending,
		running,
		stopped
	};

	class LINUXPLORER_ENGINE_API filesystem_watcher {
	private:
		using usn_journal_data_t = ::USN_JOURNAL_DATA_V2;
		using read_usn_journal_data_t = ::READ_USN_JOURNAL_DATA_V1;
		using usn_record_t = ::USN_RECORD_V3;

		inline static constexpr std::uint32_t s_supported_file_changes_at_once = 500;
		inline static constexpr std::uint32_t s_notify_filter = FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_CREATION | FILE_NOTIFY_CHANGE_ATTRIBUTES | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_FILE_NAME;
		inline static constexpr std::uint32_t s_usn_reason_mask = USN_REASON_BASIC_INFO_CHANGE | USN_REASON_DATA_OVERWRITE | USN_REASON_DATA_EXTEND | USN_REASON_FILE_CREATE | USN_REASON_DATA_TRUNCATION | USN_REASON_RENAME_NEW_NAME;
		inline static constexpr std::chrono::seconds s_directory_update_duration = std::chrono::seconds(60);
	private:
		std::atomic<filesystem_watcher_state> m_watcher_state;
		std::thread m_watcher_thread;
		void watch_actions();
		win32::unique_event_handle m_termination_event;
		
		contexts::execution_context& m_execution_context;
		
		std::optional<win32::overlapped> m_surveillance_overlapped;
		win32::unique_file_handle m_device_handle;
		win32::unique_file_handle m_root_handle;

		quill::Logger* m_logger;

		std::optional<std::filesystem::path> try_get_relative_path_from_syncroot_by_frn(const win32::file_reference_number& frn) const;

		::USN parse_and_request_changes(
			::DWORDLONG journal_id,
			::USN read_start_at
		);

		void raise_io_operations(const std::filesystem::path& relative_path, const models::usn::operation_recognizer& recognizer, std::optional<models::requests::remote::modification_type> type);
		bool try_raise_parent_directory_update_if(const std::filesystem::path& relative_path, const win32::file_reference_number& parent_frn);

		bool check_execution_necessity_for_attrop(const std::filesystem::path& absolute_path) const noexcept;

		std::filesystem::path m_absolute_watching_path;
		std::filesystem::path m_root_name;
	public:
		filesystem_watcher(const std::filesystem::path& absolute_path_to_watch, contexts::execution_context& execution_context, quill::Logger* logger);
		virtual ~filesystem_watcher();

		void start();
		void request_stop() noexcept;
		void wait() noexcept;
		
		filesystem_watcher_state get_state() const noexcept;
	};
}

#endif // LINUXPLORER_ENGINE_FILESYSTEM_WATCHER_HPP_
