#include "filesystem_watcher.hpp"
#include "../exceptions/abnormal_systems.hpp"
#include "../win32/ntfs.hpp"

#include <algorithm>
#include <array>
#include <unordered_map>

#include <shell/filesystem/cloud_filter_placeholder.hpp>

#include <quill/LogMacros.h>
#include <quill/std/FilesystemPath.h>

namespace linuxplorer::app::lxpsvc::workers {
	template <class T, class U>
	bool has_any(T lhs, U rhs) {
		return (lhs & rhs) != 0;
	}

	template <class T, class U, class... V>
	bool has_any(T lhs, U rhs, V... more) {
		return has_any(lhs, rhs) || has_any(lhs, more...);
	}

	template <class T, class U>
	bool has_all(T lhs, U rhs) {
		return (lhs & rhs) == rhs;
	}
	
	template <class T, class U, class... V>
	bool has_all(T lhs, U rhs, V... more) {
		return has_all(lhs, rhs) && has_all(lhs, more...);
	}

	template <class T, class U>
	bool equals_to(T lhs, U rhs) {
		return lhs == rhs;
	}

	filesystem_watcher::filesystem_watcher(const std::filesystem::path& absolute_path_to_watch, contexts::execution_context& execution_context, quill::Logger* logger) : 
		m_absolute_watching_path(absolute_path_to_watch), m_execution_context(execution_context), m_watcher_state(filesystem_watcher_state::pending), m_logger(logger)
	{
		this->m_termination_event = ::CreateEventW(nullptr, true, false, nullptr);
		if (!this->m_termination_event) {
			std::error_code ec(::GetLastError(), std::system_category());
			throw exceptions::fatal_runtime_exception(
				exceptions::runtime_error_domain::watcher,
				"Failed to create a termination event. (Win32: {}({}))",
				ec.message(),
				ec.value()
			);
		}

		auto drive_letter = absolute_path_to_watch.wstring().substr(0, absolute_path_to_watch.wstring().find_first_of(L':') + 1);
		std::wstring full_qualified_device_name;
		full_qualified_device_name.append(L"\\\\.\\").append(drive_letter);
		this->m_device_handle = ::CreateFileW(
			full_qualified_device_name.c_str(),
			FILE_TRAVERSE,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			nullptr,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			nullptr
		);
		if (!this->m_device_handle) {
			std::error_code ec(::GetLastError(), std::system_category());
			throw exceptions::fatal_runtime_exception(
				exceptions::runtime_error_domain::watcher,
				"Failed to open a volume handle. (Win32: {}({}))",
				ec.message(),
				ec.value()
			);
		}

		this->m_directory_handle = ::CreateFileW(
			absolute_path_to_watch.c_str(),
			FILE_GENERIC_READ | FILE_LIST_DIRECTORY,
			FILE_SHARE_READ,
			nullptr,
			OPEN_EXISTING,
			FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
			nullptr
		);
		if (!this->m_directory_handle) {
			std::error_code ec(::GetLastError(), std::system_category());
			throw exceptions::fatal_runtime_exception(
				exceptions::runtime_error_domain::watcher,
				"Failed to open a handle of the directory to surveil. (Win32: {}({}))",
				ec.message(),
				ec.value()
			);
		}

		this->m_changes_detection_event = ::CreateEventW(nullptr, true, false, nullptr);
		if (!this->m_changes_detection_event) {
			std::error_code ec(::GetLastError(), std::system_category());
			throw exceptions::fatal_runtime_exception(
				exceptions::runtime_error_domain::watcher,
				"Failed to create an event for change detection. (Win32: {}({}))",
				ec.message(),
				ec.value()
			);
		}

		this->m_watcher_thread = std::thread([this]() { this->watch_actions(); });
		this->m_watcher_state = filesystem_watcher_state::running;
	}

	filesystem_watcher::~filesystem_watcher() {
		this->request_stop();
		this->wait();
	}

	filesystem_watcher_state filesystem_watcher::get_state() const noexcept {
		return this->m_watcher_state;
	}
	
	void filesystem_watcher::request_stop() noexcept {
		if (this->m_termination_event) {
			::SetEvent(this->m_termination_event.get());
		}
	}

	void filesystem_watcher::wait() noexcept {
		if (this->m_watcher_thread.joinable()) {
			this->m_watcher_thread.join();
		}
	}

	void filesystem_watcher::watch_actions() {
		usn_journal_data_t journal;
		::DWORD bytes_io_control_returned;

		bool succeeded = ::DeviceIoControl(
			this->m_device_handle.get(),
			FSCTL_QUERY_USN_JOURNAL,
			nullptr,
			0,
			&journal,
			sizeof(journal),
			&bytes_io_control_returned,
			nullptr
		);
		if (!succeeded) {
			std::error_code ec(::GetLastError(), std::system_category());
			this->m_execution_context.enqueue_error(exceptions::fatal_runtime_exception(
				exceptions::runtime_error_domain::watcher,
				"Failed to query the USN Journal data. (Win32: {}({}))",
				ec.message(),
				ec.value()
			));
			this->m_watcher_state = filesystem_watcher_state::stopped;
			return;
		}

		::USN usn_read_start_at = journal.NextUsn;

		// Maximum of size of FILE_NOTIFY_INFORMATION structure is estimated about 532 bytes. (path length: 260 (MAX_PATH))
		// For details: https://learn.microsoft.com/ja-jp/windows/win32/api/winnt/ns-winnt-file_notify_information
		constexpr std::uint32_t notify_info_total_size_bytes = 532 * filesystem_watcher::s_supported_file_changes_at_once;

		auto bytes_notify_info = std::make_unique<std::byte[]>(notify_info_total_size_bytes);
		while (true) {
			::ResetEvent(this->m_changes_detection_event.get());

			::OVERLAPPED overlapped;
			::ZeroMemory(&overlapped, sizeof(::OVERLAPPED));

			overlapped.hEvent = this->m_changes_detection_event.get();
			bool succeeded = ::ReadDirectoryChangesW(
				this->m_directory_handle.get(),
				bytes_notify_info.get(),
				notify_info_total_size_bytes,
				true,
				filesystem_watcher::s_notify_filter,
				nullptr,
				&overlapped,
				nullptr
			);
			if (!succeeded) {
				std::error_code ec(::GetLastError(), std::system_category());
				this->m_execution_context.enqueue_error(exceptions::fatal_runtime_exception(
					exceptions::runtime_error_domain::watcher,
					"Failed to surveil under the syncroot asynchronously. (Win32: {}({}))",
					ec.message(),
					ec.value()
				));
				this->m_watcher_state = filesystem_watcher_state::stopped;
				return;
			}

			std::array<::HANDLE, 2> handles{
				this->m_termination_event.get(),
				this->m_changes_detection_event.get()
			};

			::DWORD wait_response = ::WaitForMultipleObjects(
				handles.size(),
				handles.data(),
				false,
				INFINITE
			);

			switch (wait_response) {
			case WAIT_OBJECT_0:		// termination event
			{
				this->m_watcher_state = filesystem_watcher_state::stopped;
				return;
			}
			case WAIT_OBJECT_0 + 1:	// file change event
			{
				::DWORD bytes_notify_info_returned = 0;
				succeeded = ::GetOverlappedResult(
					this->m_directory_handle.get(),
					&overlapped,
					&bytes_notify_info_returned,
					true
				);
				if (!succeeded) {
					std::error_code ec(::GetLastError(), std::system_category());
					LOG_ERROR(this->m_logger, "Failed to catch file changes under the syncroot. (Win32: {}({}))", ec.message(), ec.value());
					continue;
				}

				if (bytes_notify_info_returned <= 0) {
					std::error_code ec(::GetLastError(), std::system_category());
					LOG_ERROR(this->m_logger, "File changes were detected, but it is impossible to resolve the path.");
					continue;
				}

				std::optional<::USN> usn_read_until = std::nullopt;

				succeeded = ::DeviceIoControl(
					this->m_device_handle.get(),
					FSCTL_QUERY_USN_JOURNAL,
					nullptr,
					0,
					&journal,
					sizeof(journal),
					&bytes_io_control_returned,
					nullptr
				);
				if (succeeded) {
					usn_read_until = journal.NextUsn;
				}
				else {
					std::error_code ec(::GetLastError(), std::system_category());
					LOG_WARNING(
						this->m_logger,
						"Failed to query a USN journal."
							"Since an offset of a USN record that should be first read will not be updated, the performance of the next reading will suffer."
					);
				}

				usn_read_start_at = this->parse_and_request_changes(
					journal.UsnJournalID,
					usn_read_start_at,
					usn_read_until,
					std::span(bytes_notify_info.get(), bytes_notify_info_returned)
				);

				break;
			}
			case WAIT_FAILED:
			{
				std::error_code ec(::GetLastError(), std::system_category());
				this->m_execution_context.enqueue_error(exceptions::fatal_runtime_exception(
					exceptions::runtime_error_domain::watcher,
					"Failed to wait for the events. (Win32: {}({}))",
					ec.message(),
					ec.value()
				));
				this->m_watcher_state = filesystem_watcher_state::stopped;
				return;
			}
			default:
				break;
			}
		}
	}

	::USN filesystem_watcher::parse_and_request_changes(
		::DWORDLONG journal_id,
		::USN read_start_at,
		std::optional<::USN> read_until,
		std::span<std::byte> bytes_notify_info
	) {
		read_usn_journal_data_t read_data;
		
		read_data.ReturnOnlyOnClose = false;
		read_data.Timeout = 0;
		read_data.BytesToWaitFor = 0;
		read_data.MaxMajorVersion = 3;
		read_data.MinMajorVersion = 3;
		read_data.StartUsn = read_start_at;
		read_data.ReasonMask = filesystem_watcher::s_usn_reason_mask;
		read_data.UsnJournalID = journal_id;

		bool succeeded;
		
		std::size_t bytes_notify_info_entry_offset = 0;

		std::unordered_map<win32::file_reference_number, std::filesystem::path> relative_changed_file_paths;
		while (bytes_notify_info_entry_offset < bytes_notify_info.size_bytes()) {
			auto info = reinterpret_cast<::FILE_NOTIFY_INFORMATION*>(&bytes_notify_info[bytes_notify_info_entry_offset]);
			std::wstring_view relative_path_view(info->FileName, info->FileNameLength / sizeof(wchar_t));

			if (info->Action == FILE_ACTION_RENAMED_OLD_NAME || info->Action == FILE_ACTION_REMOVED) continue;		

			auto absolute_path = this->m_absolute_watching_path / relative_path_view;

			win32::unique_file_handle handle = ::CreateFileW(
				absolute_path.c_str(),
				FILE_READ_ATTRIBUTES,
				FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
				nullptr,
				OPEN_EXISTING,
				FILE_FLAG_BACKUP_SEMANTICS,
				nullptr
			);
			if (!handle) {
				std::error_code ec(::GetLastError(), std::system_category());
				LOG_ERROR(this->m_logger, "Failed to open a handle of '{}'. (Win32: {}({}))", absolute_path, ec.message(), ec.value());
				continue;
			}

			::FILE_ID_INFO frn_info;
			succeeded = ::GetFileInformationByHandleEx(handle.get(), ::FILE_INFO_BY_HANDLE_CLASS::FileIdInfo, &frn_info, sizeof(frn_info));
			if (!succeeded) {
				std::error_code ec(::GetLastError(), std::system_category());
				LOG_ERROR(
					this->m_logger,
					"Failed to get the FRN of the changed file: {}. (Win32: {}({}))", 
					absolute_path.string(),
					ec.message(),
					ec.value()
				);
				continue;
			}

			relative_changed_file_paths[frn_info.FileId] = relative_path_view;

			if (info->NextEntryOffset == 0) break;

			bytes_notify_info_entry_offset += info->NextEntryOffset;
		}

		constexpr std::size_t supported_journal_records_at_once = 800;

		// Each FileName field is null when FSCTL_READ_UNPRIVILEGED_USN_JOURNAL
		constexpr std::size_t bytes_journal_buffer_size = sizeof(::USN) + supported_journal_records_at_once * sizeof(usn_record_t);
		constexpr std::size_t bytes_journal_least_size = sizeof(::USN);
		auto bytes_journal = std::make_unique<std::byte[]>(bytes_journal_buffer_size);

		::USN next_read_start_at = read_start_at;
		::USN usn_read_until = read_until.has_value() ? *read_until : std::numeric_limits<::USN>::max();

		::DWORD bytes_returned;
		do {
			succeeded = ::DeviceIoControl(
				this->m_device_handle.get(),
				FSCTL_READ_UNPRIVILEGED_USN_JOURNAL,
				&read_data,
				sizeof(read_data),
				bytes_journal.get(),
				bytes_journal_buffer_size * sizeof(std::byte),
				&bytes_returned, 
				nullptr
			);
			if (!succeeded || bytes_returned < bytes_journal_least_size) {
				std::error_code ec(::GetLastError(), std::system_category());
				LOG_ERROR(this->m_logger, "Failed to read the USN Journal records. (Win32: {}({}))", ec.message(), ec.value());
				return std::min(next_read_start_at, usn_read_until);
			}
			// has read through
			else if (bytes_returned == bytes_journal_least_size) break;
			else {}

			std::size_t total_bytes_read = sizeof(::USN);
			while (total_bytes_read < bytes_returned) {
				auto journal = reinterpret_cast<usn_record_t*>(bytes_journal.get() + total_bytes_read);
				total_bytes_read += journal->RecordLength;

				if (!relative_changed_file_paths.contains(journal->FileReferenceNumber)) {
					continue;
				}

				auto relative_path = relative_changed_file_paths[journal->FileReferenceNumber];

				if (has_any(journal->Reason, USN_REASON_FILE_CREATE)) {
					this->m_execution_context.enqueue_task(std::make_unique<models::operations::creation_operation>(this->m_absolute_watching_path, relative_path));
				}

				if (has_any(journal->Reason, USN_REASON_DATA_OVERWRITE, USN_REASON_DATA_EXTEND, USN_REASON_DATA_TRUNCATION)) {
					this->m_execution_context.enqueue_task(std::make_unique<models::operations::modification_operation>(this->m_absolute_watching_path, relative_path));
				}

				if (equals_to(journal->Reason, USN_REASON_BASIC_INFO_CHANGE)) {
					this->m_execution_context.enqueue_task(std::make_unique<models::operations::attribute_operation>(this->m_absolute_watching_path, relative_path));
				}

				if (has_any(journal->Reason, USN_REASON_RENAME_NEW_NAME)) {
					this->m_execution_context.enqueue_task(std::make_unique<models::operations::import_operation>(this->m_absolute_watching_path, relative_path));
				}
			}

			read_data.StartUsn = next_read_start_at = *reinterpret_cast<::USN*>(bytes_journal.get());
		} while (next_read_start_at <= usn_read_until && bytes_returned > bytes_journal_least_size);

		return read_until.has_value() ? next_read_start_at : read_start_at;
	}

	/*
	void filesystem_watcher::on_created(const std::filesystem::path& absolute_client_path) {
		//this->m_execution_context.enqueue_task(std::make_unique<models::operations::creation_operation>())
	}

	void filesystem_watcher::on_data_modified(const std::filesystem::path& absolute_client_path) {
		if (::GetFileAttributesW(absolute_client_path.c_str()) & FILE_ATTRIBUTE_DIRECTORY) return;

		win32::unique_file_handle placeholder = ::CreateFileW(
			absolute_client_path.c_str(),
			FILE_READ_ATTRIBUTES,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			nullptr,
			OPEN_EXISTING,
			0,
			nullptr
		);
		if (!placeholder) {
			std::error_code ec(::GetLastError(), std::system_category());
			LOG_ERROR(this->m_logger, "Failed to open a handle of '{}'. (Win32: {}({}))", absolute_client_path, ec.message(), ec.value());
			return;
		}

		::LARGE_INTEGER file_size;
		if (!::GetFileSizeEx(placeholder.get(), &file_size)) {
			LOG_ERROR(this->m_logger, "Failed to get file size of '{}'.", absolute_client_path);
			return;
		}

		constexpr std::size_t ranges_count = 256;
		std::array<::CF_FILE_RANGE, ranges_count> fragmented_modified_ranges;
		::DWORD bytes_read_ranges;
		::HRESULT hr = ::CfGetPlaceholderRangeInfo(
			placeholder.get(),
			::CF_PLACEHOLDER_RANGE_INFO_CLASS::CF_PLACEHOLDER_RANGE_INFO_MODIFIED,
			::LARGE_INTEGER { .QuadPart = 0 },
			::LARGE_INTEGER { .QuadPart = CF_EOF },
			fragmented_modified_ranges.data(),
			sizeof(::CF_FILE_RANGE) * ranges_count,
			&bytes_read_ranges
		);

		std::size_t valid_range_count = bytes_read_ranges / sizeof(::CF_FILE_RANGE);
		if (FAILED(hr)) {
			LOG_WARNING(this->m_logger, "Failed to get data ranges of data not currently synchronized with the server.");

			// Transfer all the data to the server
			valid_range_count = 1;
			fragmented_modified_ranges[0].StartingOffset.QuadPart = 0;
			fragmented_modified_ranges[0].Length.QuadPart = file_size.QuadPart;
		}

		constexpr std::size_t unit_chunk_length = 262144;	// 256KiB

		for (int i = 0; i < valid_range_count; i++) {
			const auto& modified_range = fragmented_modified_ranges[i]; 
			std::size_t bytes_in_total = modified_range.Length.QuadPart == CF_EOF ? file_size.QuadPart : modified_range.Length.QuadPart;

			std::size_t bytes_relative_offset = 0;
			std::size_t bytes_remaining = modified_range.Length.QuadPart;
			do {
				std::size_t length = std::min(bytes_remaining, unit_chunk_length);
				models::range<std::size_t> range(modified_range.StartingOffset.QuadPart + bytes_relative_offset, length);

				this->m_execution_context.enqueue_task(models::modification_request(models::request_priority::lower, absolute_client_path, range));

				bytes_relative_offset += length;
				bytes_remaining -= length;
			} while (bytes_relative_offset < modified_range.Length.QuadPart && bytes_remaining > 0);
		}
	}

	void filesystem_watcher::on_attribute_changed(const std::filesystem::path& absolute_client_path) {
		win32::unique_file_handle placeholder = ::CreateFileW(
			absolute_client_path.c_str(),
			FILE_READ_ATTRIBUTES,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			nullptr,
			OPEN_EXISTING,
			0,
			nullptr
		);
		if (!placeholder) {
			std::error_code ec(::GetLastError(), std::system_category());
			LOG_ERROR(this->m_logger, "Failed to open a handle of '{}'. (Win32: {}({}))", absolute_client_path, ec.message(), ec.value());
			return;
		}

		::CF_PLACEHOLDER_STANDARD_INFO info{};
		::DWORD bytes_info_returned;
		::HRESULT hr = ::CfGetPlaceholderInfo(
			placeholder.get(),
			::CF_PLACEHOLDER_INFO_CLASS::CF_PLACEHOLDER_INFO_STANDARD,
			&info,
			sizeof(::CF_PLACEHOLDER_STANDARD_INFO),
			&bytes_info_returned
		);
		if (FAILED(hr) && hr != HRESULT_FROM_WIN32(ERROR_MORE_DATA)) {
			std::error_code ec(hr, std::system_category());
			LOG_ERROR(this->m_logger, "Failed to open a handle of '{}'. (HRESULT: {}({}))", absolute_client_path, ec.message(), ec.value());
			return;
		}

		if (info.PinState == ::CF_PIN_STATE::CF_PIN_STATE_PINNED) {
			this->m_execution_context.enqueue_task(models::attribute_request(
				models::request_priority::immediate,
				absolute_client_path,
				models::attribute_change_type::pinned
			));
		}
		else if (info.PinState == ::CF_PIN_STATE::CF_PIN_STATE_UNPINNED) {
			this->m_execution_context.enqueue_task(models::attribute_request(
				models::request_priority::immediate,
				absolute_client_path,
				models::attribute_change_type::unpinned
			));
		}
		else {}
	}

	void filesystem_watcher::on_newly_imported(const std::filesystem::path& absolute_client_path) {
		std::uint32_t attr = ::GetFileAttributesW(absolute_client_path.c_str());
		bool is_directory = attr & FILE_ATTRIBUTE_DIRECTORY;

		this->m_execution_context.enqueue_task(models::creation_request(
			models::request_priority::lower,
			absolute_client_path,
			is_directory ? std::filesystem::file_type::directory : std::filesystem::file_type::regular
		));

		if (is_directory) {
			for (const auto& entity : std::filesystem::directory_iterator(absolute_client_path)) {
				this->on_newly_imported(absolute_client_path / entity.path());
			}
		}
		else {
			win32::unique_file_handle placeholder = ::CreateFileW(
				absolute_client_path.c_str(),
				FILE_READ_ATTRIBUTES,
				FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
				nullptr,
				OPEN_EXISTING,
				0,
				nullptr
			);
			if (!placeholder) {
				std::error_code ec(::GetLastError(), std::system_category());
				LOG_ERROR(this->m_logger, "Failed to open a handle of '{}'. (Win32: {}({}))", absolute_client_path, ec.message(), ec.value());
				return;
			}

			::LARGE_INTEGER file_size;
			if (!::GetFileSizeEx(placeholder.get(), &file_size)) {
				LOG_ERROR(this->m_logger, "Failed to get file size of '{}'.", absolute_client_path);
				return;
			}

			constexpr std::size_t unit_chunk_length = 262144;	// 256KiB

			std::size_t bytes_relative_offset = 0;
			std::size_t bytes_remaining = file_size.QuadPart;
			do {
				std::size_t length = std::min(bytes_remaining, unit_chunk_length);
				models::range<std::size_t> range(bytes_relative_offset, length);

				this->m_execution_context.enqueue_task(models::modification_request(models::request_priority::lower, absolute_client_path, range));

				bytes_relative_offset += length;
				bytes_remaining -= length;
			} while (bytes_relative_offset < file_size.QuadPart && bytes_remaining > 0);
		}
	}
	*/
}