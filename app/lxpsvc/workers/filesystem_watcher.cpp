#include "filesystem_watcher.hpp"
#include "../exceptions/abnormal_systems.hpp"

#include <algorithm>
#include <array>

#include <shell/filesystem/cloud_filter_placeholder.hpp>

#include <quill/LogMacros.h>
#include <quill/std/FilesystemPath.h>
#include <quill/Backend.h>

namespace linuxplorer::lxpsvc::workers {
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

		auto root_name_str = absolute_path_to_watch.root_name().wstring();
		if (root_name_str.ends_with(L"\\")) {
			root_name_str.pop_back();
		}
		this->m_root_name = root_name_str;

		this->m_root_handle = ::CreateFileW(
			this->m_root_name.c_str(),
			GENERIC_READ,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			nullptr,
			OPEN_ALWAYS,
			FILE_FLAG_BACKUP_SEMANTICS,
			nullptr
		);
		if (!this->m_root_handle) {
			std::error_code ec(::GetLastError(), std::system_category());
			throw exceptions::fatal_runtime_exception(
				exceptions::runtime_error_domain::watcher,
				"Failed to open a volume handle. (Win32: {}({}))",
				ec.message(),
				ec.value()
			);
		}

		std::wstring full_qualified_device_name;
		full_qualified_device_name.append(L"\\\\.\\").append(this->m_root_name);
		this->m_device_handle = ::CreateFileW(
			full_qualified_device_name.c_str(),
			FILE_TRAVERSE,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
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

		win32::unique_file_handle directory_handle = ::CreateFileW(
			absolute_path_to_watch.c_str(),
			FILE_GENERIC_READ | FILE_LIST_DIRECTORY,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			nullptr,
			OPEN_EXISTING,
			FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
			nullptr
		);
		if (!directory_handle) {
			std::error_code ec(::GetLastError(), std::system_category());
			throw exceptions::fatal_runtime_exception(
				exceptions::runtime_error_domain::watcher,
				"Failed to open a handle of the directory to surveil. (Win32: {}({}))",
				ec.message(),
				ec.value()
			);
		}

		this->m_surveillance_overlapped.emplace(std::move(directory_handle));

		this->m_watcher_thread = std::thread(&filesystem_watcher::watch_actions, this);
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
		this->m_watcher_state = filesystem_watcher_state::running;

		if (!this->m_surveillance_overlapped.has_value()) {
			std::error_code ec(::GetLastError(), std::system_category());
			this->m_execution_context.enqueue_error(exceptions::fatal_runtime_exception(
				exceptions::runtime_error_domain::watcher,
				"There is no OVERLAPPED object.",
				ec.message(),
				ec.value()
			));
			this->m_watcher_state = filesystem_watcher_state::stopped;
			return;
		}

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

		LOG_INFO(this->m_logger, "The filesystem watcher thread has been started.");

		while (true) {
			try {
				this->m_surveillance_overlapped->reset();
			}
			catch (const std::system_error& e) {
				this->m_execution_context.enqueue_error(exceptions::fatal_runtime_exception(
					exceptions::runtime_error_domain::watcher,
					"Failed to initialize an OVERLAPPED object for a directory surveillance: {} (Win32: {}({}))",
					e.what(),
					e.code().message(),
					e.code().value()
				));
				this->m_watcher_state = filesystem_watcher_state::stopped;
				return;
			}
	
			bool succeeded = ::ReadDirectoryChangesW(
				this->m_surveillance_overlapped->acquire_file_handle().get(),
				bytes_notify_info.get(),
				notify_info_total_size_bytes,
				true,
				filesystem_watcher::s_notify_filter,
				nullptr,
				this->m_surveillance_overlapped->ptr(),
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

			std::array<::HANDLE, 2> handles = {
				this->m_termination_event.get(),
				this->m_surveillance_overlapped->get_event_handle().get()
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
				try {
					this->m_surveillance_overlapped->request_cancel();
					this->m_surveillance_overlapped->wait();
				}
				catch (const std::system_error& e) {
					LOG_WARNING(
						this->m_logger,
						"Failed to cancel the pending OVERLAPPED operation: {} (Win32: {}({}))",
						e.what(),
						e.code().message(),
						e.code().value()
					);
				}
				this->m_watcher_state = filesystem_watcher_state::stopped;
				LOG_INFO(this->m_logger, "The filesystem watcher has been successfully terminated.");
				return;
			}
			case WAIT_OBJECT_0 + 1:	// file change event
			{
				this->m_surveillance_overlapped->wait();
				auto bytes_notify_info_returned = this->m_surveillance_overlapped->result();
				if (bytes_io_control_returned <= 0) {
					LOG_WARNING(
						this->m_logger,
						"Failed to acquire FILE_NOTIFY_INFO objects. That will not be a problem because the watcher parse the changes using the USN journal, but something might have gone wrong."
					);
				}

				std::optional<::USN> usn_read_until = std::nullopt;
				::DWORDLONG journal_id = journal.UsnJournalID;
				
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
					journal_id,
					usn_read_start_at,
					usn_read_until,
					std::span(bytes_notify_info.get(), bytes_notify_info_returned)
				);

				break;
			}
			case WAIT_FAILED: [[fallthrough]];
			default:
			{
				std::error_code ec(::GetLastError(), std::system_category());
				this->m_execution_context.enqueue_error(exceptions::fatal_runtime_exception(
					exceptions::runtime_error_domain::watcher,
					"Failed to wait for the events. (Win32: {}({}))",
					ec.message(),
					ec.value()
				));

				try {
					this->m_surveillance_overlapped->request_cancel();
					this->m_surveillance_overlapped->wait();
				}
				catch (const std::system_error& e) {
					LOG_WARNING(
						this->m_logger,
						"Failed to cancel the pending OVERLAPPED operation: {} (Win32: {}({}))",
						e.what(),
						e.code().message(),
						e.code().value()
					);
				}

				this->m_watcher_state = filesystem_watcher_state::stopped;
				LOG_INFO(this->m_logger, "The filesystem watcher has been successfully terminated.");
				return;
			}
			}
		}
	}

	std::unordered_map<win32::file_reference_number, std::filesystem::path> filesystem_watcher::map_frn_path(std::span<const std::byte> bytes_notify_info) {
		std::unordered_map<win32::file_reference_number, std::filesystem::path> relative_changed_file_paths;

		std::size_t bytes_notify_info_entry_offset = 0;

		while (bytes_notify_info_entry_offset < bytes_notify_info.size_bytes()) {
			auto info = reinterpret_cast<const ::FILE_NOTIFY_INFORMATION*>(&bytes_notify_info[bytes_notify_info_entry_offset]);
			
			bytes_notify_info_entry_offset += info->NextEntryOffset;

			std::wstring_view relative_path_view(info->FileName, info->FileNameLength / sizeof(wchar_t));

			if (info->Action == FILE_ACTION_RENAMED_OLD_NAME || info->Action == FILE_ACTION_REMOVED) {
				if (info->NextEntryOffset == 0) break;
				else continue;
			}

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
			bool succeeded = ::GetFileInformationByHandleEx(handle.get(), ::FILE_INFO_BY_HANDLE_CLASS::FileIdInfo, &frn_info, sizeof(frn_info));
			if (!succeeded) {
				std::error_code ec(::GetLastError(), std::system_category());
				LOG_ERROR(
					this->m_logger,
					"Failed to get the FRN of the changed file: {}. (Win32: {}({}))", 
					absolute_path,
					ec.message(),
					ec.value()
				);
				continue;
			}

			if (!relative_changed_file_paths.contains(frn_info.FileId)) {
				relative_changed_file_paths[frn_info.FileId] = relative_path_view;
			}

			if (info->NextEntryOffset == 0) break;
		}

		return relative_changed_file_paths;
	}

	::USN filesystem_watcher::parse_and_request_changes(
		::DWORDLONG journal_id,
		::USN read_start_at,
		std::optional<::USN> read_until,
		std::span<const std::byte> bytes_notify_info
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
		
		auto relative_changed_file_paths = this->map_frn_path(bytes_notify_info);
		
		constexpr std::size_t supported_journal_records_at_once = 800;

		// Each FileName field is null when FSCTL_READ_UNPRIVILEGED_USN_JOURNAL
		constexpr std::size_t bytes_journal_buffer_size = sizeof(::USN) + supported_journal_records_at_once * sizeof(usn_record_t);
		constexpr std::size_t bytes_journal_least_size = sizeof(::USN);
		auto bytes_journal = std::make_unique<std::byte[]>(bytes_journal_buffer_size);

		::USN next_read_start_at = read_start_at;
		::USN usn_read_until = read_until.value_or(std::numeric_limits<::USN>::max());

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

				std::filesystem::path relative_path;

				// Attempt to resolve the file path from the FRN
				if (!relative_changed_file_paths.contains(journal->FileReferenceNumber)) {
					::FILE_ID_DESCRIPTOR descriptor{};
					descriptor.dwSize = sizeof(descriptor);
					descriptor.Type = ::FILE_ID_TYPE::ExtendedFileIdType;
					std::copy_n(
						journal->FileReferenceNumber.Identifier,
						sizeof(journal->FileReferenceNumber.Identifier),
						descriptor.ExtendedFileId.Identifier
					);

					win32::unique_file_handle file_handle = ::OpenFileById(
						this->m_root_handle.get(),
						&descriptor,
						FILE_READ_ATTRIBUTES,
						FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
						nullptr,
						FILE_FLAG_BACKUP_SEMANTICS
					);
					if (!file_handle) {
						// std::error_code ec(::GetLastError(), std::system_category());
						// LOG_ERROR(this->m_logger, "Failed to open the file by its FRN. (Win32: {}({}))", ec.message(), ec.value());
						continue;
					}

					constexpr std::size_t name_info_size = (MAX_PATH + 1) * sizeof(wchar_t) + sizeof(::DWORD);
					auto name_info_bytes = std::make_unique<std::byte[]>(name_info_size);
					succeeded = ::GetFileInformationByHandleEx(
						file_handle.get(),
						::FILE_INFO_BY_HANDLE_CLASS::FileNameInfo,
						name_info_bytes.get(),
						name_info_size
					);
					if (!succeeded) {
						// std::error_code ec(::GetLastError(), std::system_category());
						// LOG_ERROR(this->m_logger, "Failed to acquire the path from the handle. (Win32: {}({}))", ec.message(), ec.value());
						continue;
					}

					auto name_info = reinterpret_cast<::FILE_NAME_INFO*>(name_info_bytes.get());

					std::wstring_view relative_path_from_root(name_info->FileName, name_info->FileNameLength / sizeof(wchar_t));
					
					auto absolute_path = this->m_root_name / relative_path_from_root;

					if (helpers::path_helper::is_under(absolute_path, this->m_absolute_watching_path)) {
						relative_path = absolute_path.lexically_relative(this->m_absolute_watching_path);
						LOG_INFO(this->m_logger, "The file or directory path '{}' has been successfully resolved from its FRN.", absolute_path);
					}
					else {
						// LOG_INFO(this->m_logger, "The file or directory'{}' is not under the surveillance.", absolute_path);
						continue;
					}
				}
				else {
					relative_path = relative_changed_file_paths[journal->FileReferenceNumber];
				}

				this->raise_io_operations(relative_path, journal->Usn, journal->Reason);
			}

			read_data.StartUsn = next_read_start_at = *reinterpret_cast<::USN*>(bytes_journal.get());
		} while (next_read_start_at <= usn_read_until && bytes_returned > bytes_journal_least_size);

		return read_until.has_value() ? next_read_start_at : read_start_at;
	}

	void filesystem_watcher::raise_io_operations(const std::filesystem::path& relative_path, ::USN usn, std::uint32_t why) {
		try {
			auto absolute_path = this->m_absolute_watching_path / relative_path;

			if (has_any(why, USN_REASON_FILE_CREATE)) {
				auto task = std::make_unique<models::operations::creation_operation>(this->m_absolute_watching_path, relative_path);
				LOG_INFO(
					this->m_logger,
					"Detected a creation of '{}' (USN: {}, Operation: #{}).",
					absolute_path,
					usn,
					task->get_id()
				);
				this->m_execution_context.enqueue_task(std::move(task));
			}

			if (has_any(why, USN_REASON_DATA_OVERWRITE, USN_REASON_DATA_EXTEND, USN_REASON_DATA_TRUNCATION)) {
				models::requests::remote::modification_type type;
				if (has_any(why, USN_REASON_DATA_OVERWRITE)) {
					type = models::requests::remote::modification_type::overwritten;
				}
				else if (has_any(why, USN_REASON_DATA_EXTEND)) {
					type = models::requests::remote::modification_type::appended;
				}
				else {
					type = models::requests::remote::modification_type::truncated;
				}

				auto task = std::make_unique<models::operations::modification_operation>(this->m_absolute_watching_path, relative_path, type);
				LOG_INFO(
					this->m_logger,
					"Detected a modification of '{}'. (USN: {}, Operation: #{}, Modification type: {})",
					absolute_path,
					usn,
					task->get_id(),
					std::to_underlying(type)
				);
				this->m_execution_context.enqueue_task(std::move(task));
			}

			if (equals_to(why, USN_REASON_BASIC_INFO_CHANGE)) {
				if (this->auxiliarily_verify_execution_necessity_for_attribute(absolute_path)) {
					auto task = std::make_unique<models::operations::attribute_operation>(this->m_absolute_watching_path, relative_path);
					LOG_INFO(
						this->m_logger,
						"Detected attribute changes of '{}'. (USN: {}, Operation: #{})",
						absolute_path,
						usn,
						task->get_id()
					);
					this->m_execution_context.enqueue_task(std::move(task));
				}
			}

			if (has_any(why, USN_REASON_RENAME_NEW_NAME)) {
				auto task = std::make_unique<models::operations::import_operation>(this->m_absolute_watching_path, relative_path);
				LOG_INFO(
					this->m_logger,
					"Detected a move of '{}' into the syncroot. (USN: {}, Operation: #{})",
					absolute_path,
					usn,
					task->get_id()
				);
				this->m_execution_context.enqueue_task(std::move(task));
			}
		}
		catch (const shell::cloud_provider_system_error& e) {
			LOG_ERROR(
				this->m_logger,
				"Failed to a placeholder operation: {} (Win32: {}({}))",
				e.what(),
				e.code().message(),
				e.code().value()
			);
		}
	}

	bool filesystem_watcher::auxiliarily_verify_execution_necessity_for_attribute(const std::filesystem::path& absolute_path) const noexcept {
		try {
			if (!shell::filesystem::cloud_filter_placeholder::is_placeholder(absolute_path)) return false;

			shell::filesystem::cloud_filter_placeholder placeholder(absolute_path);
			switch (placeholder.get_pin_state()) {
			case shell::filesystem::placeholder_pin_state::pinned: [[fallthrough]];
			case shell::filesystem::placeholder_pin_state::unpinned:
				return true;
			default:
				break;
			}

			return !placeholder.is_marked_in_sync();
		}
		catch (...) {
			return true;
		}
	}
}