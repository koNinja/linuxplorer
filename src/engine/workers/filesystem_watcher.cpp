#include <engine/workers/filesystem_watcher.hpp>
#include <engine/exceptions/abnormal_systems.hpp>
#include <engine/models/usn/usn_normalizer.hpp>

#include <algorithm>
#include <array>

#include <shell/filesystem/cloud_filter_placeholder.hpp>

#include <quill/LogMacros.h>
#include <quill/std/FilesystemPath.h>
#include <quill/Backend.h>

namespace linuxplorer::engine::workers {
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
	}

	void filesystem_watcher::start() {
		this->m_watcher_thread = std::thread(&filesystem_watcher::watch_actions, this);

		::SetThreadDescription(this->m_watcher_thread.native_handle(), L"Filesystem Watcher");
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
		//constexpr std::uint32_t notify_info_total_size_bytes = 532 * filesystem_watcher::s_supported_file_changes_at_once;
		constexpr std::uint32_t notify_info_total_size_bytes = 4096;

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

				::DWORDLONG journal_id = journal.UsnJournalID;
				usn_read_start_at = this->parse_and_request_changes(journal_id, usn_read_start_at);

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

	bool filesystem_watcher::try_raise_parent_directory_update_if(const std::filesystem::path& relative_path, const win32::file_reference_number& parent_frn) {
		auto absolute_path = this->m_absolute_watching_path / relative_path;

		if (this->m_execution_context.is_directory_update_suppressed(relative_path)) {
			this->m_execution_context.try_release_directory_update_suppression(relative_path);
			return false;
		}

		if (::GetFileAttributesW(absolute_path.c_str()) & FILE_ATTRIBUTE_DIRECTORY) return false;

		static std::unordered_map<win32::file_reference_number, std::chrono::system_clock::time_point> last_updated_times;

		if (last_updated_times.contains(parent_frn)) {
			auto duration_since_last_updated = std::chrono::system_clock::now() - last_updated_times[parent_frn];
			if (duration_since_last_updated <= s_directory_update_duration) return false;
		}

		auto task = std::make_unique<models::operations::directory_update_operation>(this->m_absolute_watching_path, relative_path.parent_path());
		LOG_INFO(this->m_logger, "Request a directory update for '{}'. (Operation #{})", absolute_path.parent_path(), task->get_id());
		this->m_execution_context.enqueue_task(std::move(task));

		last_updated_times[parent_frn] = std::chrono::system_clock::now();
		return true;
	}

	std::optional<std::filesystem::path> filesystem_watcher::try_get_relative_path_from_syncroot_by_frn(const win32::file_reference_number& frn) const {
		::FILE_ID_DESCRIPTOR descriptor{};
		descriptor.dwSize = sizeof(descriptor);
		descriptor.Type = ::FILE_ID_TYPE::ExtendedFileIdType;
		std::copy_n(
			frn.to_native().Identifier,
			sizeof(frn.to_native().Identifier),
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
			return std::nullopt;
		}

		constexpr std::size_t name_info_size = (MAX_PATH + 1) * sizeof(wchar_t) + sizeof(::DWORD);
		auto name_info_bytes = std::make_unique<std::byte[]>(name_info_size);
		bool succeeded = ::GetFileInformationByHandleEx(
			file_handle.get(),
			::FILE_INFO_BY_HANDLE_CLASS::FileNameInfo,
			name_info_bytes.get(),
			name_info_size
		);
		if (!succeeded) {
			return std::nullopt;
		}

		auto name_info = reinterpret_cast<::FILE_NAME_INFO*>(name_info_bytes.get());

		std::wstring_view relative_path_from_root(name_info->FileName, name_info->FileNameLength / sizeof(wchar_t));

		auto absolute_path =  this->m_root_name / relative_path_from_root;
		
		return helpers::path_helper::is_under(absolute_path, this->m_absolute_watching_path) ?
			std::optional<std::filesystem::path>(absolute_path.lexically_relative(this->m_absolute_watching_path)) : std::nullopt;
	}

	::USN filesystem_watcher::parse_and_request_changes(
		::DWORDLONG journal_id,
		::USN read_start_at
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

		constexpr std::size_t supported_journal_records_at_once = 800;

		// Each FileName field is null when FSCTL_READ_UNPRIVILEGED_USN_JOURNAL
		constexpr std::size_t bytes_journal_buffer_size = sizeof(::USN) + supported_journal_records_at_once * sizeof(usn_record_t);
		constexpr std::size_t bytes_journal_least_size = sizeof(::USN);
		auto bytes_journal = std::make_unique<std::byte[]>(bytes_journal_buffer_size);

		struct operation_creation_context {
			std::filesystem::path m_relative_path;
			models::usn::operation_recognizer m_recognizer;
			std::optional<win32::file_reference_number> m_parent_frn;
			std::optional<models::requests::remote::modification_type> m_type;
		};

		std::vector<operation_creation_context> operation_contexts;
		std::unordered_map<win32::file_reference_number, std::size_t> operation_context_map;

		::USN next_read_start_at = read_start_at;

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
				break;
			}
			// has read through
			else if (bytes_returned == bytes_journal_least_size) break;
			else {}

			std::size_t total_bytes_read = sizeof(::USN);
			while (total_bytes_read < bytes_returned) {
				auto journal = reinterpret_cast<usn_record_t*>(bytes_journal.get() + total_bytes_read);
				total_bytes_read += journal->RecordLength;

				std::filesystem::path relative_path;
				if (auto nullable_relative_path = this->try_get_relative_path_from_syncroot_by_frn(journal->FileReferenceNumber)) 
					relative_path = *nullable_relative_path;
				else	// If the file or directory indicated by the FRN is not under the surveillance;
					continue;

				if (!operation_context_map.contains(journal->FileReferenceNumber)) {
					operation_contexts.push_back(operation_creation_context{
						.m_relative_path = relative_path,
						.m_parent_frn = journal->ParentFileReferenceNumber
						}
					);
					operation_context_map[journal->FileReferenceNumber] = operation_contexts.size() - 1;
				}

				auto& context = operation_contexts[operation_context_map[journal->FileReferenceNumber]];
				if (has_any(journal->Reason, USN_REASON_FILE_CREATE)) {
					context.m_recognizer.transition(models::usn::operation_recognizer::usn_symbol::created);
				}
				if (has_any(journal->Reason, USN_REASON_DATA_OVERWRITE, USN_REASON_DATA_EXTEND, USN_REASON_DATA_TRUNCATION)) {
					context.m_recognizer.transition(models::usn::operation_recognizer::usn_symbol::modified);

					models::requests::remote::modification_type type;
					if (has_any(journal->Reason, USN_REASON_DATA_OVERWRITE)) {
						type = models::requests::remote::modification_type::overwritten;
					}
					else if (has_any(journal->Reason, USN_REASON_DATA_EXTEND)) {
						type = models::requests::remote::modification_type::appended;
					}
					else {
						type = models::requests::remote::modification_type::truncated;
					}

					context.m_type = type;
				}
				if (equals_to(journal->Reason, USN_REASON_BASIC_INFO_CHANGE)) {
					context.m_recognizer.transition(models::usn::operation_recognizer::usn_symbol::attr_changed);
				}
				if (has_any(journal->Reason, USN_REASON_RENAME_NEW_NAME)) {
					context.m_recognizer.transition(models::usn::operation_recognizer::usn_symbol::renamed);
				}
			}

			read_data.StartUsn = next_read_start_at = *reinterpret_cast<::USN*>(bytes_journal.get());
		} while (bytes_returned > bytes_journal_least_size);

		for (const auto& context : operation_contexts) {
			this->raise_io_operations(context.m_relative_path, context.m_recognizer, context.m_type);
			this->try_raise_parent_directory_update_if(context.m_relative_path, *context.m_parent_frn);
		}

		return next_read_start_at;
	}

	void filesystem_watcher::raise_io_operations(const std::filesystem::path& relative_path, const models::usn::operation_recognizer& recognizer, std::optional<models::requests::remote::modification_type> type) {
		auto absolute_path = this->m_absolute_watching_path / relative_path;
		switch (recognizer.get_operation_type()) {
		case models::usn::operation_recognizer::state::creation:
		{
			auto task = std::make_unique<models::operations::creation_operation>(this->m_absolute_watching_path, relative_path);
			LOG_INFO(this->m_logger, "Detected creation of '{}'. (Operation: #{})", absolute_path, task->get_id());
			this->m_execution_context.enqueue_task(std::move(task));
			break;
		}
		case models::usn::operation_recognizer::state::modification:
		{
			auto task = std::make_unique<models::operations::modification_operation>(this->m_absolute_watching_path, relative_path, *type);
			LOG_INFO(this->m_logger, "Detected modification of '{}'. (Operation: #{}, Modification type: {})", absolute_path, task->get_id(), std::to_underlying(*type));
			this->m_execution_context.enqueue_task(std::move(task));
			break;
		}
		case models::usn::operation_recognizer::state::import:
		{
			auto task = std::make_unique<models::operations::import_operation>(this->m_absolute_watching_path, relative_path);
			LOG_INFO(this->m_logger, "Detected copy or move into the syncroot of '{}'. (Operation: #{})", absolute_path, task->get_id());
			this->m_execution_context.enqueue_task(std::move(task));
			break;
		}
		case models::usn::operation_recognizer::state::attribute:
		{
			if (!this->check_execution_necessity_for_attrop(absolute_path)) break;
			auto task = std::make_unique<models::operations::attribute_operation>(this->m_absolute_watching_path, relative_path);
			LOG_INFO(this->m_logger, "Detected attribute changes of '{}'. (Operation: #{})", absolute_path, task->get_id());
			this->m_execution_context.enqueue_task(std::move(task));
			break;
		}
		default:
			LOG_INFO(this->m_logger, "Detected an unrecognized operation of '{}'", absolute_path);
			break;
		}
	}

	bool filesystem_watcher::check_execution_necessity_for_attrop(const std::filesystem::path& absolute_path) const noexcept {
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