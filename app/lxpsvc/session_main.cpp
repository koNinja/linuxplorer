#include "session.hpp"

#include <windows.h>

#include <quill/LogMacros.h>

namespace linuxplorer::app::lxpsvc {
	int session::main() {
		unique_nthandle termination_event_handle, changes_detecion_event_handle;

		termination_event_handle.reset(::CreateEventW(nullptr, true, false, WSTRINGIFY(LINUXPLORER_APP_SERVICE_TERMINATE_EVENT_NAME)));
		if (!termination_event_handle) {
			std::error_code ec(::GetLastError(), std::system_category());
			LOG_CRITICAL(s_logger, "Failed to create a termination event in session #{} (From Win32: {}({}))", this->m_session_id, ec.message(), ec.value());
			return 1;
		}

		std::wstring drive = this->m_syncroot_dir.substr(0, this->m_syncroot_dir.find_first_of(L':') + 1);
		std::wstring full_qualified_device_name;
		full_qualified_device_name.append(L"\\\\.\\").append(drive);
		unique_nthandle volume(::CreateFileW(
			full_qualified_device_name.c_str(),
			FILE_TRAVERSE,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			nullptr,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			nullptr
		));
		if (volume.get() == INVALID_HANDLE_VALUE) {
			std::error_code ec(::GetLastError(), std::system_category());
			LOG_CRITICAL(s_logger, "Failed to open a volume in session #{} (From Win32: {}({}))", this->m_session_id, ec.message(), ec.value());
			return 1;
		}

		unique_nthandle root(::CreateFileW(
			drive.c_str(),
			GENERIC_READ,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			nullptr,
			OPEN_EXISTING,
			FILE_FLAG_BACKUP_SEMANTICS,
			nullptr
		));
		if (root.get() == INVALID_HANDLE_VALUE) {
			std::error_code ec(::GetLastError(), std::system_category());
			LOG_CRITICAL(s_logger, "Failed to open a volume in session #{} (From Win32: {}({}))", this->m_session_id, ec.message(), ec.value());
			return 1;
		}

		usn_journal_data_t journal;
		::DWORD bytes_io_control_returned;

		bool succeeded = ::DeviceIoControl(
			volume.get(),
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
			LOG_CRITICAL(s_logger, "Failed to query a USN journal in session #{} (From Win32: {}({}))", this->m_session_id, ec.message(), ec.value());
			return 1;
		}

		::USN usn_read_starts_at = journal.NextUsn;

		unique_nthandle directory_handle(::CreateFileW(
			this->m_syncroot_dir.c_str(),
			FILE_GENERIC_READ | FILE_LIST_DIRECTORY,
			FILE_SHARE_READ,
			nullptr,
			OPEN_EXISTING,
			FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
			nullptr
		));
		if (directory_handle.get() == INVALID_HANDLE_VALUE) {
			std::error_code ec(::GetLastError(), std::system_category());
			LOG_CRITICAL(s_logger, "Failed to open sync directory in session #{} (From Win32: {}({}))", this->m_session_id, ec.message(), ec.value());
			return 1;
		}

		changes_detecion_event_handle.reset(::CreateEventW(nullptr, true, false, nullptr));
		if (!changes_detecion_event_handle) {
			std::error_code ec(::GetLastError(), std::system_category());
			LOG_CRITICAL(s_logger, "Failed to create a file change surveillance event in session #{} (From Win32: {}({})))", this->m_session_id, ec.message(), ec.value());
			return 1;
		}

		// Maximum of size of FILE_NOTIFY_INFORMATION structure is estimated about 532 bytes. (path length: 260 (MAX_PATH))
		// For details: https://learn.microsoft.com/ja-jp/windows/win32/api/winnt/ns-winnt-file_notify_information
		constexpr std::uint32_t supported_file_changes_at_once = 500;	// by default
		constexpr std::uint32_t notify_info_total_size_bytes = 532 * supported_file_changes_at_once;
		constexpr std::uint32_t notify_filter = FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_CREATION | FILE_NOTIFY_CHANGE_ATTRIBUTES | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_FILE_NAME;

		auto bytes_notify_info = std::make_unique<std::byte[]>(notify_info_total_size_bytes);
		while (true) {
			::ResetEvent(changes_detecion_event_handle.get());

			::OVERLAPPED overlapped;
			::ZeroMemory(&overlapped, sizeof(::OVERLAPPED));

			overlapped.hEvent = changes_detecion_event_handle.get();
			bool succeeded = ::ReadDirectoryChangesW(
				directory_handle.get(),
				bytes_notify_info.get(),
				notify_info_total_size_bytes,
				true,
				notify_filter,
				nullptr,
				&overlapped,
				nullptr
			);
			if (!succeeded) {
				std::error_code ec(::GetLastError(), std::system_category());
				LOG_CRITICAL(s_logger, "Failed to acquire file changes at session #{} (From Win32: {}({}))", this->m_session_id, ec.message(), ec.value());
				return 1;
			}

			constexpr std::size_t handles_count = 2;
			::HANDLE handles[2] = {
				termination_event_handle.get(),
				changes_detecion_event_handle.get()
			};

			::DWORD wait_response = ::MsgWaitForMultipleObjectsEx(
				handles_count,
				handles,
				INFINITE,
				QS_ALLINPUT,
				MWMO_INPUTAVAILABLE
			);

			switch (wait_response) {
			// app termination event
			case WAIT_OBJECT_0:
			{
				return 0;
			}
			// file change event
			case WAIT_OBJECT_0 + 1:
			{
				::DWORD bytes_notify_info_returned = 0;
				succeeded = ::GetOverlappedResult(
					directory_handle.get(),
					&overlapped,
					&bytes_notify_info_returned,
					true
				);
				if (!succeeded) {
					std::error_code ec(::GetLastError(), std::system_category());
					LOG_ERROR(s_logger, "Failed to catch file changes in session #{} (From Win32: {}({}))", this->m_session_id, ec.message(), ec.value());
					continue;
				}

				// if (bytes_notify_info_returned <= 0) continue;

				usn_read_starts_at = this->on_change_read(
					volume,
					journal.UsnJournalID,
					usn_read_starts_at,
					std::span(bytes_notify_info.get(), bytes_notify_info_returned)
				);

				break;
			}
			case WAIT_FAILED:
			{
				std::error_code ec(::GetLastError(), std::system_category());
				LOG_ERROR(s_logger, "Failed to wait for the terminate event in session #{} (From Win32: {}({}))", this->m_session_id, ec.message(), ec.value());
				return 1;
			}
			default:
				break;
			}
		}
	}
}