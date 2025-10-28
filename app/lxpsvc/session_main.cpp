#include "session.hpp"

#include <ssh/ssh_exception.hpp>
#include <ssh/ssh_address.hpp>
#include <ssh/ssh_session.hpp>
#include <ssh/sftp/sftp_session.hpp>
#include <ssh/sftp/filesystem/sftp_entity.hpp>
#include <ssh/sftp/filesystem/sftp_manip.hpp>
#include <ssh/sftp/io/sftpstream.hpp>

#include <shell/filesystem/cloud_filter_placeholder.hpp>

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
		constexpr ::DWORD supported_file_changes_at_once = 1000;	// by default
		constexpr ::DWORD notify_info_total_size_bytes = 532 * supported_file_changes_at_once;
		std::byte bytes_notify_info[notify_info_total_size_bytes];
		while (true) {
			constexpr ::DWORD notify_filter = FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_SIZE | 
				FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_CREATION | FILE_NOTIFY_CHANGE_ATTRIBUTES;

			::ResetEvent(changes_detecion_event_handle.get());

			::OVERLAPPED overlapped;
			::ZeroMemory(&overlapped, sizeof(::OVERLAPPED));

			overlapped.hEvent = changes_detecion_event_handle.get();
			bool succeeded = ::ReadDirectoryChangesW(
				directory_handle.get(),
				bytes_notify_info,
				notify_info_total_size_bytes * sizeof(std::byte),
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

				if (bytes_notify_info_returned <= 0) continue;

				this->on_change_read(std::span(bytes_notify_info, notify_info_total_size_bytes));

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