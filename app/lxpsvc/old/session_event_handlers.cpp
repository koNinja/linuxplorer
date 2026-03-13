#include "session.hpp"

#include <shlwapi.h>
#include <winioctl.h>
#include <ioapiset.h>
#include <winternl.h>

#include <util/charset/multibyte_wide_compat_helper.hpp>
#include <util/charset/case_insensitive_char_traits.hpp>

#include <ssh/ssh_exception.hpp>
#include <ssh/ssh_address.hpp>
#include <ssh/ssh_session.hpp>
#include <ssh/sftp/sftp_session.hpp>
#include <ssh/sftp/filesystem/sftp_entity.hpp>
#include <ssh/sftp/filesystem/sftp_manip.hpp>
#include <ssh/sftp/io/sftpstream.hpp>

#include <shell/filesystem/cloud_filter_placeholder.hpp>

#include <quill/LogMacros.h>

#include <string>
#include <unordered_map>
#include <fstream>

namespace linuxplorer::app::lxpsvc {
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

	::USN session::on_change_read(
		const session::unique_nthandle& device,
		::DWORDLONG journal_id,
		::USN read_starts_at,
		std::optional<::USN> read_until,
		std::span<std::byte> bytes_notify_info
	) {
		constexpr std::uint32_t reason_mask = USN_REASON_BASIC_INFO_CHANGE | USN_REASON_DATA_OVERWRITE | USN_REASON_DATA_EXTEND | USN_REASON_FILE_CREATE | USN_REASON_DATA_TRUNCATION | USN_REASON_RENAME_NEW_NAME | USN_REASON_RENAME_OLD_NAME | USN_REASON_FILE_DELETE;

		read_usn_journal_data_t read_data;
		
		read_data.ReturnOnlyOnClose = false;
		read_data.Timeout = 0;
		read_data.BytesToWaitFor = 0;
		read_data.MaxMajorVersion = 3;
		read_data.MinMajorVersion = 3;
		read_data.StartUsn = read_starts_at;
		read_data.ReasonMask = reason_mask;
		read_data.UsnJournalID = journal_id;

		bool succeeded;
		
		std::size_t bytes_notify_info_entry_offset = 0;
		std::size_t bytes_notify_info_entry_diff = 0;

		std::unordered_map<::FILE_ID_128, std::wstring> relative_changed_file_paths;
		do {
			auto info = reinterpret_cast<::FILE_NOTIFY_INFORMATION*>(&bytes_notify_info[bytes_notify_info_entry_offset]);

			bytes_notify_info_entry_diff = info->NextEntryOffset;
			bytes_notify_info_entry_offset += bytes_notify_info_entry_diff;

			if (info->Action == FILE_ACTION_RENAMED_OLD_NAME || info->Action == FILE_ACTION_REMOVED) continue;		

			std::filesystem::path abs_path = this->build_absolute_path_from(std::wstring_view(info->FileName, info->FileNameLength / sizeof(wchar_t)));

			unique_nthandle handle(::CreateFileW(
				abs_path.c_str(),
				FILE_READ_ATTRIBUTES,
				FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
				nullptr,
				OPEN_ALWAYS,
				FILE_FLAG_BACKUP_SEMANTICS,
				nullptr
			));

			::FILE_ID_INFO frn_info;
			succeeded = ::GetFileInformationByHandleEx(handle.get(), ::FILE_INFO_BY_HANDLE_CLASS::FileIdInfo, &frn_info, sizeof(frn_info));
			if (!succeeded) {
				std::error_code ec(::GetLastError(), std::system_category());
				LOG_ERROR(
					s_logger,
					"Failed to get the FRN of the changed file: {}, in session #{} (Win32: {}({}))",
					abs_path.string(),
					this->m_session_id,
					ec.message(),
					ec.value()
				);
				continue;
			}

			relative_changed_file_paths[frn_info.FileId] = abs_path;
		} while (bytes_notify_info_entry_diff > 0);

		constexpr std::size_t supported_journal_records_at_once = 800;

		// Each FileName field is null when FSCTL_READ_UNPRIVILEGED_USN_JOURNAL
		constexpr std::size_t bytes_journal_buffer_size = sizeof(::USN) + supported_journal_records_at_once * sizeof(usn_record_t);
		constexpr std::size_t bytes_journal_least_size = sizeof(::USN);
		auto bytes_journal = std::make_unique<std::byte[]>(bytes_journal_buffer_size);

		::USN next_read_starts_at = read_starts_at;
		::USN usn_read_until = read_until.has_value() ? *read_until : std::numeric_limits<::USN>::max();

		::DWORD bytes_returned;
		do {
			succeeded = ::DeviceIoControl(
				device.get(),
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
				LOG_CRITICAL(s_logger, "Failed to read USN journal records in session #{} (From Win32: {}({}))", this->m_session_id, ec.message(), ec.value());
				return 1;
			}
			else if (bytes_returned == bytes_journal_least_size) continue;
			else {}

			std::size_t total_bytes_read = sizeof(::USN);
			while (total_bytes_read < bytes_returned) try {
				auto journal = reinterpret_cast<usn_record_t*>(bytes_journal.get() + total_bytes_read);
				total_bytes_read += journal->RecordLength;

				if (!relative_changed_file_paths.contains(journal->FileReferenceNumber)) {
					continue;
				}

				std::wstring absolute_client_path = relative_changed_file_paths[journal->FileReferenceNumber];

				auto relative_client_path = this->relative_path_from_syncroot(absolute_client_path);
				auto server_path = this->server_path_from_relative_path(relative_client_path);

				if (has_any(journal->Reason, USN_REASON_FILE_CREATE)) {
					this->on_created_new(absolute_client_path, relative_client_path, server_path);
				}

				if (has_any(journal->Reason, USN_REASON_DATA_OVERWRITE, USN_REASON_DATA_EXTEND, USN_REASON_DATA_TRUNCATION)) {
					this->on_content_changed(absolute_client_path, relative_client_path, server_path);
				}

				if (equals_to(journal->Reason, USN_REASON_BASIC_INFO_CHANGE)) {
					this->on_attribute_changed(absolute_client_path, relative_client_path, server_path);
				}

				if (has_any(journal->Reason, USN_REASON_RENAME_NEW_NAME) && !shell::filesystem::cloud_filter_placeholder::is_placeholder(this->m_cloud_session.value(), relative_client_path)) {
					this->on_moved_from_external(absolute_client_path, relative_client_path, server_path);
				}

				if (::GetFileAttributesW(absolute_client_path.c_str()) & FILE_ATTRIBUTE_DIRECTORY) continue;

				std::unique_lock<std::mutex> lf_lock(this->m_placeholder_last_fetched_mutex);
				if (
					!this->m_placeholder_last_fetched.contains(journal->ParentFileReferenceNumber) ||
					std::chrono::time_point_cast<std::chrono::seconds>(std::chrono::system_clock::now()) - this->m_placeholder_last_fetched[journal->ParentFileReferenceNumber] > s_refetch_period
				) {
					std::wstring relative_parent_path = this->relative_path_from_syncroot(this->extract_parent_path(absolute_client_path));
					shell::filesystem::directory_placeholder placeholder(this->m_cloud_session.value(), relative_parent_path);
					placeholder.set_enumeration_enabled(true);
					LOG_INFO(s_logger, "Enable entry enumeration for the directory '{}' in session #{}.", chcvt::convert_wide_to_multibyte(this->build_absolute_path_from(relative_parent_path)), this->m_session_id);
					placeholder.flush();
					this->m_placeholder_last_fetched[journal->ParentFileReferenceNumber] = std::chrono::time_point_cast<std::chrono::seconds>(std::chrono::system_clock::now());
				}

				lf_lock.unlock();
			}
			catch (const ssh::ssh_libssh2_sftp_exception& e) {
				LOG_ERROR(
					s_logger,
					"SFTP operations failed: {}, in session #{}. (libssh2: {}({}))",
					e.what(),
					this->m_session_id,
					e.code().message(),
					e.code().value()
				);
				continue;
			}
			catch (const shell::cloud_provider_system_error& e) {
				LOG_ERROR(
					s_logger,
					"Placeholder operations failed: {}, in session #{}. (Win32: {}({}))",
					e.what(),
					this->m_session_id,
					e.code().message(),
					e.code().value()
				);
				continue;
			}

			read_data.StartUsn = next_read_starts_at = *reinterpret_cast<::USN*>(bytes_journal.get());
		} while (next_read_starts_at <= usn_read_until && bytes_returned > bytes_journal_least_size);
	
		return std::min(next_read_starts_at, usn_read_until);
	}

	void session::on_created_new(std::wstring_view absolute_client_path, std::wstring_view relative_client_path, std::wstring_view server_path) {
		try {
			auto lock = std::unique_lock(this->m_sftp_mutex);
			
			if (shell::filesystem::cloud_filter_placeholder::is_placeholder(this->m_cloud_session.value(), relative_client_path)) {
				/*
				LOG_INFO(
					s_logger,
					"Ignore placeholder creation by the callback in session #{}.",
					this->m_session_id
				);
				*/
				return;
			}

			LOG_INFO(s_logger, "Detected creation of the file '{}' in session #{}.", chcvt::convert_wide_to_multibyte(absolute_client_path), this->m_session_id);

			std::span<const std::byte> identity(s_dummy_blob, s_dummy_blob_length);
			auto placeholder = shell::filesystem::cloud_filter_placeholder::transform(this->m_cloud_session.value(), relative_client_path, identity);

			if (placeholder.get_type() == shell::filesystem::placeholder_type::directory) {
				ssh::sftp::filesystem::create_directory(this->m_sftp_session.value(), server_path);
				placeholder.set_marked_in_sync(true);
			}
			else {
				ssh::sftp::filesystem::create(this->m_sftp_session.value(), server_path, ssh::sftp::filesystem::open_permissions::read);
				placeholder.set_marked_in_sync(false);
			}
			placeholder.flush();

			LOG_INFO(
				s_logger,
				"The file '{}' corresponding to the new file has been successfully created on the server in session #{}.",
				chcvt::convert_wide_to_multibyte(absolute_client_path),
				this->m_session_id
			);
		}
		catch (const ssh::ssh_libssh2_sftp_exception& e) {
			LOG_ERROR(
				s_logger,
				"Failed to create the file '{}' on the server corresponding to the new file in session #{}.",
				chcvt::convert_wide_to_multibyte(server_path),
				this->m_session_id
			);
		}
	}

	void session::on_attribute_changed(std::wstring_view absolute_client_path, std::wstring_view relative_client_path, std::wstring_view server_path) {
		try {
			shell::filesystem::cloud_filter_placeholder placeholder(this->m_cloud_session.value(), relative_client_path);
			
			if (placeholder.get_pin_state() == ::CF_PIN_STATE::CF_PIN_STATE_UNPINNED) {
				placeholder.set_pin_state(::CF_PIN_STATE::CF_PIN_STATE_UNSPECIFIED);

				if (placeholder.get_type() == shell::filesystem::placeholder_type::file) {
					LOG_INFO(s_logger, "Detected attribute changes to '{}' in session #{}.", chcvt::convert_wide_to_multibyte(absolute_client_path), this->m_session_id);
					shell::filesystem::file_placeholder file_ph(std::move(placeholder));
					try {
						file_ph.dehydrate();
						file_ph.set_marked_in_sync(true);
						file_ph.flush();

						LOG_INFO(
							s_logger,
							"Cache data to '{}' on the server have been cleared in session #{}.",
							chcvt::convert_wide_to_multibyte(server_path),
							this->m_session_id
						);
					}
					catch (const shell::cloud_provider_system_error& e) {
						LOG_WARNING(
							s_logger,
							"Failed to clear cache data of '{}' on the server in session #{}: {} (Win32: {}({}))",
							chcvt::convert_wide_to_multibyte(server_path),
							this->m_session_id,
							e.what(),
							e.code().message(),
							e.code().value()
						);
					}
					
				}
				else {
					/*
					LOG_INFO(
						s_logger,
						"Nothing to do for attribute changes to '{}' in session #{}.",
						chcvt::convert_wide_to_multibyte(server_path),
						this->m_session_id
					);
					*/
				}
			}
			/*
				When 'Always keep on this device' is selected in context menu, the system only sets a pinned attribute to the placeholder recursively,
				so the app should monitor placeholder's attribute changes and respond them.
				However, unloaded placeholders will be skipped to be marked as the state by the system.
			*/
			// if 'always keep on this device' is selected:
			else if (placeholder.get_pin_state() == ::CF_PIN_STATE::CF_PIN_STATE_PINNED) {
				if (placeholder.get_type() == shell::filesystem::placeholder_type::file) {
					LOG_INFO(s_logger, "Detected attribute changes to '{}' in session #{}.", chcvt::convert_wide_to_multibyte(absolute_client_path), this->m_session_id);

					shell::filesystem::file_placeholder file_ph(std::move(placeholder));
					file_ph.hydrate();
					file_ph.set_marked_in_sync(true);
					file_ph.flush();

					LOG_INFO(
						s_logger,
						"The file '{}' became available on offline in session #{}.",
						chcvt::convert_wide_to_multibyte(server_path),
						this->m_session_id
					);
				}
				else {
					/*
					LOG_INFO(
						s_logger,
						"Nothing to do for attribute changes to '{}' in session #{}.",
						chcvt::convert_wide_to_multibyte(server_path),
						this->m_session_id
					);
					*/
				}
			}
			else {
				/*
				LOG_INFO(
					s_logger,
					"Nothing to do for attribute changes to '{}' in session #{}.",
					chcvt::convert_wide_to_multibyte(server_path),
					this->m_session_id
				);
				*/
			}
		}
		catch (const ssh::ssh_libssh2_sftp_exception& e) {
			LOG_ERROR(
				s_logger,
				"Failed to transfer file data to the server in session #{}: {} (libssh2: {}({}))",
				this->m_session_id,
				e.what(),
				e.code().message(),
				e.code().value()
			);
		}
		catch (const shell::cloud_provider_system_error& e) {
			LOG_ERROR(
				s_logger,
				"Failed a placeholder operation in session #{}: {} (From Win32: {}({}))",
				this->m_session_id,
				e.what(),
				e.code().message(),
				e.code().value()
			);
		}
	}

	void session::on_content_changed(std::wstring_view absolute_client_path, std::wstring_view relative_client_path, std::wstring_view server_path) {
		try {
			std::wstring absolute_src_path(absolute_client_path);
			shell::filesystem::cloud_filter_placeholder placeholder(this->m_cloud_session.value(), relative_client_path);
			
			if (placeholder.is_marked_in_sync()) {
				//LOG_INFO(s_logger, "Ignore changes of the file '{}' because the file is already synchronized, in session #{}.", chcvt::convert_wide_to_multibyte(absolute_src_path), this->m_session_id);
				return;
			}
			
			if (::GetFileAttributesW(absolute_src_path.c_str()) & FILE_ATTRIBUTE_DIRECTORY) {
				if (!placeholder.is_marked_in_sync()) {
					placeholder.set_marked_in_sync(true);
					placeholder.flush();
				}
				//LOG_INFO(s_logger, "The changed object '{}' is a directory. Ignore the change in session #{}.", chcvt::convert_wide_to_multibyte(absolute_src_path), this->m_session_id);
				return;
			}

			LOG_INFO(s_logger, "Detected content changes to '{}' in session #{}.", chcvt::convert_wide_to_multibyte(absolute_client_path), this->m_session_id);
			
			auto lock = std::unique_lock(this->m_sftp_mutex);

			std::ifstream ifs(absolute_src_path, std::ios::binary);
			ssh::sftp::io::osftpstream oss(m_sftp_session.value(), server_path, std::ios_base::trunc | std::ios_base::out);

			constexpr std::size_t ranges_count = 256;
			::CF_FILE_RANGE fragmented_modified_ranges[ranges_count];
			::DWORD bytes_read_ranges;
			::HRESULT hr = ::CfGetPlaceholderRangeInfo(
				placeholder.get_handle(),
				::CF_PLACEHOLDER_RANGE_INFO_CLASS::CF_PLACEHOLDER_RANGE_INFO_MODIFIED,
				::LARGE_INTEGER { .QuadPart = 0 },
				::LARGE_INTEGER { .QuadPart = CF_EOF },
				fragmented_modified_ranges,
				sizeof(::CF_FILE_RANGE) * ranges_count,
				&bytes_read_ranges
			);

			std::size_t valid_range_count = bytes_read_ranges / sizeof(::CF_FILE_RANGE);
			if (FAILED(hr)) {
				LOG_WARNING(s_logger, "Failed to get data ranges of data that is not currently synchronized with the server, in session #{}", this->m_session_id);

				::LARGE_INTEGER file_size;
				if (!::GetFileSizeEx(placeholder.get_handle(), &file_size)) {
					LOG_ERROR(s_logger, "Failed to get file size of '{}' in session #{}.", chcvt::convert_wide_to_multibyte(absolute_src_path), this->m_session_id);
					return;
				}

				// Transfer all the data to the server
				valid_range_count = 1;
				fragmented_modified_ranges[0].StartingOffset.QuadPart = 0;
				fragmented_modified_ranges[0].Length.QuadPart = file_size.QuadPart;
			}

			constexpr std::size_t unit_chunk_length = 262144;	// 256KiB
			auto buffer = std::make_unique<std::byte[]>(unit_chunk_length);
			
			for (int i = 0; i < valid_range_count; i++) {
				LOG_INFO(
					s_logger,
					"Uploading for '{}', offset: {} bytes, at least length: {} bytes, in session #{}",
					chcvt::convert_wide_to_multibyte(server_path),
					fragmented_modified_ranges[i].StartingOffset.QuadPart,
					fragmented_modified_ranges[i].Length.QuadPart,
					this->m_session_id
				);

				ifs.seekg(fragmented_modified_ranges[i].StartingOffset.QuadPart);
				oss.seekp(fragmented_modified_ranges[i].StartingOffset.QuadPart);
				std::streamsize bytes_remaining = fragmented_modified_ranges->Length.QuadPart;
				std::streamsize bytes_read = 0;
				do {
					std::size_t buffer_size = std::min(unit_chunk_length, static_cast<std::size_t>(bytes_remaining));

					ifs.read(reinterpret_cast<char*>(buffer.get()), buffer_size);
					bytes_read = ifs.gcount();

					oss.write(reinterpret_cast<char*>(buffer.get()), bytes_read);

					bytes_remaining -= bytes_read;
				} while (bytes_read > 0 && bytes_remaining > 0);
				
				oss.flush();
			}
			
			placeholder.set_marked_in_sync(true);
			placeholder.flush();

			LOG_INFO(
				s_logger,
				"Changes to the file '{}' have been successfully applied to '{}' on the server in session #{}.",
				chcvt::convert_wide_to_multibyte(absolute_src_path),
				chcvt::convert_wide_to_multibyte(server_path),
				this->m_session_id
			);
		}
		catch (const ssh::ssh_libssh2_sftp_exception& e) {
			LOG_ERROR(
				s_logger,
				"Failed to transfer file data to the server in session #{}: {} (libssh2: {}({}))",
				this->m_session_id,
				e.what(),
				e.code().message(),
				e.code().value()
			);
		}
		catch (const shell::cloud_provider_system_error& e) {
			LOG_ERROR(
				s_logger,
				"Failed a placeholder operation in session #{}: {} (From Win32: {}({}))",
				this->m_session_id,
				e.what(),
				e.code().message(),
				e.code().value()
			);
		}
	}

	void session::internal_transform_children_recursive(const std::filesystem::path& absolute_client_path, const std::filesystem::path& relative_client_path, const std::filesystem::path& server_path) {
		for (const auto& entry : std::filesystem::directory_iterator(absolute_client_path)) {
			auto relative_entity_path = relative_client_path / entry.path().filename();
			
			auto server_entity_path = server_path;
			server_entity_path += L"/";
			server_entity_path += entry.path().filename();
			
			this->on_created_new(
				entry.path().wstring(),
				relative_entity_path.wstring(),
				server_entity_path.wstring()
			);
			this->on_content_changed(
				entry.path().wstring(),
				relative_entity_path.wstring(),
				server_entity_path.wstring()
			);
			
			if (entry.is_directory()) {
				shell::filesystem::directory_placeholder dir_ph(this->m_cloud_session.value(), relative_entity_path.wstring());
				dir_ph.set_enumeration_enabled(false);
				dir_ph.set_marked_in_sync(true);
				dir_ph.flush();
				internal_transform_children_recursive(entry.path(), relative_entity_path, server_entity_path);
			}
		}
	}

	void session::on_moved_from_external(std::wstring_view absolute_client_path, std::wstring_view relative_client_path, std::wstring_view server_path) {
		try {
			LOG_INFO(s_logger, "Detected external file '{}' moved into sync tree in session #{}.", chcvt::convert_wide_to_multibyte(absolute_client_path), this->m_session_id);

			this->on_created_new(absolute_client_path, relative_client_path, server_path);
			this->on_content_changed(absolute_client_path, relative_client_path, server_path);
			if (::GetFileAttributesW(std::wstring(absolute_client_path).c_str()) & FILE_ATTRIBUTE_DIRECTORY) {
				shell::filesystem::directory_placeholder dir_ph(this->m_cloud_session.value(), relative_client_path);
				dir_ph.set_enumeration_enabled(false);
				dir_ph.set_marked_in_sync(true);
				dir_ph.flush();
				this->internal_transform_children_recursive(absolute_client_path, relative_client_path, server_path);
			}

			LOG_INFO(
				s_logger,
				"The file '{}' has been successfully transferred to '{}' on the server in session #{}.",
				chcvt::convert_wide_to_multibyte(absolute_client_path),
				chcvt::convert_wide_to_multibyte(server_path),
				this->m_session_id
			);
		}
		catch (const std::filesystem::filesystem_error& e) {
			LOG_ERROR(
				s_logger,
				"Failed a filesystem operation in session #{}: {} (From Win32: {}({}))",
				this->m_session_id,
				e.what(),
				e.code().message(),
				e.code().value()
			);
		}
	}
}