#include <ntstatus.h>

#define WIN32_NO_STATUS
#include "session.hpp"

#include <fstream>
#include <util/charset/multibyte_wide_compat_helper.hpp>

#include <ssh/ssh_exception.hpp>
#include <ssh/ssh_address.hpp>
#include <ssh/ssh_session.hpp>
#include <ssh/sftp/sftp_session.hpp>
#include <ssh/sftp/filesystem/sftp_entity.hpp>
#include <ssh/sftp/filesystem/sftp_manip.hpp>
#include <ssh/sftp/io/sftpstream.hpp>

#include <quill/LogMacros.h>

#include <shell/functional/cloud_provider_callback.hpp>
#include <shell/cloud_provider_session.hpp>
#include <shell/cloud_provider_exception.hpp>
#include <shell/filesystem/cloud_filter_placeholder.hpp>
#undef WIN32_NO_STATUS

namespace linuxplorer::app::lxpsvc {
	void session::on_change_read(std::span<std::byte> bytes_notify_info) {
		using chcvt = linuxplorer::util::charset::multibyte_wide_compat_helper;

		std::optional<std::wstring> old_dest_path_str;

		std::size_t bytes_notify_info_entry_offset = 0;
		std::size_t bytes_notify_info_entry_diff = 0;

		do try {
			auto info = reinterpret_cast<::FILE_NOTIFY_INFORMATION*>(&bytes_notify_info[bytes_notify_info_entry_offset]);

			bytes_notify_info_entry_diff = info->NextEntryOffset;
			bytes_notify_info_entry_offset += bytes_notify_info_entry_diff;

			std::wstring_view relative_src_path_view(info->FileName, info->FileNameLength / sizeof(wchar_t));
			std::wstring absolute_src_path;
			absolute_src_path.append(this->m_syncroot_dir).append(L"\\").append(relative_src_path_view);

			std::wstring dest_path_str;
			dest_path_str.append(L"/").append(relative_src_path_view);
			// Replace back slash with slash
			std::replace(dest_path_str.begin(), dest_path_str.end(), L'\\', L'/');

			/*
				Handle file deletion and renaming in this block
			*/
			switch (info->Action) {
			case FILE_ACTION_REMOVED:
			try {
				LOG_INFO(s_logger, "Detected file deletion of '{}' in session #{}.", chcvt::convert_wide_to_multibyte(absolute_src_path), this->m_session_id);

				// Skip sending a request to remove the object corresponding to the placeholder when it doesn't exist in the server.
				try {
					ssh::sftp::filesystem::status(this->m_sftp_session.value(), dest_path_str);
				}
				catch (const ssh::ssh_libssh2_sftp_exception& e) {
					continue;
				}

				ssh::sftp::filesystem::remove(this->m_sftp_session.value(), dest_path_str);

				LOG_INFO(
					s_logger,
					"The file '{}' corresponding to the deleted file has been successfully removed from the server in session #{}.",
					chcvt::convert_wide_to_multibyte(dest_path_str),
					this->m_session_id
				);

				continue;
			}
			catch (const ssh::ssh_libssh2_sftp_exception& e) {
				LOG_ERROR(
					s_logger,
					"Failed to remove the file '{}' corresponding to the deleted file from the server in session #{}: {} (libssh2: {}({}))",
					chcvt::convert_wide_to_multibyte(dest_path_str),
					chcvt::convert_wide_to_multibyte(absolute_src_path),
					this->m_session_id,
					e.what(),
					e.code().message(),
					e.code().value()
				);
				continue;
			}

			case FILE_ACTION_RENAMED_OLD_NAME:
			{
				old_dest_path_str = std::move(dest_path_str);
				continue;
			}

			case FILE_ACTION_RENAMED_NEW_NAME:
			try {
				LOG_INFO(s_logger, "Detected file renaming of '{}' in session #{}.", chcvt::convert_wide_to_multibyte(absolute_src_path), this->m_session_id);

				if (!old_dest_path_str.has_value()) {
					LOG_WARNING(s_logger,
						"It appear to have missed an event that preserves the file's old name.\n"
							"Cannot send an request to rename the file corresponding to the renamed placeholder."
					);
					continue;
				}

				ssh::sftp::filesystem::rename(this->m_sftp_session.value(), *old_dest_path_str, dest_path_str);

				LOG_INFO(
					s_logger,
					"The file '{}' has been successfully renamed to '{}' on the server in session #{}.",
					chcvt::convert_wide_to_multibyte(*old_dest_path_str),
					chcvt::convert_wide_to_multibyte(dest_path_str),
					this->m_session_id
				);

				old_dest_path_str = std::nullopt;
				
				continue;
			}
			catch (const ssh::ssh_libssh2_sftp_exception& e) {
				LOG_ERROR(
					s_logger,
					"Failed to rename the file '{}' to '{}' on the server in session #{}: {} (libssh2: {}({}))",
					chcvt::convert_wide_to_multibyte(*old_dest_path_str),
					chcvt::convert_wide_to_multibyte(dest_path_str),
					this->m_session_id,
					e.what(),
					e.code().message(),
					e.code().value()
				);
				continue;
			}

			default:
				break;
			}

			if (!shell::filesystem::cloud_filter_placeholder::is_placeholder(this->m_cloud_session.value(), relative_src_path_view)) {
				std::span<const std::byte> identity(reinterpret_cast<const std::byte*>(relative_src_path_view.data()), relative_src_path_view.length() * sizeof(wchar_t));

				shell::filesystem::cloud_filter_placeholder::transform(this->m_cloud_session.value(), relative_src_path_view, identity);
			}

			shell::filesystem::cloud_filter_placeholder basic_placeholder(this->m_cloud_session.value(), relative_src_path_view);

			/*
			
				Handle file modification and creation in this block
			*/
			switch (info->Action) {
			case FILE_ACTION_MODIFIED:
			try {
				LOG_INFO(s_logger, "Detected changes to '{}' in session #{}.", chcvt::convert_wide_to_multibyte(absolute_src_path), this->m_session_id);

				if (basic_placeholder.get_type() == shell::filesystem::placeholder_type::directory) {
					shell::filesystem::directory_placeholder placeholder(std::move(basic_placeholder));

					if (placeholder.get_pin_state() == ::CF_PIN_STATE::CF_PIN_STATE_UNPINNED) {
						placeholder.set_pin_state(::CF_PIN_STATE::CF_PIN_STATE_UNSPECIFIED);
						placeholder.set_enumeration_enabled(true);
						placeholder.flush();

						LOG_INFO(
							s_logger,
							"Cache data to '{}' on the server have been cleared in session #{}.",
							chcvt::convert_wide_to_multibyte(dest_path_str),
							this->m_session_id
						);
					}
				}
				else {
					shell::filesystem::file_placeholder placeholder(std::move(basic_placeholder));

					if (placeholder.get_pin_state() == ::CF_PIN_STATE::CF_PIN_STATE_UNPINNED) {
						placeholder.set_pin_state(::CF_PIN_STATE::CF_PIN_STATE_UNSPECIFIED);
						placeholder.flush();
						placeholder.dehydrate();

						LOG_INFO(
							s_logger,
							"Cache data to '{}' on the server have been cleared in session #{}.",
							chcvt::convert_wide_to_multibyte(dest_path_str),
							this->m_session_id
						);
					}
					/*
						When 'Always keep on this device' is selected in context menu of directory, the system only sets a pinned attribute to the placeholder recursively,
						so the app should monitor placeholder's attribute changes and respond them.
					*/
					// if 'always keep on this device' is selected:
					else if (placeholder.is_marked_in_sync() && placeholder.get_pin_state() == ::CF_PIN_STATE::CF_PIN_STATE_PINNED) {
						placeholder.hydrate();
					}
					// if file data changed:
					else if (!placeholder.is_marked_in_sync())
					{
						auto lock = std::unique_lock(this->m_sftp_mutex);

						std::ifstream ifs(absolute_src_path);
						ssh::sftp::io::osftpstream oss(m_sftp_session.value(), dest_path_str, std::ios_base::trunc | std::ios_base::out);

						::LARGE_INTEGER file_size;
						bool succeeded = ::GetFileSizeEx(placeholder.get_handle(), &file_size);
						if (!succeeded) {
							LOG_CRITICAL(s_logger, "Failed to get file size of '{}' in session #{}.", chcvt::convert_wide_to_multibyte(absolute_src_path), this->m_session_id);
							continue;
						}

						constexpr std::size_t unit_chunk_length = 262144;	// 256KiB
						std::streamsize remaining_bytes = file_size.QuadPart;
						std::streamsize bytes_read = 0;
						do {
							std::size_t buffer_size = std::min(unit_chunk_length, static_cast<std::size_t>(remaining_bytes));
							auto buffer = std::make_unique<std::byte[]>(buffer_size);
							ifs.read(reinterpret_cast<char*>(buffer.get()), buffer_size);
							bytes_read = ifs.gcount();
							remaining_bytes -= bytes_read;
							oss.write(reinterpret_cast<char*>(buffer.get()), bytes_read);
						} while (bytes_read > 0 && remaining_bytes > 0);

						oss.flush();

						placeholder.set_marked_in_sync(true);
						placeholder.flush();

						LOG_INFO(
							s_logger,
							"Changes to the file '{}' have been successfully applied to '{}' on the server in session #{}.",
							chcvt::convert_wide_to_multibyte(absolute_src_path),
							chcvt::convert_wide_to_multibyte(dest_path_str),
							this->m_session_id
						);
					}
					else {
						LOG_INFO(
							s_logger,
							"Ignore changes to the file '{}' because it is already synchronized in session #{}.",
							chcvt::convert_wide_to_multibyte(absolute_src_path),
							this->m_session_id
						);
					}
				}

				break;
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
				continue;
			}
			catch (const std::system_error& e) {
				LOG_ERROR(
					s_logger,
					"Failed a placeholder operation in session #{}: {} (From Win32: {}({}))",
					this->m_session_id,
					e.what(),
					e.code().message(),
					e.code().value()
				);
				continue;
			}

			case FILE_ACTION_ADDED:
			try {
				LOG_INFO(s_logger, "Detected creation of the file '{}' in session #{}.", chcvt::convert_wide_to_multibyte(absolute_src_path), this->m_session_id);

				auto lock = std::unique_lock(this->m_sftp_mutex);
				if (basic_placeholder.get_type() == shell::filesystem::placeholder_type::directory) ssh::sftp::filesystem::create_directory(this->m_sftp_session.value(), dest_path_str);
				else ssh::sftp::filesystem::create(this->m_sftp_session.value(), dest_path_str, ssh::sftp::filesystem::open_permissions::read);

				basic_placeholder.set_marked_in_sync(true);
				basic_placeholder.flush();

				LOG_INFO(
					s_logger,
					"The file '{}' corresponding to the new file has been successfully created on the server in session #{}.",
					chcvt::convert_wide_to_multibyte(dest_path_str),
					this->m_session_id
				);

				break;
			}
			catch (const ssh::ssh_libssh2_sftp_exception& e) {
				LOG_ERROR(
					s_logger,
					"Failed to create the file '{}' on the server corresponding to the new file in session #{}.",
					chcvt::convert_wide_to_multibyte(dest_path_str),
					this->m_session_id
				);
				continue;
			}

			default:
				break;
			}
		} catch (const std::system_error& e) {
				LOG_ERROR(
					s_logger,
					"Failed a placeholder operation in session #{}: {} (From Win32: {}({}))",
					this->m_session_id,
					e.what(),
					e.code().message(),
					e.code().value()
				);
				continue;
		} while (bytes_notify_info_entry_diff > 0);
	}

	shell::models::chunked_callback_generator<shell::functional::fetch_data_operation_info> session::on_fetch_data(const shell::functional::fetch_data_callback_parameters& parameters) {
		using chcvt_helper = util::charset::multibyte_wide_compat_helper;

		LOG_INFO(s_logger, "Data fetch requested by the system in session #{}.", this->m_session_id);

		std::filesystem::path absolute_placeholder_path = parameters.get_absolute_placeholder_path();

		// Extract a relative path from the sync root directory
		std::wstring relative_placeholder_path_str;
		if (this->m_syncroot_dir != absolute_placeholder_path) {
			relative_placeholder_path_str = absolute_placeholder_path.wstring().substr(this->m_syncroot_dir.length() + 1);
		}

		// Replace back-slash with slash
		std::replace(relative_placeholder_path_str.begin(), relative_placeholder_path_str.end(), L'\\', L'/');
		std::wstring absolute_query_path_str;
		absolute_query_path_str.append(L"/").append(relative_placeholder_path_str);

		std::unique_lock lock(this->m_sftp_mutex);
		try {
			ssh::sftp::io::isftpstream iss(this->m_sftp_session.value(), absolute_query_path_str, std::ios_base::in);
			constexpr std::size_t unit_chunk_length = 2097152;	// 2MiB
			std::size_t current_offset = parameters.get_offset();
			std::streamsize remaining_length = parameters.get_length();
			std::streamsize current_length = std::min(unit_chunk_length, static_cast<std::size_t>(remaining_length));
			std::streamsize current_read_length = 0;
			do {
				std::vector<std::byte> data(current_length);

				LOG_INFO(
					s_logger,
					"Downloading for '{}', offset: {} bytes, at least length: {} bytes, in session #{}",
					chcvt_helper::convert_wide_to_multibyte(absolute_query_path_str),
					current_offset,
					current_length,
					this->m_session_id
				);

				iss.seekg(current_offset);
				iss.read(reinterpret_cast<char*>(data.data()), current_length);
				current_read_length = iss.gcount();
				
				shell::functional::fetch_data_operation_info result;
				result.set_buffer(std::move(data));
				result.set_length(current_read_length);
				result.set_offset(current_offset);
				
				co_yield std::move(result);
				
				remaining_length -= current_read_length;
				current_offset += current_read_length;
				current_length = std::min(unit_chunk_length, static_cast<std::size_t>(remaining_length));
			}
			while (current_read_length > 0 && remaining_length > 0);

			co_return;
		}
		catch (const ssh::ssh_libssh2_sftp_exception& e) {
			LOG_CRITICAL(
				s_logger,
				"Failed to read file data via isftpstream in session #{}: {} (libssh2: {}({}))",
				this->m_session_id,
				e.what(),
				e.code().message(),
				e.code().value()
			);
			throw shell::functional::callback_abort_exception(STATUS_CLOUD_FILE_UNSUCCESSFUL);
		}
		catch (const ssh::ssh_libssh2_exception& e) {
			LOG_CRITICAL(
				s_logger,
				"Failed to SSH operations in session #{}: {} (libssh2: {}({}))",
				this->m_session_id,
				e.what(),
				e.code().message(),
				e.code().value()
			);
			throw shell::functional::callback_abort_exception(STATUS_CLOUD_FILE_UNSUCCESSFUL);
		}
		catch (...) {
			LOG_CRITICAL(s_logger, "An unexpected non negligible exception has been thrown in session #{}.", this->m_session_id);
			throw shell::functional::callback_abort_exception(STATUS_CLOUD_FILE_UNSUCCESSFUL);
		}
	}

	shell::functional::fetch_placeholders_operation_info session::on_fetch_placeholders(const shell::functional::callback_parameters& parameters) {
		using chcvt_helper = util::charset::multibyte_wide_compat_helper;

		LOG_INFO(s_logger, "Placeholder fetch requested by the system in session #{}.", this->m_session_id);

		std::filesystem::path absolute_placeholder_path = parameters.get_absolute_placeholder_path();

		// Extract a relative path from the sync root directory
		std::wstring relative_placeholder_path_str;
		if (this->m_syncroot_dir != absolute_placeholder_path) {
			relative_placeholder_path_str = absolute_placeholder_path.wstring().substr(this->m_syncroot_dir.length() + 1);
		}

		// Replace back-slash with slash
		std::replace(relative_placeholder_path_str.begin(), relative_placeholder_path_str.end(), L'\\', L'/');
		std::wstring absolute_query_dir_path_str;
		absolute_query_dir_path_str.append(L"/").append(relative_placeholder_path_str);

		shell::functional::fetch_placeholders_operation_info result;
		int skipped = 0;

		std::unique_lock<std::mutex> lock(this->m_sftp_mutex);

		try {
			for (const auto& relative_query_entity : ssh::sftp::filesystem::directory_iterator(this->m_sftp_session.value(), absolute_query_dir_path_str)) {
				auto placeholder_name_str = relative_query_entity.path().filename().wstring();
				
				if (placeholder_name_str == L"." || placeholder_name_str == L"..") continue;
				
				std::filesystem::path absolute_query_entity_path = absolute_query_dir_path_str;
				absolute_query_entity_path += L"/";
				absolute_query_entity_path += relative_query_entity.path();
				
				try {
					auto file_size = ssh::sftp::filesystem::file_size(this->m_sftp_session.value(), absolute_query_entity_path);

					shell::filesystem::file_times file_times;
					file_times.set_last_write_time(ssh::sftp::filesystem::last_write_time(this->m_sftp_session.value(), absolute_query_entity_path));
					file_times.set_last_access_time(ssh::sftp::filesystem::last_access_time(this->m_sftp_session.value(), absolute_query_entity_path));
					
					std::uint32_t file_attributes;
					switch (ssh::sftp::filesystem::status(this->m_sftp_session.value(), absolute_query_entity_path).type()) {
						case std::filesystem::file_type::directory:
							file_attributes = FILE_ATTRIBUTE_DIRECTORY;
							break;
						case std::filesystem::file_type::regular:
							file_attributes = FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_ARCHIVE;
							break;
						default:
							LOG_INFO(s_logger, "Skip '{}' due to unknown file type, in session #{}.", absolute_query_entity_path.string(), this->m_session_id);
							skipped++;
							continue;
					}

					shell::filesystem::placeholder_creation_info info(
						placeholder_name_str,
						file_size,
						file_attributes,
						file_times
					);

					result.add_creation_info(shell::filesystem::placeholder_creation_info(
						placeholder_name_str,
						file_size,
						file_attributes,
						file_times
					));
				}
				catch (const ssh::ssh_libssh2_sftp_exception& e) {
					LOG_INFO(s_logger, "Failed to get file information and skip '{}', in session #{}.", absolute_query_entity_path.string(), this->m_session_id);
					skipped++;
					continue;
				}
			}
		}
		catch (const ssh::ssh_libssh2_exception& e) {
			LOG_CRITICAL(s_logger, "Failed to enumerate directory entities of '{}', in session #{}.", chcvt_helper::convert_wide_to_multibyte(absolute_query_dir_path_str), this->m_session_id);
			throw shell::functional::callback_abort_exception(STATUS_CLOUD_FILE_UNSUCCESSFUL);
		}
		catch (...) {
			LOG_CRITICAL(s_logger, "An unexpected non negligible exception has been thrown in session #{}.", this->m_session_id);
			throw shell::functional::callback_abort_exception(STATUS_CLOUD_FILE_UNSUCCESSFUL);
		}

		lock.unlock();

		auto placeholder_count = result.get_count_to_be_processed();
		result.set_total_count_to_be_processed(placeholder_count);

		LOG_INFO(s_logger, "{} placeholders will be created, and {} will be skipped, in session #{}.", placeholder_count, skipped, this->m_session_id);

		return result;
	}
}