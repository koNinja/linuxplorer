#include <ntstatus.h>

#define WIN32_NO_STATUS
#include "session.hpp"
#include <shlwapi.h>

#include <regex>
#include <unordered_set>

#include <util/charset/multibyte_wide_compat_helper.hpp>
#include <util/charset/case_insensitive_char_traits.hpp>

#include <ssh/ssh_session.hpp>
#include <ssh/sftp/sftp_session.hpp>
#include <ssh/sftp/filesystem/sftp_entity.hpp>
#include <ssh/sftp/filesystem/sftp_manip.hpp>
#include <ssh/sftp/io/sftpstream.hpp>

#include <quill/LogMacros.h>

#include <shell/functional/cloud_provider_callback.hpp>
#include <shell/cloud_provider_session.hpp>
#include <shell/filesystem/cloud_filter_placeholder.hpp>
#undef WIN32_NO_STATUS

namespace linuxplorer::app::lxpsvc {
	bool contains_invalid_ntfs_character(std::wstring_view path) {
		static std::wregex invalid_pattern(LR"([<>:"/\\|?*])");

		if (std::regex_search(path.cbegin(), path.cend(), invalid_pattern)) return true;

		static std::wregex invalid_end_pattern(LR"([ \.]$)");
		if (std::regex_search(path.cbegin(), path.cend(), invalid_end_pattern)) return true;

		static std::wregex reserved_pattern(LR"(^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$)", std::regex_constants::icase);
		if (std::regex_search(path.cbegin(), path.cend(), reserved_pattern)) return true;

		return false;
	}

	bool is_under(const std::filesystem::path& path, const std::filesystem::path& base) {
		auto p = std::filesystem::weakly_canonical(path);
		auto b = std::filesystem::weakly_canonical(base);

		auto pit = p.begin();
		auto bit = b.begin();

		for (; bit != b.end(); ++bit, ++pit) {
			if (pit == p.end() || *pit != *bit) return false;
		}
		return true;
	}

	shell::models::chunked_callback_generator<shell::functional::fetch_data_operation_info> session::on_fetch_data(const shell::functional::fetch_data_callback_parameters& parameters) {
		LOG_INFO(s_logger, "Data fetch for '{}' requested by the system in session #{}.", util::charset::multibyte_wide_compat_helper::convert_wide_to_multibyte(parameters.get_absolute_placeholder_path()), this->m_session_id);
		
		std::unique_lock fetch_cancel_token_unique_lock(this->m_fetch_cancel_tokens_mutex);
		this->m_fetch_cancel_tokens[parameters.get_native_info().FileId.QuadPart] = false;
		fetch_cancel_token_unique_lock.unlock();

		std::wstring relative_placeholder_path_str = this->relative_path_from_syncroot(std::wstring(parameters.get_absolute_placeholder_path()));
		std::wstring absolute_query_path_str = this->server_path_from_relative_path(relative_placeholder_path_str);

		std::unique_lock lock(this->m_sftp_mutex);
		try {
			ssh::sftp::io::isftpstream iss(this->m_sftp_session.value(), absolute_query_path_str, std::ios_base::in);
			constexpr std::size_t unit_chunk_length = 2097152;	// 2 MiB
			std::streamsize bytes_remaining = parameters.get_length();
			std::size_t bytes_offset = parameters.get_offset();
			std::streamsize bytes_has_read = 0;
			iss.seekg(bytes_offset);
			do {
				std::shared_lock fetch_cancel_token_shared_lock(this->m_fetch_cancel_tokens_mutex);
				if (this->m_fetch_cancel_tokens[parameters.get_native_info().FileId.QuadPart]) {
					LOG_INFO(
						s_logger,
						"Download for '{}' has been cancelled in session #{}", 
						chcvt::convert_wide_to_multibyte(absolute_query_path_str),
						this->m_session_id
					);
				}
				fetch_cancel_token_shared_lock.unlock();
				
				std::streamsize bytes_to_read = std::min(unit_chunk_length, static_cast<std::size_t>(bytes_remaining));
				std::vector<std::byte> data(bytes_to_read);

				LOG_INFO(
					s_logger,
					"Downloading for '{}', offset: {} bytes, at least length: {} bytes, in session #{}",
					chcvt::convert_wide_to_multibyte(absolute_query_path_str),
					bytes_offset,
					bytes_to_read,
					this->m_session_id
				);

				iss.read(reinterpret_cast<char*>(data.data()), bytes_to_read);
				bytes_has_read = iss.gcount();
				
				shell::functional::fetch_data_operation_info result;
				result.set_buffer(std::move(data));
				result.set_length(bytes_has_read);
				result.set_offset(bytes_offset);
				
				co_yield std::move(result);
				
				bytes_remaining -= bytes_has_read;
				bytes_offset += bytes_has_read;
			}
			while (bytes_has_read > 0 && bytes_remaining > 0);

			std::unique_lock fetch_cancel_token_unique_lock(this->m_fetch_cancel_tokens_mutex);
			this->m_fetch_cancel_tokens.erase(parameters.get_native_info().FileId.QuadPart);
			fetch_cancel_token_unique_lock.unlock();

			co_return;
		}
		catch (const ssh::ssh_libssh2_sftp_exception& e) {
			std::unique_lock fetch_cancel_token_unique_lock(this->m_fetch_cancel_tokens_mutex);
			this->m_fetch_cancel_tokens.erase(parameters.get_native_info().FileId.QuadPart);
			fetch_cancel_token_unique_lock.unlock();

			LOG_ERROR(
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
			std::unique_lock fetch_cancel_token_unique_lock(this->m_fetch_cancel_tokens_mutex);
			this->m_fetch_cancel_tokens.erase(parameters.get_native_info().FileId.QuadPart);
			fetch_cancel_token_unique_lock.unlock();

			LOG_ERROR(
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
			std::unique_lock fetch_cancel_token_unique_lock(this->m_fetch_cancel_tokens_mutex);
			this->m_fetch_cancel_tokens.erase(parameters.get_native_info().FileId.QuadPart);
			fetch_cancel_token_unique_lock.unlock();

			LOG_ERROR(s_logger, "An unexpected non negligible exception has been thrown in session #{}.", this->m_session_id);
			throw shell::functional::callback_abort_exception(STATUS_CLOUD_FILE_UNSUCCESSFUL);
		}
	}

	shell::functional::fetch_placeholders_operation_info session::on_fetch_placeholders(const shell::functional::callback_parameters& parameters) {
		LOG_INFO(s_logger, "Placeholder fetch for '{}' requested by the system in session #{}.", util::charset::multibyte_wide_compat_helper::convert_wide_to_multibyte(parameters.get_absolute_placeholder_path()), this->m_session_id);

		auto compare = [](std::wstring_view l, std::wstring_view r) -> int {
			if (l.length() == r.length()) return util::charset::case_insensitive_char_traits<wchar_t>::compare(l.data(), r.data(), std::min(l.length(), r.length()));
			else return 1;
		};

		std::wstring absolute_placeholder_path_str(parameters.get_absolute_placeholder_path());
		std::wstring relative_placeholder_path_str = this->relative_path_from_syncroot(absolute_placeholder_path_str);
		std::wstring absolute_query_dir_path_str = this->server_path_from_relative_path(relative_placeholder_path_str);

		shell::functional::fetch_placeholders_operation_info result;
		int skipped = 0;

		auto tolower_sys_localized = [](std::wstring_view str) {
			std::wstring s(str);
			std::locale loc("");
			std::transform(s.begin(), s.end(), s.begin(), [&loc](wchar_t c) { 
				return std::tolower(c, loc); }
			);
			return s;
		};

		try {
			std::unique_lock lock(this->m_sftp_mutex);

			std::unordered_set<std::filesystem::path> occupied_lower_filenames;
			for (const auto& relative_query_entity : ssh::sftp::filesystem::directory_iterator(this->m_sftp_session.value(), absolute_query_dir_path_str)) {
				auto placeholder_name_str = relative_query_entity.path().filename().wstring();
				
				if (placeholder_name_str == L"." || placeholder_name_str == L"..") continue;
				if (contains_invalid_ntfs_character(placeholder_name_str)) {
					LOG_INFO(s_logger, "Skip '{}' because its name contains invalid characters in NTFS, in session #{}.", relative_query_entity.path().filename().string(), this->m_session_id);
					skipped++;
					continue;
				}

				auto placeholder_name_str_lower = tolower_sys_localized(placeholder_name_str);
				if (occupied_lower_filenames.contains(placeholder_name_str_lower)) {
					LOG_WARNING(
						s_logger,
						"Skip '{}' because there are files that are considered to have the same name in Windows, in session #{}",
						relative_query_entity.path().filename().string(),
						this->m_session_id
					);

					auto citr = std::find_if(result.get_creation_info().cbegin(), result.get_creation_info().cend(), [&compare, placeholder_name_str_lower](const shell::filesystem::placeholder_creation_info& info) {
						return compare(info.get_relative_path(), placeholder_name_str_lower) == 0;
					});
					if (citr != result.get_creation_info().cend()) {
						LOG_WARNING(
							s_logger,
							"Cancel creation of '{}' because there are files that are considered to have the same name in Windows, in session #{}",
							util::charset::multibyte_wide_compat_helper::convert_wide_to_multibyte(citr->get_relative_path()),
							this->m_session_id
						);

						result.remove_creation_info_at(std::distance(result.get_creation_info().cbegin(), citr));
					}

					continue;
				}

				occupied_lower_filenames.emplace(placeholder_name_str_lower);
				
				std::filesystem::path absolute_query_entity_path = absolute_query_dir_path_str;
				if (absolute_query_dir_path_str != L"/") absolute_query_entity_path += L"/";
				absolute_query_entity_path += relative_query_entity.path();

				std::filesystem::path absolute_client_entity_path(absolute_placeholder_path_str);
				absolute_client_entity_path /= placeholder_name_str;

				shell::filesystem::file_times file_times;
				file_times.set_last_write_time(relative_query_entity.last_write_time());
				file_times.set_last_access_time(relative_query_entity.last_access_time());

				std::uint32_t file_attributes;
				switch (relative_query_entity.status().type()) {
					case std::filesystem::file_type::directory:
						file_attributes = FILE_ATTRIBUTE_DIRECTORY;
						break;
					case std::filesystem::file_type::regular:
						file_attributes = FILE_ATTRIBUTE_NORMAL;
						break;
					default:
						LOG_INFO(s_logger, "Skip '{}' due to unknown file type, in session #{}.", absolute_query_entity_path.string(), this->m_session_id);
						skipped++;
						continue;
				}

				if (
					::PathFileExistsW(absolute_client_entity_path.c_str()) && 
					std::filesystem::status(absolute_client_entity_path).type() == relative_query_entity.status().type()
				) {
					shell::filesystem::cloud_filter_placeholder placeholder(this->m_cloud_session.value(), this->relative_path_from_syncroot(absolute_client_entity_path));
					placeholder.set_file_times(std::move(file_times));
					if (placeholder.get_type() == shell::filesystem::placeholder_type::file) {
						shell::filesystem::file_placeholder file_ph(std::move(placeholder));
						file_ph.set_file_size(relative_query_entity.file_size());
						file_ph.set_marked_in_sync(true);
						file_ph.flush();
					}
					else {
						shell::filesystem::directory_placeholder dir_ph(std::move(placeholder));
						dir_ph.set_marked_in_sync(true);
						dir_ph.flush();
					}
				}
				else {
					shell::filesystem::placeholder_creation_info info(
						placeholder_name_str,
						relative_query_entity.file_size(),
						file_attributes,
						std::move(file_times)
					);

					auto absolute_query_entity_path_str = absolute_query_entity_path.wstring();
					info.set_identity(std::vector<std::byte>(s_dummy_blob, s_dummy_blob + s_dummy_blob_length));

					result.add_creation_info(std::move(info));
				}
			}

			lock.unlock();

			/*
			for (const auto& entity_on_disk : std::filesystem::directory_iterator(absolute_placeholder_path_str)) {
				if (occupied_lower_filenames.contains(tolower_sys_localized(entity_on_disk.path().filename().wstring()))) continue;
				std::filesystem::path path = absolute_placeholder_path_str;
				path /= entity_on_disk.path();

				LOG_INFO(s_logger, "Delete '{}' because the file does not exist in the server, in session #{}.", path.string(), this->m_session_id);
				std::filesystem::remove_all(path);
			}
			*/
		}
		catch (const ssh::ssh_libssh2_exception& e) {
			LOG_ERROR(s_logger, "Failed to enumerate directory entities of '{}', in session #{}.", chcvt::convert_wide_to_multibyte(absolute_query_dir_path_str), this->m_session_id);
			throw shell::functional::callback_abort_exception(STATUS_CLOUD_FILE_UNSUCCESSFUL);
		}
		catch (const std::filesystem::filesystem_error& e) {
			LOG_ERROR(s_logger, "Failed to filesystem operations: {}, in session #{}. (Win32: {}({}))", e.what(), this->m_session_id, e.code().message(), e.code().value());
			throw shell::functional::callback_abort_exception(STATUS_CLOUD_FILE_UNSUCCESSFUL);
		}
		catch (...) {
			LOG_ERROR(s_logger, "An unexpected non negligible exception has been thrown in session #{}.", this->m_session_id);
			throw shell::functional::callback_abort_exception(STATUS_CLOUD_FILE_UNSUCCESSFUL);
		}

		auto placeholder_count = result.get_count_to_be_processed();
		result.set_total_count_to_be_processed(placeholder_count);

		LOG_INFO(s_logger, "{} placeholders will be created, and {} will be skipped, in session #{}.", placeholder_count, skipped, this->m_session_id);

		unique_nthandle placeholder_handle(::CreateFileW(
			absolute_placeholder_path_str.c_str(),
			FILE_READ_ATTRIBUTES,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			nullptr,
			OPEN_EXISTING,
			FILE_FLAG_BACKUP_SEMANTICS,
			nullptr
		));
		if (placeholder_handle.get() == INVALID_HANDLE_VALUE) {
			std::error_code ec(::GetLastError(), std::system_category());
			LOG_WARNING(
				s_logger,
				"Failed to open the placeholder handle of '{}', in session #{} (Win32: {}({}))",
				chcvt::convert_wide_to_multibyte(absolute_placeholder_path_str),
				this->m_session_id,
				ec.message(),
				ec.value()
			);

			return result;
		}

		::FILE_ID_INFO file_id_info;
		bool succeeded = ::GetFileInformationByHandleEx(
			placeholder_handle.get(),
			::FILE_INFO_BY_HANDLE_CLASS::FileIdInfo,
			&file_id_info,
			sizeof(file_id_info)
		);
		if (!succeeded) {
			std::error_code ec(::GetLastError(), std::system_category());
			LOG_WARNING(
				s_logger,
				"Failed to get the FRN of the placeholder '{}', in session #{} (Win32: {}({}))",
				chcvt::convert_wide_to_multibyte(absolute_placeholder_path_str),
				this->m_session_id,
				ec.message(),
				ec.value()
			);

			return result;
		}

		std::unique_lock lf_lock(this->m_placeholder_last_fetched_mutex);
		this->m_placeholder_last_fetched[file_id_info.FileId] = std::chrono::time_point_cast<std::chrono::seconds>(std::chrono::system_clock::now());
		lf_lock.unlock();

		return result;
	}

	void session::on_cancel_fetch_data(const shell::functional::cancel_fetch_data_callback_parameters& parameters) {
		if (this->m_fetch_cancel_tokens.contains(parameters.get_native_info().FileId.QuadPart)) {
			std::unique_lock fetch_cancel_token_unique_lock(this->m_fetch_cancel_tokens_mutex);
			this->m_fetch_cancel_tokens[parameters.get_native_info().FileId.QuadPart] = true;
			fetch_cancel_token_unique_lock.unlock();
		}
	}

	shell::functional::delete_operation_info session::on_delete(const shell::functional::delete_callback_parameters& parameters) {
		auto server_path = this->server_path_from_relative_path(this->relative_path_from_syncroot(std::wstring(parameters.get_absolute_placeholder_path())));
		try {
			LOG_INFO(s_logger, "Detected file deletion of '{}' in session #{}.", chcvt::convert_wide_to_multibyte(parameters.get_absolute_placeholder_path()), this->m_session_id);
						
			if (parameters.is_directory() && !::PathIsDirectoryEmptyW(std::wstring(parameters.get_absolute_placeholder_path()).c_str())) {
				LOG_INFO(s_logger, "Skip deletion request for '{}' because the directory is not empty, in session #{}.", chcvt::convert_wide_to_multibyte(parameters.get_absolute_placeholder_path()), this->m_session_id);
				shell::functional::delete_operation_info result;
				result.set_status(STATUS_CLOUD_FILE_UNSUCCESSFUL);
				return result;
			}

			std::unique_lock lock(this->m_sftp_mutex);
			// Skip if the file doesn't exist on the server.
			try { ssh::sftp::filesystem::status(this->m_sftp_session.value(), server_path); } 
			catch (...) {
				return {};
			}

			ssh::sftp::filesystem::remove(this->m_sftp_session.value(), server_path);

			LOG_INFO(
				s_logger,
				"The file '{}' corresponding to the deleted file has been successfully removed from the server in session #{}.",
				chcvt::convert_wide_to_multibyte(server_path),
				this->m_session_id
			);

			return {};
		}
		catch (const ssh::ssh_libssh2_sftp_exception& e) {
			LOG_ERROR(
				s_logger,
				"Failed to remove the file '{}' corresponding to the deleted file from the server in session #{}: {} (libssh2: {}({}))",
				chcvt::convert_wide_to_multibyte(server_path),
				this->m_session_id,
				e.what(),
				e.code().message(),
				e.code().value()
			);
			
			throw shell::functional::callback_abort_exception(STATUS_CLOUD_FILE_UNSUCCESSFUL);
		}
	}

	shell::functional::operation_info session::on_rename(const shell::functional::rename_callback_parameters& parameters) {
		auto absolute_old_client_path = parameters.get_absolute_placeholder_path();
		auto absolute_new_client_path = parameters.get_absolute_new_path();
		auto absolute_old_server_path = this->server_path_from_relative_path(this->relative_path_from_syncroot(std::wstring(absolute_old_client_path)));
		auto absolute_new_server_path = this->server_path_from_relative_path(this->relative_path_from_syncroot(std::wstring(absolute_new_client_path)));

		try {
			LOG_INFO(s_logger, "Detected file renaming of '{}' in session #{}.", chcvt::convert_wide_to_multibyte(absolute_old_client_path), this->m_session_id);
			
			std::unique_lock lock(this->m_sftp_mutex);
			// If the new path is under the syncroot, rename it on the server.
			if (is_under(absolute_new_client_path, this->m_syncroot_dir)) {
				ssh::sftp::filesystem::rename(this->m_sftp_session.value(), absolute_old_server_path, absolute_new_server_path);
				LOG_INFO(
					s_logger,
					"The file '{}' has been successfully renamed to '{}' on the server in session #{}.",
					chcvt::convert_wide_to_multibyte(absolute_old_server_path),
					chcvt::convert_wide_to_multibyte(absolute_new_server_path),
					this->m_session_id
				);
			}
			// Otherwise, delete it from the server.
			else {
				// Skip if the file doesn't exist on the server.
				try { ssh::sftp::filesystem::status(this->m_sftp_session.value(), absolute_old_server_path); } 
				catch (...) {
					return {};
				}
				
				ssh::sftp::filesystem::remove_all(this->m_sftp_session.value(), absolute_old_server_path);
				LOG_INFO(
					s_logger,
					"The file '{}' has been successfully deleted on the server in session #{}.",
					chcvt::convert_wide_to_multibyte(absolute_old_server_path),
					this->m_session_id
				);
			}

			return {};
		}
		catch (const ssh::ssh_libssh2_sftp_exception& e) {
			LOG_ERROR(
				s_logger,
				"Failed to rename or delete the file '{}' the server in session #{}: {} (libssh2: {}({}))",
				chcvt::convert_wide_to_multibyte(absolute_old_server_path),
				this->m_session_id,
				e.what(),
				e.code().message(),
				e.code().value()
			);

			throw shell::functional::callback_abort_exception(STATUS_CLOUD_FILE_UNSUCCESSFUL);
		}
	}

	void session::on_rename_completion(const shell::functional::rename_completion_callback_parameters& parameters) {
		try {
			LOG_INFO(s_logger, "Rename operation completed for '{}' in session #{}.", chcvt::convert_wide_to_multibyte(parameters.get_absolute_old_path()), this->m_session_id);

			shell::filesystem::cloud_filter_placeholder placeholder(this->m_cloud_session.value(), this->relative_path_from_syncroot(std::wstring(parameters.get_absolute_placeholder_path())));
			placeholder.set_marked_in_sync(true);
			placeholder.flush();
		}
		catch (const shell::cloud_provider_system_error& e) {
			LOG_ERROR(
				s_logger,
				"Failed to mark the placeholder '{}' as synchronized in session #{}: {} (Win32: {}({}))",
				chcvt::convert_wide_to_multibyte(parameters.get_absolute_placeholder_path()),
				this->m_session_id,
				e.what(),
				e.code().message(),
				e.code().value()
			);
		}
	}
}