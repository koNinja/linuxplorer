#include <ntstatus.h>

#define WIN32_NO_STATUS
#include "session.hpp"
#include <shlwapi.h>

#include <regex>
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
		
		this->m_fetch_cancel_tokens[parameters.get_native_info().FileId.QuadPart].store(false);

		std::wstring relative_placeholder_path_str = this->relative_path_from_syncroot(std::wstring(parameters.get_absolute_placeholder_path()));
		std::wstring absolute_query_path_str = this->server_path_from_relative_path(relative_placeholder_path_str);

		std::unique_lock lock(this->m_sftp_mutex);
		try {
			ssh::sftp::io::isftpstream iss(this->m_sftp_session.value(), absolute_query_path_str, std::ios_base::in);
			constexpr std::size_t unit_chunk_length = 2097152;	// 2 MiB
			std::streamsize bytes_remaining = parameters.get_length();
			std::size_t bytes_offset = parameters.get_offset();
			std::streamsize bytes_has_read = 0;
			do {
				if (this->m_fetch_cancel_tokens[parameters.get_native_info().FileId.QuadPart].load()) co_return;
				
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

			this->m_fetch_cancel_tokens.erase(parameters.get_native_info().FileId.QuadPart);

			co_return;
		}
		catch (const ssh::ssh_libssh2_sftp_exception& e) {
			this->m_fetch_cancel_tokens.erase(parameters.get_native_info().FileId.QuadPart);

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
			this->m_fetch_cancel_tokens.erase(parameters.get_native_info().FileId.QuadPart);

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
			this->m_fetch_cancel_tokens.erase(parameters.get_native_info().FileId.QuadPart);

			LOG_CRITICAL(s_logger, "An unexpected non negligible exception has been thrown in session #{}.", this->m_session_id);
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

		std::unique_lock<std::mutex> lock(this->m_sftp_mutex);
		try {
			for (const auto& relative_query_entity : ssh::sftp::filesystem::directory_iterator(this->m_sftp_session.value(), absolute_query_dir_path_str)) {
				auto placeholder_name_str = relative_query_entity.path().filename().wstring();
				
				if (placeholder_name_str == L"." || placeholder_name_str == L"..") continue;
				if (contains_invalid_ntfs_character(placeholder_name_str)) {
					LOG_INFO(s_logger, "Skip '{}' because its name contains invalid characters in NTFS, in session #{}.", relative_query_entity.path().filename().string(), this->m_session_id);
					skipped++;
					continue;
				}
				
				std::filesystem::path absolute_query_entity_path = absolute_query_dir_path_str;
				absolute_query_entity_path += L"/";
				absolute_query_entity_path += relative_query_entity.path();

				// exclude the /tmp/* trees
				if (absolute_query_entity_path.wstring().starts_with(L"/tmp")) {
					LOG_INFO(s_logger, "Skip '{}' because the file is under the '/tmp/*' directory, in session #{}.", absolute_query_entity_path.string(), this->m_session_id);
					skipped++;
					continue;
				}

				try {
					shell::filesystem::file_times file_times;
					file_times.set_last_write_time(relative_query_entity.last_write_time());
					file_times.set_last_access_time(relative_query_entity.last_access_time());

					std::uint32_t file_attributes;
					switch (relative_query_entity.status().type()) {
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
						relative_query_entity.file_size(),
						file_attributes,
						file_times
					);

					info.set_identity(std::vector<std::byte>(
						reinterpret_cast<const std::byte*>(absolute_query_entity_path.wstring().data()),
						reinterpret_cast<const std::byte*>(absolute_query_entity_path.wstring().data() + absolute_query_entity_path.wstring().size())
					));

					result.add_creation_info(std::move(info));
				}
				catch (const ssh::ssh_libssh2_sftp_exception& e) {
					LOG_INFO(s_logger, "Failed to get file information and skip '{}', in session #{}.", absolute_query_entity_path.string(), this->m_session_id);
					skipped++;
					continue;
				}
			}
		}
		catch (const ssh::ssh_libssh2_exception& e) {
			LOG_CRITICAL(s_logger, "Failed to enumerate directory entities of '{}', in session #{}.", chcvt::convert_wide_to_multibyte(absolute_query_dir_path_str), this->m_session_id);
			throw shell::functional::callback_abort_exception(STATUS_CLOUD_FILE_UNSUCCESSFUL);
		}
		catch (const std::filesystem::filesystem_error& e) {
			LOG_CRITICAL(s_logger, "Failed to filesystem operations: {}, in session #{}. (Win32: {}({}))", e.what(), this->m_session_id, e.code().message(), e.code().value());
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
		if (this->m_fetch_cancel_tokens.contains(parameters.get_native_info().FileId.QuadPart))
			this->m_fetch_cancel_tokens[parameters.get_native_info().FileId.QuadPart].store(true);
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