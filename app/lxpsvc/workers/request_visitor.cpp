#include "operation_executor.hpp"

#include <ssh/sftp/filesystem/sftp_manip.hpp>
#include <ssh/sftp/filesystem/sftp_entity.hpp>
#include <ssh/sftp/io/sftpstream.hpp>

#include <shell/cloud_provider_session.hpp>
#include <shell/filesystem/cloud_filter_placeholder.hpp>
#include <shell/cloud_provider_exception.hpp>

#include <util/charset/case_insensitive_char_traits.hpp>

#include <quill/LogMacros.h>
#include <quill/std/FilesystemPath.h>
#include <quill/std/WideString.h>

#include <fstream>
#include <regex>
#include <unordered_set>

#include <shlwapi.h>

namespace linuxplorer::app::lxpsvc::workers {
	bool contains_invalid_ntfs_character(std::wstring_view path) {
		static std::wregex invalid_pattern(LR"([<>:"/\\|?*])");

		if (std::regex_search(path.cbegin(), path.cend(), invalid_pattern)) return true;

		static std::wregex invalid_end_pattern(LR"([ \.]$)");
		if (std::regex_search(path.cbegin(), path.cend(), invalid_end_pattern)) return true;

		static std::wregex reserved_pattern(LR"(^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$)", std::regex_constants::icase);
		if (std::regex_search(path.cbegin(), path.cend(), reserved_pattern)) return true;

		return false;
	}

	operation_executor::request_visitor::request_visitor(const ssh::sftp::sftp_session& sftp_session, const shell::cloud_provider_session& cloud_provider_session, quill::Logger* logger)
		: m_logger(logger), m_cloud_provider_session(cloud_provider_session), m_sftp_session(sftp_session), m_path_helper(this->m_cloud_provider_session.get_sync_root_dir())
	{}

	models::requests::request_result operation_executor::request_visitor::operator()(models::requests::remote::creation_request& request) {
		try {
			switch (request.get_type()) {
			case std::filesystem::file_type::directory:
				ssh::sftp::filesystem::create_directory(this->m_sftp_session, request.get_absolute_path());
				break;
			case std::filesystem::file_type::regular:
				ssh::sftp::filesystem::create(this->m_sftp_session, request.get_absolute_path(), ssh::sftp::filesystem::open_permissions::read);
				break;
			default:
				LOG_ERROR(this->m_logger, "Unsupported file type: '{}'.", request.get_absolute_path());
				return models::requests::request_result::permanent_failure;
			}

			LOG_INFO(
				this->m_logger,
				"The file or directory '{}' has been successfully created on the server.", 
				request.get_absolute_path()
			);

			return models::requests::request_result::success;
		}
		catch (const ssh::ssh_libssh2_sftp_exception& e) {
			LOG_ERROR(
				this->m_logger,
				"Failed to create the file or directory '{}' on the server.",
				request.get_absolute_path()
			);
			return models::requests::request_result::transient_failure;
		}
	}
	
	models::requests::request_result operation_executor::request_visitor::operator()(models::requests::remote::modification_request& request) {
		auto server_path = request.get_absolute_path();
		auto absolute_client_path = this->m_path_helper.to_win_style(server_path, helpers::style_conversion_class::absolute_format);

		try {
			// should cache the file stream for the same file
			std::ifstream ifs(absolute_client_path, std::ios::binary);
			ssh::sftp::io::osftpstream oss(this->m_sftp_session, server_path.wstring(), std::ios_base::trunc | std::ios_base::out);

			ifs.seekg(request.get_range().get_offset());
			oss.seekp(request.get_range().get_offset());

			std::vector<std::byte> buffer(request.get_range().get_length());
			ifs.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
			oss.write(reinterpret_cast<char*>(buffer.data()), buffer.size());

			LOG_INFO(
				this->m_logger,
				"Changes to the file '{}' have been successfully applied on the server.",
				absolute_client_path
			);

			return models::requests::request_result::success;
		}
		catch (const ssh::ssh_libssh2_sftp_exception& e) {
			LOG_ERROR(
				this->m_logger,
				"Failed to transfer file data to the server: {} (libssh2: {}({}))",
				e.what(),
				e.code().message(),
				e.code().value()
			);

			return models::requests::request_result::transient_failure;
		}
		catch (const std::filesystem::filesystem_error& e) {
			LOG_ERROR(
				this->m_logger,
				"Failed to a filesystem operation: {} (Win32: {}({}))",
				e.what(),
				e.code().message(),
				e.code().value()
			);
			
			return models::requests::request_result::transient_failure;
		}
	}

	models::requests::request_result operation_executor::request_visitor::operator()(models::requests::remote::deletion_request& request) {
		try {			
			ssh::sftp::filesystem::remove_all(this->m_sftp_session, request.get_absolute_path());

			LOG_INFO(
				this->m_logger,
				"The file or directory '{}' has been successfully removed from the server.",
				request.get_absolute_path()
			);

			request.set_value();
			return models::requests::request_result::success;
		}
		catch (const ssh::ssh_libssh2_sftp_exception& e) {
			LOG_ERROR(
				this->m_logger,
				"Failed to recursively remove the file or directory '{}' from the server: {} (libssh2: {}({}))",
				request.get_absolute_path(),
				e.what(),
				e.code().message(),
				e.code().value()
			);
			
			request.set_exception(std::move(e));
			return models::requests::request_result::transient_failure;
		}
	}

	models::requests::request_result operation_executor::request_visitor::operator()(models::requests::remote::renaming_request& request) {
		auto old_server_path = request.get_absolute_path();
		auto new_server_path = request.get_absolute_new_path();
		auto absolute_old_client_path = this->m_path_helper.to_win_style(old_server_path, helpers::style_conversion_class::absolute_format);
		auto absolute_new_client_path = this->m_path_helper.to_win_style(new_server_path, helpers::style_conversion_class::absolute_format);

		try {
			ssh::sftp::filesystem::rename(this->m_sftp_session, old_server_path, new_server_path);

			LOG_INFO(
				this->m_logger,
				"The file or directory '{}' has been successfully renamed to '{}' on the server.",
				old_server_path,
				new_server_path
			);

			request.set_value();
			return models::requests::request_result::success;
		}
		catch (const ssh::ssh_libssh2_sftp_exception& e) {
			LOG_ERROR(
				this->m_logger,
				"Failed to rename the file or directory '{}' on the server: {} (libssh2: {}({}))",
				old_server_path,
				e.what(),
				e.code().message(),
				e.code().value()
			);

			request.set_exception(std::move(e));
			return models::requests::request_result::transient_failure;
		}
	}

	models::requests::request_result operation_executor::request_visitor::operator()(models::requests::remote::hydration_request& request) {
		auto server_path = request.get_absolute_path();
		auto absolute_client_path = this->m_path_helper.to_win_style(server_path, helpers::style_conversion_class::absolute_format);

		try {
			ssh::sftp::io::isftpstream iss(this->m_sftp_session, server_path.wstring(), std::ios_base::in);
			std::vector<std::byte> data(request.get_range().get_length());

			LOG_INFO(
				this->m_logger,
				"Downloading for '{}', offset: {} bytes, length: {} bytes.",
				server_path,
				request.get_range().get_offset(),
				request.get_range().get_length()
			);

			iss.read(reinterpret_cast<char*>(data.data()), request.get_range().get_length());
			
			request.set_value(std::move(data));
			return models::requests::request_result::success;
		}
		catch (const ssh::ssh_libssh2_sftp_exception& e) {
			LOG_ERROR(
				this->m_logger,
				"Failed to read file data via isftpstream: {} (libssh2: {}({}))",
				e.what(),
				e.code().message(),
				e.code().value()
			);
			request.set_exception(std::move(e));
			return models::requests::request_result::transient_failure;
		}
	}

	models::requests::request_result operation_executor::request_visitor::operator()(models::requests::remote::population_request& request) {
		std::vector<shell::filesystem::placeholder_creation_info> info;

		auto compare = [](std::wstring_view l, std::wstring_view r) -> int {
			if (l.length() == r.length()) return util::charset::case_insensitive_char_traits<wchar_t>::compare(l.data(), r.data(), std::min(l.length(), r.length()));
			else return 1;
		};

		auto tolower_sys_localized = [](std::wstring_view str) {
			std::wstring s(str);
			std::locale loc("");
			std::transform(s.begin(), s.end(), s.begin(), [&loc](wchar_t c) { 
				return std::tolower(c, loc); }
			);
			return s;
		};

		std::unordered_set<std::filesystem::path> occupied_lower_filenames;

		int skipped = 0;

		try {
			for (const auto& entity : ssh::sftp::filesystem::directory_iterator(this->m_sftp_session, request.get_absolute_path().wstring())) {
				auto placeholder_name = entity.path().filename();
				
				if (contains_invalid_ntfs_character(placeholder_name.wstring())) {
					LOG_INFO(this->m_logger, "Skip '{}' because its name contains invalid characters in NTFS.", placeholder_name);
					skipped++;
					continue;
				}

				std::filesystem::path placeholder_name_lower = tolower_sys_localized(placeholder_name.wstring());
				if (occupied_lower_filenames.contains(placeholder_name_lower)) {
					LOG_WARNING(
						this->m_logger,
						"Skip '{}' because there are files that are considered to have the same name in Windows.",
						placeholder_name
					);
					skipped++;

					auto itr = std::find_if(info.begin(), info.end(), [&compare, &placeholder_name_lower](const shell::filesystem::placeholder_creation_info& info) {
						return compare(info.get_relative_path(), placeholder_name_lower.wstring()) == 0;
					});
					if (itr != info.end()) {
						LOG_WARNING(
							this->m_logger,
							"Cancel creation of '{}' because there are files that are considered to have the same name in Windows",
							itr->get_relative_path()
						);
						skipped++;

						info.erase(itr);
					}

					continue;
				}

				occupied_lower_filenames.emplace(placeholder_name_lower);

				shell::filesystem::file_times file_times;
				file_times.set_last_write_time(entity.last_write_time());
				file_times.set_last_access_time(entity.last_access_time());

				std::uint32_t file_attributes;
				switch (entity.status().type()) {
				case std::filesystem::file_type::directory:
					file_attributes = FILE_ATTRIBUTE_DIRECTORY;
					break;
				case std::filesystem::file_type::regular:
					file_attributes = FILE_ATTRIBUTE_NORMAL;
					break;
				default:
					LOG_INFO(this->m_logger, "Skip '{}' due to unknown file type.", placeholder_name);
					skipped++;
					continue;
				}

				info.emplace_back(
					placeholder_name.wstring(),
					entity.file_size(),
					file_attributes,
					file_times
				);
			}

			request.set_value(std::move(info));
			
			LOG_INFO(this->m_logger, "{} placeholders will be created, and {} will be skipped.", info.size(), skipped);

			return models::requests::request_result::success;
		}
		catch (const ssh::ssh_libssh2_exception& e) {
			LOG_ERROR(
				this->m_logger,
				"Failed to enumerate directory entities in '{}'.",
				request.get_absolute_path()
			);
			request.set_exception(std::move(e));
			return models::requests::request_result::transient_failure;
		}
	}

	models::requests::request_result operation_executor::request_visitor::operator()(models::requests::local::attribute_request& request) {
		try {
			shell::filesystem::cloud_filter_placeholder placeholder(request.get_absolute_path().wstring());

			switch (request.get_domain()) {
			case models::requests::local::attribute_request::change_domain::mark_in_sync:
				placeholder.set_marked_in_sync(true);
				break;
			case models::requests::local::attribute_request::change_domain::unmark_in_sync:
				placeholder.set_marked_in_sync(false);
				break;
			case models::requests::local::attribute_request::change_domain::pin:
				placeholder.set_pin_state(::CF_PIN_STATE::CF_PIN_STATE_PINNED);
				break;
			case models::requests::local::attribute_request::change_domain::unpin:
				placeholder.set_pin_state(::CF_PIN_STATE::CF_PIN_STATE_UNPINNED);
				break;
			default:
				LOG_ERROR(this->m_logger, "Unsupported attribute change domain.");
				return models::requests::request_result::permanent_failure;
			}

			placeholder.flush();
			return models::requests::request_result::success;
		}
		catch (const shell::cloud_provider_system_error& e) {
			LOG_ERROR(
				this->m_logger,
				"Failed to update attribute for '{}': {} (Win32: {}({}))",
				request.get_absolute_path(),
				e.what(),
				e.code().message(),
				e.code().value()
			);
			return models::requests::request_result::transient_failure;
		}
	}

	models::requests::request_result operation_executor::request_visitor::operator()(models::requests::local::transform_request& request) {
		try {
			shell::filesystem::cloud_filter_placeholder::transform(
				request.get_absolute_path().wstring(),
				request.get_identity()
			);

			return models::requests::request_result::success;
		}
		catch (const shell::cloud_provider_system_error& e) {
			LOG_ERROR(
				this->m_logger,
				"Failed to transform the file '{}' into a placeholder: {} (Win32: {}({}))",
				request.get_absolute_path(),
				e.what(),
				e.code().message(),
				e.code().value()
			);
			return models::requests::request_result::transient_failure;
		}
	}

	models::requests::request_result operation_executor::request_visitor::operator()(models::requests::local::dehydration_request& request) {
		// dehydrate asynchronously
		return models::requests::request_result::success;
	}

	models::requests::request_result operation_executor::request_visitor::operator()(models::requests::local::hydration_triggering_request& request) {
		// request hydration asynchronously
		return models::requests::request_result::success;
	}
}