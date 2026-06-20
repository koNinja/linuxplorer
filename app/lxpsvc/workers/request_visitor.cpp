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
#include <quill/Backend.h>

#include <regex>
#include <unordered_set>

#include <atlbase.h>
#include <ShlObj_core.h>
#include <propvarutil.h>
#include <propkey.h>
#include <shlwapi.h>

#include "../win32/ntfs.hpp"
#include "../models/lru_cache.hpp"

namespace linuxplorer::lxpsvc::workers {
	static bool contains_invalid_ntfs_character(std::wstring_view path) {
		static std::wregex invalid_pattern(LR"([<>:"/\\|?*])");

		if (std::regex_search(path.cbegin(), path.cend(), invalid_pattern)) return true;

		static std::wregex invalid_end_pattern(LR"([ \.]$)");
		if (std::regex_search(path.cbegin(), path.cend(), invalid_end_pattern)) return true;

		static std::wregex reserved_pattern(LR"(^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$)", std::regex_constants::icase);
		if (std::regex_search(path.cbegin(), path.cend(), reserved_pattern)) return true;

		return false;
	}

	static ::HRESULT raise_warning_state(const std::filesystem::path& path, bool has_warning) {
		::HRESULT hr;

		::CComPtr<::IShellItem2> shell_item;
		{
			::IShellItem2* raw_shell_item;
			hr = ::SHCreateItemFromParsingName(path.c_str(), nullptr, IID_IShellItem2, reinterpret_cast<void**>(&raw_shell_item));
			shell_item = raw_shell_item;
			if (FAILED(hr)) return hr;
		}

		::CComPtr<::IPropertyStore> extrinstic_property_store;
		{
			::IPropertyStore* raw_extrinstic_property_store;
			hr = shell_item->GetPropertyStore(
				::GETPROPERTYSTOREFLAGS::GPS_READWRITE | ::GETPROPERTYSTOREFLAGS::GPS_EXTRINSICPROPERTIESONLY,
				IID_IPropertyStore,
				reinterpret_cast<void**>(&raw_extrinstic_property_store)
			);
			if (FAILED(hr)) return hr;

			extrinstic_property_store = raw_extrinstic_property_store;
		}

		::PROPVARIANT property_variant{};
		
		if (has_warning) {
			hr = ::InitPropVariantFromUInt32(static_cast<std::uint32_t>(E_FAIL), &property_variant);
			if (FAILED(hr)) return hr;
		}
		else {
			::PropVariantInit(&property_variant);
		}

		hr = extrinstic_property_store->SetValue(PKEY_LastSyncWarning, property_variant);
		if (FAILED(hr)) return hr;

		hr = extrinstic_property_store->Commit();
		if (FAILED(hr)) return hr;

		::SHChangeNotify(SHCNE_UPDATEITEM, SHCNF_PATH, static_cast<const void*>(path.c_str()), nullptr);

		return hr;
	}

	operation_executor::request_visitor::request_visitor(
		const ssh::sftp::sftp_session& sftp_session,
		const shell::cloud_provider_session& cloud_provider_session,
		std::list<win32::overlapped>& pending_hydrations,
		quill::Logger* logger
	) : m_logger(logger), m_cloud_provider_session(cloud_provider_session),
		m_sftp_session(sftp_session), m_path_helper(cloud_provider_session.get_sync_root_dir()),
		m_pending_hydrations(pending_hydrations)
	{}

	models::requests::request_result operation_executor::request_visitor::operator()(models::requests::remote::creation_request& request, std::stop_token token) {
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
		catch (const std::system_error& e) {
			LOG_ERROR(
				this->m_logger,
				"Failed to a system call: {} (Win32: {}({}))",
				e.what(),
				e.code().message(),
				e.code().value()
			);

			return models::requests::request_result::transient_failure;
		}
	}
	
	models::requests::request_result operation_executor::request_visitor::operator()(models::requests::remote::modification_request& request, std::stop_token token) {
		const auto& server_path = request.get_absolute_path();
		auto absolute_client_path = this->m_path_helper.to_win_style(helpers::style_conversion_class::absolute_format, server_path);

		try {
			std::ios_base::openmode ostream_open_mode = std::ios_base::out;

			switch (request.get_type()) {
			case models::requests::remote::modification_type::appended:
				ostream_open_mode |= std::ios_base::app;
				break;
			case models::requests::remote::modification_type::truncated:
				ostream_open_mode |= std::ios_base::trunc;
				break;
			case models::requests::remote::modification_type::overwritten:
			{
				auto client_file_size = std::filesystem::file_size(absolute_client_path);
				auto server_file_size = ssh::sftp::filesystem::file_size(this->m_sftp_session, server_path);
				if (client_file_size < server_file_size) ostream_open_mode |= std::ios_base::trunc;
				break;
			}
			default:
				break;
			};

			std::ifstream ifs(absolute_client_path, std::ios::binary);
			if (!ifs) {
				LOG_ERROR(
					this->m_logger,
					"Failed to open the file '{}' for reading.",
					absolute_client_path
				);

				return models::requests::request_result::transient_failure;
			}

			auto& remote_stream_cache = this->m_stream_cache.remote_ostream();
			auto frn = win32::get_frn(absolute_client_path);
			if (!remote_stream_cache.contains(frn) || remote_stream_cache.get(frn)->mode() != ostream_open_mode) {
				ssh::sftp::io::osftpstream oss(this->m_sftp_session, server_path, ostream_open_mode);
				if (!oss) {
					LOG_ERROR(
						this->m_logger,
						"Failed to open the file '{}' for reading.",
						server_path
					);
					
					return models::requests::request_result::transient_failure;
				}

				remote_stream_cache.put(frn, std::move(oss));
			}

			auto& oss = *remote_stream_cache.get(frn);

			if (ifs.tellg() != request.get_range().get_offset()) {
				ifs.seekg(request.get_range().get_offset());
			}
			if (oss.tellp() != request.get_range().get_offset()) {
				oss.seekp(request.get_range().get_offset());
			}

			std::vector<std::byte> buffer(request.get_range().get_length());
			ifs.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
			oss.write(reinterpret_cast<char*>(buffer.data()), buffer.size());

			oss.flush();

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
		catch (const std::system_error& e) {
			LOG_ERROR(
				this->m_logger,
				"Failed to a system call: {} (Win32: {}({}))",
				e.what(),
				e.code().message(),
				e.code().value()
			);

			return models::requests::request_result::transient_failure;
		}
	}

	models::requests::request_result operation_executor::request_visitor::operator()(models::requests::remote::deletion_request& request, std::stop_token token) {
		try {
			auto absolute_client_path = this->m_path_helper.to_win_style(helpers::style_conversion_class::absolute_format, request.get_absolute_path());
			auto frn = win32::get_frn(absolute_client_path);
			this->m_stream_cache.remote_istream().try_erase(frn);
			this->m_stream_cache.remote_ostream().try_erase(frn);

			if (ssh::sftp::filesystem::exists(this->m_sftp_session, request.get_absolute_path())) {
				ssh::sftp::filesystem::remove_all(this->m_sftp_session, request.get_absolute_path());
				LOG_INFO(
					this->m_logger,
					"The file or directory '{}' has been successfully removed from the server.",
					request.get_absolute_path()
				);
			}

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
			
			request.set_exception(e);
			return models::requests::request_result::transient_failure;
		}
	}

	models::requests::request_result operation_executor::request_visitor::operator()(models::requests::remote::renaming_request& request, std::stop_token token) {
		const auto& old_server_path = request.get_absolute_path();
		const auto& new_server_path = request.get_absolute_new_path();
		auto absolute_old_client_path = this->m_path_helper.to_win_style(helpers::style_conversion_class::absolute_format, old_server_path);
		auto absolute_new_client_path = this->m_path_helper.to_win_style(helpers::style_conversion_class::absolute_format, new_server_path);

		auto frn = win32::get_frn(absolute_old_client_path);
		this->m_stream_cache.remote_istream().try_erase(frn);
		this->m_stream_cache.remote_ostream().try_erase(frn);

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

			request.set_exception(e);
			return models::requests::request_result::transient_failure;
		}
	}

	models::requests::request_result operation_executor::request_visitor::operator()(models::requests::remote::hydration_request& request, std::stop_token token) {
		const auto& server_path = request.get_absolute_path();
		auto absolute_client_path = this->m_path_helper.to_win_style(helpers::style_conversion_class::absolute_format, server_path);

		try {
			auto& remote_stream_cache = this->m_stream_cache.remote_istream();
			
			auto frn = win32::get_frn(absolute_client_path);
			if (!remote_stream_cache.contains(frn)) {
				ssh::sftp::io::isftpstream iss(this->m_sftp_session, server_path, std::ios_base::in);
				if (!iss) {
					LOG_ERROR(
						this->m_logger,
						"Failed to open the file '{}' for reading.",
						server_path
					);
					
					return models::requests::request_result::transient_failure;
				}

				remote_stream_cache.put(frn, std::move(iss));
			}

			auto& iss = *remote_stream_cache.get(frn);
			
			if (iss.tellg() != request.get_range().get_offset()) {
				iss.seekg(request.get_range().get_offset());
			}
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
			request.set_exception(e);
			return models::requests::request_result::transient_failure;
		}
	}

	models::requests::request_result operation_executor::request_visitor::operator()(models::requests::remote::population_request& request, std::stop_token token) {
		auto absolute_client_path = this->m_path_helper.to_win_style(helpers::style_conversion_class::absolute_format, request.get_absolute_path()).lexically_normal();

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

		try {
			std::unordered_set<std::filesystem::path> existent_files_in_server_lower;
			auto frn = win32::get_frn(absolute_client_path);
			int	skipped = 0;

			for (const auto& entity : ssh::sftp::filesystem::directory_iterator(this->m_sftp_session, request.get_absolute_path())) {
				if (token.stop_requested()) {
					request.set_exception(shell::functional::callback_abort_exception(ERROR_CLOUD_FILE_REQUEST_CANCELED));
					LOG_INFO(this->m_logger, "The cancellation for this placeholder enumeration has been accepted.");
					return models::requests::request_result::cancelled;
				}

				auto absolute_placeholder_path = this->m_path_helper.to_win_style(helpers::style_conversion_class::absolute_format, entity.path());
				auto placeholder_name = absolute_placeholder_path.filename();

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
					LOG_INFO(this->m_logger, "Skip '{}' due to not supported file type.", placeholder_name);
					skipped++;
					continue;
				}

				shell::filesystem::placeholder_creation_info metadata(
					placeholder_name,
					entity.file_size(),
					file_attributes,
					file_times
				);
				metadata.set_identity({ std::byte(0) });

				std::filesystem::path placeholder_name_lower = tolower_sys_localized(placeholder_name.wstring());
				if (existent_files_in_server_lower.contains(placeholder_name_lower)) {
					LOG_WARNING(
						this->m_logger,
						"Skip '{}' because there are files that are considered to have the same name in Windows.",
						placeholder_name
					);
					skipped++;

					auto itr = std::find_if(info.begin(), info.end(), [&compare, &placeholder_name_lower](const shell::filesystem::placeholder_creation_info& info) {
						return compare(info.get_relative_path().wstring(), placeholder_name_lower.wstring()) == 0;
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
				existent_files_in_server_lower.emplace(placeholder_name_lower);

				if (::PathFileExistsW(absolute_placeholder_path.c_str())) {
					this->m_population_cache.push_existent_file_metadata(frn, std::move(metadata));
					skipped++;
					continue;
				}
				
				if (contains_invalid_ntfs_character(placeholder_name.wstring())) {
					LOG_INFO(this->m_logger, "Skip '{}' because its name contains invalid characters in NTFS.", placeholder_name);
					skipped++;
					continue;
				}

				info.push_back(std::move(metadata));
			}

			LOG_INFO(this->m_logger, "{} placeholders will be created, and {} will be skipped.", std::min<std::size_t>(info.size() - skipped, 0), skipped);

			request.set_value(std::move(info));
			this->m_population_cache.set_existent_file_set(frn, std::move(existent_files_in_server_lower));

			return models::requests::request_result::success;
		}
		catch (const ssh::ssh_libssh2_exception& e) {
			LOG_ERROR(
				this->m_logger,
				"Failed to enumerate directory entities in '{}'.",
				request.get_absolute_path()
			);
			request.set_exception(e);
			return models::requests::request_result::transient_failure;
		}
		catch (const std::system_error& e) {
			LOG_ERROR(
				this->m_logger,
				"Failed to acquire the FRN of '{}': {} (Win32: {}({}))",
				request.get_absolute_path(),
				e.what(),
				e.code().message(),
				e.code().value()
			);
			return models::requests::request_result::transient_failure;
		}
	}

	models::requests::request_result operation_executor::request_visitor::operator()(models::requests::local::attribute_request& request, std::stop_token token) {
		try {
			shell::filesystem::cloud_filter_placeholder placeholder(request.get_absolute_path());

			switch (request.get_domain()) {
			case models::requests::local::attribute_request::change_domain::mark_in_sync:
				placeholder.set_marked_in_sync(true);
				placeholder.flush();
				LOG_INFO(this->m_logger, "The file '{}' has been successfully marked in sync.", request.get_absolute_path());
				break;
			case models::requests::local::attribute_request::change_domain::unmark_in_sync:
				placeholder.set_marked_in_sync(false);
				placeholder.flush();
				LOG_INFO(this->m_logger, "The file '{}' has been successfully unmarked from sync.", request.get_absolute_path());
				break;
			case models::requests::local::attribute_request::change_domain::pin:
				placeholder.set_pin_state(shell::filesystem::placeholder_pin_state::pinned);
				placeholder.flush();
				LOG_INFO(this->m_logger, "The file '{}' has been successfully pinned.", request.get_absolute_path());
				break;
			case models::requests::local::attribute_request::change_domain::unpin:
				placeholder.set_pin_state(shell::filesystem::placeholder_pin_state::unpinned);
				placeholder.flush();
				LOG_INFO(this->m_logger, "The file '{}' has been successfully unpinned.", request.get_absolute_path());
				break;
			case models::requests::local::attribute_request::change_domain::enable_placeholder_enumeration:
			{
				shell::filesystem::directory_placeholder dir_placeholder(std::move(placeholder));
				dir_placeholder.set_enumeration_enabled(true);
				dir_placeholder.flush();
				LOG_INFO(this->m_logger, "Placeholder enumeration in the directory '{}' has been successfully enabled.", request.get_absolute_path());
				break;
			}
			default:
				LOG_ERROR(this->m_logger, "Unsupported attribute change domain.");
				return models::requests::request_result::permanent_failure;
			}

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

	models::requests::request_result operation_executor::request_visitor::operator()(models::requests::local::transform_request& request, std::stop_token token) {
		try {
			shell::filesystem::cloud_filter_placeholder::transform(
				request.get_absolute_path(),
				request.get_identity()
			);

			LOG_INFO(this->m_logger, "The file '{}' has been successfully transformed into a placeholder.", request.get_absolute_path());

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

	models::requests::request_result operation_executor::request_visitor::operator()(models::requests::local::dehydration_request& request, std::stop_token token) {
		try {
			shell::filesystem::file_placeholder placeholder(request.get_absolute_path());
			placeholder.dehydrate_unsafe();

			LOG_INFO(this->m_logger, "The file '{}' has been successfully dehydrated.", request.get_absolute_path());

			return models::requests::request_result::success;
		}
		catch (const shell::cloud_provider_system_error& e) {
			LOG_ERROR(
				this->m_logger,
				"Failed to dehydrate the file '{}': {} (Win32: {}({}))",
				request.get_absolute_path(),
				e.what(),
				e.code().message(),
				e.code().value()
			);
			return models::requests::request_result::transient_failure;
		}
	}

	models::requests::request_result operation_executor::request_visitor::operator()(models::requests::local::hydration_triggering_request& request, std::stop_token token) {
		win32::unique_file_handle file = ::CreateFileW(
			request.get_absolute_path().c_str(),
			FILE_READ_ATTRIBUTES,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			nullptr,
			OPEN_ALWAYS,
			FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
			nullptr
		);
		if (!file) {
			std::error_code ec(::GetLastError(), std::system_category());
			LOG_ERROR(
				this->m_logger,
				"Failed to open the file '{}'. (Win32: {}({}))",
				request.get_absolute_path(),
				ec.message(),
				ec.value()
			);
			return models::requests::request_result::transient_failure;
		}

		auto& overlapped = this->m_pending_hydrations.emplace_back(std::move(file));
		
		::HRESULT hr = ::CfHydratePlaceholder(
			overlapped.acquire_file_handle().get(),
			::LARGE_INTEGER { .QuadPart = 0 },
			::LARGE_INTEGER { .QuadPart = CF_EOF },
			::CF_HYDRATE_FLAGS::CF_HYDRATE_FLAG_NONE,
			overlapped.ptr()
		);
		if (FAILED(hr) && hr != HRESULT_FROM_WIN32(ERROR_IO_PENDING)) {
			std::error_code ec(hr, std::system_category());
			LOG_ERROR(
				this->m_logger,
				"Failed to request hydration of the file '{}'. (Win32: {}({}))",
				request.get_absolute_path(),
				ec.message(),
				ec.value()
			);
			return models::requests::request_result::transient_failure;
		}

		return models::requests::request_result::success;
	}
}