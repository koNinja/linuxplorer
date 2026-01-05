#define WIN32_NO_STATUS
#include <shell/functional/cloud_provider_callback.hpp>
#include <unordered_map>
#undef WIN32_NO_STATUS
#include <ntstatus.h>

namespace linuxplorer::shell::functional {
	template <>
	void specialized_cloud_provider_callback<cloud_provider_callback_type::fetch_data>::internal_nt_callback(
		const ::CF_CALLBACK_INFO* info,
		const ::CF_CALLBACK_PARAMETERS* parameters
	) const {
		::CF_OPERATION_INFO operation_info;
		::ZeroMemory(&operation_info, sizeof(::CF_OPERATION_INFO));
		operation_info.StructSize = sizeof(::CF_OPERATION_INFO);
		operation_info.ConnectionKey = info->ConnectionKey;
		operation_info.TransferKey = info->TransferKey;
		operation_info.Type = ::CF_OPERATION_TYPE::CF_OPERATION_TYPE_TRANSFER_DATA;
		operation_info.CorrelationVector = info->CorrelationVector;
		operation_info.RequestKey = info->RequestKey;
		operation_info.SyncStatus = nullptr;

		::CF_OPERATION_PARAMETERS operation_parameters;
		::ZeroMemory(&operation_parameters, sizeof(::CF_OPERATION_PARAMETERS));
		operation_parameters.ParamSize = FIELD_OFFSET(::CF_OPERATION_PARAMETERS, TransferData) + sizeof(::CF_OPERATION_PARAMETERS::TransferData);
		operation_parameters.TransferData.Flags = ::CF_OPERATION_TRANSFER_DATA_FLAGS::CF_OPERATION_TRANSFER_DATA_FLAG_NONE;

		try {
			std::size_t bytes_transferred = 0;

			// The parameter object may have already been discarded if the function is called late.
			// Thus the object must be binded by some variable.
			auto coroutine_parameters = fetch_data_callback_parameters(info, parameters);
			for (const auto& result : this->m_callback(coroutine_parameters)) {
				operation_parameters.TransferData.CompletionStatus = STATUS_SUCCESS;
				operation_parameters.TransferData.Offset.QuadPart = result.get_offset();
				operation_parameters.TransferData.Length.QuadPart = result.get_length();
				operation_parameters.TransferData.Buffer = result.get_buffer().data();

				::HRESULT hr = ::CfExecute(&operation_info, &operation_parameters);
				if (SUCCEEDED(hr)) {
					bytes_transferred += result.get_length();
				}

				::LARGE_INTEGER transferred;
				transferred.QuadPart = bytes_transferred;
				::CfReportProviderProgress(info->ConnectionKey, info->TransferKey, parameters->FetchData.RequiredLength, transferred);
			}
		}
		catch (const shell::functional::callback_abort_exception& e) {
			operation_parameters.TransferData.CompletionStatus = e.code();
			operation_parameters.TransferData.Length.QuadPart = 1;
			operation_parameters.TransferData.Offset.QuadPart = 0;
			char dummy_buffer;
			operation_parameters.TransferData.Buffer = &dummy_buffer;
			::CfExecute(&operation_info, &operation_parameters);
		}
		catch (...) {
			operation_parameters.TransferData.CompletionStatus = STATUS_UNSUCCESSFUL;
			operation_parameters.TransferData.Length.QuadPart = 1;
			operation_parameters.TransferData.Offset.QuadPart = 0;
			char dummy_buffer;
			operation_parameters.TransferData.Buffer = &dummy_buffer;
			::CfExecute(&operation_info, &operation_parameters);
		}
	}

	template <>
	void specialized_cloud_provider_callback<cloud_provider_callback_type::fetch_placeholders>::internal_nt_callback(
		const ::CF_CALLBACK_INFO* info,
		const ::CF_CALLBACK_PARAMETERS* parameters
	) const {
		static std::unordered_map<std::int64_t, std::size_t> s_sum_of_processed_count;
		auto file_id = info->FileId.QuadPart;
		auto itr = s_sum_of_processed_count.find(file_id);

		::CF_OPERATION_INFO operation_info;
		::ZeroMemory(&operation_info, sizeof(::CF_OPERATION_INFO));
		operation_info.StructSize = sizeof(::CF_OPERATION_INFO);
		operation_info.ConnectionKey = info->ConnectionKey;
		operation_info.TransferKey = info->TransferKey;
		operation_info.Type = ::CF_OPERATION_TYPE::CF_OPERATION_TYPE_TRANSFER_PLACEHOLDERS;
		operation_info.CorrelationVector = info->CorrelationVector;
		operation_info.RequestKey = info->RequestKey;
		operation_info.SyncStatus = nullptr;

		::CF_OPERATION_PARAMETERS operation_parameters;
		::ZeroMemory(&operation_parameters, sizeof(::CF_OPERATION_PARAMETERS));
		operation_parameters.ParamSize = FIELD_OFFSET(::CF_OPERATION_PARAMETERS, TransferPlaceholders) + sizeof(::CF_OPERATION_PARAMETERS::TransferPlaceholders);
		
		try {
			auto result = this->m_callback(callback_parameters(info, parameters));
			operation_parameters.TransferPlaceholders.CompletionStatus = STATUS_SUCCESS;
			size_t placeholder_count = result.get_count_to_be_processed();
			operation_parameters.TransferPlaceholders.PlaceholderCount = placeholder_count;
			operation_parameters.TransferPlaceholders.PlaceholderTotalCount.QuadPart = result.get_total_count_to_be_processed();

			auto nt_placeholder_creation_info = placeholder_count > 0 ? std::make_unique<::CF_PLACEHOLDER_CREATE_INFO[]>(placeholder_count) : nullptr;
			for (std::size_t i = 0; i < placeholder_count; i++) {
				nt_placeholder_creation_info[i].Flags = ::CF_PLACEHOLDER_CREATE_FLAGS::CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC;
				nt_placeholder_creation_info[i].RelativeFileName = result.get_creation_info()[i].get_relative_path().data();
				nt_placeholder_creation_info[i].FileIdentity = result.get_creation_info()[i].get_identity().data();
				nt_placeholder_creation_info[i].FileIdentityLength = result.get_creation_info()[i].get_identity().size() * sizeof(std::byte);

				::ZeroMemory(&nt_placeholder_creation_info[i].FsMetadata, sizeof(::CF_FS_METADATA));
				nt_placeholder_creation_info[i].FsMetadata.FileSize.QuadPart = result.get_creation_info()[i].get_file_size();
				if (result.get_creation_info()[i].get_file_attributes() & FILE_ATTRIBUTE_DIRECTORY)
					nt_placeholder_creation_info[i].FsMetadata.FileSize.QuadPart = 0;
				nt_placeholder_creation_info[i].FsMetadata.BasicInfo.FileAttributes = result.get_creation_info()[i].get_file_attributes();
				
				// The epoch time in MSVC STD's std::filesystem::file_time_type and Windows FILETIME are the same.
				auto file_times = result.get_creation_info()[i].get_file_times();
				nt_placeholder_creation_info[i].FsMetadata.BasicInfo.CreationTime.QuadPart = file_times.get_creation_time().time_since_epoch().count();
				nt_placeholder_creation_info[i].FsMetadata.BasicInfo.LastAccessTime.QuadPart = file_times.get_last_access_time().time_since_epoch().count();
				nt_placeholder_creation_info[i].FsMetadata.BasicInfo.LastWriteTime.QuadPart = file_times.get_last_write_time().time_since_epoch().count();
				nt_placeholder_creation_info[i].FsMetadata.BasicInfo.ChangeTime.QuadPart = file_times.get_change_time().time_since_epoch().count();
			}
			operation_parameters.TransferPlaceholders.PlaceholderArray = nt_placeholder_creation_info.get();

			std::size_t sum_of_processed_count = itr != s_sum_of_processed_count.end() ? itr->second : 0;
			bool need_to_memorize_sum;
			if (operation_parameters.TransferPlaceholders.PlaceholderTotalCount.QuadPart <= placeholder_count + sum_of_processed_count)
			{
				operation_parameters.TransferPlaceholders.Flags = ::CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAGS::CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAG_DISABLE_ON_DEMAND_POPULATION;
				if (itr != s_sum_of_processed_count.end()) {
					s_sum_of_processed_count.erase(itr);
				}

				need_to_memorize_sum = false;
			}
			else {
				operation_parameters.TransferPlaceholders.Flags = ::CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAGS::CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAG_NONE;
				need_to_memorize_sum = true;
			}

			::CfExecute(&operation_info, &operation_parameters);
			if (need_to_memorize_sum) {
				s_sum_of_processed_count[file_id] = sum_of_processed_count + operation_parameters.TransferPlaceholders.EntriesProcessed;
			}
		}
		catch (const callback_abort_exception& e) {
			if (itr != s_sum_of_processed_count.end()) {
				s_sum_of_processed_count.erase(itr);
			}
			operation_parameters.TransferPlaceholders.CompletionStatus = e.code();
			::CfExecute(&operation_info, &operation_parameters);
		}
		catch (...) {
			operation_parameters.TransferPlaceholders.CompletionStatus = STATUS_UNSUCCESSFUL;
			operation_parameters.TransferPlaceholders.Flags = CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAG_NONE;
			operation_parameters.TransferPlaceholders.PlaceholderCount = 0;
			operation_parameters.TransferPlaceholders.PlaceholderTotalCount.QuadPart = 0;
			operation_parameters.TransferPlaceholders.PlaceholderArray = nullptr;
			::CfExecute(&operation_info, &operation_parameters);
		}
	}

	template <>
	void specialized_cloud_provider_callback<cloud_provider_callback_type::cancel_fetching_data>::internal_nt_callback(
		const ::CF_CALLBACK_INFO* info,
		const ::CF_CALLBACK_PARAMETERS* parameters
	) const {
		try {
			this->m_callback(cancel_fetch_data_callback_parameters(info, parameters));
		}
		// ignore all
		catch (...) {}
	}

	template <>
	void specialized_cloud_provider_callback<cloud_provider_callback_type::notify_renaming>::internal_nt_callback(
		const ::CF_CALLBACK_INFO* info,
		const ::CF_CALLBACK_PARAMETERS* parameters
	) const {
		::CF_OPERATION_INFO operation_info;
		::ZeroMemory(&operation_info, sizeof(::CF_OPERATION_INFO));
		operation_info.StructSize = sizeof(::CF_OPERATION_INFO);
		operation_info.ConnectionKey = info->ConnectionKey;
		operation_info.TransferKey = info->TransferKey;
		operation_info.Type = ::CF_OPERATION_TYPE::CF_OPERATION_TYPE_ACK_RENAME;
		operation_info.CorrelationVector = info->CorrelationVector;
		operation_info.RequestKey = info->RequestKey;
		operation_info.SyncStatus = nullptr;

		::CF_OPERATION_PARAMETERS operation_parameters;
		::ZeroMemory(&operation_parameters, sizeof(::CF_OPERATION_PARAMETERS));
		operation_parameters.ParamSize = FIELD_OFFSET(::CF_OPERATION_PARAMETERS, AckRename) + sizeof(::CF_OPERATION_PARAMETERS::AckRename);
		operation_parameters.AckRename.Flags = ::CF_OPERATION_ACK_RENAME_FLAGS::CF_OPERATION_ACK_RENAME_FLAG_NONE;

		try {
			this->m_callback(rename_callback_parameters(info, parameters));
			operation_parameters.AckRename.CompletionStatus = STATUS_SUCCESS;
		}
		catch (const callback_abort_exception& e) {
			operation_parameters.AckRename.CompletionStatus = e.code();
		}
		catch (...) {
			operation_parameters.AckRename.CompletionStatus = STATUS_UNSUCCESSFUL;
		}

		::CfExecute(&operation_info, &operation_parameters);
	}

	template <>
	void specialized_cloud_provider_callback<cloud_provider_callback_type::notify_renaming_completion>::internal_nt_callback(
		const ::CF_CALLBACK_INFO* info,
		const ::CF_CALLBACK_PARAMETERS* parameters
	) const {
		try {
			this->m_callback(rename_completion_callback_parameters(info, parameters));
		}
		// ignore all
		catch (...) {}
	}

	template <>
	void specialized_cloud_provider_callback<cloud_provider_callback_type::notify_deletion>::internal_nt_callback(
		const ::CF_CALLBACK_INFO* info,
		const ::CF_CALLBACK_PARAMETERS* parameters
	) const {
		::CF_OPERATION_INFO operation_info;
		::ZeroMemory(&operation_info, sizeof(::CF_OPERATION_INFO));
		operation_info.StructSize = sizeof(::CF_OPERATION_INFO);
		operation_info.ConnectionKey = info->ConnectionKey;
		operation_info.TransferKey = info->TransferKey;
		operation_info.Type = ::CF_OPERATION_TYPE::CF_OPERATION_TYPE_ACK_DELETE;
		operation_info.CorrelationVector = info->CorrelationVector;
		operation_info.RequestKey = info->RequestKey;
		operation_info.SyncStatus = nullptr;

		::CF_OPERATION_PARAMETERS operation_parameters;
		::ZeroMemory(&operation_parameters, sizeof(::CF_OPERATION_PARAMETERS));
		operation_parameters.ParamSize = FIELD_OFFSET(::CF_OPERATION_PARAMETERS, AckDelete) + sizeof(::CF_OPERATION_PARAMETERS::AckDelete);
		operation_parameters.AckDelete.Flags = ::CF_OPERATION_ACK_DELETE_FLAGS::CF_OPERATION_ACK_DELETE_FLAG_NONE;
		try {
			auto result = this->m_callback(delete_callback_parameters(info, parameters));
			operation_parameters.AckDelete.CompletionStatus = result.get_status();
		}
		catch (const callback_abort_exception& e) {
			operation_parameters.AckDelete.CompletionStatus = e.code();
		}
		catch (...) {
			operation_parameters.AckDelete.CompletionStatus = STATUS_UNSUCCESSFUL;
		}

		::CfExecute(&operation_info, &operation_parameters);
	}

	template <>
	void specialized_cloud_provider_callback<cloud_provider_callback_type::notify_deletion_completion>::internal_nt_callback(
		const ::CF_CALLBACK_INFO* info,
		const ::CF_CALLBACK_PARAMETERS* parameters
	) const {
		try {
			this->m_callback(rename_completion_callback_parameters(info, parameters));
		}
		// ignore all
		catch (...) {}
	}

	template class LINUXPLORER_SHELL_API specialized_cloud_provider_callback<cloud_provider_callback_type::fetch_data>;
    template class LINUXPLORER_SHELL_API specialized_cloud_provider_callback<cloud_provider_callback_type::fetch_placeholders>;
	template class LINUXPLORER_SHELL_API specialized_cloud_provider_callback<cloud_provider_callback_type::cancel_fetching_data>;
	template class LINUXPLORER_SHELL_API specialized_cloud_provider_callback<cloud_provider_callback_type::notify_renaming>;
	template class LINUXPLORER_SHELL_API specialized_cloud_provider_callback<cloud_provider_callback_type::notify_renaming_completion>;
	template class LINUXPLORER_SHELL_API specialized_cloud_provider_callback<cloud_provider_callback_type::notify_deletion>;
	template class LINUXPLORER_SHELL_API specialized_cloud_provider_callback<cloud_provider_callback_type::notify_deletion_completion>;
}