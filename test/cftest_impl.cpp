#include "cftest_impl.h"

#include <string>

namespace cftest {
	void on_fetch_data(const ::CF_CALLBACK_INFO *callback_info, const ::CF_CALLBACK_PARAMETERS *parameters) {
		::CF_OPERATION_INFO operation_info;
		operation_info.StructSize = sizeof(::CF_OPERATION_INFO);
		operation_info.Type = ::CF_OPERATION_TYPE::CF_OPERATION_TYPE_TRANSFER_DATA;
		operation_info.ConnectionKey = callback_info->ConnectionKey;
		operation_info.TransferKey = callback_info->TransferKey;
		operation_info.CorrelationVector = callback_info->CorrelationVector;
		operation_info.SyncStatus = nullptr;
		operation_info.RequestKey = callback_info->RequestKey;
	
		::CF_OPERATION_PARAMETERS operation_parameters;
		operation_parameters.ParamSize = FIELD_OFFSET(::CF_OPERATION_PARAMETERS, TransferData) + sizeof((reinterpret_cast<CF_OPERATION_PARAMETERS*>(0))->TransferData);
		operation_parameters.TransferData.Offset.QuadPart = 0;
		operation_parameters.TransferData.Flags = ::CF_OPERATION_TRANSFER_DATA_FLAGS::CF_OPERATION_TRANSFER_DATA_FLAG_NONE;
		operation_parameters.TransferData.CompletionStatus = 0;
		operation_parameters.TransferData.Buffer = cftest::dummy_data;
		operation_parameters.TransferData.Length.QuadPart = sizeof(cftest::dummy_data);
	
		::CfExecute(&operation_info, &operation_parameters);
	}

	
	void on_fetch_placeholders(const ::CF_CALLBACK_INFO *callback_info, const ::CF_CALLBACK_PARAMETERS *parameters) {
		::CF_OPERATION_INFO operation_info;
		ZeroMemory(&operation_info, sizeof(::CF_OPERATION_INFO));
		operation_info.StructSize = sizeof(::CF_OPERATION_INFO);
		operation_info.Type = ::CF_OPERATION_TYPE::CF_OPERATION_TYPE_TRANSFER_PLACEHOLDERS;
		operation_info.ConnectionKey = callback_info->ConnectionKey;
		operation_info.TransferKey = callback_info->TransferKey;
		operation_info.CorrelationVector = callback_info->CorrelationVector;
		operation_info.SyncStatus = nullptr;
		operation_info.RequestKey = callback_info->RequestKey;

		::CF_FS_METADATA metadata;
		ZeroMemory(&metadata, sizeof(::CF_FS_METADATA));
		metadata.BasicInfo.FileAttributes = FILE_ATTRIBUTE_DIRECTORY;
		metadata.FileSize.QuadPart = 0;
		//metadata.FileSize.QuadPart = sizeof(cftest::dummy_data);

		std::wstring relative_path = L"sample.txt";
		std::wstring filename = relative_path.substr(relative_path.find_last_of(L'\\') + 1);
		
		::CF_OPERATION_PARAMETERS operation_parameters;
		ZeroMemory(&operation_parameters, sizeof(::CF_OPERATION_PARAMETERS));
		operation_parameters.ParamSize = FIELD_OFFSET(::CF_OPERATION_PARAMETERS, TransferPlaceholders) + sizeof(CF_OPERATION_PARAMETERS::TransferPlaceholders);
		operation_parameters.TransferPlaceholders.Flags = ::CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAGS::CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAG_DISABLE_ON_DEMAND_POPULATION;
		operation_parameters.TransferPlaceholders.PlaceholderCount = 1;
		operation_parameters.TransferPlaceholders.PlaceholderTotalCount.QuadPart = 1;

		auto placeholders = static_cast<::CF_PLACEHOLDER_CREATE_INFO*>(::LocalAlloc(LPTR, sizeof(::CF_PLACEHOLDER_CREATE_INFO) * operation_parameters.TransferPlaceholders.PlaceholderCount));
		placeholders[0].Flags = ::CF_PLACEHOLDER_CREATE_FLAGS::CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC;
		placeholders[0].FsMetadata = metadata;
		placeholders[0].RelativeFileName = filename.c_str();
		placeholders[0].FileIdentity = relative_path.c_str();
		placeholders[0].FileIdentityLength = (relative_path.size() + 1) * sizeof(wchar_t);
		operation_parameters.TransferPlaceholders.PlaceholderArray = placeholders;

		::CfExecute(&operation_info, &operation_parameters);
	}
} // namespace cftest