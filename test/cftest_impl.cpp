#include "cftest_impl.h"

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
		operation_parameters.ParamSize = FIELD_OFFSET(::CF_OPERATION_PARAMETERS, TransferData) + sizeof(((CF_OPERATION_PARAMETERS*)0)->TransferData);
		operation_parameters.TransferData.Offset.QuadPart = 0;
		operation_parameters.TransferData.Flags = ::CF_OPERATION_TRANSFER_DATA_FLAGS::CF_OPERATION_TRANSFER_DATA_FLAG_NONE;
		operation_parameters.TransferData.CompletionStatus = 0;
		operation_parameters.TransferData.Buffer = cftest::dummy_data;
		operation_parameters.TransferData.Length.QuadPart = sizeof(cftest::dummy_data);
	
		::CfExecute(&operation_info, &operation_parameters);
	}
} // namespace cftest