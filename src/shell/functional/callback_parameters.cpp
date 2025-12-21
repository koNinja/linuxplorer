#include <shell/functional/callback_parameters.hpp>

namespace linuxplorer::shell::functional {
	callback_parameters::callback_parameters(const ::CF_CALLBACK_INFO* info, const ::CF_CALLBACK_PARAMETERS* parameters) : m_info_ptr(info), m_parameters_ptr(parameters) 
	{
		this->m_absolute_placeholder_path = std::wstring();
		
		this->m_absolute_placeholder_path.append(info->VolumeDosName);
		this->m_absolute_placeholder_path.append(info->NormalizedPath);
	}

	const ::CF_CALLBACK_INFO& callback_parameters::get_native_info() const noexcept {
		return *this->m_info_ptr;
	}

	const ::CF_CALLBACK_PARAMETERS& callback_parameters::get_native_parameters() const noexcept {
		return *this->m_parameters_ptr;
	}

	std::wstring_view callback_parameters::get_absolute_placeholder_path() const noexcept{
		return this->m_absolute_placeholder_path;
	}

	fetch_data_callback_parameters::fetch_data_callback_parameters(const ::CF_CALLBACK_INFO* info, const ::CF_CALLBACK_PARAMETERS* parameters) : callback_parameters(info, parameters), m_length(parameters->FetchData.RequiredLength.QuadPart), m_offset(parameters->FetchData.RequiredFileOffset.QuadPart)
	{}

	std::size_t fetch_data_callback_parameters::get_offset() const noexcept {
		return this->m_offset;
	}

	std::size_t fetch_data_callback_parameters::get_length() const noexcept {
		return this->m_length;
	}

	cancel_fetch_data_callback_parameters::cancel_fetch_data_callback_parameters(const ::CF_CALLBACK_INFO* info, const ::CF_CALLBACK_PARAMETERS* parameters) : callback_parameters(info, parameters), m_length(parameters->Cancel.FetchData.Length.QuadPart), m_offset(parameters->Cancel.FetchData.FileOffset.QuadPart)
	{}

	std::size_t cancel_fetch_data_callback_parameters::get_offset() const noexcept {
		return this->m_offset;
	}

	std::size_t cancel_fetch_data_callback_parameters::get_length() const noexcept {
		return this->m_length;
	}

	rename_callback_parameters::rename_callback_parameters(const ::CF_CALLBACK_INFO* info, const ::CF_CALLBACK_PARAMETERS* parameters) : callback_parameters(info, parameters)
	{
		if (parameters->Rename.TargetPath) this->m_absolute_new_path.append(info->VolumeDosName).append(parameters->Rename.TargetPath);
	}

	std::wstring_view rename_callback_parameters::get_absolute_new_path() const noexcept {
		return this->m_absolute_new_path;
	}

	rename_completion_callback_parameters::rename_completion_callback_parameters(const ::CF_CALLBACK_INFO* info, const ::CF_CALLBACK_PARAMETERS* parameters) : callback_parameters(info, parameters)
	{
		if (parameters->RenameCompletion.SourcePath) {
			this->m_absolute_old_path.append(info->VolumeDosName).append(parameters->RenameCompletion.SourcePath);
		}
	}

	std::wstring_view rename_completion_callback_parameters::get_absolute_old_path() const noexcept {
		return this->m_absolute_old_path;
	}

	delete_callback_parameters::delete_callback_parameters(const ::CF_CALLBACK_INFO* info, const ::CF_CALLBACK_PARAMETERS* parameters) : callback_parameters(info, parameters), 
		m_has_deleted(!(parameters->Delete.Flags & ::CF_CALLBACK_DELETE_FLAGS::CF_CALLBACK_DELETE_FLAG_IS_UNDELETE)),
		m_is_directory(parameters->Delete.Flags & ::CF_CALLBACK_DELETE_FLAGS::CF_CALLBACK_DELETE_FLAG_IS_DIRECTORY)
	{}

	bool delete_callback_parameters::has_deleted() const noexcept {
		return this->m_has_deleted;
	}

	bool delete_callback_parameters::is_directory() const noexcept {
		return this->m_is_directory;
	}
}