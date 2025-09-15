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

	std::size_t fetch_data_operation_info::get_offset() const noexcept {
		return this->m_offset;
	}
	void fetch_data_operation_info::set_offset(std::size_t offset) noexcept {
		this->m_offset = offset;
	}

	std::size_t fetch_data_operation_info::get_length() const noexcept {
		return this->m_length;
	}
	void fetch_data_operation_info::set_length(std::size_t length) noexcept {
		this->m_length = length;
	}

	std::span<const std::byte> fetch_data_operation_info::get_buffer() const noexcept {
		return std::span<const std::byte>(this->m_buffer);
	}
	void fetch_data_operation_info::set_buffer(const std::vector<std::byte>& buffer) noexcept {
		this->m_buffer = buffer;
	}

	void fetch_data_operation_info::set_buffer(std::vector<std::byte>&& buffer) noexcept {
		this->m_buffer = std::move(buffer);
	}

	const std::vector<filesystem::placeholder_creation_info>& fetch_placeholders_operation_info::get_creation_info() const noexcept {
		return this->m_creation_info;
	}

	std::size_t fetch_placeholders_operation_info::get_total_count_to_be_processed() const noexcept {
		return this->m_total_count_to_be_processed;
	}
	void fetch_placeholders_operation_info::set_total_count_to_be_processed(std::size_t count) noexcept {
		this->m_total_count_to_be_processed = count;
	}

	std::size_t fetch_placeholders_operation_info::get_count_to_be_processed() const noexcept {
		return this->m_creation_info.size();
	}

	void fetch_placeholders_operation_info::add_creation_info(const filesystem::placeholder_creation_info& info) {
		this->m_creation_info.push_back(info);
	}
	void fetch_placeholders_operation_info::remove_creation_info_at(std::size_t i) {
		if (i < this->m_creation_info.size()) {
			this->m_creation_info.erase(this->m_creation_info.begin() + i);
		}
	}
}