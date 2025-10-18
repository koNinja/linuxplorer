#include <shell/filesystem/placeholder_info.hpp>

namespace linuxplorer::shell::filesystem {
	file_times::file_times(
		const std::filesystem::file_time_type& last_write_time,
		const std::filesystem::file_time_type& creation_time,
		const std::filesystem::file_time_type& last_access_time,
		const std::filesystem::file_time_type& change_time
	) : m_last_write_time(last_write_time), m_creation_time(creation_time), m_last_access_time(last_access_time), m_change_time(change_time) {}
		
	std::filesystem::file_time_type file_times::get_last_write_time() const noexcept {
		return this->m_last_write_time;
	}
	void file_times::set_last_write_time(const std::filesystem::file_time_type& time) noexcept {
		this->m_last_write_time = time;
	}

	std::filesystem::file_time_type file_times::get_creation_time() const noexcept {
		return this->m_creation_time;
	}
	void file_times::set_creation_time(const std::filesystem::file_time_type& time) noexcept {
		this->m_creation_time = time;
	}

	std::filesystem::file_time_type file_times::get_last_access_time() const noexcept {
		return this->m_last_access_time;
	}
	void file_times::set_last_access_time(const std::filesystem::file_time_type& time) noexcept {
		this->m_last_access_time = time;
	}

	std::filesystem::file_time_type file_times::get_change_time() const noexcept {
		return this->m_change_time;
	}
	void file_times::set_change_time(const std::filesystem::file_time_type& time) noexcept {
		this->m_change_time = time;
	}

	placeholder_creation_info::placeholder_creation_info(
		std::wstring_view relative_path,
		std::size_t file_size,
		std::uint32_t file_attributes
	) : m_relative_path(relative_path), m_file_size(file_size), m_file_attributes(file_attributes) {}

	placeholder_creation_info::placeholder_creation_info(
		std::wstring_view relative_path,
		std::size_t file_size,
		std::uint32_t file_attributes,
		const file_times& times
	) : m_relative_path(relative_path), m_file_size(file_size), m_file_attributes(file_attributes), m_file_times(times) {}

	std::wstring_view placeholder_creation_info::get_relative_path() const noexcept {
		return this->m_relative_path;
	}
	
	std::size_t placeholder_creation_info::get_file_size() const noexcept {
		return this->m_file_size;
	}

	std::uint32_t placeholder_creation_info::get_file_attributes() const noexcept {
		return this->m_file_attributes;
	}

	const file_times& placeholder_creation_info::get_file_times() const noexcept {
		return this->m_file_times;
	}
}