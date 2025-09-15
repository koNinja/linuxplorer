#ifndef LINUXPLORER_PLACEHOLDER_INFO_HPP_
#define LINUXPLORER_PLACEHOLDER_INFO_HPP_

#include <shell/shellfwd.hpp>

#include <windows.h>
#include <filesystem>

namespace linuxplorer::shell::filesystem {
	struct LINUXPLORER_SHELL_API file_times {
	private:
		std::filesystem::file_time_type m_last_write_time;
		std::filesystem::file_time_type m_creation_time;
		std::filesystem::file_time_type m_last_access_time;
		std::filesystem::file_time_type m_change_time;
	public:
		file_times() = default;

		file_times(
			const std::filesystem::file_time_type& last_write_time,
			const std::filesystem::file_time_type& creation_time,
			const std::filesystem::file_time_type& last_access_time,
			const std::filesystem::file_time_type& change_time
		);
		
		std::filesystem::file_time_type get_last_write_time() const noexcept;
		void set_last_write_time(const std::filesystem::file_time_type& time) noexcept;

		std::filesystem::file_time_type get_creation_time() const noexcept;
		void set_creation_time(const std::filesystem::file_time_type& time) noexcept;

		std::filesystem::file_time_type get_last_access_time() const noexcept;
		void set_last_access_time(const std::filesystem::file_time_type& time) noexcept;

		std::filesystem::file_time_type get_change_time() const noexcept;
		void set_change_time(const std::filesystem::file_time_type& time) noexcept;
	};

	class LINUXPLORER_SHELL_API placeholder_creation_info {
	private:
		std::wstring m_relative_path;
		std::size_t m_file_size;
		file_times m_file_times;
		std::uint32_t m_file_attributes;
	public:
		placeholder_creation_info(
			std::wstring_view relative_path,
			std::size_t file_size,
			std::uint32_t file_attributes = FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_ARCHIVE
		);

		placeholder_creation_info(
			std::wstring_view relative_path,
			std::size_t file_size,
			std::uint32_t file_attributes,
			const file_times& times
		);

		std::wstring_view get_relative_path() const noexcept;
		
		std::size_t get_file_size() const noexcept;

		std::uint32_t get_file_attributes() const noexcept;

		const file_times& get_file_times() const noexcept;
	};
}

#endif // LINUXPLORER_PLACEHOLDER_INFO_HPP_