#ifndef LINUXPLORER_CALLBACK_OPERATION_INFO_HPP_
#define LINUXPLORER_CALLBACK_OPERATION_INFO_HPP_

#include <shell/shellfwd.hpp>

#include <shell/filesystem/placeholder_info.hpp>

#include <vector>
#include <span>

namespace linuxplorer::shell::functional {
	class operation_info {};

	class LINUXPLORER_SHELL_API fetch_data_operation_info : public operation_info {
	private:
		std::size_t m_offset;
		std::size_t m_length;
		std::vector<std::byte> m_buffer;
	public:
		using operation_info::operation_info;

		std::size_t get_offset() const noexcept;
		void set_offset(std::size_t offset) noexcept;

		std::size_t get_length() const noexcept;
		void set_length(std::size_t length) noexcept;

		std::span<const std::byte> get_buffer() const noexcept;
		void set_buffer(const std::vector<std::byte>& buffer) noexcept;
		void set_buffer(std::vector<std::byte>&& buffer) noexcept;
	};

	class LINUXPLORER_SHELL_API fetch_placeholders_operation_info : public operation_info {
		std::vector<filesystem::placeholder_creation_info> m_creation_info;
		std::size_t m_total_count_to_be_processed;
	public:
		using operation_info::operation_info;

		const std::vector<filesystem::placeholder_creation_info>& get_creation_info() const noexcept;
		std::size_t get_total_count_to_be_processed() const noexcept;
		void set_total_count_to_be_processed(std::size_t count) noexcept;
		std::size_t get_count_to_be_processed() const noexcept;
		void add_creation_info(const filesystem::placeholder_creation_info& info);
		void remove_creation_info_at(std::size_t i);
	};

	class LINUXPLORER_SHELL_API delete_operation_info : public operation_info {
		::NTSTATUS m_status;
	public:
		delete_operation_info();

		::NTSTATUS get_status() const noexcept;
		void set_status(::NTSTATUS status) noexcept;
	};
}

#endif // LINUXPLORER_CALLBACK_OPERATION_INFO_HPP_