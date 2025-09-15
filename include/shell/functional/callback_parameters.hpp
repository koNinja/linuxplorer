#ifndef LINUXPLORER_CALLBACK_PARAMETERS_HPP_
#define LINUXPLORER_CALLBACK_PARAMETERS_HPP_

#include <shell/shellfwd.hpp>
#include <shell/filesystem/placeholder_info.hpp>
#include <shell/models/chunked_callback_generator.hpp>

#include <windows.h>
#include <cfapi.h>

#include <vector>
#include <span>

namespace linuxplorer::shell::functional {
	class LINUXPLORER_SHELL_API callback_parameters {
	private:
		const ::CF_CALLBACK_INFO* m_info_ptr;
		const ::CF_CALLBACK_PARAMETERS* m_parameters_ptr;

		std::wstring m_absolute_placeholder_path;
	public:
		callback_parameters(const ::CF_CALLBACK_INFO* info, const ::CF_CALLBACK_PARAMETERS* parameters);
		callback_parameters(const callback_parameters& lhs) = default;
		callback_parameters(callback_parameters&& rhs) = default;
		virtual ~callback_parameters() = default;

		callback_parameters& operator=(const callback_parameters& lhs) = default;
		callback_parameters& operator=(callback_parameters&& rhs) = default;

		const ::CF_CALLBACK_INFO& get_native_info() const noexcept;
		const ::CF_CALLBACK_PARAMETERS& get_native_parameters() const noexcept;
		std::wstring_view get_absolute_placeholder_path() const noexcept;
	};

	class LINUXPLORER_SHELL_API fetch_data_callback_parameters : public callback_parameters {
	private:
		std::size_t m_offset;
		std::size_t m_length;
	public:
		fetch_data_callback_parameters(const ::CF_CALLBACK_INFO* info, const ::CF_CALLBACK_PARAMETERS* parameters);
		fetch_data_callback_parameters(const fetch_data_callback_parameters& lhs) = default;
		fetch_data_callback_parameters(fetch_data_callback_parameters&& rhs) = default;
		virtual ~fetch_data_callback_parameters() = default;

		fetch_data_callback_parameters& operator=(const fetch_data_callback_parameters& lhs) = default;
		fetch_data_callback_parameters& operator=(fetch_data_callback_parameters&& rhs) = default;

		std::size_t get_offset() const noexcept;
		std::size_t get_length() const noexcept;
	};

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
}

#endif // CALLBACK_PARAMETERS_HPP_
