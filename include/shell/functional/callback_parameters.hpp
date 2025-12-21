#ifndef LINUXPLORER_CALLBACK_PARAMETERS_HPP_
#define LINUXPLORER_CALLBACK_PARAMETERS_HPP_

#include <shell/shellfwd.hpp>

#include <windows.h>
#include <cfapi.h>

#include <string>

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

	class LINUXPLORER_SHELL_API cancel_fetch_data_callback_parameters : public callback_parameters {
	private:
		std::size_t m_offset;
		std::size_t m_length;
	public:
		cancel_fetch_data_callback_parameters(const ::CF_CALLBACK_INFO* info, const ::CF_CALLBACK_PARAMETERS* parameters);
		cancel_fetch_data_callback_parameters(const cancel_fetch_data_callback_parameters& lhs) = default;
		cancel_fetch_data_callback_parameters(cancel_fetch_data_callback_parameters&& rhs) = default;
		virtual ~cancel_fetch_data_callback_parameters() = default;

		cancel_fetch_data_callback_parameters& operator=(const cancel_fetch_data_callback_parameters& lhs) = default;
		cancel_fetch_data_callback_parameters& operator=(cancel_fetch_data_callback_parameters&& rhs) = default;

		std::size_t get_offset() const noexcept;
		std::size_t get_length() const noexcept;
	};

	class LINUXPLORER_SHELL_API rename_callback_parameters : public callback_parameters {
	private:
		std::wstring m_absolute_new_path;
	public:
		rename_callback_parameters(const ::CF_CALLBACK_INFO* info, const ::CF_CALLBACK_PARAMETERS* parameters);
		rename_callback_parameters(const rename_callback_parameters& lhs) = default;
		rename_callback_parameters(rename_callback_parameters&& rhs) = default;
		virtual ~rename_callback_parameters() = default;

		rename_callback_parameters& operator=(const rename_callback_parameters& lhs) = default;
		rename_callback_parameters& operator=(rename_callback_parameters&& rhs) = default;

		std::wstring_view get_absolute_new_path() const noexcept;
	};

	class LINUXPLORER_SHELL_API rename_completion_callback_parameters : public callback_parameters {
	private:
		std::wstring m_absolute_old_path;
	public:
		rename_completion_callback_parameters(const ::CF_CALLBACK_INFO* info, const ::CF_CALLBACK_PARAMETERS* parameters);
		rename_completion_callback_parameters(const rename_completion_callback_parameters& lhs) = default;
		rename_completion_callback_parameters(rename_completion_callback_parameters&& rhs) = default;
		virtual ~rename_completion_callback_parameters() = default;

		rename_completion_callback_parameters& operator=(const rename_completion_callback_parameters& lhs) = default;
		rename_completion_callback_parameters& operator=(rename_completion_callback_parameters&& rhs) = default;

		std::wstring_view get_absolute_old_path() const noexcept;
	};

	class LINUXPLORER_SHELL_API delete_callback_parameters : public callback_parameters {
	private:
		bool m_has_deleted;
		bool m_is_directory;
	public:
		delete_callback_parameters(const ::CF_CALLBACK_INFO* info, const ::CF_CALLBACK_PARAMETERS* parameters);
		delete_callback_parameters(const delete_callback_parameters& lhs) = default;
		delete_callback_parameters(delete_callback_parameters&& rhs) = default;
		virtual ~delete_callback_parameters() = default;

		delete_callback_parameters& operator=(const delete_callback_parameters& lhs) = default;
		delete_callback_parameters& operator=(delete_callback_parameters&& rhs) = default;

		bool has_deleted() const noexcept;
		bool is_directory() const noexcept;
	};
}

#endif // CALLBACK_PARAMETERS_HPP_
