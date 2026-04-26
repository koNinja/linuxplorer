#ifndef LINUXPLORER_LXPSVC_REMOTE_REQUESTS_HPP_
#define LINUXPLORER_LXPSVC_REMOTE_REQUESTS_HPP_

#include "../io_requests.hpp"
#include "../../data_range.hpp"

#include <shell/filesystem/placeholder_info.hpp>

namespace linuxplorer::lxpsvc::models::requests::remote {
	class creation_request : public io_request {
	private:
		std::filesystem::file_type m_type;
	public:
		creation_request(const std::filesystem::path& absolute_path, std::filesystem::file_type type, const std::stop_token& stop_token) : 
			io_request(absolute_path, stop_token), m_type(type)
		{}

		std::filesystem::file_type get_type() const noexcept {
			return this->m_type;
		}
	};

	enum class modification_type {
		overwritten,
		appended,
		truncated
	};
	class modification_request : public io_request {
	private:
		range<std::size_t> m_range;
		models::requests::remote::modification_type m_type;

	public:
		modification_request(const std::filesystem::path& absolute_path, const range<std::size_t>& range, models::requests::remote::modification_type type, const std::stop_token& stop_token) : 
			io_request(absolute_path, stop_token), m_range(range), m_type(type)
		{}

		const range<std::size_t> get_range() const noexcept {
			return this->m_range;
		}

		models::requests::remote::modification_type get_type() const noexcept {
			return this->m_type;
		}
	};

	class deletion_request : public synchronous_io_request<void> {
	public:
		deletion_request(const std::filesystem::path& absolute_path, result_adapter<void>& adapter, const std::stop_token& stop_token) :
			synchronous_io_request<void>(absolute_path, adapter, stop_token) 
		{}
	};

	class renaming_request : public synchronous_io_request<> {
	private:
		std::filesystem::path m_absolute_new_path;
	public:
		renaming_request(const std::filesystem::path& absolute_old_path, const std::filesystem::path& absolute_new_path, result_adapter<void>& adapter, const std::stop_token& stop_token) : 
			synchronous_io_request<>(absolute_old_path, adapter, stop_token), m_absolute_new_path(absolute_new_path)
		{}

		const std::filesystem::path& get_absolute_new_path() const noexcept {
			return this->m_absolute_new_path;
		}
	};

	class hydration_request : public synchronous_io_request<std::vector<std::byte>> {
	public:
		using result_t = std::vector<std::byte>;
	private:
		range<std::size_t> m_range;
	public:
		hydration_request(const std::filesystem::path& absolute_path, const range<std::size_t>& range, result_adapter<result_t>& adapter, const std::stop_token& stop_token) : 
			synchronous_io_request<result_t>(absolute_path, adapter, stop_token), m_range(range)
		{}

		const range<std::size_t> get_range() const noexcept {
			return this->m_range;
		}
	};

	class population_request : public synchronous_io_request<std::vector<shell::filesystem::placeholder_creation_info>> {
	public:
		using result_t = std::vector<shell::filesystem::placeholder_creation_info>;
	public:
		population_request(const std::filesystem::path& absolute_path, result_adapter<result_t>& adapter, const std::stop_token& stop_token) :
			synchronous_io_request<result_t>(absolute_path, adapter, stop_token) 
		{}
	};
}

#endif // LINUXPLORER_LXPSVC_REMOTE_REQUESTS_HPP_