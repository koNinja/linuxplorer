#ifndef LINUXPLORER_REMOTE_REQUESTS_HPP_
#define LINUXPLORER_REMOTE_REQUESTS_HPP_

#include "io_requests.hpp"
#include "../data_range.hpp"

#include <shell/filesystem/placeholder_info.hpp>

namespace linuxplorer::app::lxpsvc::models::requests::remote {
	class creation_request : public io_request {
	private:
		std::filesystem::file_type m_type;
	public:
		creation_request(const std::filesystem::path& absolute_path, std::filesystem::file_type type) : 
			io_request(absolute_path), m_type(type)
		{}

		std::filesystem::file_type get_type() const noexcept {
			return this->m_type;
		}
	};

	class modification_request : public io_request {
	private:
		range<std::size_t> m_range;
	public:
		modification_request(const std::filesystem::path& absolute_path, const range<std::size_t>& range) : 
			io_request(absolute_path), m_range(range)
		{}

		const range<std::size_t> get_range() const noexcept {
			return this->m_range;
		}
	};

	class deletion_request : public synchronous_io_request<> {
	public:
		using synchronous_io_request<>::synchronous_io_request;
	};

	class renaming_request : public synchronous_io_request<> {
	private:
		std::filesystem::path m_absolute_new_path;
	public:
		renaming_request(const std::filesystem::path& absolute_old_path, const std::filesystem::path& absolute_new_path, result_adapter<void>& adapter) : 
			synchronous_io_request<>(absolute_old_path, adapter), m_absolute_new_path(absolute_new_path)
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
		hydration_request(const std::filesystem::path& absolute_path, const range<std::size_t>& range, result_adapter<result_t>& adapter) : 
			synchronous_io_request<result_t>(absolute_path, adapter), m_range(range)
		{}

		const range<std::size_t> get_range() const noexcept {
			return this->m_range;
		}
	};

	class population_request : public synchronous_io_request<std::vector<shell::filesystem::placeholder_creation_info>> {
	public:
		using result_t = std::vector<shell::filesystem::placeholder_creation_info>;
	public:
		using synchronous_io_request<result_t>::synchronous_io_request;
	};
}

#endif // LINUXPLORER_REMOTE_REQUESTS_HPP_