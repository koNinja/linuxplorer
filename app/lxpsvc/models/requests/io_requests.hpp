#ifndef LINUXPLORER_LXPSVC_IO_REQUESTS_HPP_
#define LINUXPLORER_LXPSVC_IO_REQUESTS_HPP_

#include <filesystem>
#include <utility>

#include "result_adapter.hpp"

namespace linuxplorer::app::lxpsvc::models::requests {
	class io_request {
	private:
		std::filesystem::path m_absolute_path;
	protected:
		io_request(const std::filesystem::path& absolute_path) : m_absolute_path(absolute_path)
		{}
	public:
		io_request(const io_request& lhs) = delete;
		io_request& operator=(const io_request& lhs) = delete;

		io_request(io_request&& rhs) = default;
		io_request& operator=(io_request&& rhs) = default;

		const std::filesystem::path& get_absolute_path() const noexcept {
			return this->m_absolute_path;
		}
	};

	template <class result_t = void>
	class synchronous_io_request : public io_request {
	private:
		result_adapter<result_t>& m_adapter;
	protected:
		synchronous_io_request(const std::filesystem::path& absolute_path, result_adapter<result_t>& adapter) :
			io_request(absolute_path), m_adapter(adapter)
		{}
	public:
		template <class T>
		void set_value(T&& value) {
			this->m_adapter.set_value(std::forward<T>(value));
		}

		template <class T>
		void set_exception(T&& exception) {
			this->m_adapter.set_exception(std::forward<T>(exception));
		}
	};

	template <>
	class synchronous_io_request<void> : public io_request {
	private:
		result_adapter<void>& m_adapter;
	public:
		synchronous_io_request(const std::filesystem::path& absolute_path, result_adapter<void>& adapter) :
			io_request(absolute_path), m_adapter(adapter)
		{}

		void set_value() {
			this->m_adapter.set_value();
		}

		template <class T>
		void set_exception(T&& exception) {
			this->m_adapter.set_exception(std::forward<T>(exception));
		}
	};

	template <class T>
	concept is_request_v = std::is_base_of_v<io_request, T>;

	template <class... T>
	concept are_request_v = (is_request_v<T> && ...);
}

#endif // LINUXPLORER_LXPSVC_IO_REQUESTS_HPP_