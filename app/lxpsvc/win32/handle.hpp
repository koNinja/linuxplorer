#ifndef LINUXPLORER_LXPSVC_HANDLE_HPP_
#define LINUXPLORER_LXPSVC_HANDLE_HPP_

#include <utility>
#include <windows.h>

namespace linuxplorer::app::lxpsvc::win32 {
	struct basic_invalid_handle_traits {
		using handle_type = ::HANDLE;
		static inline handle_type invalid() noexcept {
			return INVALID_HANDLE_VALUE;
		}
		static inline void close(handle_type handle) noexcept {
			::CloseHandle(handle);
		}
	};

	struct basic_null_handle_traits {
		using handle_type = ::HANDLE;
		static inline handle_type invalid() noexcept {
			return nullptr;
		}
		static inline void close(handle_type handle) noexcept {
			::CloseHandle(handle);
		}
	};

	template <class handle_traits>
	struct basic_unique_handle {
	private:
		using handle_type = typename handle_traits::handle_type;
		handle_type m_handle;
	public:
		basic_unique_handle() : m_handle(handle_traits::invalid()) {}
		basic_unique_handle(handle_type handle) : m_handle(handle) {}
		basic_unique_handle(const basic_unique_handle<handle_traits>& lhs) = delete;
		basic_unique_handle(basic_unique_handle<handle_traits>&& rhs) noexcept : m_handle(rhs.release()) {}

		basic_unique_handle<handle_traits>& operator=(const basic_unique_handle<handle_traits>& lhs) = delete;
		basic_unique_handle<handle_traits>& operator=(basic_unique_handle<handle_traits>&& rhs) noexcept {
			this->reset(rhs.release());
			return *this;
		}

		handle_type get() const noexcept {
			return this->m_handle;
		}
		void reset(handle_type handle = handle_traits::invalid()) noexcept {
			if (this->m_handle != handle_traits::invalid()) {
				handle_traits::close(this->m_handle);
			}
			this->m_handle = handle;
		}
		[[nodiscard("Losing references can cause memory leaks")]]
		handle_type release() noexcept {
			handle_type handle = std::exchange(this->m_handle, handle_traits::invalid());
			return handle;
		}
		~basic_unique_handle() noexcept {
			this->reset();
		}

		operator bool() const noexcept {
			return this->m_handle != handle_traits::invalid();
		}
	};

	using unique_file_handle = basic_unique_handle<basic_invalid_handle_traits>;
	using unique_event_handle = basic_unique_handle<basic_null_handle_traits>;
}

#endif // LINUXPLORER_LXPSVC_HANDLE_HPP_