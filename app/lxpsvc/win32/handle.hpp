#ifndef LINUXPLORER_LXPSVC_HANDLE_HPP_
#define LINUXPLORER_LXPSVC_HANDLE_HPP_

#include <utility>
#include <windows.h>
#include <memory>

namespace linuxplorer::lxpsvc::win32 {
	struct basic_invalid_handle_traits {
		using handle_type = ::HANDLE;
		inline static constexpr handle_type invalid() noexcept {
			return INVALID_HANDLE_VALUE;
		}
		static inline void close(handle_type handle) noexcept {
			::CloseHandle(handle);
		}
	};

	struct basic_null_handle_traits {
		using handle_type = ::HANDLE;
		inline static constexpr handle_type invalid() noexcept {
			return nullptr;
		}
		static inline void close(handle_type handle) noexcept {
			::CloseHandle(handle);
		}
	};

	template <class handle_traits>
	struct basic_unique_handle {
	public:
		using traits_type = handle_traits;
	private:
		using handle_type = typename traits_type::handle_type;
		handle_type m_handle;
	public:
		basic_unique_handle() noexcept : m_handle(handle_traits::invalid()) {}
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

		explicit operator bool() const noexcept {
			return this->m_handle != handle_traits::invalid();
		}
	};

	using unique_file_handle = basic_unique_handle<basic_invalid_handle_traits>;
	using unique_event_handle = basic_unique_handle<basic_null_handle_traits>;
	using unique_mutex_handle = basic_unique_handle<basic_null_handle_traits>;

	namespace internal {
		template <class handle_traits>
		struct handle_sharing_context {
		public:
			using traits_type = handle_traits;
		private:
			using handle_type = typename traits_type::handle_type;
			basic_unique_handle<traits_type> m_handle;
		public:
			handle_sharing_context(handle_type handle) : m_handle(handle) {}
			handle_sharing_context(const handle_sharing_context& lhs) = delete;
			handle_sharing_context(handle_sharing_context&& rhs) = delete;

			handle_type get_ptr() const noexcept {
				return this->m_handle.get();
			}
		};
	}

	template <class handle_traits>
	struct basic_shared_handle {
	public:
		using traits_type = handle_traits;
	private:
		using handle_type = typename traits_type::handle_type;

		std::shared_ptr<internal::handle_sharing_context<traits_type>> m_context;
	public:
		basic_shared_handle() noexcept : m_context(traits_type::invalid()) {}
		basic_shared_handle(handle_type handle) : m_context(std::make_shared<internal::handle_sharing_context<traits_type>>(handle)) {}
		basic_shared_handle(const basic_shared_handle<handle_traits>& lhs) noexcept : m_context(lhs.m_context) {}
		basic_shared_handle(basic_shared_handle<handle_traits>&& rhs) noexcept : m_context(std::move(rhs.m_context)) {}
		basic_shared_handle(basic_unique_handle<traits_type> u) : m_context(std::make_shared<internal::handle_sharing_context<traits_type>>(u.release())) {}

		basic_shared_handle<handle_traits>& operator=(const basic_shared_handle<handle_traits>& lhs) noexcept {
			if (this == &lhs) return *this;
			this->m_context = lhs.m_context;
			return *this;
		}
		basic_shared_handle<handle_traits>& operator=(basic_shared_handle<handle_traits>&& rhs) noexcept {
			if (this == &rhs) return *this;
			this->m_context = std::move(rhs.m_context);
			return *this;
		}

		handle_type get() const noexcept {
			return this->m_context ? this->m_context->get_ptr() : traits_type::invalid();
		}
		long use_count() const noexcept {
			return this->m_context.use_count();
		}
		void reset(handle_type handle = handle_traits::invalid()) {
			this->m_context = std::make_shared<internal::handle_sharing_context<traits_type>>(handle);
		}

		explicit operator bool() const noexcept {
			return this->m_context && (this->m_context->get_ptr() != traits_type::invalid());
		}
	};

	using shared_file_handle = basic_shared_handle<basic_invalid_handle_traits>;
	using shared_event_handle = basic_shared_handle<basic_null_handle_traits>;
}

#endif // LINUXPLORER_LXPSVC_HANDLE_HPP_