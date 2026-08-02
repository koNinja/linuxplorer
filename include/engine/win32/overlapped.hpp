#ifndef LINUXPLORER_ENGINE_OVERLAPPED_HPP_
#define LINUXPLORER_ENGINE_OVERLAPPED_HPP_

#include <engine/enginefwd.hpp>
#include <engine/win32/handle.hpp>
#include <chrono>

namespace linuxplorer::engine::win32 {
	class invalid_overlapped_state_exception : public std::logic_error {
	public:
		using std::logic_error::logic_error;
	};

	enum class overlapped_state {
		pending,
		completed,
		cancelled
	};

	enum class overlapped_wait_result {
		completed,
		timed_out
	};

	class LINUXPLORER_ENGINE_API overlapped {
	public:
		using result_type = ::DWORD;
	private:
		shared_file_handle m_file_handle;
		unique_event_handle m_event_handle;
		::OVERLAPPED m_overlapped;

		overlapped_state m_state;
		std::optional<result_type> m_result;
	public:
		overlapped(const shared_file_handle& file_handle);

		overlapped(const overlapped& lhs) = delete;
		overlapped(overlapped&& rhs) noexcept;
		~overlapped();

		::OVERLAPPED* ptr() noexcept;
		const ::OVERLAPPED* ptr() const noexcept;

		::OVERLAPPED& get() noexcept;
		const ::OVERLAPPED& get() const noexcept;

		shared_file_handle acquire_file_handle() const noexcept;
		const unique_event_handle& get_event_handle() const noexcept;

		overlapped_state poll_state();

		void wait();
		overlapped_wait_result wait_for(std::chrono::milliseconds timeout);

		result_type result();

		void request_cancel();

		void reset();
	private:
		overlapped_wait_result internal_wait_for(::DWORD timeout);
	};
}

#endif // LINUXPLORER_ENGINE_OVERLAPPED_HPP_