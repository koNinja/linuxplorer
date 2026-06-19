#include "overlapped.hpp"
#include <ioapiset.h>

namespace linuxplorer::lxpsvc::win32 {
	overlapped::overlapped(const shared_file_handle& file_handle) : 
		m_file_handle(file_handle), m_state(overlapped_state::pending), m_result(std::nullopt)
	{
		this->m_event_handle = ::CreateEventW(nullptr, true, false, nullptr);
		if (!this->m_event_handle) {
			throw std::system_error(std::error_code(::GetLastError(), std::system_category()), "Failed to create an event for OVERLAPPED.");
		}

		::ZeroMemory(&this->m_overlapped, sizeof(this->m_overlapped));
		this->m_overlapped.hEvent = this->m_event_handle.get();
	}

	overlapped::overlapped(overlapped&& rhs) noexcept : 
		m_file_handle(std::move(rhs.m_file_handle)), m_event_handle(std::move(rhs.m_event_handle)),
		m_overlapped(rhs.m_overlapped), m_result(rhs.m_result), m_state(rhs.m_state)
	{
		::ZeroMemory(&rhs.m_overlapped, sizeof(rhs.m_overlapped));
		this->m_overlapped.hEvent = this->m_event_handle.get();
	}

	overlapped::~overlapped() {
		try {
			this->request_cancel();
		}
		catch (...) {}
	}

	overlapped_state overlapped::poll_state() {
		if (this->m_state != overlapped_state::pending) return this->m_state;
		
		result_type bytes_transferred = 0;
		bool succeeded = ::GetOverlappedResult(
			this->m_file_handle.get(),
			&this->m_overlapped,
			&bytes_transferred,
			false
		);
		if (succeeded) {
			this->m_result = bytes_transferred;
			return this->m_state = overlapped_state::completed;
		}
		else {
			std::error_code ec(::GetLastError(), std::system_category());
			switch (ec.value()) {
			case ERROR_IO_INCOMPLETE: [[fallthrough]];
			case ERROR_IO_PENDING:
			{
				this->m_result = std::nullopt;
				return this->m_state = overlapped_state::pending;
			}
			case ERROR_OPERATION_ABORTED:
			{
				this->m_result = std::nullopt;
				return this->m_state = overlapped_state::cancelled;
			}
			default:
				throw std::system_error(ec, "Failed to acquire a result of the OVERLAPPED operation.");
			}
		}
	}

	overlapped_wait_result overlapped::internal_wait_for(::DWORD timeout) {
		if (this->poll_state() != overlapped_state::pending) return overlapped_wait_result::completed;
	
		while (true) {
			auto response = ::WaitForSingleObject(this->m_event_handle.get(), timeout);
			switch (response) {
			case WAIT_OBJECT_0:
			{
				if (this->poll_state() != overlapped_state::pending) return overlapped_wait_result::completed;
				break;
			}
			case WAIT_TIMEOUT:
			{
				return overlapped_wait_result::timed_out;
			}
			default:
				throw std::system_error(std::error_code(::GetLastError(), std::system_category()), "Failed to wait for the completion event for the OVERLAPPED operation.");
			}
		}
	}

	overlapped::result_type overlapped::result() {
		if (this->poll_state() != overlapped_state::completed || !this->m_result.has_value()) {
			throw invalid_overlapped_state_exception("The OVERLAPPED object is not in a state to retrieve the result.");
		}

		return *this->m_result;
	}

	void overlapped::request_cancel() {
		bool succeeded = ::CancelIoEx(
			this->m_file_handle.get(),
			&this->m_overlapped
		);
		if (!succeeded) {
			std::error_code ec(::GetLastError(), std::system_category());
			if (ec.value() != ERROR_NOT_FOUND) throw std::system_error(ec, "Failed to request a cancellation of the OVERLAPPED operation.");
		}
	}

	void overlapped::reset() {
		if (this->poll_state() == overlapped_state::pending) throw invalid_overlapped_state_exception("The OVERLAPPED object is not in a state to reuse.");

		::ZeroMemory(&this->m_overlapped, sizeof(this->m_overlapped));
		this->m_overlapped.hEvent = this->m_event_handle.get();
		bool succeeded = ::ResetEvent(this->m_event_handle.get());
		if (!succeeded) {
			throw std::system_error(std::error_code(::GetLastError(), std::system_category()), "Failed to set the event to the nonsignaled state.");
		}
		this->m_state = overlapped_state::pending;
	}

	void overlapped::wait() {
		this->internal_wait_for(INFINITE);
	}

	overlapped_wait_result overlapped::wait_for(std::chrono::milliseconds timeout) {
		return this->internal_wait_for(timeout.count());
	}

	shared_file_handle overlapped::acquire_file_handle() const noexcept {
		return this->m_file_handle;
	}

	const unique_event_handle& overlapped::get_event_handle() const noexcept {
		return this->m_event_handle;
	}

	::OVERLAPPED* overlapped::ptr() noexcept {
		return &this->m_overlapped;
	}
	const ::OVERLAPPED* overlapped::ptr() const noexcept {
		return &this->m_overlapped;
	}

	::OVERLAPPED& overlapped::get() noexcept {
		return this->m_overlapped;
	}
	const ::OVERLAPPED& overlapped::get() const noexcept {
		return this->m_overlapped;
	}
}