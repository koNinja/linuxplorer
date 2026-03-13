#include "execution_context.hpp"

namespace linuxplorer::app::lxpsvc::contexts {
	execution_context::execution_context() {
		this->m_task_scheduled_event = ::CreateEventW(nullptr, true, false, nullptr);
		if (!this->m_task_scheduled_event) {
			std::error_code ec(::GetLastError(), std::system_category());
			throw exceptions::fatal_runtime_exception(
				exceptions::runtime_error_domain::context,
				"Failed to create an event for task scheduling. (Win32: {}({}))",
				ec.message(),
				ec.value()
			);
		}
	
		this->m_error_propagated_event = ::CreateEventW(nullptr, true, false, nullptr);
		if (!this->m_error_propagated_event) {
			std::error_code ec(::GetLastError(), std::system_category());
			throw exceptions::fatal_runtime_exception(
				exceptions::runtime_error_domain::context,
				"Failed to create an event for error propagation. (Win32: {}({}))",
				ec.message(),
				ec.value()
			);
		}
	}

	execution_context::~execution_context() {
	
	}

	void execution_context::enqueue_task(std::unique_ptr<models::operations::io_operation> task) {
		std::unique_lock lock(this->m_tasks_mutex);
		this->m_tasks.push(std::move(task));
		::SetEvent(this->m_task_scheduled_event.get());
	}

	std::unique_ptr<models::operations::io_operation> execution_context::dequeue_task() {
		std::unique_lock lock(this->m_tasks_mutex);
		if (this->m_tasks.empty()) {
			return nullptr;
		}

		auto task = std::move(const_cast<std::unique_ptr<models::operations::io_operation>&>(this->m_tasks.top()));
		this->m_tasks.pop();

		if (this->m_tasks.empty()) {
			::ResetEvent(this->m_task_scheduled_event.get());
		}
		
		return task;
	}

	void execution_context::enqueue_error(const exceptions::fatal_runtime_exception& request) {
		std::unique_lock lock(this->m_errors_mutex);
		this->m_errors.push(request);
		::SetEvent(this->m_error_propagated_event.get());
	}

	std::optional<exceptions::fatal_runtime_exception> execution_context::dequeue_error() {
		std::unique_lock lock(this->m_errors_mutex);
		if (this->m_errors.empty()) {
			return std::nullopt;
		}
		auto error = this->m_errors.front();
		this->m_errors.pop();
	
		if (this->m_errors.empty()) {
			::ResetEvent(this->m_error_propagated_event.get());
		}
	
		return error;
	}

	const win32::unique_event_handle& execution_context::get_task_event() const noexcept {
		return this->m_task_scheduled_event;
	}

	const win32::unique_event_handle& execution_context::get_error_event() const noexcept {
		return this->m_error_propagated_event;
	}
}