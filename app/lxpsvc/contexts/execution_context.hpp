#ifndef LINUXPLORER_LXPSVC_EXECUTION_CONTEXT_HPP_
#define LINUXPLORER_LXPSVC_EXECUTION_CONTEXT_HPP_

#include "../exceptions/abnormal_systems.hpp"
#include "../models/operations/io_operations.hpp"

#include "../win32/handle.hpp"

#include <memory>
#include <queue>
#include <mutex>
#include <optional>

namespace linuxplorer::lxpsvc::contexts {
	class execution_context {
	private:
		std::mutex m_tasks_mutex;
		std::queue<std::unique_ptr<models::operations::io_operation>> m_tasks;
		win32::unique_event_handle m_task_scheduled_event;

		std::mutex m_errors_mutex;
		std::queue<exceptions::fatal_runtime_exception> m_errors;
		win32::unique_event_handle m_error_propagated_event;
	public:
		execution_context();
		virtual ~execution_context();

		void enqueue_task(std::unique_ptr<models::operations::io_operation> task);
		std::unique_ptr<models::operations::io_operation> dequeue_task();

		void enqueue_error(const exceptions::fatal_runtime_exception& request);
		std::optional<exceptions::fatal_runtime_exception> dequeue_error();

		const win32::unique_event_handle& get_task_event() const noexcept;
		const win32::unique_event_handle& get_error_event() const noexcept;
	};
}

#endif // LINUXPLORER_LXPSVC_EXECUTION_CONTEXT_HPP_