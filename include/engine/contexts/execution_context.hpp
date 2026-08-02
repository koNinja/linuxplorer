#ifndef LINUXPLORER_ENGINE_EXECUTION_CONTEXT_HPP_
#define LINUXPLORER_ENGINE_EXECUTION_CONTEXT_HPP_

#include <engine/enginefwd.hpp>
#include <engine/exceptions/abnormal_systems.hpp>
#include <engine/models/operations/io_operations.hpp>

#include <engine/win32/handle.hpp>

#include <memory>
#include <queue>
#include <mutex>
#include <optional>

#include "cancellation_map.hpp"

namespace linuxplorer::engine::contexts {
	class LINUXPLORER_ENGINE_API execution_context {
	private:
		cancellation_map m_cancellation_map;
		io_operation_factory m_factory;

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

		io_operation_factory& get_factory() noexcept;
		bool try_cancel_operation(models::operations::io_operation::identifier_type id);

		void enqueue_error(const exceptions::fatal_runtime_exception& request);
		std::optional<exceptions::fatal_runtime_exception> dequeue_error();

		const win32::unique_event_handle& get_task_event() const noexcept;
		const win32::unique_event_handle& get_error_event() const noexcept;
	};
}

#endif // LINUXPLORER_ENGINE_EXECUTION_CONTEXT_HPP_