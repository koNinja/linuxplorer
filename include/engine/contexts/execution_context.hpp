#ifndef LINUXPLORER_ENGINE_EXECUTION_CONTEXT_HPP_
#define LINUXPLORER_ENGINE_EXECUTION_CONTEXT_HPP_

#include <engine/enginefwd.hpp>
#include <engine/exceptions/abnormal_systems.hpp>
#include <engine/models/operations/io_operations.hpp>

#include <engine/win32/handle.hpp>
#include <engine/win32/ntfs.hpp>

#include <memory>
#include <queue>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <optional>

#include <engine/contexts/cancellation_map.hpp>

namespace linuxplorer::engine::contexts {
	class LINUXPLORER_ENGINE_API execution_context {
	private:
		struct directory_update_suppression_context_node {
			struct directory_update_suppressing_instructions {
				bool m_suppress = false;
				bool m_recursively_suppress = false;
			};

			std::unordered_map<std::filesystem::path, directory_update_suppression_context_node> m_children;
			std::optional<directory_update_suppressing_instructions> m_instructions;
		};

		struct directory_update_suppression_context {
			directory_update_suppression_context_node m_root;
		};

	private:
		cancellation_map m_cancellation_map;
		io_operation_factory m_factory;

		std::mutex m_tasks_mutex;
		std::queue<std::unique_ptr<models::operations::io_operation>> m_tasks;
		win32::unique_event_handle m_task_scheduled_event;

		directory_update_suppression_context m_directory_update_suppressed;

		std::mutex m_errors_mutex;
		std::queue<exceptions::fatal_runtime_exception> m_errors;
		win32::unique_event_handle m_error_propagated_event;

		std::unordered_set<win32::file_reference_number> m_pending_placeholders;
		mutable std::mutex m_pending_placeholders_mutex;
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

		void mark_placeholder_as_pending(const win32::file_reference_number& frn) noexcept;
		bool is_placeholder_pending(const win32::file_reference_number& frn) const noexcept;
		void unmark_placeholder_as_pending(const win32::file_reference_number& frn) noexcept;

		void suppress_directory_update(const std::filesystem::path& relative_path_from_syncroot, bool recursively_suppress = false);
		bool is_directory_update_suppressed(const std::filesystem::path& relative_path_from_syncroot);
		bool try_release_directory_update_suppression(const std::filesystem::path& relative_path_from_syncroot);
	};
}

#endif // LINUXPLORER_ENGINE_EXECUTION_CONTEXT_HPP_