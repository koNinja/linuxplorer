#include <engine/contexts/execution_context.hpp>
#include <engine/helpers/path_helper.hpp>
#include <ranges>

namespace linuxplorer::engine::contexts {
	execution_context::execution_context() : m_factory(this->m_cancellation_map) {
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

		auto task = std::move(this->m_tasks.front());
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

	io_operation_factory& execution_context::get_factory() noexcept {
		return this->m_factory;
	}

	bool execution_context::try_cancel_operation(models::operations::io_operation::identifier_type id) {
		return this->m_cancellation_map.try_cancel_operation(id);
	}

	void execution_context::mark_placeholder_as_pending(const win32::file_reference_number& frn) noexcept {
		{
			std::unique_lock lock(this->m_pending_placeholders_mutex);
			this->m_pending_placeholders.insert(frn);
		}
	}

	bool execution_context::is_placeholder_pending(const win32::file_reference_number& frn) const noexcept {
		{
			std::unique_lock lock(this->m_pending_placeholders_mutex);
			return this->m_pending_placeholders.contains(frn);
		}
	}

	void execution_context::unmark_placeholder_as_pending(const win32::file_reference_number& frn) noexcept {
		{
			std::unique_lock lock(this->m_pending_placeholders_mutex);
			this->m_pending_placeholders.erase(frn);
		}
	}

	void execution_context::suppress_directory_update(const std::filesystem::path& relative_path_from_syncroot, bool recursively_suppress) {
		auto lower_relative_path_elements = helpers::path_helper::tolower_localized(relative_path_from_syncroot) | std::ranges::to<std::vector<std::filesystem::path>>();
		directory_update_suppression_context_node* node_ptr = &this->m_directory_update_suppressed.m_root;
		for (int i = 0; const auto& lower_path_element : lower_relative_path_elements) {
			node_ptr = &node_ptr->m_children[lower_path_element];
			
			if (i >= lower_relative_path_elements.size() - 1) {
				node_ptr->m_instructions.emplace();
				node_ptr->m_instructions->m_suppress = true;
				node_ptr->m_instructions->m_recursively_suppress = recursively_suppress;
			}
		}
	}

	bool execution_context::is_directory_update_suppressed(const std::filesystem::path& relative_path_from_syncroot) {
		auto lower_relative_path_elements = helpers::path_helper::tolower_localized(relative_path_from_syncroot) | std::ranges::to<std::vector<std::filesystem::path>>();
		directory_update_suppression_context_node* node_ptr = &this->m_directory_update_suppressed.m_root;
		for (int i = 0; const auto& lower_path_element : lower_relative_path_elements) {
			if (node_ptr->m_instructions.has_value() && node_ptr->m_instructions->m_recursively_suppress) {
				return true;
			}

			if (node_ptr->m_children.contains(lower_path_element)) {
				node_ptr = &node_ptr->m_children[lower_path_element];

				if (i >= lower_relative_path_elements.size() - 1) {
					if (node_ptr->m_instructions.has_value()) return node_ptr->m_instructions->m_suppress;
				}
			}
		}
		return false;
	}

	bool execution_context::try_release_directory_update_suppression(const std::filesystem::path& relative_path_from_syncroot) {
		auto lower_relative_path_elements = helpers::path_helper::tolower_localized(relative_path_from_syncroot) | std::ranges::to<std::vector<std::filesystem::path>>();
		directory_update_suppression_context_node* node_ptr = &this->m_directory_update_suppressed.m_root;
		for (int i = 0; const auto& lower_path_element : lower_relative_path_elements) {
			if (node_ptr->m_children.contains(lower_path_element)) {
				node_ptr = &node_ptr->m_children[lower_path_element];

				if (i >= lower_relative_path_elements.size() - 1) {
					node_ptr->m_instructions.reset();
					return true;
				}
			}
		}

		return false;
	}
}