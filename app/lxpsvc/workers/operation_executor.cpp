#include "operation_executor.hpp"

#include <quill/LogMacros.h>
#include <quill/Backend.h>
#include <quill/std/FilesystemPath.h>

namespace linuxplorer::lxpsvc::workers {
	operation_executor::operation_executor(
		const ssh::sftp::sftp_session& sftp_session,
		const shell::cloud_provider_session& cloud_provider_session,
		contexts::execution_context& execution_context,
		std::mutex& sftp_mutex,
		quill::Logger* logger
	) : 
		m_logger(logger), m_execution_context(execution_context), 
		m_executor_state(operation_executor_state::pending), m_sftp_mutex(sftp_mutex),
		m_visitor(sftp_session, cloud_provider_session, this->m_pending_hydrations, logger)
	{
		this->m_termination_event = ::CreateEventW(nullptr, true, false, nullptr);
		if (!this->m_termination_event) {
			std::error_code ec(::GetLastError(), std::system_category());
			throw exceptions::fatal_runtime_exception(
				exceptions::runtime_error_domain::executor,
				"Failed to create an event for termination. (Win32: {}({}))",
				ec.message(),
				ec.value()
			);
		}
	}

	void operation_executor::start() {
		this->m_executor_thread = std::thread(&operation_executor::execute_operations, this);
	}

	operation_executor::~operation_executor() {
		this->request_stop();
		this->wait();
	}

	operation_executor_state operation_executor::get_state() const noexcept {
		return this->m_executor_state;
	}

	void operation_executor::request_stop() noexcept {
		if (this->m_termination_event) {
			::SetEvent(this->m_termination_event.get());
		}
	}

	void operation_executor::wait() noexcept {
		if (this->m_executor_thread.joinable()) {
			this->m_executor_thread.join();
		}
	}

	void operation_executor::execute_operations() {
		LOG_INFO(this->m_logger, "The operation executor has been started.");
		this->m_executor_state = operation_executor_state::running;

		while (true) {
			std::vector<::HANDLE> handles{
				this->m_termination_event.get(),
				this->m_execution_context.get_task_event().get()
			};
			std::size_t overlappeds_offset = handles.size();

			for (auto itr = this->m_pending_hydrations.begin(); itr != this->m_pending_hydrations.end();) {
				try {
					if (itr->poll_state() == win32::overlapped_state::pending) {
						handles.push_back(itr->get_event_handle().get());
					}

					itr++;
				}
				catch (const std::system_error& e) {
					LOG_ERROR(
						this->m_logger,
						"Failed to acquire a state of the OVERLAPPED completion: {} (Win32: {}({}))",
						e.what(),
						e.code().message(),
						e.code().value()
					);

					// abandon the OVERLAPPED which it is impossible to query information for.
					itr = this->m_pending_hydrations.erase(itr);
				}
			}

			auto response = ::WaitForMultipleObjects(handles.size(), handles.data(), false, INFINITE);
			switch (response) {
			case WAIT_OBJECT_0:
			{
				this->m_executor_state = operation_executor_state::stopped;
				LOG_INFO(this->m_logger, "The operation executor has been successfully terminated.");
				return;
			}
			case WAIT_OBJECT_0 + 1:
			{
				this->on_task_scheduled();
				break;
			}
			case WAIT_TIMEOUT: [[fallthrough]];
			case WAIT_FAILED:
			{
				
				std::error_code ec(::GetLastError(), std::system_category());
				this->m_execution_context.enqueue_error(exceptions::fatal_runtime_exception(
					exceptions::runtime_error_domain::executor,
					"Failed to wait for the events. (Win32: {}({}))",
					ec.message(),
					ec.value()
				));
				this->m_executor_state = operation_executor_state::stopped;
				return;
			}
			default:
			{
				if (response >= WAIT_ABANDONED_0) break;
				
				// handle the overlapped result
				auto itr = std::next(this->m_pending_hydrations.begin(), response - overlappeds_offset);
				try {
					if (itr->poll_state() == win32::overlapped_state::pending) itr->wait();
				}
				catch (const std::system_error& e) {
					LOG_ERROR(
						this->m_logger,
						"Failed to wait for OVERLAPPED completion: {} (Win32: {}({}))",
						e.what(),
						e.code().message(),
						e.code().value()
					);
				}

				this->m_pending_hydrations.erase(itr);

				break;
			}
			}
		}
	}

	void operation_executor::on_task_scheduled() {
		try {
			std::unique_lock lock(this->m_sftp_mutex);

			auto nullable_task = this->m_execution_context.dequeue_task();
			if (!nullable_task || !nullable_task->is_necessary()) {
				if (nullable_task)	LOG_INFO(this->m_logger, "An operation #{} is deemed unnecessary to execute and thus skipped.", nullable_task->get_id());
				return;
			}

			LOG_INFO(this->m_logger, "Start processing operation #{}.", nullable_task->get_id());

			while (!nullable_task->done()) {
				try {
					if (nullable_task->has_cancel_requested()) {
						nullable_task->transition(models::requests::request_result::cancelled);
						break;
					}

					auto any_request = nullable_task->fetch();
					models::requests::request_result result = std::visit(this->m_visitor, any_request);
					nullable_task->transition(result);

					bool need_to_exit_loop = false;
					switch (result) {
					case models::requests::request_result::transient_failure:
						LOG_ERROR(this->m_logger, "Operation #{} has encountered a transient failure at its request.", nullable_task->get_id());
						// implement retry logic here
						need_to_exit_loop = true;
						[[fallthrough]];
					default:
						break;
					}

					// In case of transient failure, break the loop to avoid processing further requests until the retry logic is implemented.
					if (need_to_exit_loop) break;
				}
				catch (const models::operations::invalid_state_exception& e) {
					LOG_ERROR(this->m_logger, "Failed to acquire the next I/O request for operation #{}: {}", nullable_task->get_id(), e.what());
					break;
				}
				catch (...) {
					LOG_ERROR(this->m_logger, "Failed to process request for operation #{}.", nullable_task->get_id());
					break;
				}
			}

			switch (nullable_task->get_result()) {
			case models::operations::operation_result::pending:
				LOG_ERROR(this->m_logger, "Operation #{} is still pending after processing all requests.", nullable_task->get_id());
				break;
			case models::operations::operation_result::succeeded:
				LOG_INFO(this->m_logger, "Operation #{} has been completed successfully.", nullable_task->get_id());
				break;
			case models::operations::operation_result::failed:
				LOG_ERROR(this->m_logger, "Operation #{} has been failed.", nullable_task->get_id());
				break;
			case models::operations::operation_result::cancelled:
				LOG_WARNING(this->m_logger, "Operation #{} has been cancelled.", nullable_task->get_id());
				break;
			default:
				LOG_ERROR(this->m_logger, "Operation #{} has an unknown result.", nullable_task->get_id());
				break;
			}
		}
		catch (...) {
			LOG_ERROR(this->m_logger, "Failed to parse an I/O event.");
			return;
		}
	}
}