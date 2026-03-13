#include "operation_executor.hpp"

#include <array>

#include <quill/LogMacros.h>

namespace linuxplorer::app::lxpsvc::workers {
	operation_executor::operation_executor(
		const ssh::sftp::sftp_session& sftp_session,
		const shell::cloud_provider_session& cloud_provider_session,
		contexts::execution_context& execution_context,
		quill::Logger* logger
	) : 
		m_visitor(sftp_session, cloud_provider_session, logger), m_logger(logger),
		m_execution_context(execution_context), m_executor_state(operation_executor_state::pending)
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

		this->m_executor_thread = std::thread([this]() { this->execute_operations(); });
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
		std::array<::HANDLE, 2> handles{
			this->m_termination_event.get(),
			this->m_execution_context.get_task_event().get()
		};

		while (true) {
			auto response = ::WaitForMultipleObjects(handles.size(), handles.data(), false, INFINITE);
			switch (response) {
			case WAIT_OBJECT_0:
			{
				this->m_executor_state = operation_executor_state::stopped;
				return;
			}
			case WAIT_OBJECT_0 + 1:
			{
				try {
					auto nullable_task = this->m_execution_context.dequeue_task();
					if (!nullable_task || nullable_task->get_result() != models::operations::operation_result::pending) break;

					LOG_INFO(this->m_logger, "Start processing operation #{}.", nullable_task->get_id());

					while (!nullable_task->done()) {
						try {
							auto any_request = nullable_task->fetch();
							models::requests::request_result result = std::visit(this->m_visitor, any_request);
							nullable_task->transition(result);

							switch (result) {
							case models::requests::request_result::transient_failure:
								LOG_ERROR(this->m_logger, "Operation #{} has encountered a transient failure at its request #{}.", nullable_task->get_id(), nullable_task->get_request_index());
								// implement retry logic here
								break;
							default:
								break;
							}
						}
						catch (const models::operations::invalid_state_exception& e) {
							LOG_ERROR(this->m_logger, "Failed to acquire the next I/O request for operation #{}: {}", nullable_task->get_id(), e.what());
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
					break;
				}
				break;
			}
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
				break;
			}
		}
	}
}