#include "callback_table.hpp"

#include <ntstatus.h>
#include "../models/operations/io_operations.hpp"

#include <quill/Backend.h>
#include <quill/LogMacros.h>
#include <quill/std/FilesystemPath.h>

namespace linuxplorer::lxpsvc::workers {
	shell::functional::specialized::fetch_data_operation_info callback_table::on_fetch_data(const shell::functional::specialized::fetch_data_callback_parameters& parameters) {
		LOG_INFO(
			this->m_logger,
			"Data fetch requested for '{}', offset: {}, length: {}",
			parameters.get_absolute_placeholder_path(),
			parameters.get_offset(),
			parameters.get_length()
		);

		auto operation = std::make_unique<models::operations::hydration_operation>(
			this->m_syncroot_path,
			std::filesystem::relative(parameters.get_absolute_placeholder_path(), this->m_syncroot_path),
			models::range<std::size_t>(parameters.get_offset(), parameters.get_length())
		);
		
		auto adapter = operation->get_adapter().lock();

		this->m_execution_context.enqueue_task(std::move(operation));

		std::size_t current_offset = 0;
		std::optional<models::operations::hydration_operation::result_t> result;
		while ((result = adapter->wait_head())) {
			auto length = result->size();

			shell::functional::specialized::fetch_data_operation_info_yielded yielded;
			yielded.set_length(length);
			yielded.set_offset(current_offset);

			yielded.set_buffer(std::move(*result));

			co_yield yielded;

			current_offset += length;
		}

		co_return;
	}

	shell::functional::specialized::fetch_placeholders_operation_info callback_table::on_fetch_placeholders(const shell::functional::callback_parameters& parameters) {
		LOG_INFO(this->m_logger, "Placeholder fetch requested for '{}'.", parameters.get_absolute_placeholder_path());

		auto operation = std::make_unique<models::operations::population_operation>(
			this->m_syncroot_path,
			std::filesystem::relative(parameters.get_absolute_placeholder_path(), this->m_syncroot_path)
		);
		
		auto adapter = operation->get_adapter().lock();

		this->m_execution_context.enqueue_task(std::move(operation));

		// Since `fetch_placeholder` does not yet support yield returning, the adapter will only return one object.
		auto result = adapter->wait_head();
		if (!result) {
			throw shell::functional::callback_abort_exception(STATUS_CLOUD_FILE_UNSUCCESSFUL);
		}

		shell::functional::specialized::fetch_placeholders_operation_info info;
		info.set_total_count_to_be_processed(result->size());
		for (auto& creation_info : *result) {
			info.add_creation_info(std::move(creation_info));
		}

		return info;
	}

	shell::functional::specialized::delete_operation_info callback_table::on_deleted(const shell::functional::specialized::delete_callback_parameters& parameters) {
		LOG_INFO(this->m_logger, "Deletion requested for '{}'.", parameters.get_absolute_placeholder_path());

		auto operation = std::make_unique<models::operations::deletion_operation>(
			this->m_syncroot_path,
			std::filesystem::relative(parameters.get_absolute_placeholder_path(), this->m_syncroot_path)
		);
		
		auto adapter = operation->get_adapter().lock();

		this->m_execution_context.enqueue_task(std::move(operation));

		while (adapter->wait_head());

		return {};
	}

	shell::functional::operation_info callback_table::on_renamed(const shell::functional::specialized::rename_callback_parameters& parameters) {
		LOG_INFO(
			this->m_logger,
			"Renaming requested for '{}' to '{}'.",
			parameters.get_absolute_placeholder_path(),
			parameters.get_absolute_new_path()
		);

		auto operation = std::make_unique<models::operations::renaming_operation>(
			this->m_syncroot_path,
			std::filesystem::relative(parameters.get_absolute_placeholder_path(), this->m_syncroot_path),
			parameters.get_absolute_new_path()
		);
		
		auto adapter = operation->get_adapter().lock();

		this->m_execution_context.enqueue_task(std::move(operation));

		while (adapter->wait_head());

		return {};
	}

	void callback_table::on_cancel_fetch_data(const shell::functional::specialized::cancel_fetch_data_callback_parameters& parameters) {

	}
}