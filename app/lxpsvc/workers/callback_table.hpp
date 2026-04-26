#ifndef LINUXPLORER_LXPSVC_CALLBACK_TABLE_HPP_
#define LINUXPLORER_LXPSVC_CALLBACK_TABLE_HPP_

#include <memory>
#include <filesystem>
#include <vector>

#include <shell/functional/cloud_provider_callback.hpp>

#include "../contexts/execution_context.hpp"
#include "../win32/ntfs.hpp"
#include "../models/operations/io_operations.hpp"

#include <quill/Logger.h>

namespace linuxplorer::lxpsvc::workers {
	template <shell::functional::cloud_provider_callback_type T, class F, class O>
	std::unique_ptr<shell::functional::cloud_provider_callback> make_callback(F&& method, O& object) {
		using raw_return_t = typename shell::functional::specialized_cloud_provider_callback<T>;
		return std::make_unique<raw_return_t>(shell::functional::make_callback<T>(std::forward<F>(method), object));
	}

	class callback_table {
	private:
		std::unordered_map<win32::file_reference_number, models::operations::io_operation::identifier_type> m_cancellable_operations;
		std::mutex m_cancellable_map_mutex;

		contexts::execution_context& m_execution_context;
		std::filesystem::path m_syncroot_path;
		quill::Logger* m_logger;

		shell::functional::specialized::fetch_data_operation_info on_fetch_data(const shell::functional::specialized::fetch_data_callback_parameters& parameters);
		shell::functional::specialized::fetch_placeholders_operation_info on_fetch_placeholders(const shell::functional::callback_parameters& parameters);
		shell::functional::specialized::delete_operation_info on_deleted(const shell::functional::specialized::delete_callback_parameters& parameters);
		shell::functional::operation_info on_renamed(const shell::functional::specialized::rename_callback_parameters& parameters);
		void on_cancel_fetch_data(const shell::functional::specialized::cancel_fetch_data_callback_parameters& parameters);
		void on_cancel_fetch_placeholders(const shell::functional::callback_parameters& parameters);
	public:
		callback_table(const std::filesystem::path& syncroot_path, contexts::execution_context& execution_context, quill::Logger* logger) : 
			m_execution_context(execution_context), m_syncroot_path(syncroot_path), m_logger(logger) {}
		callback_table(const callback_table& lhs) = delete;
		callback_table(callback_table&& rhs) = delete;

		std::vector<std::unique_ptr<shell::functional::cloud_provider_callback>> generate_table() {
			std::vector<std::unique_ptr<shell::functional::cloud_provider_callback>> table;

			table.push_back(workers::make_callback<shell::functional::cloud_provider_callback_type::fetch_data>(&callback_table::on_fetch_data, *this));
			table.push_back(workers::make_callback<shell::functional::cloud_provider_callback_type::fetch_placeholders>(&callback_table::on_fetch_placeholders, *this));
			table.push_back(workers::make_callback<shell::functional::cloud_provider_callback_type::notify_deletion>(&callback_table::on_deleted, *this));
			table.push_back(workers::make_callback<shell::functional::cloud_provider_callback_type::notify_renaming>(&callback_table::on_renamed, *this));
			table.push_back(workers::make_callback<shell::functional::cloud_provider_callback_type::cancel_fetching_data>(&callback_table::on_cancel_fetch_data, *this));
			table.push_back(workers::make_callback<shell::functional::cloud_provider_callback_type::cancel_fetching_placeholders>(&callback_table::on_cancel_fetch_placeholders, *this));

			return table;
		}
	};
}

#endif // LINUXPLORER_LXPSVC_CALLBACK_TABLE_HPP_