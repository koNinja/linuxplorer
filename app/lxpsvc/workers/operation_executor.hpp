#ifndef LINUXPLORER_LXPSVC_OPERATION_EXECUTOR_HPP_
#define LINUXPLORER_LXPSVC_OPERATION_EXECUTOR_HPP_

#include <ntstatus.h>

#include <ssh/sftp/sftp_session.hpp>
#include <ssh/sftp/io/sftpstream.hpp>
#include <shell/cloud_provider_session.hpp>

#include "../win32/handle.hpp"
#include "../win32/ntfs.hpp"
#include "../win32/overlapped.hpp"
#include "../contexts/execution_context.hpp"
#include "../models/requests/local/local_requests.hpp"
#include "../models/requests/remote/remote_requests.hpp"
#include "../models/lru_cache.hpp"
#include "../helpers/path_helper.hpp"

#include <atomic>
#include <list>
#include <thread>
#include <unordered_map>
#include <unordered_set>

#include <quill/Logger.h>

namespace linuxplorer::lxpsvc::workers {
	enum class operation_executor_state {
		pending,
		running,
		stopped
	};

	class operation_executor {
	private:
		class request_visitor {
		private:
			const ssh::sftp::sftp_session& m_sftp_session;
			const shell::cloud_provider_session& m_cloud_provider_session;
			quill::Logger* m_logger;
			helpers::path_helper m_path_helper;
			std::list<win32::overlapped>& m_pending_hydrations;

			struct stream_cache_wrapper {
			public:
				inline static constexpr std::size_t s_cache_capacity = 10;
			private:
				models::lru_cache<win32::file_reference_number, ssh::sftp::io::isftpstream> m_remote_istream;
				models::lru_cache<win32::file_reference_number, ssh::sftp::io::osftpstream> m_remote_ostream;
			public:
				stream_cache_wrapper() : m_remote_istream(s_cache_capacity), m_remote_ostream(s_cache_capacity) {}	

				models::lru_cache<win32::file_reference_number, ssh::sftp::io::isftpstream>& remote_istream() noexcept {
					return this->m_remote_istream;
				}

				models::lru_cache<win32::file_reference_number, ssh::sftp::io::osftpstream>& remote_ostream() noexcept {
					return this->m_remote_ostream;
				}
			} m_stream_cache;

			struct population_cache_wrapper {
			private:
				std::unordered_map<win32::file_reference_number, std::unordered_set<std::filesystem::path>> m_existent_files_in_server;
				std::unordered_map<win32::file_reference_number, std::vector<shell::filesystem::placeholder_creation_info>> m_existent_file_metadata_cache;
			public:
				population_cache_wrapper() = default;

				std::unordered_set<std::filesystem::path>* get_existent_file_set(const win32::file_reference_number& directory_frn) {
					return this->m_existent_files_in_server.contains(directory_frn) ? &this->m_existent_files_in_server[directory_frn] : nullptr;
				}
				void set_existent_file_set(const win32::file_reference_number& directory_frn, std::unordered_set<std::filesystem::path>&& set) {
					this->m_existent_files_in_server[directory_frn] = std::move(set);
				}
				bool erase_existent_file_set(const win32::file_reference_number& directory_frn) {
					return this->m_existent_files_in_server.erase(directory_frn);
				}

				std::vector<shell::filesystem::placeholder_creation_info>* get_existent_file_metadata(const win32::file_reference_number& directory_frn) {
					return this->m_existent_file_metadata_cache.contains(directory_frn) ? &this->m_existent_file_metadata_cache[directory_frn] : nullptr;
				}
				void set_existent_file_metadata(const win32::file_reference_number& directory_frn, std::vector<shell::filesystem::placeholder_creation_info>&& map) {
					this->m_existent_file_metadata_cache[directory_frn] = std::move(map);
				}
				void push_existent_file_metadata(const win32::file_reference_number& directory_frn, shell::filesystem::placeholder_creation_info&& metadata) {
					this->m_existent_file_metadata_cache[directory_frn].push_back(std::move(metadata));
				}
				bool erase_existent_file_metadata(const win32::file_reference_number& directory_frn) {
					return this->m_existent_file_metadata_cache.erase(directory_frn);
				}
			} m_population_cache;
		public:
			request_visitor(
				const ssh::sftp::sftp_session& sftp_session,
				const shell::cloud_provider_session& cloud_provider_session,
				std::list<win32::overlapped>& pending_hydrations,
				quill::Logger* logger
			);

			models::requests::request_result operator()(models::requests::remote::creation_request& request, std::stop_token token);
			models::requests::request_result operator()(models::requests::remote::modification_request& request, std::stop_token token);
			models::requests::request_result operator()(models::requests::remote::deletion_request& request, std::stop_token token);
			models::requests::request_result operator()(models::requests::remote::renaming_request& request, std::stop_token token);
			models::requests::request_result operator()(models::requests::remote::hydration_request& request, std::stop_token token);
			models::requests::request_result operator()(models::requests::remote::population_request& request, std::stop_token token);
			models::requests::request_result operator()(models::requests::local::attribute_request& request, std::stop_token token);
			models::requests::request_result operator()(models::requests::local::transform_request& request, std::stop_token token);
			models::requests::request_result operator()(models::requests::local::dehydration_request& request, std::stop_token token);
			models::requests::request_result operator()(models::requests::local::hydration_triggering_request& request, std::stop_token token);
		};
	private:
		std::atomic<operation_executor_state> m_executor_state;

		std::thread m_executor_thread;
		void execute_operations();
		win32::unique_event_handle m_termination_event;

		void on_task_scheduled();

		contexts::execution_context& m_execution_context;
		std::mutex& m_sftp_mutex;
		quill::Logger* m_logger;

		std::list<win32::overlapped> m_pending_hydrations;

		request_visitor m_visitor;
	public:
		operation_executor(
			const ssh::sftp::sftp_session& sftp_session,
			const shell::cloud_provider_session& cloud_provider_session,
			contexts::execution_context& execution_context,
			std::mutex& sftp_mutex,
			quill::Logger* logger
		);
		virtual ~operation_executor();

		void start();

		void request_stop() noexcept;
		void wait() noexcept;
		
		operation_executor_state get_state() const noexcept;
	};
}

#endif // LINUXPLORER_LXPSVC_OPERATION_EXECUTOR_HPP_