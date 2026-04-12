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

			const ssh::sftp::sftp_session& m_sftp_session;
			const shell::cloud_provider_session& m_cloud_provider_session;
			quill::Logger* m_logger;
			helpers::path_helper m_path_helper;
			std::list<win32::overlapped>& m_pending_hydrations;
		public:
			request_visitor(
				const ssh::sftp::sftp_session& sftp_session,
				const shell::cloud_provider_session& cloud_provider_session,
				std::list<win32::overlapped>& pending_hydrations,
				quill::Logger* logger
			);

			models::requests::request_result operator()(models::requests::remote::creation_request& request);
			models::requests::request_result operator()(models::requests::remote::modification_request& request);
			models::requests::request_result operator()(models::requests::remote::deletion_request& request);
			models::requests::request_result operator()(models::requests::remote::renaming_request& request);
			models::requests::request_result operator()(models::requests::remote::hydration_request& request);
			models::requests::request_result operator()(models::requests::remote::population_request& request);
			models::requests::request_result operator()(models::requests::local::attribute_request& request);
			models::requests::request_result operator()(models::requests::local::transform_request& request);
			models::requests::request_result operator()(models::requests::local::dehydration_request& request);
			models::requests::request_result operator()(models::requests::local::hydration_triggering_request& request);
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

		request_visitor m_visitor;

		std::list<win32::overlapped> m_pending_hydrations;
	public:
		operation_executor(
			const ssh::sftp::sftp_session& sftp_session,
			const shell::cloud_provider_session& cloud_provider_session,
			contexts::execution_context& execution_context,
			std::mutex& sftp_mutex,
			quill::Logger* logger
		);
		virtual ~operation_executor();

		void request_stop() noexcept;
		void wait() noexcept;
		
		operation_executor_state get_state() const noexcept;
	};
}

#endif // LINUXPLORER_LXPSVC_OPERATION_EXECUTOR_HPP_