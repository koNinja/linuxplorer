#ifndef LINUXPLORER_LXPSVC_OPERATION_EXECUTOR_HPP_
#define LINUXPLORER_LXPSVC_OPERATION_EXECUTOR_HPP_

#include <ntstatus.h>

#include <ssh/sftp/sftp_session.hpp>
#include <shell/cloud_provider_session.hpp>

#include "../win32/handle.hpp"
#include "../contexts/execution_context.hpp"
#include "../models/requests/local_requests.hpp"
#include "../models/requests/remote_requests.hpp"
#include "../helpers/path_helper.hpp"

#include <atomic>
#include <thread>

#include <quill/Logger.h>

namespace linuxplorer::app::lxpsvc::workers {
	enum class operation_executor_state {
		pending,
		running,
		stopped
	};

	class operation_executor {
	private:
		class request_visitor {
		private:
			inline static constexpr std::array<std::byte, 1> s_dummy_identity = {};
		private:
			const ssh::sftp::sftp_session& m_sftp_session;
			const shell::cloud_provider_session& m_cloud_provider_session;
			quill::Logger* m_logger;
			helpers::path_helper m_path_helper;
		public:
			request_visitor(const ssh::sftp::sftp_session& sftp_session, const shell::cloud_provider_session& cloud_provider_session, quill::Logger* logger);

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

		contexts::execution_context& m_execution_context;
		quill::Logger* m_logger;

		request_visitor m_visitor;
	public:
		operation_executor(
			const ssh::sftp::sftp_session& sftp_session,
			const shell::cloud_provider_session& cloud_provider_session,
			contexts::execution_context& execution_context,
			quill::Logger* logger
		);
		virtual ~operation_executor();

		void request_stop() noexcept;
		void wait() noexcept;
		
		operation_executor_state get_state() const noexcept;
	};
}

#endif // LINUXPLORER_LXPSVC_OPERATION_EXECUTOR_HPP_