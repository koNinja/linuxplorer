#ifndef LINUXPLORER_ENGINE_PROFILE_RUNTIME_HPP_
#define LINUXPLORER_ENGINE_PROFILE_RUNTIME_HPP_

#include <engine/enginefwd.hpp>

#include <thread>
#include <optional>

#include <util/config/profiles.hpp>

#include <ssh/ssh_session.hpp>
#include <ssh/sftp/sftp_session.hpp>

#include <shell/cloud_provider_session.hpp>

#include <engine/win32/handle.hpp>

#include <engine/workers/operation_executor.hpp>
#include <engine/workers/filesystem_watcher.hpp>
#include <engine/workers/callback_table.hpp>
#include <engine/resilience/session_keepalive.hpp>

#include <quill/Logger.h>

namespace linuxplorer::engine::services {
	bool LINUXPLORER_ENGINE_API has_logger_backend_initialized();
	bool LINUXPLORER_ENGINE_API try_initialize_logger_backend();
	bool LINUXPLORER_ENGINE_API try_uninitialize_logger_backend();

	class LINUXPLORER_ENGINE_API profile_runtime {
	public:
		inline static constexpr std::chrono::seconds s_keepalive_duration{30};
	private:
		quill::Logger* m_logger;
		quill::Logger* m_executor_logger;
		quill::Logger* m_watcher_logger;
		std::filesystem::path m_log_directory;
		std::wstring m_log_file_suffix;

		util::config::profile m_profile;

		std::optional<ssh::ssh_session> m_ssh_session;
		std::optional<ssh::sftp::sftp_session> m_sftp_session;
		std::optional<shell::cloud_provider_session> m_cloud_provider_session;

		contexts::execution_context m_execution_context;
		std::mutex m_ssh_mutex;
		std::optional<workers::operation_executor> m_executor;
		std::optional<workers::filesystem_watcher> m_watcher;
		std::optional<workers::callback_table> m_callback_table;
		std::optional<resilience::session_keeper> m_keeper;

		std::thread m_runtime_thread;
		win32::unique_event_handle m_stop_event;
		win32::unique_event_handle m_death_event;

		void thread_main();
		void establish();
		void run();
		void cleanup() noexcept;

		quill::Logger* create_or_get_logger(std::filesystem::path log_file_stem);
	public:
		profile_runtime(const util::config::profile& profile);

		void start();
		void request_stop() noexcept;
		void wait() noexcept;

		const win32::unique_event_handle& get_death_event() const noexcept;

		virtual ~profile_runtime();
	};
}

#endif // LINUXPLORER_ENGINE_PROFILE_RUNTIME_HPP_