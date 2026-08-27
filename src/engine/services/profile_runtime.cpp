#include <engine/services/profile_runtime.hpp>

#include <chrono>
#include <array>

#include <util/charset/multibyte_wide_compat_helper.hpp>

#include <quill/LogMacros.h>

#include <quill/Backend.h>
#include <quill/Frontend.h>
#include <quill/std/FilesystemPath.h>
#include <quill/std/WideString.h>
#include <quill/sinks/FileSink.h>

#define TO_WSTRING(x)	L#x
#define WSTRINGIFY(x)	TO_WSTRING(x)

namespace linuxplorer::engine::services {
	static bool has_initialized_once = false;

	bool try_initialize_logger_backend() {
		if (!has_initialized_once) {
			quill::Backend::start();
			has_initialized_once = true;
			return true;
		}
		else return false;
	}

	bool try_uninitialize_logger_backend() {
		if (has_initialized_once) {
			quill::Backend::stop();
			has_initialized_once = false;
			return true;
		}
		else return false;
	}

	bool has_logger_backend_initialized() {
		return has_initialized_once;
	}
	
	profile_runtime::profile_runtime(const util::config::profile& profile) : 
		m_profile(profile.get_name(), std::filesystem::canonical(profile.get_syncroot()), profile.get_port(), profile.get_credential())
	{
		this->m_log_directory = util::config::configuration_manager::get_log_path() / profile.get_name();

		auto now_sec = std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now());
		std::chrono::zoned_time zt(std::chrono::current_zone(), now_sec);
		this->m_log_file_suffix = std::format(L"{:%Y_%m_%d_%H_%M_%S_%Z}", zt);

		try {
			this->m_logger = this->create_or_get_logger("runtime");
			this->m_executor_logger = this->create_or_get_logger("executor");
			this->m_watcher_logger = this->create_or_get_logger("watcher");

			this->m_stop_event = ::CreateEventW(nullptr, true, false, nullptr);
			if (!this->m_stop_event) {
				std::error_code ec(::GetLastError(), std::system_category());
				LOG_CRITICAL(
					this->m_logger,
					"Failed to create a stop event for the runtime. (Win32: {}({}))",
					ec.message(),
					ec.value()
				);
				return;
			}

			this->m_death_event = ::CreateEventW(nullptr, true, false, nullptr);
			if (!this->m_death_event) {
				std::error_code ec(::GetLastError(), std::system_category());
				LOG_CRITICAL(
					this->m_logger,
					"Failed to create an event to propagate runtime termination to the main thread. (Win32: {}({}))",
					ec.message(),
					ec.value()
				);
				return;
			}
		}
		catch (...) {
			::MessageBoxW(nullptr, L"An unexpected error has occurred in the runtime.", L"Runtime Error", MB_ICONERROR | MB_OK);
			return;
		}
	}

	quill::Logger* profile_runtime::create_or_get_logger(std::filesystem::path log_file_stem) {
		auto sink = quill::Frontend::create_or_get_sink<quill::FileSink>(
			(this->m_log_directory / std::format(L"{}_{}.log", log_file_stem.wstring(), this->m_log_file_suffix)).string(),
			[]() {
				quill::FileSinkConfig cfg;
				cfg.set_open_mode('w');
				return cfg;
			}(),
			quill::FileEventNotifier{}
		);

		auto logger_name = std::format(
			L"{}::{}::{}",
			WSTRINGIFY(LINUXPLORER_LOGGING_DOMAIN),
			this->m_profile.get_name(),
			log_file_stem.wstring()
		);

		return quill::Frontend::create_or_get_logger(
			util::charset::multibyte_wide_compat_helper::convert_wide_to_multibyte(logger_name),
			std::move(sink)
		);
	}

	void profile_runtime::start() {
		this->m_runtime_thread = std::thread(&profile_runtime::thread_main, this);
	}

	void profile_runtime::request_stop() noexcept {
		if (this->m_stop_event) {
			::SetEvent(this->m_stop_event.get());
		}
	}

	void profile_runtime::wait() noexcept {
		if (this->m_runtime_thread.joinable()) {
			this->m_runtime_thread.join();
		}
	}

	profile_runtime::~profile_runtime() {
		this->request_stop();
		this->wait();
	}

	void profile_runtime::thread_main() {
		try {
			this->establish();
			this->run();
		}
		catch (const ssh::invalid_address_format_exception& e) {
			LOG_CRITICAL(this->m_logger, "Invalid SSH address format: {}", e.what());
		}
		catch (const ssh::ssh_libssh2_sftp_exception& e) {
			LOG_CRITICAL(this->m_logger, "An SFTP error occurred: {} (libssh2: {}({}))", 
				e.what(),
				e.code().message(),
				e.code().value()
			);
		}
		catch (const ssh::ssh_libssh2_exception& e) {
			LOG_CRITICAL(
				this->m_logger,
				"An SSH error occurred: {} (libssh2: {}({}))", 
				e.what(),
				e.code().message(),
				e.code().value()
			);
		}
		catch (const ssh::ssh_wsa_exception& e) {
			LOG_CRITICAL(
				this->m_logger,
				"An WSA error during the SSH session: {} (WSA2: {}({}))",
				e.what(),
				e.code().message(),
				e.code().value()
			);
		}
		catch (const ssh::ssh_invalid_state_operation& e) {
			LOG_CRITICAL(this->m_logger, "An operation in the invalid state detected in the SSH session: {}", e.what());
		}
		catch (const ssh::ssh_exception& e) {
			LOG_CRITICAL(this->m_logger, "An unexpected SSH error occurred: {}", e.what());
		}
		catch (const shell::cloud_provider_system_error& e) {
			LOG_CRITICAL(
				this->m_logger,
				"Failed a cloud provider operation: {} (From Win32: {}({}))",
				e.what(),
				e.code().message(),
				e.code().value()
			);
		}
		catch (const shell::cloud_provider_runtime_exception& e) {
			LOG_CRITICAL(this->m_logger, "An unexpected cloud provider service error occurred: {}", e.what());
		}
		catch (const std::system_error& e) {
			LOG_CRITICAL(
				this->m_logger,
				"An system error occurred: {} (From Win32: {}({}))",
				e.what(),
				e.code().message(),
				e.code().value()
			);
		}
		catch (...) {
			LOG_CRITICAL(
				this->m_logger,
				"An unhandled exception has thrown in the runtime for profile '{}'.",
				this->m_profile.get_name()
			);
		}

		this->cleanup();
	}

	void profile_runtime::establish() {
		LOG_INFO(this->m_logger, "Starting runtime...");

		this->m_ssh_session.emplace(ssh::ssh_address(this->m_profile.get_credential().get_host()), this->m_profile.get_port());

		this->m_ssh_session->connect();
		LOG_INFO(this->m_logger, "The SSH session established successfully.");
		
		this->m_ssh_session->authenticate(this->m_profile.get_credential().get_username(), this->m_profile.get_credential().get_password());
		LOG_INFO(
			this->m_logger,
			"Successfully authenticated to SSH server as '{}'.", this->m_profile.get_credential().get_username()
		);
		
		this->m_sftp_session.emplace(*this->m_ssh_session);
		LOG_INFO(this->m_logger, "The SFTP channel established successfully.");
		
		::libssh2_keepalive_config(this->m_ssh_session->get_session(), true, s_keepalive_duration.count());

		this->m_callback_table.emplace(this->m_profile.get_syncroot(), this->m_execution_context, this->m_watcher_logger);
		LOG_INFO(this->m_logger, "The callback table initialized.");

		this->m_cloud_provider_session.emplace(this->m_profile.get_syncroot());

		for (auto& callback : this->m_callback_table->generate_table()) {
			this->m_cloud_provider_session->register_callback(std::move(callback));
		}

		this->m_cloud_provider_session->connect();
		LOG_INFO(this->m_logger, "The cloud provider service started successfully.");

		this->m_executor.emplace(
			*this->m_sftp_session,
			*this->m_cloud_provider_session,
			this->m_execution_context,
			this->m_ssh_mutex,
			this->m_executor_logger
		);
		this->m_executor->start();
		LOG_INFO(this->m_logger, "The operation executor started.");

		this->m_watcher.emplace(this->m_profile.get_syncroot(), this->m_execution_context, this->m_watcher_logger);
		this->m_watcher->start();
		LOG_INFO(this->m_logger, "The filesystem watcher started.");

		this->m_keeper.emplace(s_keepalive_duration, *this->m_ssh_session, *this->m_sftp_session, this->m_execution_context, this->m_ssh_mutex);
		this->m_keeper->start();
		LOG_INFO(this->m_logger, "The session keeper started.");
	}

	void profile_runtime::run() {
		const auto& error_event = this->m_execution_context.get_error_event();
		std::array<::HANDLE, 2> handles = { this->m_stop_event.get(), error_event.get() };

		while (true) {
			auto response = ::WaitForMultipleObjects(handles.size(), handles.data(), false, INFINITE);

			switch (response) {
			case WAIT_OBJECT_0:
			{
				LOG_INFO(this->m_logger, "A stop request received. Stopping the runtime...");
				return;
			}
			case WAIT_OBJECT_0 + 1:
			{
				auto exception = this->m_execution_context.dequeue_error();
				
				LOG_CRITICAL(
					this->m_logger,
					"A permanent failure has propagated to the runtime: {} (Domain: {})",
					exception->what(),
					std::to_underlying(exception->get_domain())
				);

				return;
			}
			case WAIT_FAILED:
			{
				std::error_code ec(::GetLastError(), std::system_category());
				LOG_CRITICAL(
					this->m_logger,
					"Failed to wait for the events. (Win32: {}({}))",
					ec.message(),
					ec.value()
				);
				return;
			}
			default:
				break;
			}
		}
	}

	void profile_runtime::cleanup() noexcept {
		try {
			if (this->m_death_event) {
				::SetEvent(this->m_death_event.get());
			}

			if (this->m_executor.has_value() && this->m_executor->get_state() == workers::operation_executor_state::running) {
				this->m_executor->request_stop();
				this->m_executor->wait();
			}

			if (this->m_watcher.has_value() && this->m_watcher->get_state() == workers::filesystem_watcher_state::running) {
				this->m_watcher->request_stop();
				this->m_watcher->wait();
			}

			if (this->m_keeper.has_value() && this->m_keeper->get_state() == resilience::session_keeper_state::running) {
				this->m_keeper->request_stop();
				this->m_keeper->wait();
			}

			if (this->m_cloud_provider_session.has_value()) {
				this->m_cloud_provider_session->disconnect();
				this->m_cloud_provider_session.reset();
			}

			if (this->m_ssh_session.has_value()) {
				this->m_sftp_session.reset();
				if (this->m_ssh_session->get_state() == ssh::ssh_session_state::connected) {
					this->m_ssh_session->disconnect();
				}
				this->m_ssh_session.reset();
			}
		}
		catch (const ssh::ssh_libssh2_sftp_exception& e) {
			LOG_CRITICAL(
				this->m_logger,
				"A SFTP error occurred: {} (libssh2: {}({}))", 
				e.what(),
				e.code().message(),
				e.code().value()
			);
		}
		catch (const ssh::ssh_libssh2_exception& e) {
			LOG_ERROR(
				this->m_logger,
				"Failed to disconnect to the server: {} (libssh2: {}({}))", 
				e.what(),
				e.code().message(),
				e.code().value()
			);
		}
		catch (const shell::cloud_provider_runtime_exception& e) {
			LOG_ERROR(this->m_logger, "Failed to close the cloud provider session: {}", e.what());
		}
		catch (const std::system_error& e) {
			LOG_CRITICAL(
				this->m_logger,
				"An system error occurred: {} (From Win32: {}({}))",
				e.what(),
				e.code().message(),
				e.code().value()
			);
		}
		catch (...) {
			LOG_CRITICAL(
				this->m_logger,
				"An unhandled exception has thrown during cleanup in the runtime for profile '{}'.",
				this->m_profile.get_name()
			);
		}
	}

	const win32::unique_event_handle& profile_runtime::get_death_event() const noexcept {
		return this->m_death_event;
	}
}