#include "session.hpp"

#include <util/charset/multibyte_wide_compat_helper.hpp>

#include <ssh/ssh_exception.hpp>
#include <ssh/ssh_address.hpp>
#include <ssh/ssh_session.hpp>
#include <ssh/sftp/sftp_session.hpp>

#include <shell/cloud_provider_session.hpp>
#include <shell/functional/cloud_provider_callback.hpp>
#include <shell/cloud_provider_exception.hpp>
#include <shell/filesystem/cloud_provider_registrar.hpp>

#include <quill/LogMacros.h>

#define GENERATE_CALLBACK_THIS(callback_type, callback)	shell::functional::specialized_cloud_provider_callback<callback_type>([this](const shell::functional::internal::typed_callback_aliases<callback_type>::callback_parameters& parameters) -> shell::functional::internal::typed_callback_aliases<callback_type>::operation_info { return callback(parameters); })

namespace linuxplorer::app::lxpsvc {
	void session::start() noexcept {
		try {
			LOG_INFO(s_logger, "Starting session #{}", this->m_session_id);

			LOG_INFO(s_logger, "Loading configuration for session #{}", this->m_session_id);
			const auto& profile = util::config::profile_manager::get(this->m_profile_name);

			this->m_ssh_session.emplace(ssh::ssh_address(profile.get_credential().get_host()), profile.get_port());
			LOG_INFO(s_logger, "Configuration loaded successfully for session #{}", this->m_session_id);


			LOG_INFO(s_logger, "Connecting to SSH server at session #{}", this->m_session_id);

			this->m_ssh_session->connect();
			LOG_INFO(s_logger, "Connected to SSH server successfully at session #{}", this->m_session_id);


			LOG_INFO(s_logger,
				"Authenticating to SSH server as {} at session #{}", 
				util::charset::multibyte_wide_compat_helper::convert_wide_to_multibyte(profile.get_credential().get_username()),
				this->m_session_id
			);
			this->m_ssh_session->authenticate(profile.get_credential().get_username(), profile.get_credential().get_password());
			LOG_INFO(s_logger, "Authenticated successfully to SSH server at session #{}", this->m_session_id);


			LOG_INFO(s_logger, "Establishing SFTP session at session #{}", this->m_session_id);
			this->m_sftp_session.emplace(this->m_ssh_session.value());
			LOG_INFO(s_logger, "SFTP session established successfully at session #{}", this->m_session_id);


			LOG_INFO(s_logger, "Starting cloud provider service at session #{}", this->m_session_id);
			this->m_syncroot_dir = profile.get_syncroot();
			shell::filesystem::cp_registration_options options(
				shell::filesystem::hydration_behavior::progressive_on_demand,
				shell::filesystem::placeholder_enumeration_behavior::full_on_demand
			);
			//shell::filesystem::cloud_provider_registrar::unregister_provider(this->m_syncroot_dir);
			this->m_cloud_session = shell::filesystem::cloud_provider_registrar::register_provider(this->m_syncroot_dir, s_provider_name, s_provider_version, options);
			//this->m_cloud_session = shell::cloud_provider_session(this->m_syncroot_dir);

			auto fdx = GENERATE_CALLBACK_THIS(shell::functional::cloud_provider_callback_type::fetch_data, this->on_fetch_data);
			auto fpx = GENERATE_CALLBACK_THIS(shell::functional::cloud_provider_callback_type::fetch_placeholders, this->on_fetch_placeholders);
			this->m_cloud_session->register_callback(fdx);
			this->m_cloud_session->register_callback(fpx);

			this->m_cloud_session->connect();
			LOG_INFO(s_logger, "Cloud provider service started successfully at session #{}", this->m_session_id);


			LOG_INFO(s_logger, "Session #{} is started successfully.", this->m_session_id);
			this->m_exit_code = this->main();
			this->stop();
		}
		catch (const util::config::config_io_exception& e) {
			LOG_CRITICAL(s_logger, "Configuration I/O error occurred at session #{}: {}", this->m_session_id, e.what());
		}
		catch (const util::config::cryptographic_exception& e) {
			LOG_CRITICAL(s_logger, "Cryptographic process of configuration data failed at session #{}: {}", this->m_session_id, e.what());
		}
		catch (const util::config::config_exception& e) {
			LOG_CRITICAL(s_logger, "Unexpected configuration error occurred at session #{}: {}", this->m_session_id, e.what());
		}
		catch (const ssh::invalid_address_format_exception& e) {
			LOG_CRITICAL(s_logger, "Invalid SSH address format at session #{}: {}", this->m_session_id, e.what());
		}
		catch (const ssh::ssh_libssh2_exception& e) {
			LOG_CRITICAL(s_logger, "SSH error at session #{}: {} (libssh2 error code: {})", this->m_session_id, e.what(), e.code());
		}
		catch (const ssh::ssh_wsa_exception& e) {
			LOG_CRITICAL(s_logger, "WSA error during SSH session at session #{}: {} (WSA error code: {})", this->m_session_id, e.what(), e.code());
		}
		catch (const ssh::ssh_invalid_state_operation& e) {
			LOG_CRITICAL(s_logger, "Invalid state operation during SSH session at session #{}: {}", this->m_session_id, e.what());
		}
		catch (const ssh::ssh_exception& e) {
			LOG_CRITICAL(s_logger, "Unexpected SSH error occurred at session #{}: {}", this->m_session_id, e.what());
		}
		catch (const shell::cloud_provider_runtime_exception& e) {
			LOG_CRITICAL(s_logger, "Cloud provider runtime error occurred at session #{}: {}", this->m_session_id, e.what());
		}
		catch (const std::system_error& e) {
			LOG_CRITICAL(s_logger, "An system error occurred at session #{}: {} (GetLastError: {})", this->m_session_id, e.what(), e.code().value());
		}
		catch (...) {
			LOG_CRITICAL(s_logger, "Unknown error occurred at session #{}.", this->m_session_id);
		}
	}

	void session::stop() noexcept {
		try {
			LOG_INFO(s_logger, "Stopping session #{}", this->m_session_id);

			if (this->m_ssh_session && this->m_ssh_session->get_state() == ssh::ssh_session_state::connected) {
				this->m_ssh_session->disconnect();
				LOG_INFO(s_logger, "SSH session disconnected successfully at session #{}", this->m_session_id);
			}

			if (this->m_cloud_session) {
				this->m_cloud_session->disconnect();
				LOG_INFO(s_logger, "Cloud provider service has been terminated successfully at session #{}", this->m_session_id);
			}

			LOG_INFO(s_logger, "Session #{} stopped.", this->m_session_id);
		}
		catch (const ssh::ssh_libssh2_exception& e) {
			LOG_ERROR(s_logger, "Failed to disconnect SSH session at session #{}: {} (libssh2 error code: {})", this->m_session_id, e.what(), e.code());
		}
		catch (const shell::cloud_provider_runtime_exception& e) {
			LOG_ERROR(s_logger, "Cloud provider runtime error occurred at session #{}: {}", this->m_session_id, e.what());
		}
		catch (...) {
			LOG_CRITICAL(s_logger, "Unknown error occurred at session #{}.", this->m_session_id);
		}
	}
}