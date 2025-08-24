#include <shell/filesystem/cloud_provider_registrar.hpp>

#include <windows.h>
#include <cfapi.h>

#include <system_error>

namespace linuxplorer::shell::filesystem {
	cp_registration_options::cp_registration_options(hydration_behavior hydration, placeholder_enumeration_behavior enumeration) {
		this->m_hydration_policy = hydration;
		this->m_placeholder_enumeration_policy = enumeration;
	}

	hydration_behavior cp_registration_options::get_hydration_behavior() const noexcept {
		return this->m_hydration_policy;
	}

	placeholder_enumeration_behavior cp_registration_options::get_placeholder_enumeration_behavior() const noexcept {
		return this->m_placeholder_enumeration_policy;
	}

	cloud_provider_session cloud_provider_registrar::internal_register_provider(
		std::wstring_view sync_root_dir,
		std::wstring_view provider_name,
		std::wstring_view provider_version,
		const cp_registration_options* options
	) {
		::CF_SYNC_REGISTRATION registration;
		registration.StructSize = sizeof(::CF_SYNC_REGISTRATION);
		registration.ProviderName = provider_name.data();
		registration.ProviderVersion = provider_version.data();
		registration.SyncRootIdentity = nullptr;
		registration.SyncRootIdentityLength = 0;
		registration.FileIdentity = nullptr;
		registration.FileIdentityLength = 0;

		::CF_SYNC_POLICIES policies;
		policies.StructSize = sizeof(::CF_SYNC_POLICIES);
		if (options) {
			policies.Hydration.Primary = static_cast<::CF_HYDRATION_POLICY_PRIMARY>(options->get_hydration_behavior());
			policies.Population.Primary = static_cast<::CF_POPULATION_POLICY_PRIMARY>(options->get_placeholder_enumeration_behavior());
		}
		else {
			policies.Hydration.Primary = ::CF_HYDRATION_POLICY_PRIMARY::CF_HYDRATION_POLICY_FULL;
			policies.Population.Primary = ::CF_POPULATION_POLICY_PRIMARY::CF_POPULATION_POLICY_FULL;
		}
		policies.InSync = ::CF_INSYNC_POLICY::CF_INSYNC_POLICY_TRACK_FILE_CREATION_TIME | ::CF_INSYNC_POLICY::CF_INSYNC_POLICY_TRACK_DIRECTORY_CREATION_TIME;

		::HRESULT hr = ::CfRegisterSyncRoot(
			sync_root_dir.data(),
			&registration,
			&policies,
			::CF_REGISTER_FLAGS::CF_REGISTER_FLAG_NONE
		);
		if (FAILED(hr)) {
			std::error_code ec(hr, std::system_category());
			throw std::system_error(ec, "Failed to register cloud provider");
		}

		return cloud_provider_session(sync_root_dir);
	}

	cloud_provider_session cloud_provider_registrar::register_provider(
		std::wstring_view sync_root_dir,
		std::wstring_view provider_name,
		std::wstring_view provider_version
	) {
		return internal_register_provider(sync_root_dir, provider_name, provider_version, nullptr);
	}

	cloud_provider_session cloud_provider_registrar::register_provider(
		std::wstring_view sync_root_dir,
		std::wstring_view provider_name,
		std::wstring_view provider_version,
		const cp_registration_options& options
	) {
		return internal_register_provider(sync_root_dir, provider_name, provider_version, &options);
	}

	void cloud_provider_registrar::unregister_provider(std::wstring_view sync_root_dir) {
		::HRESULT hr = ::CfUnregisterSyncRoot(sync_root_dir.data());
		if (FAILED(hr)) {
			std::error_code ec(hr, std::system_category());
			throw std::system_error(ec, "Failed to unregister cloud provider");
		}
	}
}