#ifndef LINUXPLORER_CLOUD_PROVIDER_REGISTRAR_HPP_
#define LINUXPLORER_CLOUD_PROVIDER_REGISTRAR_HPP_

#include <shell/shellfwd.hpp>
#include <shell/cloud_provider_session.hpp>
#include <string_view>

namespace linuxplorer::shell::filesystem {
	enum class hydration_behavior {
		full_on_demand = ::CF_HYDRATION_POLICY_PRIMARY::CF_HYDRATION_POLICY_FULL,
		progressive_on_demand = ::CF_HYDRATION_POLICY_PRIMARY::CF_HYDRATION_POLICY_PROGRESSIVE,
		non_on_demand = ::CF_HYDRATION_POLICY_PRIMARY::CF_HYDRATION_POLICY_ALWAYS_FULL
	};

	enum class placeholder_enumeration_behavior {
		full_on_demand = ::CF_POPULATION_POLICY_PRIMARY::CF_POPULATION_POLICY_FULL,
		partial_on_demand = ::CF_POPULATION_POLICY_PRIMARY::CF_POPULATION_POLICY_PARTIAL,
		non_on_demand = ::CF_POPULATION_POLICY_PRIMARY::CF_POPULATION_POLICY_ALWAYS_FULL
	};

	struct LINUXPLORER_SHELL_API registration_options {
	private:
		hydration_behavior m_hydration_policy;
		placeholder_enumeration_behavior m_placeholder_enumeration_policy;
	public:
		registration_options(hydration_behavior hydration, placeholder_enumeration_behavior enumeration);

		hydration_behavior get_hydration_behavior() const noexcept;
		placeholder_enumeration_behavior get_placeholder_enumeration_behavior() const noexcept;
	};

	class LINUXPLORER_SHELL_API cloud_provider_registrar {
	private:
		static cloud_provider_session internal_register_provider(
			std::wstring_view sync_root_dir,
			std::wstring_view provider_name,
			std::wstring_view provider_version,
			const registration_options* options
		);
	public:
		cloud_provider_registrar() = delete;
		cloud_provider_registrar(const cloud_provider_registrar&) = delete;
		cloud_provider_registrar(cloud_provider_registrar&&) = delete;
		~cloud_provider_registrar() = delete;

		static cloud_provider_session register_provider(
			std::wstring_view sync_root_dir,
			std::wstring_view provider_name,
			std::wstring_view provider_version
		);

		static cloud_provider_session register_provider(
			std::wstring_view sync_root_dir,
			std::wstring_view provider_name,
			std::wstring_view provider_version,
			const registration_options& options
		);

		static void unregister_provider(std::wstring_view sync_root_dir);
	};
}

#endif // LINUXPLORER_CLOUD_PROVIDER_REGISTRAR_HPP_