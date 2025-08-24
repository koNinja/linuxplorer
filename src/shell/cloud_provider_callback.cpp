#include <shell/cloud_provider_callback.hpp>

namespace linuxplorer::shell {
	cloud_provider_callback::cloud_provider_callback(cloud_provider_callback_type type, cloud_provider_callback_t callback)
		: m_type(type), m_callback(callback) {
	}

	cloud_provider_callback::~cloud_provider_callback() noexcept {
	}

	cloud_provider_callback_type cloud_provider_callback::get_type() const noexcept {
		return this->m_type;
	}

	const cloud_provider_callback_t cloud_provider_callback::get_callback() const noexcept {
		return this->m_callback;
	}
}