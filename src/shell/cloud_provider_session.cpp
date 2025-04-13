#include <shell/cloud_provider_session.h>
#include <shell/cloud_provider_exception.hpp>

#include <memory>

namespace linuxplorer::shell {
	cloud_provider_session::cloud_provider_session(std::wstring_view sync_root_dir)
		: m_sync_root_dir(sync_root_dir) {

	}

	cloud_provider_session::cloud_provider_session(cloud_provider_session&& right)
		: m_sync_root_dir(std::move(right.m_sync_root_dir)) {
	}

	cloud_provider_session& cloud_provider_session::operator=(cloud_provider_session&& right) {
		if (this != &right) {
			this->m_sync_root_dir = std::move(right.m_sync_root_dir);
			this->m_connection_key = right.m_connection_key;
			this->m_callbacks = std::move(right.m_callbacks);
		}
		return *this;
	}

	void cloud_provider_session::register_callback(const cloud_provider_callback& callback) {
		this->m_callbacks.push_back(callback);
	}

	void cloud_provider_session::register_callbacks(const std::vector<cloud_provider_callback>& callbacks) {
		for (const auto& callback : callbacks) {
			this->m_callbacks.push_back(callback);
		}
	}

	void cloud_provider_session::connect() {
		std::size_t callback_table_size = this->m_callbacks.size() + 1;
		auto callback_table = std::make_unique<::CF_CALLBACK_REGISTRATION[]>(callback_table_size);
		for (std::size_t i = 0; i < callback_table_size - 1; ++i) {
			callback_table[i].Callback = this->m_callbacks[i].get_callback();
			
			callback_table[i].Type = static_cast<::CF_CALLBACK_TYPE>(this->m_callbacks[i].get_type());
		}
		callback_table[callback_table_size - 1].Callback = nullptr;
		callback_table[callback_table_size - 1].Type = ::CF_CALLBACK_TYPE::CF_CALLBACK_TYPE_NONE;
		

		::HRESULT hr = ::CfConnectSyncRoot(
			this->m_sync_root_dir.c_str(),
			callback_table.get(),
			nullptr,
			::CF_CONNECT_FLAGS::CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH | ::CF_CONNECT_FLAGS::CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO,
			&(this->m_connection_key)
		);
		if (FAILED(hr)) {
			throw cloud_provider_exception("Failed to connect to the cloud provider.", hr);
		}

		this->m_is_connected = true;
	}

	void cloud_provider_session::disconnect() {
		::HRESULT hr = ::CfDisconnectSyncRoot(this->m_connection_key);
		if (FAILED(hr)) {
			throw cloud_provider_exception("Failed to disconnect from the cloud provider.", hr);
		}

		this->m_is_connected = false;
	}

	cloud_provider_session::~cloud_provider_session() noexcept {
		if (this->m_is_connected) {
			this->disconnect();
		}
	}
}