#include <shell/cloud_provider_session.hpp>
#include <shell/cloud_provider_exception.hpp>
#include <shell/functional/cloud_provider_callback.hpp>

#include <memory>
#include <system_error>

namespace linuxplorer::shell {
	cloud_provider_session::cloud_provider_session(std::wstring_view sync_root_dir)
		: m_sync_root_dir(sync_root_dir), m_is_connected(false), m_connection_key(::CF_CONNECTION_KEY{}) {}

	cloud_provider_session::cloud_provider_session(cloud_provider_session&& right)
		: m_sync_root_dir(std::move(right.m_sync_root_dir)), m_is_connected(right.m_is_connected), m_connection_key(right.m_connection_key) {}

	cloud_provider_session& cloud_provider_session::operator=(cloud_provider_session&& right) {
		if (this != &right) {
			this->m_sync_root_dir = std::move(right.m_sync_root_dir);
			this->m_connection_key = right.m_connection_key;
		}
		return *this;
	}

	void cloud_provider_session::connect() {
		if (this->m_is_connected) {
			throw cloud_provider_runtime_exception("Synchronization provider is already running.");
		}

		std::size_t callback_table_size = this->m_temporary_callback_table.size() + 1;
		auto callback_table = std::make_unique<::CF_CALLBACK_REGISTRATION[]>(callback_table_size);
		for (std::size_t i = 0; i < this->m_temporary_callback_table.size(); i++) {
			auto type = this->m_temporary_callback_table[i]->get_type();
			callback_table[i].Callback = this_t::get_typed_caller_from_type(type);
			callback_table[i].Type = static_cast<::CF_CALLBACK_TYPE>(type);
		}
		callback_table[callback_table_size - 1].Callback = nullptr;
		callback_table[callback_table_size - 1].Type = ::CF_CALLBACK_TYPE::CF_CALLBACK_TYPE_NONE;

		::CF_CONNECTION_KEY key;
		
		::HRESULT hr = ::CfConnectSyncRoot(
			this->m_sync_root_dir.c_str(),
			callback_table.get(),
			nullptr,
			::CF_CONNECT_FLAGS::CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH | ::CF_CONNECT_FLAGS::CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO,
			&key
		);
		this->m_connection_key = key;
		if (FAILED(hr)) {
			std::error_code ec(hr, std::system_category());
			throw std::system_error(ec, "Failed to initiate bi-directional communication between a sync provider and the Cloud Filter API.");
		}

		this->m_is_connected = true;
		this_t::s_callbacks[this->m_connection_key] = std::move(this->m_temporary_callback_table);
	}

	void cloud_provider_session::disconnect() {
		if (!this->m_is_connected) {
			throw cloud_provider_runtime_exception("Synchronization provider is not running.");
		}

		::HRESULT hr = ::CfDisconnectSyncRoot(this->m_connection_key.get());
		if (FAILED(hr)) {
			std::error_code ec(hr, std::system_category());
			throw std::system_error(ec, "Failed to disconnect a communication channel.");
		}

		this->m_is_connected = false;
		this->m_temporary_callback_table = std::move(this_t::s_callbacks[this->m_connection_key.get()]);
	}

	std::wstring_view cloud_provider_session::get_sync_root_dir() const noexcept {
		return this->m_sync_root_dir;
	}

	cloud_provider_session_token cloud_provider_session::get_connection_key() const noexcept {
		return this->m_connection_key;
	}

	cloud_provider_session::~cloud_provider_session() noexcept {
		std::erase_if(this_t::s_callbacks, [this](const decltype(this_t::s_callbacks)::value_type& px) -> bool {
			return px.first.get().Internal == this->get_connection_key().get().Internal;
		});
	}

	::CF_CALLBACK cloud_provider_session::get_typed_caller_from_type(functional::cloud_provider_callback_type type) noexcept {
		::CF_CALLBACK result;
		switch (type) {
			case functional::cloud_provider_callback_type::fetch_data:
				result = this_t::typed_internal_caller<functional::cloud_provider_callback_type::fetch_data>;
				break;
			case functional::cloud_provider_callback_type::validate_data:
				result = this_t::typed_internal_caller<functional::cloud_provider_callback_type::validate_data>;
				break;
			case functional::cloud_provider_callback_type::cancel_fetching_data:
				result = this_t::typed_internal_caller<functional::cloud_provider_callback_type::cancel_fetching_data>;
				break;
			case functional::cloud_provider_callback_type::fetch_placeholders:
				result = this_t::typed_internal_caller<functional::cloud_provider_callback_type::fetch_placeholders>;
				break;
			case functional::cloud_provider_callback_type::cancel_fetching_placeholders: 
				result = this_t::typed_internal_caller<functional::cloud_provider_callback_type::cancel_fetching_placeholders>;
				break;
			case functional::cloud_provider_callback_type::notify_file_open_completion:
				result = this_t::typed_internal_caller<functional::cloud_provider_callback_type::notify_file_open_completion>;
				break;
			case functional::cloud_provider_callback_type::notify_file_close_completion: 
				result = this_t::typed_internal_caller<functional::cloud_provider_callback_type::notify_file_close_completion>;
				break;
			case functional::cloud_provider_callback_type::notify_dehydration:
				result = this_t::typed_internal_caller<functional::cloud_provider_callback_type::notify_dehydration>;
				break;
			case functional::cloud_provider_callback_type::notify_dehydration_completion:
				result = this_t::typed_internal_caller<functional::cloud_provider_callback_type::notify_dehydration_completion>;
				break;
			case functional::cloud_provider_callback_type::notify_deletion:
				result = this_t::typed_internal_caller<functional::cloud_provider_callback_type::notify_deletion>;
				break;
			case functional::cloud_provider_callback_type::notify_deletion_completion:
				result = this_t::typed_internal_caller<functional::cloud_provider_callback_type::notify_deletion_completion>;
				break;
			case functional::cloud_provider_callback_type::notify_renaming:
				result = this_t::typed_internal_caller<functional::cloud_provider_callback_type::notify_renaming>;
				break;
			case functional::cloud_provider_callback_type::notify_renaming_completion:
				result = this_t::typed_internal_caller<functional::cloud_provider_callback_type::notify_renaming_completion>;
				break;
			default:
				result = nullptr;
		}

		return result;
	}

	template <functional::cloud_provider_callback_type T>
	void cloud_provider_session::typed_internal_caller(const ::CF_CALLBACK_INFO* info, const ::CF_CALLBACK_PARAMETERS* parameters) {
		const auto& callbacks = this_t::s_callbacks[info->ConnectionKey];

		constexpr auto type = T;
		const auto& callback_ptr_itr = std::find_if(callbacks.begin(), callbacks.end(), [type](const std::unique_ptr<functional::cloud_provider_callback>& ptr) { return ptr->get_type() == type; });
		callback_ptr_itr->get()->get_nt_callback()(info, parameters);
	}
}