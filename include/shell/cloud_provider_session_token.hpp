#ifndef LINUXPLORER_CLOUD_PROVIDER_SESSION_TOKEN_HPP_
#define LINUXPLORER_CLOUD_PROVIDER_SESSION_TOKEN_HPP_

#include <shell/shellfwd.hpp>
#include <functional>
#include <windows.h>
#include <cfapi.h>

namespace linuxplorer::shell {
	class cloud_provider_session_token {
	public:
		cloud_provider_session_token(const ::CF_CONNECTION_KEY& key) : m_key(key) {}

		inline const ::CF_CONNECTION_KEY& get() const noexcept { return this->m_key; }
		
		bool operator==(const cloud_provider_session_token& lhs) const noexcept { return this->m_key.Internal == lhs.m_key.Internal; }
		bool operator!=(const cloud_provider_session_token& lhs) const noexcept { return this->m_key.Internal != lhs.m_key.Internal; }
	private:
		::CF_CONNECTION_KEY m_key;
	};
}

namespace std {
	template <>
	struct hash<linuxplorer::shell::cloud_provider_session_token> {
		size_t operator()(const linuxplorer::shell::cloud_provider_session_token& t) const noexcept {
			return std::hash<std::int64_t>{}(t.get().Internal);
		}
	};
}

#endif // LINUXPLORER_CLOUD_PROVIDER_SESSION_TOKEN_HPP_