#include <windows.h>

#include <ssh/auth/ssh_knownhosts.hpp>
#include <ssh/ssh_exception.hpp>
#include <util/charset/multibyte_wide_compat_helper.hpp>

namespace linuxplorer::ssh::auth {
	ssh_knownhosts::ssh_knownhosts(const ssh_session& session, std::wstring_view path) : m_session(session) {
		using charset_helper = linuxplorer::util::charset::multibyte_wide_compat_helper;

		if (path.compare(default_knownhosts_path) == 0) {
			std::int32_t userprofile_path_length = ::GetEnvironmentVariableW(L"USERPROFILE", nullptr, 0);
			if (userprofile_path_length == 0) {
				std::error_code ec(::GetLastError(), std::system_category());
				throw ssh_system_error(ec, "Failed to get user profile path.");
			}

			auto userprofile_path = std::make_unique<wchar_t[]>(userprofile_path_length);
			::DWORD ret = ::GetEnvironmentVariableW(L"USERPROFILE", userprofile_path.get(), userprofile_path_length);
			if (ret == 0) {
				std::error_code ec(::GetLastError(), std::system_category());
				throw ssh_system_error(ec, "Failed to get user profile path.");
			}

			this->m_knownhosts_path = std::move(std::wstring(userprofile_path.get()) + L"\\.ssh\\known_hosts");
		}
		else {
			this->m_knownhosts_path = path;
		}

		this->m_knownhosts = internal::unique_ssh_knownhosts_ptr(::libssh2_knownhost_init(this->m_session.get_session()));
		if (this->m_knownhosts == nullptr) {
			throw ssh_libssh2_exception(std::error_code(session.get_last_errno(), libssh2_category(session)), "Failed to initialize known hosts.");
		}

		int result = libssh2_knownhost_readfile(this->m_knownhosts.get(), charset_helper::convert_wide_to_multibyte(this->m_knownhosts_path).c_str(), LIBSSH2_KNOWNHOST_FILE_OPENSSH);
		if (result < 0) {
			throw ssh_libssh2_exception(std::error_code(result, libssh2_category(session)), "Failed to read known hosts file.");
		}
	}

	void ssh_knownhosts::register_this(std::wstring_view comment) {
		using charset_helper = linuxplorer::util::charset::multibyte_wide_compat_helper;

		std::size_t length;
		int type;
		const char* fingerprint = ::libssh2_session_hostkey(this->m_session.get_session(), &length, &type);

		int result = ::libssh2_knownhost_addc(
			this->m_knownhosts.get(),
			charset_helper::convert_wide_to_multibyte(this->m_session.get_host().get_string_address()).c_str(),
			nullptr,
			fingerprint,
			length,
			charset_helper::convert_wide_to_multibyte(comment).c_str(),
			comment.size() * sizeof(char),
			LIBSSH2_KNOWNHOST_TYPE_PLAIN | LIBSSH2_KNOWNHOST_KEYENC_RAW | LIBSSH2_KNOWNHOST_KEY_SSHRSA,
			nullptr
		);
		if (result < 0) {
			throw ssh_libssh2_exception(std::error_code(result, libssh2_category(this->m_session)), "Failed to add a known host.");
		}
	}

	void ssh_knownhosts::unregister() {
		using charset_helper = linuxplorer::util::charset::multibyte_wide_compat_helper;

		::libssh2_knownhost* store, prev;
		int rc;
		int result;
		::libssh2_knownhost* target;

		while ((rc = ::libssh2_knownhost_get(this->m_knownhosts.get(), &store, &prev)) == 0) {
			if (this->m_session.get_host().get_string_address().compare(charset_helper::convert_multibyte_to_wide(store->name)) == 0) {
				target = store;
				result = ::libssh2_knownhost_del(this->m_knownhosts.get(), store);
				break;
			}
		}
		if (rc < 0) {
			throw ssh_libssh2_exception(std::error_code(rc, libssh2_category(this->m_session)), "Failed to enumerate known hosts.");
		}
		if (result < 0) {
			throw ssh_libssh2_exception(std::error_code(result, libssh2_category(this->m_session)), "Failed to remove a known host.");
		}
	}

	std::vector<ssh_address> ssh_knownhosts::enumerate() const {
		using charset_helper = linuxplorer::util::charset::multibyte_wide_compat_helper;

		::libssh2_knownhost* store = nullptr;
		::libssh2_knownhost* prev = nullptr;
		int rc;
		std::vector<ssh_address> result;

		while ((rc = ::libssh2_knownhost_get(this->m_knownhosts.get(), &store, prev)) == 0) {
			prev = store;
			result.push_back(ssh_address(charset_helper::convert_multibyte_to_wide(store->name)));
		}
		if (rc < 0) {
			throw ssh_libssh2_exception(std::error_code(rc, libssh2_category(this->m_session)), "Failed to enumerate known hosts.");
		}

		return std::move(result);
	}

	ssh_knownhosts_verify_result ssh_knownhosts::verify() const {
		using charset_helper = linuxplorer::util::charset::multibyte_wide_compat_helper;

		::libssh2_knownhost* entry;
		std::size_t length;
		int type;

		const char* fingerprint = ::libssh2_session_hostkey(this->m_session.get_session(), &length, &type);

		int result = ::libssh2_knownhost_checkp(
			this->m_knownhosts.get(),
			charset_helper::convert_wide_to_multibyte(this->m_session.get_host().get_string_address()).c_str(),
			this->m_session.get_port(),
			fingerprint,
			length,
			LIBSSH2_KNOWNHOST_TYPE_PLAIN | LIBSSH2_KNOWNHOST_KEYENC_RAW,
			&entry
		);

		switch (result) {
			case LIBSSH2_KNOWNHOST_CHECK_FAILURE:
				throw ssh_libssh2_exception(std::error_code(result, libssh2_category(this->m_session)), "Failed to check known host.");
			case LIBSSH2_KNOWNHOST_CHECK_MATCH:
				return ssh_knownhosts_verify_result::matched;
			case LIBSSH2_KNOWNHOST_CHECK_MISMATCH:
				return ssh_knownhosts_verify_result::mismatch;
			case LIBSSH2_KNOWNHOST_CHECK_NOTFOUND:
				return ssh_knownhosts_verify_result::missing;
			default:
				throw ssh_libssh2_exception(std::error_code(0, libssh2_category(this->m_session)), "Unknown known hosts check result.");
		}
	}

	void ssh_knownhosts::flush() const {
		using charset_helper = util::charset::multibyte_wide_compat_helper;

		int rc = ::libssh2_knownhost_writefile(this->m_knownhosts.get(), charset_helper::convert_wide_to_multibyte(this->m_knownhosts_path).c_str(), LIBSSH2_KNOWNHOST_FILE_OPENSSH);
		if (rc < 0) {
			throw ssh_libssh2_exception(std::error_code(rc, libssh2_category(this->m_session)), "Failed to write data to a known hosts file.");
		}
	}
}