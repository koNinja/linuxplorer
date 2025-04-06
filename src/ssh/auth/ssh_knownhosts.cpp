#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <ssh/auth/ssh_knownhosts.hpp>
#include <ssh/ssh_exception.hpp>
#include <fstream>

namespace linuxplorer::ssh::auth {
	ssh_knownhosts::ssh_knownhosts(const ssh_session& session, std::string_view path) : m_session(session) {
		if (path.compare(default_knownhosts_path) == 0) {
			std::int32_t userprofile_path_length = ::GetEnvironmentVariableA("USERPROFILE", nullptr, 0);
			if (userprofile_path_length == 0) {
				std::error_code ec(::GetLastError(), std::system_category());
				throw std::system_error(ec, "Failed to get user profile path.");
			}

			auto userprofile_path = std::make_unique<char[]>(userprofile_path_length);
			::DWORD ret = ::GetEnvironmentVariableA("USERPROFILE", userprofile_path.get(), userprofile_path_length);
			if (ret == 0) {
				std::error_code ec(::GetLastError(), std::system_category());
				throw std::system_error(ec, "Failed to get user profile path.");
			}

			this->m_knownhosts_path = std::move(std::string(userprofile_path.get()) + "\\.ssh\\known_hosts");
		}
		else {
			this->m_knownhosts_path = path;
		}

		this->m_knownhosts = ssh_knownhosts_ptr_t(::libssh2_knownhost_init(this->m_session.get_session()));
		if (this->m_knownhosts == nullptr) {
			throw ssh_libssh2_exception(::libssh2_session_last_errno(this->m_session.get_session()), "Failed to initialize known hosts.");
		}

		int result = libssh2_knownhost_readfile(this->m_knownhosts.get(), this->m_knownhosts_path.c_str(), LIBSSH2_KNOWNHOST_FILE_OPENSSH);
		if (result < 0) {
			throw ssh_libssh2_exception(result, "Failed to read known hosts file.");
		}
	}

	void ssh_knownhosts::add(std::string_view comment) {
		std::size_t length;
		int type;
		const char* fingerprint = ::libssh2_session_hostkey(this->m_session.get_session(), &length, &type);

		int result = ::libssh2_knownhost_addc(
			this->m_knownhosts.get(),
			this->m_session.get_host().get_string_address().data(),
			nullptr,
			fingerprint,
			length,
			comment.data(),
			comment.size(),
			LIBSSH2_KNOWNHOST_TYPE_PLAIN | LIBSSH2_KNOWNHOST_KEYENC_RAW | LIBSSH2_KNOWNHOST_KEY_SSHDSS,
			nullptr
		);
		if (result < 0) {
			throw ssh_libssh2_exception(result, "Failed to add known host.");
		}

		::libssh2_knownhost* target;

		int rc;
		::libssh2_knownhost* store, prev;
		while ((rc = ::libssh2_knownhost_get(this->m_knownhosts.get(), &store, &prev)) == 0) {
			if (this->m_session.get_host().get_string_address().compare(store->name) == 0) {
				target = store;
				break;
			}
		}
		if (rc < 0) {
			throw ssh_libssh2_exception(rc, "Failed to enumerate known hosts.");
		}

		this->write(target);
	}

	void ssh_knownhosts::remove() {
		::libssh2_knownhost* store, prev;
		int rc;
		int result;
		::libssh2_knownhost* target;

		while ((rc = ::libssh2_knownhost_get(this->m_knownhosts.get(), &store, &prev)) == 0) {
			if (this->m_session.get_host().get_string_address().compare(store->name) == 0) {
				target = store;
				result = ::libssh2_knownhost_del(this->m_knownhosts.get(), store);
				break;
			}
		}
		if (rc < 0) {
			throw ssh_libssh2_exception(rc, "Failed to enumerate known hosts.");
		}
		if (result < 0) {
			throw ssh_libssh2_exception(result, "Failed to remove known host.");
		}


		this->write(target);
	}

	ssh_knownhosts_check_result ssh_knownhosts::check() const {
		::libssh2_knownhost* entry;
		std::size_t length;
		int type;

		const char* fingerprint = ::libssh2_session_hostkey(this->m_session.get_session(), &length, &type);

		int result = ::libssh2_knownhost_checkp(
			this->m_knownhosts.get(),
			this->m_session.get_host().get_string_address().data(),
			this->m_session.get_port(),
			fingerprint,
			length,
			LIBSSH2_KNOWNHOST_TYPE_PLAIN | LIBSSH2_KNOWNHOST_KEYENC_RAW,
			&entry
		);

		switch (result) {
			case LIBSSH2_KNOWNHOST_CHECK_FAILURE:
				throw ssh_libssh2_exception(result, "Failed to check known host.");
			case LIBSSH2_KNOWNHOST_CHECK_MATCH:
				return ssh_knownhosts_check_result::matched;
			case LIBSSH2_KNOWNHOST_CHECK_MISMATCH:
				return ssh_knownhosts_check_result::mismatch;
			case LIBSSH2_KNOWNHOST_CHECK_NOTFOUND:
				return ssh_knownhosts_check_result::missing;
			default:
				throw std::logic_error("Unknown known hosts check result.");
		}
	}

	void ssh_knownhosts::write(::libssh2_knownhost* target) const {
		std::size_t length;
		::libssh2_knownhost_writeline(this->m_knownhosts.get(), target, nullptr, 0, &length, LIBSSH2_KNOWNHOST_FILE_OPENSSH);
		if (length == 0) {
			throw ssh_libssh2_exception(::libssh2_session_last_errno(this->m_session.get_session()), "Failed to calculate buffer size for writing known hosts.");
		}
		length++;

		auto buffer = std::make_unique<char[]>(length);
		int result = ::libssh2_knownhost_writeline(this->m_knownhosts.get(), target, buffer.get(), length, &length, LIBSSH2_KNOWNHOST_FILE_OPENSSH);
		if (result < 0) {
			throw ssh_libssh2_exception(result, "Failed to convert a known host to a line for storage.");
		}

		std::ofstream ofs(this->m_knownhosts_path);
		ofs << buffer.get() << std::endl;
	}
}