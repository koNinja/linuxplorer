#include <gtest/gtest.h>

#include <ssh/ssh_session.hpp>
#include <ssh/auth/ssh_knownhosts.hpp>
#include <windows.h>
#include <libssh2_sftp.h>
#include <fstream>

#include <util/charset/multibyte_wide_compat_helper.hpp>

using namespace linuxplorer::ssh;

TEST(session_test, write) {
	ssh_session ss(ssh_address("<hostaddr>"));

	ss.connect();
	ss.authenticate("<username>", "<password>");

	::LIBSSH2_SESSION* session = ss.get_session();
	::LIBSSH2_SFTP* sftp = ::libssh2_sftp_init(session);
	if (sftp == nullptr) {
		throw ssh_libssh2_exception(-1, "Failed to initialize an SFTP session.");
	}
	::LIBSSH2_SFTP_HANDLE *handle = ::libssh2_sftp_open(sftp, "/home/koninja/libssh2-errno.csv", LIBSSH2_FXF_READ | LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_TRUNC, 0);
	if (handle == nullptr) {
		throw ssh_libssh2_exception(::libssh2_sftp_last_error(sftp), "Failed to open a file.");
	}

	std::ifstream ifs("C:\\users\\koninja\\desktop\\libssh2-errno.csv");
	std::string data;

	while (std::getline(ifs, data)) {
		::ssize_t written_bytes = 0;
		do {
			written_bytes = ::libssh2_sftp_write(handle, data.c_str(), data.size());

			if (written_bytes > 0) {
				data = data.substr(written_bytes);
			}
			else if (written_bytes == 0) {
				break;
			}
			else {
				throw ssh_libssh2_exception(::libssh2_sftp_last_error(sftp), "Failed to write to a file.");
			}
		} while (true);

		written_bytes = ::libssh2_sftp_write(handle, "\n", 1);
		if (written_bytes <= 0) {
			throw ssh_libssh2_exception(::libssh2_sftp_last_error(sftp), "Failed to append a new line.");
		}
	}

	::libssh2_sftp_close(handle);
	::libssh2_sftp_shutdown(sftp);

	ss.disconnect();
}