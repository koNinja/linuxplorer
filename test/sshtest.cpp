#include <gtest/gtest.h>

#include <ssh/ssh_session.hpp>
#include <ssh/auth/ssh_knownhosts.hpp>
#include <util/charset/multibyte_wide_compat_helper.hpp>
#include <ssh/sftp/sftpstream.hpp>

#include <windows.h>
#include <libssh2_sftp.h>
#include <fstream>
#include <tuple>
#include <fstream>
#include <filesystem>

#include <nlohmann/json.hpp>

using namespace linuxplorer;

constexpr const wchar_t* relative_cert_path = L"..\\..\\cert.json";
std::tuple<ssh::ssh_address, std::wstring, std::wstring> get_cert() {
	using charset_helper = util::charset::multibyte_wide_compat_helper;

	auto p = std::filesystem::current_path();
	p.append(relative_cert_path);

	std::ifstream ifs(p);
	auto json = nlohmann::json::parse(ifs);

	return std::make_tuple(
		ssh::ssh_address(charset_helper::convert_multibyte_to_wide(json["addr"])),
		charset_helper::convert_multibyte_to_wide(json["user"]),
		charset_helper::convert_multibyte_to_wide(json["passwd"])
	);
}

TEST(sftp, exec) {
	auto [addr, user, passwd] = get_cert();

	ssh::ssh_session ss(addr);

	ss.connect();
	ss.authenticate(user, passwd);

	::LIBSSH2_CHANNEL* channel = ::libssh2_channel_open_session(ss.get_session());
	if (!channel) {
		throw ssh::ssh_libssh2_exception(::libssh2_session_last_errno(ss.get_session()), "Failed to open a channel.");
	}

	int rc = ::libssh2_channel_exec(channel, "pwd");
	if (rc < 0) {
		throw ssh::ssh_libssh2_exception(rc, "Failed to request a shell on a chennel.");
	}

	::ssize_t nread;
	do {
		char buffer[0x1000];
		nread = ::libssh2_channel_read(channel, buffer, sizeof(buffer));

		::ssize_t i;
		std::cout << "We read: " << std::endl;

		for(i = 0; i < nread; ++i)
			std::cout << buffer[i];

		std::cout << std::endl;
	} while(nread > 0);

	::libssh2_channel_close(channel);
	::libssh2_channel_free(channel);

	ss.disconnect();
}

TEST(sftp, write) {
	auto [addr, user, passwd] = get_cert();

	ssh::ssh_session ss(addr);

	ss.connect();
	ss.authenticate(user, passwd);

	::LIBSSH2_SESSION* session = ss.get_session();
	::LIBSSH2_SFTP* sftp = ::libssh2_sftp_init(session);
	if (sftp == nullptr) {
		throw ssh::ssh_libssh2_exception(-1, "Failed to initialize an SFTP session.");
	}
	::LIBSSH2_SFTP_HANDLE *handle = ::libssh2_sftp_open(sftp, "/home/koninja/libssh2-errno.csv", LIBSSH2_FXF_READ | LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_TRUNC, 0);
	if (handle == nullptr) {
		throw ssh::ssh_libssh2_exception(::libssh2_sftp_last_error(sftp), "Failed to open a file.");
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
				throw ssh::ssh_libssh2_exception(::libssh2_sftp_last_error(sftp), "Failed to write to a file.");
			}
		} while (true);

		written_bytes = ::libssh2_sftp_write(handle, "\n", 1);
		if (written_bytes <= 0) {
			throw ssh::ssh_libssh2_exception(::libssh2_sftp_last_error(sftp), "Failed to append a new line.");
		}
	}

	::libssh2_sftp_close(handle);
	::libssh2_sftp_shutdown(sftp);

	ss.disconnect();
}

TEST(sftp, read) {
	auto [addr, user, passwd] = get_cert();

	ssh::ssh_session ss(addr);

	ss.connect();
	ss.authenticate(user, passwd);

	::LIBSSH2_SESSION* session = ss.get_session();
	::LIBSSH2_SFTP* sftp = ::libssh2_sftp_init(session);
	if (sftp == nullptr) {
		throw ssh::ssh_libssh2_exception(-1, "Failed to initialize an SFTP session.");
	}
	::LIBSSH2_SFTP_HANDLE *handle = ::libssh2_sftp_open(sftp, "/home/koninja/libssh2-errno.csv", LIBSSH2_FXF_READ, 0);
	if (handle == nullptr) {
		throw ssh::ssh_libssh2_exception(::libssh2_sftp_last_error(sftp), "Failed to open a file.");
	}

	constexpr std::size_t buflen = 0x1000;
	
	::ssize_t nread = 0;
	char buf[buflen];
	do {
		::ssize_t bytes_read = libssh2_sftp_read(handle, buf + nread, sizeof(buf) - nread);
		nread += bytes_read;
    } while(nread > 0 && nread < buflen);

	for (int i = 0; i < nread; i++) {
		std::cout.put(buf[i]);
	}

	// flush
	std::cout.flush();

	::libssh2_sftp_close(handle);
	::libssh2_sftp_shutdown(sftp);

	ss.disconnect();
}

TEST(sftpstream, read) {
	using namespace linuxplorer;

	auto [addr, user, passwd] = get_cert();

	ssh::ssh_session ss(addr);

	ss.connect();
	ss.authenticate(user, passwd);

	::LIBSSH2_SESSION* session = ss.get_session();
	::LIBSSH2_SFTP* sftp = ::libssh2_sftp_init(session);
	if (sftp == nullptr) {
		throw ssh::ssh_libssh2_exception(-1, "Failed to initialize an SFTP session.");
	}
	::LIBSSH2_SFTP_HANDLE *handle = ::libssh2_sftp_open(sftp, "/home/koninja/libssh2-errno.csv", LIBSSH2_FXF_READ, 0);
	if (handle == nullptr) {
		throw ssh::ssh_libssh2_exception(::libssh2_sftp_last_error(sftp), "Failed to open a file.");
	}

	ssh::sftp::sftpbuf buffer(sftp, handle);

	char data[0x1000];

	buffer.sgetn(data, 1477);

	::libssh2_sftp_close(handle);
	::libssh2_sftp_shutdown(sftp);

	ss.disconnect();
}

TEST(sftpstream, write) {
	using namespace linuxplorer;

	auto [addr, user, passwd] = get_cert();

	ssh::ssh_session ss(addr);

	ss.connect();
	ss.authenticate(user, passwd);

	::LIBSSH2_SESSION* session = ss.get_session();
	::LIBSSH2_SFTP* sftp = ::libssh2_sftp_init(session);
	if (sftp == nullptr) {
		throw ssh::ssh_libssh2_exception(-1, "Failed to initialize an SFTP session.");
	}
	::LIBSSH2_SFTP_HANDLE *handle = ::libssh2_sftp_open(sftp, "/home/koninja/sshtest.txt", LIBSSH2_FXF_READ | LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_TRUNC, 0);
	if (handle == nullptr) {
		throw ssh::ssh_libssh2_exception(::libssh2_sftp_last_error(sftp), "Failed to open a file.");
	}

	ssh::sftp::sftpbuf buffer(sftp, handle);

	char data[] = "hello, world!\n";
	buffer.sputn(data, sizeof(data));
	buffer.pubsync();

	::libssh2_sftp_close(handle);
	::libssh2_sftp_shutdown(sftp);

	ss.disconnect();
}