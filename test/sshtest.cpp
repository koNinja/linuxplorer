#include <gtest/gtest.h>

#include <ssh/ssh_session.hpp>
#include <ssh/sftp/sftp_session.hpp>
#include <ssh/ssh_exception.hpp>
#include <util/charset/multibyte_wide_compat_helper.hpp>
#include <ssh/sftp/io/sftpstream.hpp>

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

/*
TEST(ssh, exec) {
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

TEST(sftp, read) {
	using namespace linuxplorer;

	auto [addr, user, passwd] = get_cert();

	auto ss = new ssh::ssh_session(addr);

	ss->connect();
	ss->authenticate(user, passwd);

	auto sftp = new ssh::sftp::sftp_session(*ss);
	::LIBSSH2_SFTP_HANDLE *handle = ::libssh2_sftp_open(sftp->get_session(), "/home/koninja/libssh2-errno.csv", LIBSSH2_FXF_READ, 0);
	if (handle == nullptr) {
		throw ssh::ssh_libssh2_exception(::libssh2_sftp_last_error(sftp->get_session()), "Failed to open a file.");
	}

	auto hfile = new ssh::sftp::sftp_handle(*sftp, handle);

	constexpr std::size_t buflen = 0x1000;

	char buf[buflen];
	::ssize_t bytes_read = ::libssh2_sftp_read(handle, buf, sizeof(buf));

	for (int i = 0; i < 1477; i++) {
		std::cout.put(buf[i]);
	}

	// flush
	std::cout.flush();

	auto weakref1 = ss->get_weak();
	auto weakref2 = sftp->get_weak();
	delete ss;
	delete sftp;
	delete hfile;

	EXPECT_TRUE(weakref1.expired());
	EXPECT_TRUE(weakref2.expired());
}
*/

TEST(sftpstream, isftpstream) {
	using namespace linuxplorer;

	auto [addr, user, passwd] = get_cert();

	ssh::ssh_session ss(addr);

	ss.connect();
	ss.authenticate(user, passwd);
	
	char data[0x1000];
	ssh::sftp::io::isftpstream iss(ss, L"/home/koninja/libssh2-errno.csv");

	std::string str;
	while (std::getline(iss, str)) {
		std::cout << str << std::endl;
	}

	ss.disconnect();
}


TEST(sftpstream, osftpstream) {
	using namespace linuxplorer;

	auto [addr, user, passwd] = get_cert();

	ssh::ssh_session ss(addr);

	ss.connect();
	ss.authenticate(user, passwd);

	ssh::sftp::io::osftpstream ofs(ss, L"/home/koninja/sample.txt");
	ofs << "Hello, world!" << std::endl;
}