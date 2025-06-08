#include <gtest/gtest.h>

#include <ssh/ssh_exception.hpp>
#include <ssh/ssh_session.hpp>
#include <ssh/sftp/sftp_session.hpp>
#include <ssh/sftp/filesystem/sftp_manip.hpp>
#include <ssh/sftp/filesystem/sftp_entity.hpp>
#include <ssh/auth/ssh_knownhosts.hpp>
#include <util/charset/multibyte_wide_compat_helper.hpp>

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

TEST(sftp_manip, stat) {
	const auto& [addr, user, pass] = get_cert();
	using namespace linuxplorer;

	ssh::ssh_session ss(addr);
	ss.connect();
	ss.authenticate(user, pass);
}

TEST(knownhosts, write) {
	const auto& [addr, user, pass] = get_cert();
	using namespace linuxplorer;

	ssh::ssh_session ss(addr);
	ss.connect();
	ss.authenticate(user, pass);

	ssh::auth::ssh_knownhosts hosts(ss);

	hosts.enumerate();
}