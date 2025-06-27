#include <gtest/gtest.h>

#include <util/config/credentials.hpp>

TEST(credentials_test, save_config) {
	using namespace linuxplorer::util::config;

	credential_info info(L"255.255.255.255", L"username", L"password");

	credential_config config;

	config.set(info);

	config.save();
}

TEST(credentials_test, load_config) {
	using namespace linuxplorer::util::config;

	credential_config config;

	config.load();

	auto data = config.get();
}