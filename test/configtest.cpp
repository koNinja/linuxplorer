#include <gtest/gtest.h>

#include <util/config/credentials.hpp>
#include <util/config/startup_config.hpp>

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

TEST(startup_test, save) {
	using namespace linuxplorer::util::config;
	try {
		startup_config config;
		config.set(true);
		config.save();
	}
	catch (const config_exception& e) {
		std::cout << "Exception: " << e.what() << std::endl;
		FAIL();
	}
}