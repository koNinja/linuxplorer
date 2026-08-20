#include <gtest/gtest.h>

#include <engine/models/requests/result_adapter.hpp>

TEST(result_adapter, normal_path) {
	using namespace linuxplorer::engine::models::requests;

	result_adapter<std::string> adapter;

	adapter.set_value("Hello");
	adapter.set_value("World!");
	adapter.finalize();

	while (auto opt = adapter.wait_head()) {
		std::cout << *opt << std::endl;
	}
}

TEST(result_adapter, exception_path) {
	using namespace linuxplorer::engine::models::requests;

	result_adapter<std::string> adapter;

	adapter.set_value("Hello");
	adapter.set_value("World!");
	adapter.finalize();

	try {
		while (auto opt = adapter.wait_head()) std::cout << *opt << std::endl;
		adapter.set_exception(std::runtime_error("Runtime error!"));
	}
	catch (const std::exception& e) {
		FAIL() << e.what() << std::endl;;
	}
}