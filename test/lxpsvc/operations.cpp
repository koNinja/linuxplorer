#include <gtest/gtest.h>

#include "../../app/lxpsvc/models/operations/io_operations.hpp"

using namespace linuxplorer::lxpsvc;

TEST(operation_test, modification_operation) {
	models::operations::modification_operation op(L"C:\\Users\\koNinja\\server", L"home\\koninja\\c.md", models::requests::remote::modification_type::overwritten);

	while (!op.done()) {
		auto req = op.fetch();

		op.transition(models::requests::request_result::success);
	}

	return;
}