#include <gtest/gtest.h>

#include "../../app/lxpsvc/helpers/path_helper.hpp"

using namespace linuxplorer::lxpsvc;

std::filesystem::path syncroot = L"C:\\syncroot";
std::filesystem::path linux_root = L"/";

TEST(path_helper_test, abs_rel) {
	helpers::path_helper helper(syncroot, linux_root);

	auto absoluted = helper.to_absolute(L"home\\user\\c.md");
	EXPECT_EQ(absoluted, syncroot / L"home\\user\\c.md");

	auto relatived = helper.to_relative_from_syncroot(absoluted);
	EXPECT_EQ(relatived, L"home\\user\\c.md");
}

TEST(path_helper_test, win_linux_style) {
	helpers::path_helper helper(syncroot, linux_root);

	auto linux_styled_from_abs = helper.to_linux_style(syncroot / L"home\\user\\c.md", helpers::style_conversion_class::absolute_format);
	EXPECT_EQ(linux_styled_from_abs, L"/home/user/c.md");
	auto linux_styled_from_rel = helper.to_linux_style(L"home\\user\\c.md", helpers::style_conversion_class::relative_format);
	EXPECT_EQ(linux_styled_from_rel, L"/home/user/c.md");

	auto abs_win_styled = helper.to_win_style(helpers::style_conversion_class::absolute_format, L"/home/user/c.md");
	EXPECT_EQ(abs_win_styled, syncroot / L"home\\user\\c.md");
	auto rel_win_styled = helper.to_win_style(helpers::style_conversion_class::relative_format, L"/home/user/c.md");
	EXPECT_EQ(rel_win_styled, L"home\\user\\c.md");
}