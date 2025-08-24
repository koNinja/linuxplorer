#include <gtest/gtest.h>

#include <shell/cloud_provider_session.hpp>
#include <shell/filesystem/cloud_provider_registrar.hpp>
#include <shell/filesystem/cloud_filter_placeholder.hpp>

#include "cftest_impl.h"

constexpr const wchar_t* sync_root_path = L"C:\\Users\\koNinja\\desktop\\client";
constexpr const wchar_t* provider_name = L"MyProvider";
constexpr const wchar_t* provider_version = L"1.0.0";

TEST(registrar, register) {
	linuxplorer::shell::filesystem::cloud_provider_registrar::register_provider(sync_root_path, provider_name, provider_version);
}

TEST(registrar, unregister) {
	linuxplorer::shell::filesystem::cloud_provider_registrar::unregister_provider(sync_root_path);
}

TEST(placeholders, create_placeholders) {
	cloud_provider_session ss(sync_root_path);

	ss.connect();

	::CF_FS_METADATA file_metadata;
	ZeroMemory(&file_metadata, sizeof(::CF_FS_METADATA));
	file_metadata.BasicInfo.FileAttributes = FILE_ATTRIBUTE_DIRECTORY;

	auto ph = filesystem::cloud_filter_placeholder::create(ss, L"sample", file_metadata);

	//filesystem::cloud_filter_placeholder::remove(ss, std::move(ph));

	ss.disconnect();
}

TEST(placeholders, transfer_data) {
	linuxplorer::shell::cloud_provider_session ss(sync_root_path);

	ss.register_callback(cloud_provider_callback(cloud_provider_callback_type::fetch_data, cftest::on_fetch_data));
	ss.register_callback(cloud_provider_callback(cloud_provider_callback_type::fetch_placeholders, cftest::on_fetch_placeholders));
	ss.connect();

	::CF_FS_METADATA file_metadata;
	ZeroMemory(&file_metadata, sizeof(::CF_FS_METADATA));
	file_metadata.FileSize.QuadPart = sizeof(cftest::dummy_data);
	//auto ph = filesystem::cloud_filter_placeholder::create(ss, L"sample.txt", file_metadata);

	// watch a hydration request every 0.5s for 10s .
	for (int i = 0; i < 20; i++) {
		std::this_thread::sleep_for(std::chrono::milliseconds(500));
	}

	//filesystem::cloud_filter_placeholder::remove(ss, std::move(ph));

	ss.disconnect();
}