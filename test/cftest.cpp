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

TEST(placeholders, create_directory) 
{
	linuxplorer::shell::cloud_provider_session ss(sync_root_path);

	ss.register_callback(linuxplorer::shell::cloud_provider_callback(linuxplorer::shell::cloud_provider_callback_type::fetch_data, cftest::on_fetch_data));

	ss.connect();

	::FILE_BASIC_INFO metadata;
	ZeroMemory(&metadata, sizeof(::FILE_BASIC_INFO));

	auto ph = linuxplorer::shell::filesystem::cloud_filter_placeholder::create_directory(ss, L"sampledir", metadata);

	linuxplorer::shell::filesystem::cloud_filter_placeholder::remove(ss, std::move(ph));

	ss.disconnect();
}

TEST(placeholders, create_placeholder) {
	linuxplorer::shell::cloud_provider_session ss(sync_root_path);

	ss.register_callback(linuxplorer::shell::cloud_provider_callback(linuxplorer::shell::cloud_provider_callback_type::fetch_data, cftest::on_fetch_data));

	ss.connect();

	::CF_FS_METADATA file_metadata, directory_metadata;
	ZeroMemory(&file_metadata, sizeof(::CF_FS_METADATA));
	ZeroMemory(&directory_metadata, sizeof(::CF_FS_METADATA));

	auto dir = linuxplorer::shell::filesystem::cloud_filter_placeholder::create_directory(ss, L"sampledir", directory_metadata.BasicInfo);
	auto ph = linuxplorer::shell::filesystem::cloud_filter_placeholder::create(ss, L"sampledir\\sample.txt", file_metadata);

	ph.remove(ss, std::move(ph));
	//linuxplorer::shell::filesystem::cloud_filter_placeholder::remove(ss, std::move(ph));

	ss.disconnect();
}