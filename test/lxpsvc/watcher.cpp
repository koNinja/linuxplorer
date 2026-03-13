#include <gtest/gtest.h>

#include "../../app/lxpsvc/workers/filesystem_watcher.hpp"
#include "dummy_callbacks.hpp"

#include <util/config/profiles.hpp>

#include <shell/cloud_provider_session.hpp>

#include <ssh/sftp/sftp_session.hpp>

#include <quill/Backend.h>
#include <quill/Frontend.h>
#include <quill/LogMacros.h>
#include <quill/sinks/FileSink.h>

using namespace linuxplorer;

TEST(watcher_test, watching) {
	const auto& profile = util::config::profile_manager::enumerate()[0];

	shell::cloud_provider_session provider(profile.get_syncroot());
	provider.register_callback(shell::functional::fetch_data_callback(on_fetch_data));
	provider.register_callback(shell::functional::fetch_placeholders_callback(on_fetch_placeholders));
	provider.connect();

	app::lxpsvc::contexts::execution_context ctx;
	
	std::filesystem::path log_path;
	log_path = std::filesystem::current_path() / L"watcher.log";

	quill::Backend::start();
	auto sink = quill::Frontend::create_or_get_sink<quill::FileSink>(
		log_path.string(),
		[]() {
			quill::FileSinkConfig cfg;
			cfg.set_open_mode('w');
			cfg.set_filename_append_option(quill::FilenameAppendOption::StartDateTime);
			return cfg;
		}(),
		quill::FileEventNotifier{}
	);

	quill::Logger* logger = quill::Frontend::create_or_get_logger("lxpsvc_test", std::move(sink));

	app::lxpsvc::workers::filesystem_watcher watcher(provider.get_sync_root_dir(), ctx, logger);

	std::this_thread::sleep_for(std::chrono::seconds(10));
	watcher.request_stop();
	watcher.wait();
}