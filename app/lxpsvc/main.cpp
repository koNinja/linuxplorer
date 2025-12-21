#include "session.hpp"
#include <util/config/profiles.hpp>

namespace {
	int thread_main(std::wstring_view profile_name) {
		linuxplorer::app::lxpsvc::session session(profile_name);
		session.start();
		return session.get_exit_code();
	}
}

int APIENTRY wWinMain(
	::HINSTANCE	hInstance,
	::HINSTANCE	/* hPrevInstance */,
	::LPWSTR	lpCmdLine,
	int 		nCmdShow
) {
	using unique_mutex_ptr = std::unique_ptr<std::remove_pointer_t<::HANDLE>, decltype([](::HANDLE mutex) {
		::ReleaseMutex(mutex);
		::CloseHandle(mutex);
	})>;

	constexpr const wchar_t* mutex_name = L"LinuxplorerAppServiceMutex";
	unique_mutex_ptr mutex(::CreateMutexW(nullptr, true, mutex_name));
	if (::GetLastError() == ERROR_ALREADY_EXISTS || mutex.get() == nullptr) {
		return 1;
	}

	try {
		std::vector<std::thread> threads;
		for (const auto& profile : linuxplorer::util::config::profile_manager::enumerate()) {
			threads.emplace_back(thread_main, profile.get_name());
		}

		for (auto& th : threads) {
			if (th.joinable()) th.join();
		}
	}
	catch (...) {
		return 1;
	}

	return 0;
}