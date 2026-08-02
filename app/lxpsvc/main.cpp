#include <engine/services/profile_runtime.hpp>
#include <vector>
#include <memory>

#include <objbase.h>

#define TO_WSTRING(x)	L#x
#define WSTRINGIFY(x)	TO_WSTRING(x)

int APIENTRY wWinMain(::HINSTANCE hInstance, ::HINSTANCE, ::LPWSTR lpCmdLine, int nCmdShow) {
	constexpr const wchar_t* mutex_name = L"LinuxplorerAppServiceMutex";
	linuxplorer::engine::win32::unique_mutex_handle mutex = ::CreateMutexW(nullptr, true, mutex_name);
	if (::GetLastError() == ERROR_ALREADY_EXISTS || !mutex) {
		return 1;
	}

	try {
		linuxplorer::engine::services::try_initialize_logger_backend();

		::HRESULT hr = ::CoInitializeEx(nullptr, ::COINIT::COINIT_MULTITHREADED);
		if (FAILED(hr)) {
			std::error_code ec(hr, std::system_category());
			std::string message = std::format("Failed to initialize the COM library. (HRESULT: {}({}))", ec.message(), ec.value());
			::MessageBoxA(nullptr, message.c_str(), "Initialization error", MB_ICONERROR | MB_OK);
			return 1;
		}

		linuxplorer::engine::win32::unique_event_handle termination_event = ::CreateEventW(nullptr, true, false, WSTRINGIFY(LINUXPLORER_APP_SERVICE_TERMINATE_EVENT_NAME));
		if (!termination_event) {
			std::error_code ec(::GetLastError(), std::system_category());
			std::string message = std::format("Failed to create a termination event. (Win32: {}({}))", ec.message(), ec.value());
			::MessageBoxA(nullptr, message.c_str(), "Initialization error", MB_ICONERROR | MB_OK);
			return 1;
		}
		
		std::vector<std::unique_ptr<linuxplorer::engine::services::profile_runtime>> runtimes;
		const auto& profiles = linuxplorer::util::config::profile_manager::enumerate();
		std::vector<::HANDLE> events;
		events.push_back(termination_event.get());

		for (const auto& profile : profiles) {
			auto runtime = std::make_unique<linuxplorer::engine::services::profile_runtime>(profile);
			runtime->start();
			events.push_back(runtime->get_death_event().get());
			runtimes.push_back(std::move(runtime));
		}

		std::size_t alive_runtimes = runtimes.size();
		if (alive_runtimes <= 0) return 0;
		
		while (true) {
			auto response = ::WaitForMultipleObjects(events.size(), events.data(), false, INFINITE);
			switch (response) {
			case WAIT_OBJECT_0:
			{
				for (auto& runtime : runtimes) {
					runtime->request_stop();
				}

				for (auto& runtime : runtimes) {
					runtime->wait();
				}
				return 0;
			}
			case WAIT_FAILED:
			{
				std::error_code ec(::GetLastError(), std::system_category());
				std::string message = std::format("Failed to wait for the termination event. (Win32: {}({}))", ec.message(), ec.value());
				::MessageBoxA(nullptr, message.c_str(), "Application error", MB_ICONERROR | MB_OK);
				return 1;
			}
			default:
			{
				runtimes[response - 1]->request_stop();
				runtimes[response - 1]->wait();
				if (--alive_runtimes <= 0) return 0;
				break;
			}
			}
		}
	}
	catch (const linuxplorer::util::config::config_exception& e) {
		auto message = std::format("Failed to load profiles: {}", e.what());
		::MessageBoxA(nullptr, message.c_str(), "Loading error", MB_ICONERROR | MB_OK);
		return 1;
	}
	catch (...) {
		::MessageBoxW(nullptr, L"An unexpected error has occurred in the application.", L"Application Error", MB_ICONERROR | MB_OK);
		return 1;
	}

	linuxplorer::engine::services::try_uninitialize_logger_backend();
	::CoUninitialize();

	return 0;
}