#include "session.hpp"

int APIENTRY wWinMain(
	::HINSTANCE	hInstance,
	::HINSTANCE	/* hPrevInstance */,
	::LPWSTR	lpCmdLine,
	int 		nCmdShow
) {
	constexpr const wchar_t* mutex_name = L"LinuxplorerAppServiceMutex";
	::HANDLE nt_mutex_handle = ::CreateMutexW(nullptr, true, mutex_name);
	if (::GetLastError() == ERROR_ALREADY_EXISTS || nt_mutex_handle == nullptr) {
		return 1;
	}

	linuxplorer::app::lxpsvc::session app_session;
	app_session.start();

	app_session.stop();
	
	::ReleaseMutex(nt_mutex_handle);
	::CloseHandle(nt_mutex_handle);

	return app_session.get_exit_code();
}