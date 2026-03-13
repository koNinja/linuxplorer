#include "ntfs.hpp"
#include "handle.hpp"

namespace linuxplorer::app::lxpsvc::win32 {
	file_reference_number get_frn(const std::filesystem::path& path) {
		unique_file_handle handle = ::CreateFileW(
			path.c_str(),
			FILE_READ_ATTRIBUTES,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			nullptr,
			OPEN_EXISTING,
			FILE_FLAG_BACKUP_SEMANTICS,
			nullptr
		);
		if (!handle) {
			throw std::system_error(std::error_code(::GetLastError(), std::system_category()), "Failed to open a handle to the file.");
		}

		::FILE_ID_INFO info{};
		bool succeeded = ::GetFileInformationByHandleEx(
			handle.get(),
			::FILE_INFO_BY_HANDLE_CLASS::FileIdInfo,
			&info,
			sizeof(info)
		);
		if (!succeeded) {
			throw std::system_error(std::error_code(::GetLastError(), std::system_category()), "Failed to get file reference number.");
		}

		return info.FileId;
	}
}