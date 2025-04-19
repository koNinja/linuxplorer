#include <shell/filesystem/cloud_filter_placeholder.hpp>
#include <shell/cloud_provider_exception.hpp>

#include <system_error>

using namespace linuxplorer::shell;

namespace linuxplorer::shell::filesystem {
	cloud_filter_placeholder::cloud_filter_placeholder() noexcept {}

	cloud_filter_placeholder::cloud_filter_placeholder(cloud_filter_placeholder&& right) 
		: m_relative_path(std::move(right.m_relative_path)), m_handle(right.m_handle), m_type(placeholder_type::file)
	{
		right.m_relative_path.clear();
		right.m_handle = INVALID_HANDLE_VALUE;
	}

	cloud_filter_placeholder cloud_filter_placeholder::internal_create(const cloud_provider_session& session, std::wstring_view relative_path, ::CF_PLACEHOLDER_CREATE_INFO& create_info) {
		auto filename = relative_path.substr(relative_path.find_last_of(L"\\") + 1);
		auto dirname = relative_path.substr(0, relative_path.find_last_of(L"\\"));

		std::wstring absolute_dir_path(session.get_sync_root_dir());
		if (!dirname.empty()) {
			absolute_dir_path += L"\\";
			absolute_dir_path += dirname;
		}

		::DWORD count_of_proceeded_entries = 0;
		::HRESULT hr = ::CfCreatePlaceholders(
			absolute_dir_path.c_str(),
			&create_info,
			1,
			::CF_CREATE_FLAGS::CF_CREATE_FLAG_NONE,
			&count_of_proceeded_entries
		);
		if (FAILED(hr) || count_of_proceeded_entries == 0) {
			std::error_code ec(hr, std::system_category());
			throw std::system_error(ec, "Failed to create a placeholder.");
		}

		std::wstring absolute_path(session.get_sync_root_dir());
		absolute_path += L"\\";
		absolute_path += relative_path;

		cloud_filter_placeholder result;
		result.m_relative_path = relative_path;
		result.m_handle = ::CreateFileW(
			absolute_path.c_str(),
			0,
			FILE_SHARE_READ,
			nullptr,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			nullptr
		);
		if (result.m_handle == INVALID_HANDLE_VALUE) {
			std::error_code ec(::GetLastError(), std::system_category());
			throw std::system_error(ec, "Failed to open placeholder file.");
		}

		return result;
	}

	cloud_filter_placeholder cloud_filter_placeholder::create(const cloud_provider_session& session, std::wstring_view relative_path, const ::CF_FS_METADATA& metadata) {		
		auto filename = relative_path.substr(relative_path.find_last_of(L'\\') + 1);
		std::size_t dir_file_separator_pos = relative_path.find_last_of(L'\\');
		std::size_t dirname_substr_count = dir_file_separator_pos == std::wstring_view::npos ? 0 : dir_file_separator_pos;
		auto dirname = relative_path.substr(0, dirname_substr_count);
		
		::CF_PLACEHOLDER_CREATE_INFO create_info;
		create_info.RelativeFileName = filename.data();
		create_info.FsMetadata = metadata;
		create_info.FileIdentity = relative_path.data();
		create_info.FileIdentityLength = static_cast<std::uint32_t>((relative_path.size() + 1) * sizeof(wchar_t));
		create_info.Flags = ::CF_PLACEHOLDER_CREATE_FLAGS::CF_PLACEHOLDER_CREATE_FLAG_NONE;		

		std::wstring absolute_dir_path(session.get_sync_root_dir());
		if (!dirname.empty()) {
			absolute_dir_path += L"\\";
			absolute_dir_path += dirname;
		}

		::DWORD count_of_proceeded_entries = 0;
		::HRESULT hr = ::CfCreatePlaceholders(
			absolute_dir_path.c_str(),
			&create_info,
			1,
			::CF_CREATE_FLAGS::CF_CREATE_FLAG_NONE,
			&count_of_proceeded_entries
		);
		if (FAILED(hr) || count_of_proceeded_entries == 0) {
			std::error_code ec(hr, std::system_category());
			throw std::system_error(ec, "Failed to create a placeholder.");
		}

		std::wstring absolute_path(session.get_sync_root_dir());
		absolute_path += L"\\";
		absolute_path += relative_path;

		cloud_filter_placeholder result;
		result.m_relative_path = relative_path;
		result.m_handle = ::CreateFileW(
			absolute_path.c_str(),
			0,
			FILE_SHARE_READ,
			nullptr,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			nullptr
		);
		if (result.m_handle == INVALID_HANDLE_VALUE) {
			std::error_code ec(::GetLastError(), std::system_category());
			throw std::system_error(ec, "Failed to open placeholder file.");
		}

		result.m_type = placeholder_type::file;
		return result;
	}

	cloud_filter_placeholder cloud_filter_placeholder::create_directory(const cloud_provider_session &session, std::wstring_view relative_path, ::FILE_BASIC_INFO& metadata) {
		std::wstring absolute_path(session.get_sync_root_dir());
		absolute_path += L"\\";
		absolute_path += relative_path;

		bool succeeded = ::CreateDirectoryW(absolute_path.c_str(), nullptr);
		if (!succeeded) {
			std::error_code ec(::GetLastError(), std::system_category());
			throw std::system_error(ec, "Failed to create a directory.");
		}

		::HANDLE handle = ::CreateFileW(
			absolute_path.c_str(),
			FILE_WRITE_ATTRIBUTES,
			FILE_SHARE_READ,
			nullptr,
			OPEN_EXISTING,
			FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
			nullptr
		);
		if (!handle || handle == INVALID_HANDLE_VALUE) {
			std::error_code ec(::GetLastError(), std::system_category());
			throw std::system_error(ec, "Failed to open a directory.");
		}

		auto ulltoft = [](std::uint64_t v) -> ::FILETIME {
			auto low = static_cast<std::uint32_t>(v & 0xffffffff00000000);
			auto high = static_cast<std::uint32_t>(v & 0x00000000ffffffff);
			return ::FILETIME{ low, high };
		};

		auto creation = ulltoft(metadata.CreationTime.QuadPart);
		auto last_access = ulltoft(metadata.LastAccessTime.QuadPart);
		auto last_write = ulltoft(metadata.LastWriteTime.QuadPart);

		succeeded = ::SetFileTime(handle, &creation, &last_access, &last_write);
		if (!succeeded) {
			std::error_code ec(::GetLastError(), std::system_category());
			throw std::system_error(ec, "Failed to set directory metadata.");
		}

		metadata.FileAttributes |= FILE_ATTRIBUTE_DIRECTORY;
		succeeded = ::SetFileAttributesW(absolute_path.c_str(), metadata.FileAttributes);
		if (!succeeded) {
			std::error_code ec(::GetLastError(), std::system_category());
			throw std::system_error(ec, "Failed to set directory attributes.");
		}

		cloud_filter_placeholder result;
		result.m_relative_path = relative_path;
		result.m_handle = handle;
		result.m_type = placeholder_type::directory;

		return result;
	}

	cloud_filter_placeholder cloud_filter_placeholder::open(const cloud_provider_session& session, std::wstring_view relative_path) {
		std::wstring absolute_path(session.get_sync_root_dir());
		absolute_path += L"\\";
		absolute_path += relative_path;

		::DWORD target_attr = ::GetFileAttributesW(absolute_path.c_str());
		bool is_directory = target_attr & FILE_ATTRIBUTE_DIRECTORY;
		::DWORD open_flags_and_attr = is_directory ? 0 : FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT;  

		cloud_filter_placeholder result;
		result.m_relative_path = relative_path;
		result.m_handle = ::CreateFileW(
			absolute_path.c_str(),
			0,
			FILE_SHARE_READ,
			nullptr,
			OPEN_EXISTING,
			open_flags_and_attr,
			nullptr
		);
		if (result.m_handle == INVALID_HANDLE_VALUE) {
			std::error_code ec(::GetLastError(), std::system_category());
			throw std::system_error(ec, "Failed to open placeholder file.");
		}
		result.m_type = is_directory ? placeholder_type::directory : placeholder_type::file;

		return result;
	}

	void cloud_filter_placeholder::remove(const cloud_provider_session& session, cloud_filter_placeholder &&placeholder) {
		std::wstring path(session.get_sync_root_dir());
		path += L"\\";
		path += std::move(placeholder.m_relative_path);

		::CloseHandle(placeholder.m_handle);
		placeholder.m_handle = nullptr;

		bool succeeded;
		::BOOL(*deleter)(::LPCWSTR);
		
		switch (placeholder.m_type) {
			case linuxplorer::shell::filesystem::placeholder_type::file:
				deleter = ::DeleteFileW;
				break;
			case linuxplorer::shell::filesystem::placeholder_type::directory:
				deleter = ::RemoveDirectoryW;
				break;
			default:
				throw std::runtime_error("Invalid placeholder type.");
		}
		succeeded = deleter(path.c_str());
		if (!succeeded) {
			std::error_code ec(::GetLastError(), std::system_category());
			throw std::system_error(ec, "Failed to remove the placeholder.");
		}
	}

	void cloud_filter_placeholder::hydrate() const {
		if (this->m_type != placeholder_type::file) {
			throw cloud_provider_runtime_exception("Hydration not supported for non-file type placeholders.");
		}

		::LARGE_INTEGER offset;
		offset.QuadPart = 0;
		::LARGE_INTEGER length;
		length.QuadPart = std::numeric_limits<std::int64_t>::max();

		::HRESULT hr = ::CfHydratePlaceholder(this->m_handle, offset, length, ::CF_HYDRATE_FLAGS::CF_HYDRATE_FLAG_NONE, nullptr);
		if (FAILED(hr)) {
			std::error_code ec(hr, std::system_category());
			throw std::system_error(ec, "Failed to hydrate placeholder file.");
		}
	}

	void cloud_filter_placeholder::dehydrate() const {
		if (this->m_type != placeholder_type::file) {
			throw cloud_provider_runtime_exception("Hydration not supported for non-file type placeholders.");
		}

		::LARGE_INTEGER offset;
		offset.QuadPart = 0;
		::LARGE_INTEGER length;
		length.QuadPart = std::numeric_limits<std::int64_t>::max();

		::HRESULT hr = ::CfDehydratePlaceholder(this->m_handle, offset, length, ::CF_DEHYDRATE_FLAGS::CF_DEHYDRATE_FLAG_NONE, nullptr);
		if (FAILED(hr)) {
			std::error_code ec(hr, std::system_category());
			throw std::system_error(ec, "Failed to dehydrate placeholder file.");
		}
	}

	cloud_filter_placeholder::~cloud_filter_placeholder() noexcept {
		if (this->m_handle != INVALID_HANDLE_VALUE) {
			::CloseHandle(this->m_handle);
		}
	}
}