#include <shell/filesystem/cloud_filter_placeholder.h>
#include <shell/cloud_provider_exception.hpp>

#include <system_error>

using namespace linuxplorer::shell;

namespace linuxplorer::shell::filesystem {
	cloud_filter_placeholder::cloud_filter_placeholder(const cloud_provider_session& session) : m_session(session) {}

	cloud_filter_placeholder::cloud_filter_placeholder(cloud_filter_placeholder&& right) 
		: m_relative_path(std::move(right.m_relative_path)), m_session(right.m_session), m_handle(right.m_handle)
	{
		right.m_relative_path.clear();
		right.m_handle = INVALID_HANDLE_VALUE;
	}

	cloud_filter_placeholder cloud_filter_placeholder::internal_create(const cloud_provider_session& session, std::wstring_view relative_path, ::CF_PLACEHOLDER_CREATE_INFO& create_info) {
		auto filename = relative_path.substr(relative_path.find_last_of(L"\\") + 1);
		auto dirname = relative_path.substr(0, relative_path.find_last_of(L"\\") + 1);

		std::wstring absolute_dir_path(session.get_client_dir());
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
			throw cloud_provider_exception("Failed to create placeholder file.", hr);
		}

		std::wstring absolute_path(session.get_client_dir());
		absolute_path += L"\\";
		absolute_path += relative_path;

		cloud_filter_placeholder result(session);
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

		return std::move(result);
	}

	cloud_filter_placeholder cloud_filter_placeholder::create(const cloud_provider_session& session, std::wstring_view relative_path, const ::CF_FS_METADATA& metadata) {		
		auto filename = relative_path.substr(relative_path.find_last_of(L"\\") + 1);
		
		::CF_PLACEHOLDER_CREATE_INFO create_info;
		create_info.RelativeFileName = filename.data();
		create_info.FsMetadata = metadata;
		create_info.FileIdentity = relative_path.data();
		create_info.FileIdentityLength = static_cast<std::uint32_t>((relative_path.size() + 1) * sizeof(wchar_t));
		create_info.Flags = ::CF_PLACEHOLDER_CREATE_FLAGS::CF_PLACEHOLDER_CREATE_FLAG_NONE;

		return internal_create(session, relative_path, create_info);
	}

	cloud_filter_placeholder cloud_filter_placeholder::create_directory(const cloud_provider_session &session, std::wstring_view relative_path) {
		auto dirname = relative_path.substr(relative_path.find_last_of(L"\\") + 1);

		::CF_PLACEHOLDER_CREATE_INFO create_info;
		create_info.RelativeFileName = dirname.data();
		create_info.Flags = ::CF_PLACEHOLDER_CREATE_FLAGS::CF_PLACEHOLDER_CREATE_FLAG_DISABLE_ON_DEMAND_POPULATION;

		return internal_create(session, relative_path, create_info);
	}

	cloud_filter_placeholder cloud_filter_placeholder::open(const cloud_provider_session& session, std::wstring_view relative_path) {
		std::wstring absolute_path(session.get_client_dir());
		absolute_path += L"\\";
		absolute_path += relative_path;

		cloud_filter_placeholder result(session);
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

		return std::move(result);
	}

	cloud_filter_placeholder cloud_filter_placeholder::open_directory(const cloud_provider_session& session, std::wstring_view relative_path) {
		std::wstring absolute_path(session.get_client_dir());
		absolute_path += L"\\";
		absolute_path += relative_path;

		cloud_filter_placeholder result(session);
		result.m_relative_path = relative_path;
		result.m_handle = ::CreateFileW(
			absolute_path.c_str(),
			0,
			FILE_SHARE_READ,
			nullptr,
			OPEN_EXISTING,
			FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
			nullptr
		);
		if (result.m_handle == INVALID_HANDLE_VALUE) {
			std::error_code ec(::GetLastError(), std::system_category());
			throw std::system_error(ec, "Failed to open placeholder file.");
		}

		return std::move(result);
	}

	void cloud_filter_placeholder::remove(cloud_filter_placeholder &&placeholder) {
		std::wstring path(placeholder.m_session.get_client_dir());
		path += L"\\";
		path += std::move(placeholder.m_relative_path);

		if (!::DeleteFileW(path.c_str())) {
			std::error_code ec(::GetLastError(), std::system_category());
			throw std::system_error(ec, "Failed to remove placeholder file.");
		}
	}

	void cloud_filter_placeholder::hydrate() const {
		::LARGE_INTEGER offset;
		offset.QuadPart = 0;
		::LARGE_INTEGER length;
		length.QuadPart = std::numeric_limits<std::int64_t>::max();

		::HRESULT hr = ::CfHydratePlaceholder(this->m_handle, offset, length, ::CF_HYDRATE_FLAGS::CF_HYDRATE_FLAG_NONE, nullptr);
		if (FAILED(hr)) {
			throw cloud_provider_exception("Failed to hydrate placeholder file.", hr);
		}
	}

	void cloud_filter_placeholder::dehydrate() const {
		::LARGE_INTEGER offset;
		offset.QuadPart = 0;
		::LARGE_INTEGER length;
		length.QuadPart = std::numeric_limits<std::int64_t>::max();

		::HRESULT hr = ::CfDehydratePlaceholder(this->m_handle, offset, length, ::CF_DEHYDRATE_FLAGS::CF_DEHYDRATE_FLAG_NONE, nullptr);
		if (FAILED(hr)) {
			throw cloud_provider_exception("Failed to dehydrate placeholder file.", hr);
		}
	}

	cloud_filter_placeholder::~cloud_filter_placeholder() noexcept {
		if (this->m_handle != INVALID_HANDLE_VALUE) {
			::CloseHandle(this->m_handle);
		}
	}
}