#include <shell/filesystem/cloud_filter_placeholder.hpp>
#include <shell/cloud_provider_exception.hpp>

using namespace linuxplorer::shell;

namespace linuxplorer::shell::filesystem {
	cloud_filter_placeholder::cloud_filter_placeholder(const cloud_provider_session& session, std::wstring_view relative_path) {
		this->m_absolute_path.append(session.get_sync_root_dir()).append(L"\\").append(relative_path);
		
		this->open_handle();
		this->fetch();
	}

	cloud_filter_placeholder::cloud_filter_placeholder(cloud_filter_placeholder&& rhs) : 
		m_id(rhs.m_id),
		m_absolute_path(std::move(rhs.m_absolute_path)),
		m_handle(rhs.m_handle),
		m_type(rhs.m_type),
		m_in_sync_marked(rhs.m_in_sync_marked),
		m_pin_state(rhs.m_pin_state),
		m_identity(std::move(rhs.m_identity)),
		m_file_times(std::move(rhs.m_file_times))
	{
		rhs.m_handle = INVALID_HANDLE_VALUE;
	}

	cloud_filter_placeholder cloud_filter_placeholder::create(const cloud_provider_session& session, const placeholder_creation_info& metadata) {		
		auto relative_path = metadata.get_relative_path();
		auto filename = relative_path.substr(relative_path.find_last_of(L"\\") + 1);
		auto dirname = relative_path.substr(0, relative_path.find_last_of(L"\\"));
		
		::CF_FS_METADATA nt_metadata;
		nt_metadata.FileSize.QuadPart = metadata.get_file_size();
		nt_metadata.BasicInfo.FileAttributes = metadata.get_file_attributes();
		auto file_times = metadata.get_file_times();
		nt_metadata.BasicInfo.ChangeTime.QuadPart = file_times.get_change_time().time_since_epoch().count();
		nt_metadata.BasicInfo.CreationTime.QuadPart = file_times.get_creation_time().time_since_epoch().count();
		nt_metadata.BasicInfo.LastAccessTime.QuadPart = file_times.get_last_access_time().time_since_epoch().count();
		nt_metadata.BasicInfo.LastWriteTime.QuadPart = file_times.get_last_write_time().time_since_epoch().count();

		::CF_PLACEHOLDER_CREATE_INFO create_info;
		create_info.RelativeFileName = filename.data();
		create_info.FsMetadata = nt_metadata;
		create_info.FileIdentity = relative_path.data();
		create_info.FileIdentityLength = (relative_path.size() + 1) * sizeof(wchar_t);
		create_info.Flags = ::CF_PLACEHOLDER_CREATE_FLAGS::CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC;		

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
			throw cloud_provider_system_error(ec, "Failed to create a placeholder.");
		}

		return cloud_filter_placeholder(session, relative_path);
	}

	cloud_filter_placeholder cloud_filter_placeholder::transform(const cloud_provider_session& session, std::wstring_view relative_path, std::span<const std::byte> identity) {
		using nt_unique_handle = std::unique_ptr<std::remove_pointer_t<::HANDLE>, decltype([](::HANDLE handle) { ::CloseHandle(handle); })>;
		std::wstring absolute_path;
		absolute_path.append(session.get_sync_root_dir()).append(L"\\").append(relative_path);

		nt_unique_handle handle(::CreateFileW(
			absolute_path.c_str(),
			FILE_READ_ATTRIBUTES,
			FILE_SHARE_READ,
			nullptr,
			OPEN_EXISTING,
			FILE_FLAG_BACKUP_SEMANTICS,
			nullptr
		));
		if (handle.get() == INVALID_HANDLE_VALUE) {
			std::error_code ec(::GetLastError(), std::system_category());
			throw cloud_provider_system_error(ec, "Failed to open the file.");
		}

		::HRESULT hr = ::CfConvertToPlaceholder(
			handle.get(),
			identity.data(),
			identity.size_bytes(),
			::CF_CONVERT_FLAGS::CF_CONVERT_FLAG_NONE,
			nullptr,
			nullptr
		);
		if (FAILED(hr)) {
			std::error_code ec(hr, std::system_category());
			throw cloud_provider_system_error(ec, "Failed to convert the existing file or directory to the placeholder.");
		}

		return cloud_filter_placeholder(session, relative_path);
	}

	void cloud_filter_placeholder::revert(const cloud_provider_session& session, cloud_filter_placeholder&& placeholder) {
		::HANDLE handle = placeholder.m_handle;
		placeholder.m_handle = INVALID_HANDLE_VALUE;

		::HRESULT hr = ::CfRevertPlaceholder(
			handle,
			::CF_REVERT_FLAGS::CF_REVERT_FLAG_NONE,
			nullptr
		);
		if (handle && handle != INVALID_HANDLE_VALUE) ::CloseHandle(handle);
		if (FAILED(hr)) {
			std::error_code ec(hr, std::system_category());
			throw cloud_provider_system_error(ec, "Failed to revert the placeholder back to a regular file.");
		}
	}

	bool cloud_filter_placeholder::is_placeholder(const cloud_provider_session& session, std::wstring_view relative_path) {
		std::wstring absolute_src_path;
		absolute_src_path.append(session.get_sync_root_dir()).append(L"\\").append(relative_path);

		using unique_nthandle = std::unique_ptr<std::remove_pointer_t<::HANDLE>, decltype([](::HANDLE hd) { ::CloseHandle(hd); })>;
		unique_nthandle handle(::CreateFileW(
			absolute_src_path.c_str(),
			READ_ATTRIBUTES,
			FILE_SHARE_READ,
			nullptr,
			OPEN_EXISTING,
			FILE_FLAG_BACKUP_SEMANTICS,
			nullptr
		));
		if (handle.get() == INVALID_HANDLE_VALUE) {
			std::error_code ec(::GetLastError(), std::system_category());
			throw cloud_provider_system_error(ec, "Failed to open the file handle.");
		}

		::CF_PLACEHOLDER_BASIC_INFO info;
		::HRESULT hr = ::CfGetPlaceholderInfo(
			handle.get(),
			::CF_PLACEHOLDER_INFO_CLASS::CF_PLACEHOLDER_INFO_BASIC,
			&info,
			sizeof(::CF_PLACEHOLDER_BASIC_INFO),
			nullptr
		);
		
		constexpr ::HRESULT ERROR_FILE_NOT_CLOUD_FILE = static_cast<::HRESULT>(0x80070178);
		if (FAILED(hr) && hr != HRESULT_FROM_WIN32(ERROR_MORE_DATA) && hr != ERROR_FILE_NOT_CLOUD_FILE) {
			std::error_code ec(hr, std::system_category());
			throw cloud_provider_system_error(ec, "Failed to get placeholder information.");
		}

		return hr != ERROR_FILE_NOT_CLOUD_FILE;
	}

	void cloud_filter_placeholder::internal_primary_fetch() {
		::HRESULT hr;

		auto placeholder_info = std::make_unique<::CF_PLACEHOLDER_STANDARD_INFO>();
		hr = ::CfGetPlaceholderInfo(
			this->m_handle,
			::CF_PLACEHOLDER_INFO_CLASS::CF_PLACEHOLDER_INFO_STANDARD,
			placeholder_info.get(),
			sizeof(::CF_PLACEHOLDER_STANDARD_INFO),
			nullptr
		);
		
		if (hr == HRESULT_FROM_WIN32(ERROR_MORE_DATA)) {
			std::size_t bytes_placeholder_info = sizeof(CF_PLACEHOLDER_STANDARD_INFO) + placeholder_info->FileIdentityLength;
			placeholder_info.reset(reinterpret_cast<::CF_PLACEHOLDER_STANDARD_INFO*>(new std::byte[bytes_placeholder_info]));
			hr = ::CfGetPlaceholderInfo(
				this->m_handle,
				::CF_PLACEHOLDER_INFO_CLASS::CF_PLACEHOLDER_INFO_STANDARD,
				placeholder_info.get(),
				bytes_placeholder_info,
				nullptr
			);
		}
		if (FAILED(hr)) {
			std::error_code ec(hr, std::system_category());
			throw cloud_provider_system_error(ec, "Failed to get placeholder information.");
		}

		::FILE_BASIC_INFO xattr{};
		if (!::GetFileInformationByHandleEx(this->get_handle(), ::FILE_INFO_BY_HANDLE_CLASS::FileBasicInfo, &xattr, sizeof(::FILE_BASIC_INFO))) {
			std::error_code ec(::GetLastError(), std::system_category());
			throw cloud_provider_system_error(ec, "Failed to get file attributes and metadata.");
		}

		this->m_id = placeholder_info->FileId.QuadPart;
		this->m_in_sync_marked = placeholder_info->InSyncState;
		this->m_type = xattr.FileAttributes & FILE_ATTRIBUTE_DIRECTORY ? placeholder_type::directory : placeholder_type::file;
		this->m_pin_state = placeholder_info->PinState;
		this->m_identity = std::vector<std::byte>(
			reinterpret_cast<std::byte*>(placeholder_info->FileIdentity),
			reinterpret_cast<std::byte*>(placeholder_info->FileIdentity + placeholder_info->FileIdentityLength)
		);

		this->m_file_times.set_last_write_time(std::filesystem::file_time_type(std::filesystem::file_time_type::duration(xattr.LastWriteTime.QuadPart)));
		this->m_file_times.set_last_access_time(std::filesystem::file_time_type(std::filesystem::file_time_type::duration(xattr.LastAccessTime.QuadPart)));
		this->m_file_times.set_creation_time(std::filesystem::file_time_type(std::filesystem::file_time_type::duration(xattr.CreationTime.QuadPart)));
		this->m_file_times.set_change_time(std::filesystem::file_time_type(std::filesystem::file_time_type::duration(xattr.ChangeTime.QuadPart)));
	}

	void cloud_filter_placeholder::internal_primary_flush() const {
		::CF_UPDATE_FLAGS flags = ::CF_UPDATE_FLAGS::CF_UPDATE_FLAG_NONE;
		flags |= this->m_in_sync_marked ? ::CF_UPDATE_FLAGS::CF_UPDATE_FLAG_MARK_IN_SYNC : ::CF_UPDATE_FLAGS::CF_UPDATE_FLAG_CLEAR_IN_SYNC;

		::CF_FS_METADATA metadata{};
		if (this->m_type == placeholder_type::file) {
			::LARGE_INTEGER size;
			if (!::GetFileSizeEx(this->m_handle, &size)) {
				std::error_code ec(::GetLastError(), std::system_category());
				throw cloud_provider_system_error(ec, "Failed to get size of the placeholder.");
			}
			metadata.FileSize.QuadPart = size.QuadPart;
		}
		else {
			metadata.FileSize.QuadPart = 0;
		}

		metadata.BasicInfo.ChangeTime.QuadPart = this->m_file_times.get_change_time().time_since_epoch().count();
		metadata.BasicInfo.CreationTime.QuadPart = this->m_file_times.get_creation_time().time_since_epoch().count();
		metadata.BasicInfo.LastAccessTime.QuadPart = this->m_file_times.get_last_access_time().time_since_epoch().count();
		metadata.BasicInfo.LastWriteTime.QuadPart = this->m_file_times.get_last_write_time().time_since_epoch().count();

		::HRESULT hr = ::CfUpdatePlaceholder(
		this->m_handle,
		&metadata,
		this->m_identity.data(),
		this->m_identity.size() * sizeof(std::byte),
		nullptr,
		0,
		flags,
		nullptr,
		nullptr
		);
		if (FAILED(hr)) {
			std::error_code ec(hr, std::system_category());
			throw cloud_provider_system_error(ec, "Failed to update placeholder information.");
		}

		hr = ::CfSetPinState(this->m_handle, this->m_pin_state, ::CF_SET_PIN_FLAGS::CF_SET_PIN_FLAG_RECURSE, nullptr);
		if (FAILED(hr)) {
			std::error_code ec(hr, std::system_category());
			throw cloud_provider_system_error(ec, "Failed to set the pin state.");
		}
	}

	void cloud_filter_placeholder::internal_secondary_fetch() {}
	void cloud_filter_placeholder::internal_secondary_flush() const {}

	void cloud_filter_placeholder::fetch() {
		this->internal_primary_fetch();
		this->internal_secondary_fetch();
	}
	void cloud_filter_placeholder::flush() {
		this->internal_primary_flush();
		this->internal_secondary_flush();
	}

	std::wstring_view cloud_filter_placeholder::get_path() const noexcept {
		return this->m_absolute_path;
	}

	placeholder_type cloud_filter_placeholder::get_type() const noexcept {
		return this->m_type;
	}

	::HANDLE cloud_filter_placeholder::get_handle() const noexcept {
		return this->m_handle;
	}

	std::uint64_t cloud_filter_placeholder::get_id() const noexcept {
		return this->m_id;
	}

	bool cloud_filter_placeholder::is_marked_in_sync() const noexcept {
		return this->m_in_sync_marked;
	}
	void cloud_filter_placeholder::set_marked_in_sync(bool synchronized) noexcept {
		this->m_in_sync_marked = static_cast<::CF_IN_SYNC_STATE>(synchronized);
	}
	::CF_PIN_STATE cloud_filter_placeholder::get_pin_state() const noexcept {
		return this->m_pin_state;
	}
	void cloud_filter_placeholder::set_pin_state(::CF_PIN_STATE state) noexcept {
		this->m_pin_state = state;
	}

	const std::vector<std::byte>& cloud_filter_placeholder::get_identity() const noexcept {
		return this->m_identity;
	}

	void cloud_filter_placeholder::set_identity(const std::vector<std::byte>& identity) noexcept {
		this->m_identity = identity;
	}

	const file_times& cloud_filter_placeholder::get_file_times() const noexcept {
		return this->m_file_times;
	}

	void cloud_filter_placeholder::set_file_times(const file_times& file_times) noexcept {
		this->m_file_times = file_times;
	}

	void cloud_filter_placeholder::close_handle() {
		if (this->m_handle != INVALID_HANDLE_VALUE) {
			::CloseHandle(this->m_handle);
		}
		this->m_handle = INVALID_HANDLE_VALUE;
	}

	void cloud_filter_placeholder::open_handle() {
		this->m_handle = ::CreateFileW(
			this->m_absolute_path.c_str(),
			FILE_READ_ATTRIBUTES,
			FILE_SHARE_READ,
			nullptr,
			OPEN_EXISTING,
			FILE_FLAG_BACKUP_SEMANTICS,
			nullptr
		);
		if (this->m_handle == INVALID_HANDLE_VALUE) {
			std::error_code ec(::GetLastError(), std::system_category());
			throw cloud_provider_system_error(ec, "Failed to open a file.");
		}
	}

	cloud_filter_placeholder::~cloud_filter_placeholder() {
		this->close_handle();
	}

	file_placeholder::file_placeholder(const cloud_provider_session& session, std::wstring_view relative_path) : cloud_filter_placeholder(session, relative_path) {
		this->internal_secondary_fetch();
	}

	file_placeholder::file_placeholder(file_placeholder&& rhs) : cloud_filter_placeholder(std::move(rhs)), m_file_size(rhs.m_file_size) {}

	file_placeholder::file_placeholder(cloud_filter_placeholder&& rhs) : cloud_filter_placeholder(std::move(rhs)) {
		if (this->get_type() != placeholder_type::file) {
			throw placeholder_type_inconsistency_exception("The placeholder is not a file.");
		}
		this->internal_secondary_fetch();
	}

	file_placeholder::~file_placeholder() {}

	void file_placeholder::internal_secondary_fetch() {
		::LARGE_INTEGER size;
		if (!::GetFileSizeEx(this->get_handle(), &size)) {
			std::error_code ec(::GetLastError(), std::system_category());
			throw cloud_provider_system_error(ec, "Failed to get size of the placeholder.");
		}
		this->m_file_size = size.QuadPart;
	}

	void file_placeholder::internal_secondary_flush() const {
		::CF_FS_METADATA metadata{};
		metadata.FileSize.QuadPart = this->m_file_size;
		
		::HRESULT hr = ::CfUpdatePlaceholder(
		this->get_handle(),
		&metadata,
		nullptr,
		0,
		nullptr,
		0,
		::CF_UPDATE_FLAGS::CF_UPDATE_FLAG_NONE,
		nullptr,
		nullptr
		);
		if (FAILED(hr)) {
			std::error_code ec(hr, std::system_category());
			throw cloud_provider_system_error(ec, "Failed to update placeholder information.");
		}
	}

	void file_placeholder::hydrate() const {
		this->hydrate(0, CF_EOF);
	}

	void file_placeholder::hydrate(std::size_t offset, std::streamsize length) const {
		if (this->get_type() != placeholder_type::file) {
			throw cloud_provider_runtime_exception("Hydration not supported for non-file type placeholders.");
		}

		::LARGE_INTEGER nt_offset;
		nt_offset.QuadPart = offset;
		::LARGE_INTEGER nt_length;
		nt_length.QuadPart = length;

		::HRESULT hr = ::CfHydratePlaceholder(this->get_handle(), nt_offset, nt_length, ::CF_HYDRATE_FLAGS::CF_HYDRATE_FLAG_NONE, nullptr);
		if (FAILED(hr)) {
			std::error_code ec(hr, std::system_category());
			throw cloud_provider_system_error(ec, "Failed to hydrate placeholder file.");
		}
	}

	void file_placeholder::dehydrate() {
		this->dehydrate(0, CF_EOF);
	}

	void file_placeholder::dehydrate(std::size_t offset, std::streamsize length) {
		std::exception_ptr exptr;
		this->close_handle();

		try {
			this->internal_dehydrate(offset, length);
		}
		catch (...) {
			exptr = std::current_exception();
		}
		this->open_handle();

		if (exptr) std::rethrow_exception(exptr);
	}

	void file_placeholder::internal_dehydrate(std::size_t offset, std::streamsize length) {
		if (this->get_type() != placeholder_type::file) {
			throw cloud_provider_runtime_exception("Hydration not supported for non-file type placeholders.");
		}

		::HRESULT hr;

		using unique_cfhandle = std::unique_ptr<std::remove_pointer_t<::HANDLE>, decltype([](::HANDLE handle) { ::CfCloseHandle(handle); })>;
		unique_cfhandle protected_handle;
		
		{
			::HANDLE protected_nthandle;
			hr = ::CfOpenFileWithOplock(
				this->get_path().data(),
				::CF_OPEN_FILE_FLAGS::CF_OPEN_FILE_FLAG_EXCLUSIVE | ::CF_OPEN_FILE_FLAGS::CF_OPEN_FILE_FLAG_WRITE_ACCESS,
				&protected_nthandle
			);
			if (FAILED(hr)) {
				std::error_code ec(hr, std::system_category());
				throw cloud_provider_system_error(ec, "Failed to acquire exclusiveness to prevent data corruption by simultaneously dehydrations.");
			}

			protected_handle.reset(protected_nthandle);
		}

		::CF_FILE_RANGE range;
		range.Length.QuadPart = length;
		range.StartingOffset.QuadPart = offset;

		hr = ::CfUpdatePlaceholder(protected_handle.get(), nullptr, nullptr, 0, &range, 1, ::CF_UPDATE_FLAGS::CF_UPDATE_FLAG_NONE, nullptr, nullptr);
		if (FAILED(hr)) {
			std::error_code ec(hr, std::system_category());
			throw cloud_provider_system_error(ec, "Failed to dehydrate placeholder file.");
		}
	}

	std::size_t file_placeholder::get_file_size() const noexcept {
		return this->m_file_size;
	}

	void file_placeholder::set_file_size(std::size_t file_size) noexcept {
		this->m_file_size = file_size;
	}

	directory_placeholder::directory_placeholder(const cloud_provider_session& session, std::wstring_view relative_path) : cloud_filter_placeholder(session, relative_path) {
		this->internal_secondary_fetch();
	}

	directory_placeholder::directory_placeholder(directory_placeholder&& rhs) : cloud_filter_placeholder(std::move(rhs)), m_enumeration_enabled(rhs.m_enumeration_enabled) {}

	directory_placeholder::directory_placeholder(cloud_filter_placeholder&& rhs) : cloud_filter_placeholder(std::move(rhs)) {
		if (this->get_type() != placeholder_type::directory) {
			throw placeholder_type_inconsistency_exception("The placeholder is not a directory.");
		}
		this->internal_secondary_fetch();
	}

	void directory_placeholder::internal_secondary_flush() const {
		::CF_UPDATE_FLAGS flags = ::CF_UPDATE_FLAGS::CF_UPDATE_FLAG_NONE;
		flags |= this->m_enumeration_enabled ? ::CF_UPDATE_FLAGS::CF_UPDATE_FLAG_ENABLE_ON_DEMAND_POPULATION : ::CF_UPDATE_FLAGS::CF_UPDATE_FLAG_DISABLE_ON_DEMAND_POPULATION;

		::HRESULT hr = ::CfUpdatePlaceholder(
		this->get_handle(),
		nullptr,
		nullptr,
		0,
		nullptr,
		0,
		flags,
		nullptr,
		nullptr
		);
		if (FAILED(hr)) {
			std::error_code ec(hr, std::system_category());
			throw cloud_provider_system_error(ec, "Failed to update placeholder information.");
		}
	}

	void directory_placeholder::set_enumeration_enabled(bool enabled) {
		this->m_enumeration_enabled = enabled;
	}

	directory_placeholder::~directory_placeholder() {}
}