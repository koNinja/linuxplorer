#include <ssh/sftp/filesystem/sftp_entity.hpp>
#include <ssh/sftp/filesystem/sftp_manip.hpp>
#include <ssh/ssh_exception.hpp>
#include <iostream>

namespace linuxplorer::ssh::sftp::filesystem {
	namespace internal {
		std::filesystem::file_status status_flags_to_file_status(unsigned long status) {
			std::filesystem::file_type type;
		if (LIBSSH2_SFTP_S_ISLNK(status)) {
			type = std::filesystem::file_type::symlink;
		}
		else if (LIBSSH2_SFTP_S_ISREG(status)) {
			type = std::filesystem::file_type::regular;
		}
		else if (LIBSSH2_SFTP_S_ISDIR(status)) {
			type = std::filesystem::file_type::directory;
		}
		else if (LIBSSH2_SFTP_S_ISCHR(status)) {
			type = std::filesystem::file_type::character;
		}
		else if (LIBSSH2_SFTP_S_ISBLK(status)) {
			type = std::filesystem::file_type::block;
		}
		else if (LIBSSH2_SFTP_S_ISFIFO(status)) {
			type = std::filesystem::file_type::fifo;
		}
		else if (LIBSSH2_SFTP_S_ISSOCK(status)) {
			type = std::filesystem::file_type::socket;
		}
		else {
			type = std::filesystem::file_type::unknown;
		}

		std::filesystem::perms perm = std::filesystem::perms::none;
		if (status & LIBSSH2_SFTP_S_IRUSR) {
			perm |= std::filesystem::perms::owner_read;
		}
		if (status & LIBSSH2_SFTP_S_IWUSR) {
			perm |= std::filesystem::perms::owner_write;
		}
		if (status & LIBSSH2_SFTP_S_IXUSR) {
			perm |= std::filesystem::perms::owner_exec;
		}
		if (status & LIBSSH2_SFTP_S_IRGRP) {
			perm |= std::filesystem::perms::group_read;
		}
		if (status & LIBSSH2_SFTP_S_IWGRP) {
			perm |= std::filesystem::perms::group_write;
		}
		if (status & LIBSSH2_SFTP_S_IXGRP) {
			perm |= std::filesystem::perms::group_exec;
		}
		if (status & LIBSSH2_SFTP_S_IROTH) {
			perm |= std::filesystem::perms::others_read;
		}
		if (status & LIBSSH2_SFTP_S_IWOTH) {
			perm |= std::filesystem::perms::others_write;
		}
		if (status & LIBSSH2_SFTP_S_IXOTH) {
			perm |= std::filesystem::perms::others_exec;
		}

		return std::filesystem::file_status(type, perm);
		}
	}

	std::filesystem::file_time_type unix_to_filetime(std::uint64_t time) {
		auto utc = std::chrono::file_clock::from_utc(std::chrono::utc_clock::from_sys(std::chrono::system_clock::from_time_t(time)));

		return std::chrono::time_point_cast<std::filesystem::file_time_type::duration>(utc);
	}

	directory_entry::directory_entry(
		const std::filesystem::path& path,
		std::uintmax_t file_size,
		const std::filesystem::file_status& status,
		std::filesystem::file_time_type last_access_time,
		std::filesystem::file_time_type last_write_time
	) : m_path(path), m_file_size(file_size), m_file_status(status), m_last_access_time(last_access_time), m_last_write_time(last_write_time) {}

	const std::filesystem::path& directory_entry::path() const noexcept {
		return this->m_path;
	}

	directory_entry::operator const std::filesystem::path&() const noexcept {
		return this->m_path;
	}

	std::uintmax_t directory_entry::file_size() const noexcept {
		return this->m_file_size;
	}

	const std::filesystem::file_status& directory_entry::status() const noexcept {
		return this->m_file_status;
	}

	std::filesystem::file_time_type directory_entry::last_write_time() const noexcept {
		return this->m_last_write_time;
	}

	std::filesystem::file_time_type directory_entry::last_access_time() const noexcept {
		return this->m_last_access_time;
	}

	directory_iterator::directory_iterator() noexcept : m_pos(-1) {}

	directory_iterator::directory_iterator(const sftp_session& session, const std::filesystem::path& path, std::filesystem::directory_options options) : m_pos(-1) {
		auto handle = open(session, path, open_permissions::read);

		int bytes_read;
		// filename limit is 255 bytes in linux;
		char8_t buffer[0xFF];
		while (true) {
			::LIBSSH2_SFTP_ATTRIBUTES attr;

			bytes_read = ::libssh2_sftp_readdir_ex(handle.get_handle(), reinterpret_cast<char*>(buffer), sizeof(buffer), nullptr, 0, &attr);
			if (bytes_read <= 0) break;

			this->m_entities.push_back(directory_entry(
				buffer,
				attr.filesize,
				internal::status_flags_to_file_status(attr.permissions),
				unix_to_filetime(attr.atime),
				unix_to_filetime(attr.mtime))
			);
		}
		
		if (bytes_read < 0) {
			throw ssh_libssh2_sftp_exception(std::error_code(bytes_read, libssh2_sftp_category()), "Failed to read directory data.");
		}

		this->m_pos = 0;
	}

	const directory_iterator::value_type& directory_iterator::operator*() const noexcept {
		return this->m_entities[this->m_pos];
	}

	const directory_iterator::value_type* directory_iterator::operator->() const noexcept {
		return &this->m_entities[this->m_pos];
	}

	directory_iterator& directory_iterator::operator++() noexcept {
		this->m_pos += 1;
		if (this->m_pos >= this->m_entities.size()) {
			this->m_pos = -1;
		}
		return *this;
	}

	bool directory_iterator::operator==(const directory_iterator& itr) const noexcept {
		return this->m_pos == itr.m_pos;
	}

	bool directory_iterator::operator!=(const directory_iterator& itr) const noexcept {
		return this->m_pos != itr.m_pos;
	}

	directory_iterator::~directory_iterator() {}
}