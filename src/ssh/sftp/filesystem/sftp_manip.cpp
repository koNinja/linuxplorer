#include <ssh/sftp/filesystem/sftp_manip.hpp>
#include <ssh/sftp/io/sftpstream.hpp>
#include <ssh/ssh_exception.hpp>

namespace linuxplorer::ssh::sftp::filesystem {
	sftp_handle create(const sftp_session& session, const std::filesystem::path& path, open_permissions perm, std::filesystem::perms created, create_options options) {
		auto p = path.generic_string();
		
		int flags = LIBSSH2_FXF_CREAT;
		switch (options) {
		case create_options::exclusive:
			flags |= LIBSSH2_FXF_EXCL;
			break;
		case create_options::truncate:
			flags |= LIBSSH2_FXF_TRUNC;
			break;
		default:
			break;
		}
		switch (perm) {
		case open_permissions::read:
			flags |= LIBSSH2_FXF_READ;
			break;
		case open_permissions::write:
			flags |= LIBSSH2_FXF_WRITE;
		default:
			break;
		}

		::LIBSSH2_SFTP_HANDLE* result = nullptr;
		result = ::libssh2_sftp_open_ex(session.get_session(), p.c_str(), p.length() * sizeof(char), flags, static_cast<long>(created), LIBSSH2_SFTP_OPENFILE);

		if (!result) {
			throw ssh_libssh2_sftp_exception(session.get_last_errno(), "Failed to open a file or directory handle.");
		}

		return std::move(sftp_handle(session, result));
	}

	bool create_directory(const sftp_session& session, const std::filesystem::path& path, std::filesystem::perms created) {
		auto p = path.generic_string();
		int rc = ::libssh2_sftp_mkdir_ex(session.get_session(), p.c_str(), p.length() * sizeof(char), static_cast<long>(created));
		if (rc < 0) {
			throw ssh_libssh2_sftp_exception(rc, "Failed to make a directory");
			return false;
		}

		return true;
	}

	sftp_handle open(const sftp_session& session, const std::filesystem::path& path, open_permissions perms) {
		auto p = path.generic_string();

		::LIBSSH2_SFTP_ATTRIBUTES attr{};
		int rc = ::libssh2_sftp_stat_ex(session.get_session(), p.c_str(), p.length() * sizeof(char), LIBSSH2_SFTP_STAT, &attr);
		if (rc < 0) {
			throw ssh_libssh2_sftp_exception(rc, "Failed to get status about an SFTP file.");
		}

		std::uint32_t flags = 0;
		std::int32_t target = 0;
		if (LIBSSH2_SFTP_S_ISREG(attr.permissions)) {
			flags = static_cast<std::uint32_t>(perms);
			target = LIBSSH2_SFTP_OPENFILE;
		}
		else {
			flags = 0;
			target = LIBSSH2_SFTP_OPENDIR;
		}

		auto result = ::libssh2_sftp_open_ex(session.get_session(), p.c_str(), p.length() * sizeof(char), flags, 0, target);
		if (!result) {
			throw ssh_libssh2_sftp_exception(session.get_last_errno(), "Failed to open an SFTP object.");
		}

		return std::move(sftp_handle(session, result));
	}

	std::filesystem::file_status status(const sftp_session& session, const std::filesystem::path& path) {
		auto p = path.generic_string();

		::LIBSSH2_SFTP_ATTRIBUTES attr{};
		int rc = ::libssh2_sftp_stat_ex(session.get_session(), p.c_str(), p.length() * sizeof(char), LIBSSH2_SFTP_STAT, &attr);
		if (rc < 0) {
			throw ssh_libssh2_sftp_exception(rc, "Failed to get status about an SFTP file.");
		}

		std::filesystem::file_type type;
		if (LIBSSH2_SFTP_S_ISLNK(attr.permissions)) {
			type = std::filesystem::file_type::symlink;
		}
		else if (LIBSSH2_SFTP_S_ISREG(attr.permissions)) {
			type = std::filesystem::file_type::regular;
		}
		else if (LIBSSH2_SFTP_S_ISDIR(attr.permissions)) {
			type = std::filesystem::file_type::directory;
		}
		else if (LIBSSH2_SFTP_S_ISCHR(attr.permissions)) {
			type = std::filesystem::file_type::character;
		}
		else if (LIBSSH2_SFTP_S_ISBLK(attr.permissions)) {
			type = std::filesystem::file_type::block;
		}
		else if (LIBSSH2_SFTP_S_ISFIFO(attr.permissions)) {
			type = std::filesystem::file_type::fifo;
		}
		else if (LIBSSH2_SFTP_S_ISSOCK(attr.permissions)) {
			type = std::filesystem::file_type::socket;
		}
		else {
			type = std::filesystem::file_type::unknown;
		}

		std::filesystem::perms perm = std::filesystem::perms::none;
		if (attr.permissions & LIBSSH2_SFTP_S_IRUSR) {
			perm |= std::filesystem::perms::owner_read;
		}
		if (attr.permissions & LIBSSH2_SFTP_S_IWUSR) {
			perm |= std::filesystem::perms::owner_write;
		}
		if (attr.permissions & LIBSSH2_SFTP_S_IXUSR) {
			perm |= std::filesystem::perms::owner_exec;
		}
		if (attr.permissions & LIBSSH2_SFTP_S_IRGRP) {
			perm |= std::filesystem::perms::group_read;
		}
		if (attr.permissions & LIBSSH2_SFTP_S_IWGRP) {
			perm |= std::filesystem::perms::group_write;
		}
		if (attr.permissions & LIBSSH2_SFTP_S_IXGRP) {
			perm |= std::filesystem::perms::group_exec;
		}
		if (attr.permissions & LIBSSH2_SFTP_S_IROTH) {
			perm |= std::filesystem::perms::others_read;
		}
		if (attr.permissions & LIBSSH2_SFTP_S_IWOTH) {
			perm |= std::filesystem::perms::others_write;
		}
		if (attr.permissions & LIBSSH2_SFTP_S_IXOTH) {
			perm |= std::filesystem::perms::others_exec;
		}

		return std::filesystem::file_status(type, perm);
	}

	std::filesystem::file_status status(const sftp_handle& handle) {
		::LIBSSH2_SFTP_ATTRIBUTES attr{};
		int rc = ::libssh2_sftp_fstat_ex(handle.get_handle(), &attr, LIBSSH2_SFTP_STAT);
		if (rc < 0) {
			throw ssh_libssh2_sftp_exception(rc, "Failed to get file attributes.");
		}

		std::filesystem::file_type type;
		if (LIBSSH2_SFTP_S_ISLNK(attr.permissions)) {
			type = std::filesystem::file_type::symlink;
		}
		else if (LIBSSH2_SFTP_S_ISREG(attr.permissions)) {
			type = std::filesystem::file_type::regular;
		}
		else if (LIBSSH2_SFTP_S_ISDIR(attr.permissions)) {
			type = std::filesystem::file_type::directory;
		}
		else if (LIBSSH2_SFTP_S_ISCHR(attr.permissions)) {
			type = std::filesystem::file_type::character;
		}
		else if (LIBSSH2_SFTP_S_ISBLK(attr.permissions)) {
			type = std::filesystem::file_type::block;
		}
		else if (LIBSSH2_SFTP_S_ISFIFO(attr.permissions)) {
			type = std::filesystem::file_type::fifo;
		}
		else if (LIBSSH2_SFTP_S_ISSOCK(attr.permissions)) {
			type = std::filesystem::file_type::socket;
		}
		else {
			type = std::filesystem::file_type::unknown;
		}

		std::filesystem::perms perm = std::filesystem::perms::none;
		if (attr.permissions & LIBSSH2_SFTP_S_IRUSR) {
			perm |= std::filesystem::perms::owner_read;
		}
		if (attr.permissions & LIBSSH2_SFTP_S_IWUSR) {
			perm |= std::filesystem::perms::owner_write;
		}
		if (attr.permissions & LIBSSH2_SFTP_S_IXUSR) {
			perm |= std::filesystem::perms::owner_exec;
		}
		if (attr.permissions & LIBSSH2_SFTP_S_IRGRP) {
			perm |= std::filesystem::perms::group_read;
		}
		if (attr.permissions & LIBSSH2_SFTP_S_IWGRP) {
			perm |= std::filesystem::perms::group_write;
		}
		if (attr.permissions & LIBSSH2_SFTP_S_IXGRP) {
			perm |= std::filesystem::perms::group_exec;
		}
		if (attr.permissions & LIBSSH2_SFTP_S_IROTH) {
			perm |= std::filesystem::perms::others_read;
		}
		if (attr.permissions & LIBSSH2_SFTP_S_IWOTH) {
			perm |= std::filesystem::perms::others_write;
		}
		if (attr.permissions & LIBSSH2_SFTP_S_IXOTH) {
			perm |= std::filesystem::perms::others_exec;
		}

		return std::filesystem::file_status(type, perm);
	}

	std::uintmax_t file_size(const sftp_session& session, const std::filesystem::path& path) {
		auto p = path.generic_string();

		::LIBSSH2_SFTP_ATTRIBUTES attr{};
		int rc = ::libssh2_sftp_stat_ex(session.get_session(), p.c_str(), p.length() * sizeof(char), LIBSSH2_SFTP_STAT, &attr);
		if (rc < 0) {
			throw ssh_libssh2_sftp_exception(rc, "Failed to get status about an SFTP file.");
		}

		return attr.filesize;
	}

	std::uintmax_t file_size(const sftp_handle &handle) {
		::LIBSSH2_SFTP_ATTRIBUTES attr;
		int rc = ::libssh2_sftp_fstat_ex(handle.get_handle(), &attr, 0);
		if (rc < 0) {
			throw ssh_libssh2_sftp_exception(rc, "Failed to get file attributes.");
		}

		return attr.filesize;
	}

	void rename(const sftp_session& session, const std::filesystem::path& old_path, const std::filesystem::path& new_path) {
		int rc = ::libssh2_sftp_rename_ex(
			session.get_session(),
			old_path.string().c_str(),
			old_path.string().length() * sizeof(char),
			new_path.string().c_str(),
			new_path.string().length() * sizeof(char),
			LIBSSH2_SFTP_RENAME_OVERWRITE
		);
		if (rc < 0) {
			throw ssh_libssh2_sftp_exception(rc, "Failed to rename a file.");
		}
	}

	void remove(const sftp_session& session, const std::filesystem::path& path) {
		auto stat = status(session, path);

		switch (stat.type()) {
		case std::filesystem::file_type::regular:
		{
			int rc = ::libssh2_sftp_unlink_ex(session.get_session(), path.string().c_str(), path.string().length() * sizeof(char));
			if (rc < 0) {
				throw ssh_libssh2_sftp_exception(rc, "Failed to remove the file.");
			}
			break;
		}
		case std::filesystem::file_type::directory:
		{
			int rc = ::libssh2_sftp_rmdir_ex(session.get_session(), path.string().c_str(), path.string().length() * sizeof(char));
			if (rc < 0) {
				throw ssh_libssh2_sftp_exception(rc, "Failed to remove the directory");
			}
			break;
		}
		default:
		{
			std::error_code ec(static_cast<int>(std::errc::not_supported), std::generic_category());
			throw std::system_error(ec, "Not supported file type.");
			break;
		}
		}
	}

	std::filesystem::file_time_type last_write_time(const sftp_session& session, const std::filesystem::path& path) {
		auto p = path.generic_string();

		::LIBSSH2_SFTP_ATTRIBUTES attr{};
		int rc = ::libssh2_sftp_stat_ex(session.get_session(), p.c_str(), p.length() * sizeof(char), LIBSSH2_SFTP_STAT, &attr);
		if (rc < 0) {
			throw ssh_libssh2_sftp_exception(rc, "Failed to get status about an SFTP file.");
		}

		auto utc_lm = std::chrono::file_clock::from_utc(std::chrono::utc_clock::from_sys(std::chrono::system_clock::from_time_t(attr.mtime)));
		
		return std::chrono::time_point_cast<std::filesystem::file_time_type::duration>(utc_lm);
	}

	std::filesystem::file_time_type last_access_time(const sftp_session& session, const std::filesystem::path& path) {
		auto p = path.generic_string();

		::LIBSSH2_SFTP_ATTRIBUTES attr{};
		int rc = ::libssh2_sftp_stat_ex(session.get_session(), p.c_str(), p.length() * sizeof(char), LIBSSH2_SFTP_STAT, &attr);
		if (rc < 0) {
			throw ssh_libssh2_sftp_exception(rc, "Failed to get status about an SFTP file.");
		}

		auto utc_la = std::chrono::file_clock::from_utc(std::chrono::utc_clock::from_sys(std::chrono::system_clock::from_time_t(attr.atime)));
		
		return std::chrono::time_point_cast<std::filesystem::file_time_type::duration>(utc_la);
	}
}