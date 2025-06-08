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
		default:
			flags |= LIBSSH2_FXF_WRITE;
		}

		::LIBSSH2_SFTP_HANDLE* result = nullptr;
		result = ::libssh2_sftp_open_ex(session.get_session(), p.c_str(), p.length() * sizeof(char), flags, static_cast<long>(created), LIBSSH2_SFTP_OPENFILE);

		if (!result) {
			throw ssh_libssh2_sftp_exception(session.get_last_errno(), "Failed to open a file or directory handle.");
		}

		return std::move(sftp_handle(session, result));
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

	std::filesystem::file_status status(const sftp_handle& handle) {
		::LIBSSH2_SFTP_ATTRIBUTES attr;
		int rc = ::libssh2_sftp_fstat_ex(handle.get_handle(), &attr, 0);
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

	std::uintmax_t file_size(const sftp_handle &handle) {
		::LIBSSH2_SFTP_ATTRIBUTES attr;
		int rc = ::libssh2_sftp_fstat_ex(handle.get_handle(), &attr, 0);
		if (rc < 0) {
			throw ssh_libssh2_sftp_exception(rc, "Failed to get file attributes.");
		}

		return attr.filesize;
	}
}