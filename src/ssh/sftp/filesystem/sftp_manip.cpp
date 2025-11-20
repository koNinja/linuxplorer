#include <ssh/sftp/filesystem/sftp_manip.hpp>
#include <ssh/sftp/io/sftpstream.hpp>
#include <ssh/sftp/filesystem/sftp_entity.hpp>
#include <ssh/ssh_exception.hpp>

namespace linuxplorer::ssh::sftp::filesystem {
	sftp_handle create(const sftp_session& session, const std::filesystem::path& path, open_permissions perm, std::filesystem::perms created, create_options options) {
		auto p = path.u8string();
		
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
		result = ::libssh2_sftp_open_ex(session.get_session(), reinterpret_cast<const char*>(p.c_str()), p.length() * sizeof(char8_t), flags, static_cast<long>(created), LIBSSH2_SFTP_OPENFILE);

		if (!result) {
			throw ssh_libssh2_sftp_exception(std::error_code(session.get_last_errno(), libssh2_sftp_category()), "Failed to open a file or directory handle.");
		}

		return std::move(sftp_handle(session, result));
	}

	bool create_directory(const sftp_session& session, const std::filesystem::path& path, std::filesystem::perms created) {
		auto p = path.u8string();
		int rc = ::libssh2_sftp_mkdir_ex(session.get_session(), reinterpret_cast<const char*>(p.c_str()), p.length() * sizeof(char8_t), static_cast<long>(created));
		if (rc < 0) 
			throw ssh_libssh2_sftp_exception(std::error_code(rc, libssh2_sftp_category()), "Failed to make a directory");

		return true;
	}

	sftp_handle open(const sftp_session& session, const std::filesystem::path& path, open_permissions perms) {
		auto p = path.u8string();

		::LIBSSH2_SFTP_ATTRIBUTES attr{};
		int rc = ::libssh2_sftp_stat_ex(session.get_session(), reinterpret_cast<const char*>(p.c_str()), p.length() * sizeof(char8_t), LIBSSH2_SFTP_STAT, &attr);
		if (rc < 0) {
			throw ssh_libssh2_sftp_exception(std::error_code(rc, libssh2_sftp_category()), "Failed to get status about an SFTP file.");
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

		auto result = ::libssh2_sftp_open_ex(session.get_session(), reinterpret_cast<const char*>(p.c_str()), p.length() * sizeof(char8_t), flags, 0, target);
		if (!result) {
			throw ssh_libssh2_sftp_exception(std::error_code(session.get_last_errno(), libssh2_sftp_category()), "Failed to open an SFTP object.");
		}

		return std::move(sftp_handle(session, result));
	}

	std::filesystem::file_status status(const sftp_session& session, const std::filesystem::path& path) {
		auto p = path.u8string();

		::LIBSSH2_SFTP_ATTRIBUTES attr{};
		int rc = ::libssh2_sftp_stat_ex(session.get_session(), reinterpret_cast<const char*>(p.c_str()), p.length() * sizeof(char8_t), LIBSSH2_SFTP_STAT, &attr);
		if (rc < 0) {
			throw ssh_libssh2_sftp_exception(std::error_code(rc, libssh2_sftp_category()), "Failed to get status about an SFTP file.");
		}

		return internal::status_flags_to_file_status(attr.permissions);
	}

	std::filesystem::file_status status(const sftp_handle& handle) {
		::LIBSSH2_SFTP_ATTRIBUTES attr{};
		int rc = ::libssh2_sftp_fstat_ex(handle.get_handle(), &attr, LIBSSH2_SFTP_STAT);
		if (rc < 0) {
			throw ssh_libssh2_sftp_exception(std::error_code(rc, libssh2_sftp_category()), "Failed to get file attributes.");
		}

		return internal::status_flags_to_file_status(attr.permissions);
	}

	std::uintmax_t file_size(const sftp_session& session, const std::filesystem::path& path) {
		auto p = path.u8string();

		::LIBSSH2_SFTP_ATTRIBUTES attr{};
		int rc = ::libssh2_sftp_stat_ex(session.get_session(), reinterpret_cast<const char*>(p.c_str()), p.length() * sizeof(char8_t), LIBSSH2_SFTP_STAT, &attr);
		if (rc < 0) {
			throw ssh_libssh2_sftp_exception(std::error_code(rc, libssh2_sftp_category()), "Failed to get status about an SFTP file.");
		}

		return attr.filesize;
	}

	std::uintmax_t file_size(const sftp_handle &handle) {
		::LIBSSH2_SFTP_ATTRIBUTES attr;
		int rc = ::libssh2_sftp_fstat_ex(handle.get_handle(), &attr, 0);
		if (rc < 0) {
			throw ssh_libssh2_sftp_exception(std::error_code(rc, libssh2_sftp_category()), "Failed to get file attributes.");
		}

		return attr.filesize;
	}

	void rename(const sftp_session& session, const std::filesystem::path& old_path, const std::filesystem::path& new_path) {
		auto op = old_path.u8string();
		auto np = new_path.u8string();

		int rc = ::libssh2_sftp_rename_ex(
			session.get_session(),
			reinterpret_cast<const char*>(op.c_str()),
			op.length() * sizeof(char8_t),
			reinterpret_cast<const char*>(np.c_str()),
			np.length() * sizeof(char8_t),
			LIBSSH2_SFTP_RENAME_OVERWRITE
		);
		if (rc < 0) {
			throw ssh_libssh2_sftp_exception(std::error_code(rc, libssh2_sftp_category()), "Failed to rename a file.");
		}
	}

	void remove(const sftp_session& session, const std::filesystem::path& path) {
		auto stat = status(session, path);

		auto p = path.u8string();

		switch (stat.type()) {
		case std::filesystem::file_type::regular:
		{
			int rc = ::libssh2_sftp_unlink_ex(session.get_session(), reinterpret_cast<const char*>(p.c_str()), p.length() * sizeof(char8_t));
			if (rc < 0) {
				throw ssh_libssh2_sftp_exception(std::error_code(rc, libssh2_sftp_category()), "Failed to remove the file.");
			}
			break;
		}
		case std::filesystem::file_type::directory:
		{
			int rc = ::libssh2_sftp_rmdir_ex(session.get_session(), reinterpret_cast<const char*>(p.c_str()), p.length() * sizeof(char8_t));
			if (rc < 0) {
				throw ssh_libssh2_sftp_exception(std::error_code(rc, libssh2_sftp_category()), "Failed to remove the directory");
			}
			break;
		}
		default:
		{
			std::error_code ec(static_cast<int>(std::errc::not_supported), std::generic_category());
			throw ssh_libssh2_sftp_exception(ec, "Not supported file type.");
			break;
		}
		}
	}

	std::filesystem::file_time_type last_write_time(const sftp_session& session, const std::filesystem::path& path) {
		auto p = path.u8string();

		::LIBSSH2_SFTP_ATTRIBUTES attr{};
		int rc = ::libssh2_sftp_stat_ex(session.get_session(), reinterpret_cast<const char*>(p.c_str()), p.length() * sizeof(char8_t), LIBSSH2_SFTP_STAT, &attr);
		if (rc < 0) {
			throw ssh_libssh2_sftp_exception(std::error_code(rc, libssh2_sftp_category()), "Failed to get status about an SFTP file.");
		}

		return unix_to_filetime(attr.mtime);
	}

	std::filesystem::file_time_type last_access_time(const sftp_session& session, const std::filesystem::path& path) {
		auto p = path.u8string();

		::LIBSSH2_SFTP_ATTRIBUTES attr{};
		int rc = ::libssh2_sftp_stat_ex(session.get_session(), reinterpret_cast<const char*>(p.c_str()), p.length() * sizeof(char8_t), LIBSSH2_SFTP_STAT, &attr);
		if (rc < 0) {
			throw ssh_libssh2_sftp_exception(std::error_code(rc, libssh2_sftp_category()), "Failed to get status about an SFTP file.");
		}

		return unix_to_filetime(attr.atime);
	}
}