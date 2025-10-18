#ifndef LINUXPLORER_SFTP_MANIP_HPP_
#define LINUXPLORER_SFTP_MANIP_HPP_

#include <ssh/sftp/sftp_session.hpp>
#include <filesystem>
#include <libssh2_sftp.h>

namespace linuxplorer::ssh::sftp::filesystem {
	enum class open_permissions {
		read = LIBSSH2_FXF_READ,
		write = LIBSSH2_FXF_WRITE
	};
	inline open_permissions operator|(open_permissions lt, open_permissions rt) {
		return static_cast<open_permissions>(static_cast<int>(lt) | static_cast<int>(rt));
	}
	inline open_permissions operator&(open_permissions lt, open_permissions rt) {
		return static_cast<open_permissions>(static_cast<int>(lt) | static_cast<int>(rt));
	}
	inline open_permissions operator|=(open_permissions lhs, open_permissions rhs) {
		return lhs = lhs | rhs;
	}
	inline open_permissions operator&=(open_permissions lhs, open_permissions rhs) {
		return lhs = lhs & rhs;
	}
	inline open_permissions operator~(open_permissions v) {
		return static_cast<open_permissions>(~static_cast<int>(v));
	}
	inline open_permissions operator^(open_permissions lt, open_permissions rt) {
		return static_cast<open_permissions>(static_cast<int>(lt) ^ static_cast<int>(rt));
	}
	inline open_permissions operator^=(open_permissions lhs, open_permissions rhs) {
		return lhs = lhs ^ rhs;
	}

	constexpr std::filesystem::perms default_file_perms_created = std::filesystem::perms::owner_read | std::filesystem::perms::owner_write | std::filesystem::perms::group_read | std::filesystem::perms::owner_read;
	constexpr std::filesystem::perms default_dir_perms_created = std::filesystem::perms::owner_all | std::filesystem::perms::group_read | std::filesystem::perms::group_exec | std::filesystem::perms::others_read | std::filesystem::perms::others_exec;

	enum class create_options {
		none,
		truncate,
		exclusive
	};

	LINUXPLORER_SSH_API sftp_handle create(const sftp_session& session, const std::filesystem::path& path, open_permissions perm, std::filesystem::perms created = default_file_perms_created, create_options options = create_options::none);
	LINUXPLORER_SSH_API bool create_directory(const sftp_session& session, const std::filesystem::path& path, std::filesystem::perms created = default_dir_perms_created);
	LINUXPLORER_SSH_API sftp_handle open(const sftp_session& session, const std::filesystem::path& path, open_permissions perm);
	LINUXPLORER_SSH_API std::uintmax_t file_size(const sftp_session& session, const std::filesystem::path& path);
	LINUXPLORER_SSH_API std::uintmax_t file_size(const sftp_handle& handle);
	LINUXPLORER_SSH_API std::filesystem::file_status status(const sftp_session& session, const std::filesystem::path& path);
	LINUXPLORER_SSH_API std::filesystem::file_status status(const sftp_handle& handle);
	//LINUXPLORER_SSH_API void copy(const sftp_session& session, const std::filesystem::path& from, const std::filesystem::path& to, std::filesystem::copy_options options = std::filesystem::copy_options::none);
	//LINUXPLORER_SSH_API void permissions(const std::filesystem::path& path, std::filesystem::perms perms, std::filesystem::perm_options opts = std::filesystem::perm_options::replace);
	//LINUXPLORER_SSH_API void permissions(const sftp_handle& handle, std::filesystem::perms perms, std::filesystem::perm_options opts = std::filesystem::perm_options::replace);
	LINUXPLORER_SSH_API void rename(const sftp_session& session, const std::filesystem::path& old_path, const std::filesystem::path& new_path);
	LINUXPLORER_SSH_API void remove(const sftp_session& session, const std::filesystem::path& path);
	LINUXPLORER_SSH_API std::filesystem::file_time_type last_write_time(const sftp_session& session, const std::filesystem::path& path);
	LINUXPLORER_SSH_API std::filesystem::file_time_type last_access_time(const sftp_session& session, const std::filesystem::path& path);
}

#endif // LINUXPLORER_SFTP_MANIP_HPP_