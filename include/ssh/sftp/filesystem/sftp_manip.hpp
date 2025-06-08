#ifndef SFTP_MANIP_HPP
#define SFTP_MANIP_HPP

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

	sftp_handle create(const sftp_session& session, const std::filesystem::path& path, open_permissions perm, std::filesystem::perms created = default_file_perms_created, create_options options = create_options::none);
	bool create_directory(const sftp_session& session, const std::filesystem::path& path, std::filesystem::perms created = default_dir_perms_created);
	sftp_handle open(const sftp_session& session, const std::filesystem::path& path, open_permissions perm);
	std::uintmax_t file_size(const sftp_handle& handle);
	std::filesystem::file_status status(const sftp_handle& handle);
	//void copy(const sftp_handle& from, const std::filesystem::path& to, std::filesystem::copy_options options = std::filesystem::copy_options::none);
	//void permissions(const sftp_handle& handle, std::filesystem::perms perms, std::filesystem::perm_options opts = std::filesystem::perm_options::replace);
	//void rename(const sftp_handle& handle, const std::filesystem::path& new_path);
	//void remove(sftp_handle&& handle);
}

#endif // SFTP_MANIP_HPP