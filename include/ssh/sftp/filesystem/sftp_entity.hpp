#ifndef LINUXPLORER_SFTP_ENTITY_HPP_
#define LINUXPLORER_SFTP_ENTITY_HPP_

#include <ssh/sshfwd.hpp>
#include <ssh/ssh_session.hpp>
#include <ssh/sftp/sftp_session.hpp>
#include <filesystem>
#include <vector>

namespace linuxplorer::ssh::sftp::filesystem {
	namespace internal {
		LINUXPLORER_SSH_API std::filesystem::file_status status_flags_to_file_status(unsigned long status);
	}
	LINUXPLORER_SSH_API std::filesystem::file_time_type unix_to_filetime(std::uint64_t time);

	class LINUXPLORER_SSH_API directory_entry {
	private:
		std::filesystem::path m_path;
		std::uintmax_t m_file_size;
		std::filesystem::file_status m_file_status;
		std::filesystem::file_time_type m_last_access_time;
		std::filesystem::file_time_type m_last_write_time;
	public:
		explicit directory_entry() = default;
		explicit directory_entry(
			const std::filesystem::path& path,
			std::uintmax_t file_size,
			const std::filesystem::file_status& status,
			std::filesystem::file_time_type last_access_time,
			std::filesystem::file_time_type last_write_time
		);
		directory_entry(const directory_entry& lhs) noexcept = default;
		directory_entry(directory_entry&& rhs) noexcept = default;
		
		directory_entry& operator=(const directory_entry& lhs) noexcept = default;
		directory_entry& operator=(directory_entry&& rhs) noexcept = default;

		const std::filesystem::path& path() const noexcept;
		operator const std::filesystem::path&() const noexcept;

		std::uintmax_t file_size() const noexcept;
		const std::filesystem::file_status& status() const noexcept;
		std::filesystem::file_time_type last_write_time() const noexcept;
		std::filesystem::file_time_type last_access_time() const noexcept;

		virtual ~directory_entry() = default;
	};

	class LINUXPLORER_SSH_API directory_iterator {
	public:
		using iterator_category = std::input_iterator_tag;
		using value_type = directory_entry;
		using difference_type = std::ptrdiff_t;
		using pointer = const directory_entry*;
		using reference = const directory_entry&;
		using pos_type = std::streampos;

		directory_iterator() noexcept;
		explicit directory_iterator(const sftp_session& session, const std::filesystem::path& path, std::filesystem::directory_options options = std::filesystem::directory_options::none);
		directory_iterator(const directory_iterator&) noexcept = default;
		directory_iterator(directory_iterator&& rhs) noexcept = default;

		const value_type& operator*() const noexcept;
		const value_type* operator->() const noexcept;
		directory_iterator& operator++() noexcept;
		bool operator==(const directory_iterator& itr) const noexcept;
		bool operator!=(const directory_iterator& itr) const noexcept;

		virtual ~directory_iterator();
	private:
		std::streampos m_pos;
		std::vector<value_type> m_entities;
	};

	inline directory_iterator begin(directory_iterator itr) noexcept {
		return itr;
	}

	inline directory_iterator end(directory_iterator itr) noexcept {
		return directory_iterator{};
	}
}

#endif // LINUXPLORER_SFTP_ENTITY_HPP_