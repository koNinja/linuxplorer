#include <ssh/sftp/filesystem/sftp_entity.hpp>
#include <ssh/sftp/filesystem/sftp_manip.hpp>
#include <ssh/ssh_exception.hpp>
#include <iostream>

namespace linuxplorer::ssh::sftp::filesystem {
	directory_entry::directory_entry(const std::filesystem::path& path) {
		this->m_path = path;
	}

	const std::filesystem::path& directory_entry::path() const noexcept {
		return this->m_path;
	}

	directory_entry::operator const std::filesystem::path&() const noexcept {
		return this->m_path;
	}

	directory_iterator::directory_iterator() noexcept : m_pos(-1) {}

	directory_iterator::directory_iterator(const sftp_session& session, const std::filesystem::path& path, std::filesystem::directory_options options) : m_pos(-1) {
		auto handle = open(session, path, open_permissions::read);

		int bytes_read;
		std::vector<std::u8string> paths;
		while (true) {
			// filename limit is 255 bytes in linux;
			char8_t buffer[0xFF];
			
			bytes_read = ::libssh2_sftp_readdir_ex(handle.get_handle(), reinterpret_cast<char*>(buffer), sizeof(buffer), nullptr, 0, nullptr);
			if (bytes_read <= 0) break;

			paths.push_back(buffer);
		}
		
		if (bytes_read < 0) {
			throw ssh_libssh2_exception(bytes_read, "Failed to read directory data.");
		}
		
		this->m_ptr = std::make_unique<directory_iterator::value_type[]>(paths.size());
		
		for (int i = 0; const auto& p : paths) {
			this->m_ptr[i] = std::move(directory_entry(p));
			i++;
		}
		
		this->m_count = paths.size();
		this->m_pos = 0;
	}

	const directory_iterator::value_type& directory_iterator::operator*() const noexcept {
		return *(this->m_ptr.get() + this->m_pos);
	}

	const directory_iterator::value_type* directory_iterator::operator->() const noexcept {
		return this->m_ptr.get() + this->m_pos;
	}

	directory_iterator& directory_iterator::operator++() noexcept {
		this->m_pos += 1;
		if (this->m_pos >= this->m_count) {
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