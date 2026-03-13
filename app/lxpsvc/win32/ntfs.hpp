#ifndef LINUXPLORER_LXPSVC_NTFS_HPP_
#define LINUXPLORER_LXPSVC_NTFS_HPP_

#include <windows.h>
#include <functional>
#include <cstring>
#include <filesystem>

namespace linuxplorer::app::lxpsvc::win32 {
	struct file_reference_number {
	private:
		::FILE_ID_128 m_frn;
	public:
		file_reference_number(const ::FILE_ID_128& frn) : m_frn(frn) {}
		file_reference_number(::FILE_ID_128&& frn) : m_frn(frn) {}
		file_reference_number(const file_reference_number& lhs) : m_frn(lhs.m_frn) {}
		file_reference_number(file_reference_number&& rhs) : m_frn(rhs.m_frn) {}
		file_reference_number& operator=(const file_reference_number& lhs) {
			if (this != &lhs) {
				std::copy(lhs.m_frn.Identifier, lhs.m_frn.Identifier + 16, this->m_frn.Identifier);
			}
			return *this;
		}

		file_reference_number& operator=(file_reference_number&& rhs) {
			if (this != &rhs) {
				std::copy(rhs.m_frn.Identifier, rhs.m_frn.Identifier + 16, this->m_frn.Identifier);
			}
			return *this;
		}

		file_reference_number& operator=(const FILE_ID_128& lhs) {
			this->m_frn = lhs;
			return *this;
		}

		file_reference_number& operator=(FILE_ID_128&& rhs) {
			this->m_frn = rhs;
			return *this;
		}

		const ::FILE_ID_128& to_native() const noexcept {
			return m_frn;
		}

		bool operator==(const file_reference_number& other) const noexcept {
			return std::equal(this->m_frn.Identifier, this->m_frn.Identifier + 16, other.m_frn.Identifier);
		}
		bool operator!=(const file_reference_number& other) const noexcept {
			return !(*this == other);
		}
	};

	file_reference_number get_frn(const std::filesystem::path& path);
}

namespace std {
	template <>
	struct hash<linuxplorer::app::lxpsvc::win32::file_reference_number> {
		size_t operator()(const linuxplorer::app::lxpsvc::win32::file_reference_number& key) const noexcept {
            static_assert(sizeof(size_t) == 8, "This hash requires 64-bit size_t.");

            std::uint64_t high, low;
            std::memcpy(&high, key.to_native().Identifier, 8);
            std::memcpy(&low, key.to_native().Identifier + 8, 8);

            return high ^ (low * 0x9e3779b97f4a7c15ull);
        }
	};
}

#endif // LINUXPLORER_LXPSVC_NTFS_HPP_