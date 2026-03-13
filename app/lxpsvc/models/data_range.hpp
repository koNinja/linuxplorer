#ifndef LINUXPLORER_LXPSVC_DATA_RANGE_HPP_
#define LINUXPLORER_LXPSVC_DATA_RANGE_HPP_

#include <type_traits>

namespace linuxplorer::app::lxpsvc::models {
	template <class T>
	requires std::is_arithmetic_v<T>
	struct range {
	private:
		T m_offset;
		T m_length;
	public:
		range(T offset, T length) : m_offset(offset), m_length(length) {};

		inline T get_offset() const noexcept {
			return this->m_offset;
		}
		inline void set_offset(T offset) noexcept {
			this->m_offset = offset;
		}

		inline T get_length() const noexcept {
			return this->m_length;
		}
		inline void set_length(T length) noexcept {
			this->m_length = length;
		}
	};
}

#endif // LINUXPLORER_LXPSVC_DATA_RANGE_HPP_