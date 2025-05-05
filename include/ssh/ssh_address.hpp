#ifndef SSH_ADDRESS_HPP
#define SSH_ADDRESS_HPP

#include <winsock2.h>
#include <in6addr.h>

#include <string>
#include <string_view>
#include <variant>
#include <optional>

namespace linuxplorer::ssh {
	enum class ssh_address_type {
		ipv4,
		ipv6
	};

	class ssh_address {
		std::wstring m_str_addr;
		std::variant<::in_addr, ::in_addr6> m_bin_addr;
	public:
		ssh_address(std::wstring_view address);
		ssh_address(const ssh_address& left) noexcept;
		ssh_address(ssh_address&& right) noexcept;

		ssh_address_type get_type() const noexcept;
		
		std::wstring_view get_string_address() const noexcept;
		
		std::optional<::in_addr> try_get_address_ipv4() const noexcept;
		std::optional<::in_addr6> try_get_address_ipv6() const noexcept;
		
		virtual ~ssh_address();
	};
}

#endif // SSH_ADDRESS_HPP