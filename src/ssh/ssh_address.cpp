#include <ssh/ssh_address.hpp>

#include <util/charset/multibyte_wide_compat_helper.hpp>

#include <ws2tcpip.h>
#include <regex>

namespace linuxplorer::ssh {
	ssh_address::ssh_address(const ssh_address& left) : m_bin_addr(left.m_bin_addr), m_str_addr(left.m_str_addr)
	{}

	ssh_address::ssh_address(ssh_address&& right) : m_bin_addr(std::move(right.m_bin_addr)), m_str_addr(std::move(right.m_str_addr))
	{}

	ssh_address::ssh_address(std::wstring_view address) {
		using charset_helper = linuxplorer::util::charset::multibyte_wide_compat_helper;

		this->m_str_addr = address;

		std::wregex ipv4_pattern(LR"(^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$)");
		std::wregex ipv6_pattern(LR"(^([0-9a-fA-F]{1,4}:){7}([0-9a-fA-F]{1,4})$|^([0-9a-fA-F]{1,4}:){1,7}:$|^:([0-9a-fA-F]{1,4}:){1,6}$|^([0-9a-fA-F]{1,4}:){0,5}:([0-9a-fA-F]{1,4}:){1,6}$)");

		std::match_results<decltype(address)::const_iterator> match;
		if (std::regex_match(address.cbegin(), address.cend(), match, ipv4_pattern)) {
			for (size_t i = 1; i <= 4; ++i) {
				int part = std::stoi(match[i]);
				if (part < 0 || part > 255) {
					throw std::invalid_argument("Invalid IP address.");
				}
			}

			::in_addr bin_addr;
			int result = ::inet_pton(AF_INET, charset_helper::convert_wide_to_multibyte(address).c_str(), &bin_addr);
			this->m_bin_addr = bin_addr;
		}
		else if (std::regex_match(address.cbegin(), address.cend(), ipv6_pattern)) {
			::in_addr6 bin_addr;
			int result = ::inet_pton(AF_INET6, charset_helper::convert_wide_to_multibyte(address).c_str(), &bin_addr);
			this->m_bin_addr = bin_addr;
		}
		else {
			throw std::invalid_argument("Invalid IP address.");
		}
	}

	ssh_address_type ssh_address::get_type() const noexcept {
		if (std::holds_alternative<::in_addr>(this->m_bin_addr)) {
			return ssh_address_type::ipv4;
		}
		else return ssh_address_type::ipv6;
	}

	std::wstring_view ssh_address::get_string_address() const noexcept {
		return this->m_str_addr;
	}

	std::optional<::in_addr> ssh_address::try_get_address_ipv4() const noexcept {
		return std::holds_alternative<::in_addr>(this->m_bin_addr) ? std::optional<::in_addr>(std::get<::in_addr>(this->m_bin_addr)) : std::nullopt;
	}

	std::optional<::in_addr6> ssh_address::try_get_address_ipv6() const noexcept {
		return std::holds_alternative<::in_addr6>(this->m_bin_addr) ? std::optional<::in_addr6>(std::get<::in_addr6>(this->m_bin_addr)) : std::nullopt;
	}

	ssh_address::~ssh_address() {}
}