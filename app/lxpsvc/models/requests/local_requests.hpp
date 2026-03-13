#ifndef LINUXPLORER_LOCAL_REQUESTS_HPP_
#define LINUXPLORER_LOCAL_REQUESTS_HPP_

#include "io_requests.hpp"

namespace linuxplorer::app::lxpsvc::models::requests::local {
	class attribute_request : public io_request {
	public:
		enum class change_domain {
			pin,
			unpin,
			mark_in_sync,
			unmark_in_sync
		};

	private:
		change_domain m_domain;
	public:
		attribute_request(const std::filesystem::path& absolute_path, change_domain domain) :
			io_request(absolute_path), m_domain(domain)
		{}

		change_domain get_domain() const noexcept {
			return this->m_domain;
		}
	};

	class transform_request : public io_request {
	private:
		std::vector<std::byte> m_identity;
	public:
		transform_request(const std::filesystem::path& absolute_path, const std::vector<std::byte>& identity) : 
			io_request(absolute_path), m_identity(identity)
		{}

		const std::vector<std::byte>& get_identity() const noexcept {
			return this->m_identity;
		}
	};

	inline attribute_request::change_domain operator&(attribute_request::change_domain lhs, attribute_request::change_domain rhs) {
		return static_cast<attribute_request::change_domain>(static_cast<std::underlying_type_t<attribute_request::change_domain>>(lhs) & static_cast<std::underlying_type_t<attribute_request::change_domain>>(rhs));
	}

	inline attribute_request::change_domain operator|(attribute_request::change_domain lhs, attribute_request::change_domain rhs) {
		return static_cast<attribute_request::change_domain>(static_cast<std::underlying_type_t<attribute_request::change_domain>>(lhs) | static_cast<std::underlying_type_t<attribute_request::change_domain>>(rhs));
	}

	class dehydration_request : public io_request {
	public:
		using io_request::io_request;
	};

	class hydration_triggering_request : public io_request {
	public:
		using io_request::io_request;
	};
}

#endif // LINUXPLORER_LOCAL_REQUESTS_HPP_