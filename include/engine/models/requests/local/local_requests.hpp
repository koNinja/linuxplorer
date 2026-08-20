#ifndef LINUXPLORER_ENGINE_LOCAL_REQUESTS_HPP_
#define LINUXPLORER_ENGINE_LOCAL_REQUESTS_HPP_

#include <engine/models/requests/io_requests.hpp>

#include <functional>
#include <ranges>

namespace linuxplorer::engine::models::requests::local {
	class attribute_request : public io_request {
	public:
		enum class change_domain {
			pin,
			unpin,
			pin_unspecified,
			mark_in_sync,
			unmark_in_sync,
			enable_placeholder_enumeration
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
		dehydration_request(const std::filesystem::path& absolute_path) : io_request(absolute_path) {}
	};

	class hydration_triggering_request : public io_request {
	public:
		hydration_triggering_request(const std::filesystem::path& absolute_path) : io_request(absolute_path) {}
	};

	class directory_update_request : public io_request {
	public:
		using result_t = std::vector<shell::filesystem::placeholder_creation_info>;
	private:
		const result_t& m_placeholder_set;
	public:
		directory_update_request(const std::filesystem::path& absolute_path, const result_t& placeholder_set) : io_request(absolute_path), m_placeholder_set(placeholder_set) {}

		const result_t& get_placeholder_set() const noexcept {
			return this->m_placeholder_set;
		}
	};
}

#endif // LINUXPLORER_ENGINE_LOCAL_REQUESTS_HPP_