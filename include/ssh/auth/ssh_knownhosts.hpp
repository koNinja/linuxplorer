#ifndef SSH_KNOWNHOSTS_HPP
#define SSH_KNOWNHOSTS_HPP

#include <ssh/ssh_session.hpp>
#include <ssh/ssh_exception.hpp>
#include <string_view>
#include <memory>

namespace linuxplorer::ssh::auth {
	namespace internal {
		struct ssh_knownhosts_delete {
			void operator()(::LIBSSH2_KNOWNHOSTS* _ptr) const noexcept {
				::libssh2_knownhost_free(_ptr);
			}
		};

		using unique_ssh_knownhosts_ptr = std::unique_ptr<::LIBSSH2_KNOWNHOSTS, ssh_knownhosts_delete>;
	}

	enum class ssh_knownhosts_verify_result {
		matched,
		mismatch,
		missing
	};

	constexpr const wchar_t* default_knownhosts_path = L"<default_path>";
	
	class ssh_knownhosts {
		const ssh_session& m_session;

		internal::unique_ssh_knownhosts_ptr m_knownhosts;
		std::wstring m_knownhosts_path;
	public:
		ssh_knownhosts(const ssh_session& host, std::wstring_view path = default_knownhosts_path);

		ssh_knownhosts(const ssh_knownhosts&) = delete;
		ssh_knownhosts(ssh_knownhosts&&) = default;

		void register_this(std::wstring_view comment = L"");
		void unregister();
		ssh_knownhosts_verify_result verify() const;

		std::vector<ssh_address> enumerate() const;

		void flush() const;

		~ssh_knownhosts() = default;
	};
}

#endif // SSH_KNOWNHOSTS_HPP