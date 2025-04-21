#ifndef SSH_KNOWNHOSTS_HPP
#define SSH_KNOWNHOSTS_HPP

#include <string_view>
#include <memory>
#include <ssh/ssh_session.hpp>
#include <ssh/ssh_exception.hpp>

namespace linuxplorer::ssh::auth {
	namespace internal {
		struct ssh_knownhosts_ptr_delete {
			void operator()(::LIBSSH2_KNOWNHOSTS* _ptr) const noexcept {
				::libssh2_knownhost_free(_ptr);
			}
		};
	}

	enum class ssh_knownhosts_check_result {
		matched,
		mismatch,
		missing
	};

	constexpr const wchar_t* default_knownhosts_path = L"<default_path>";
	
	class ssh_knownhosts {
		using ssh_knownhosts_ptr_t = std::unique_ptr<::LIBSSH2_KNOWNHOSTS, internal::ssh_knownhosts_ptr_delete>;
		const ssh_session& m_session;
		ssh_knownhosts_ptr_t m_knownhosts;
		std::wstring m_knownhosts_path;

		void write(::libssh2_knownhost* target) const;
	public:
		ssh_knownhosts(const ssh_session& host, std::wstring_view path = default_knownhosts_path);

		ssh_knownhosts(const ssh_knownhosts&) = delete;
		ssh_knownhosts& operator=(const ssh_knownhosts&) = delete;
		ssh_knownhosts(ssh_knownhosts&&) = delete;
		ssh_knownhosts& operator=(ssh_knownhosts&&) = delete;

		void add(std::wstring_view comment = L"");
		void remove();
		ssh_knownhosts_check_result check() const;

		~ssh_knownhosts() = default;
	};

	class ssh_knownhost_exception : public ssh_exception {
		protected:
			ssh_knownhosts_check_result m_result;
		public:
			ssh_knownhost_exception(ssh_knownhosts_check_result result, const std::string& what) : ssh_exception(what), m_result(result) {};
			ssh_knownhost_exception(ssh_knownhosts_check_result result, const char* what) : ssh_exception(what), m_result(result) {};

			inline auth::ssh_knownhosts_check_result result() const noexcept { 
				return this->m_result;
			}
		};
}

#endif // SSH_KNOWNHOSTS_HPP