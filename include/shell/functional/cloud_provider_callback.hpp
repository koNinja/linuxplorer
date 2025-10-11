#ifndef LINUXPLORER_CLOUD_PROVIDER_CALLBACK_HPP_
#define LINUXPLORER_CLOUD_PROVIDER_CALLBACK_HPP_

#include <shell/shellfwd.hpp>
#include <shell/cloud_provider_exception.hpp>
#include <shell/cloud_provider_session_token.hpp>
#include <shell/functional/callback_parameters.hpp>
#include <shell/models/chunked_callback_generator.hpp>

#define DECLARE_TYPED_CALLBACK_SIGNITURE_ALIASES(Type, Return, Parameter)	\
	template <>																\
	struct typed_callback_aliases<cloud_provider_callback_type::Type> {		\
		using callback_parameters = Parameter;								\
		using operation_info = Return;										\
	}

namespace linuxplorer::shell::functional {
	enum class cloud_provider_callback_type : std::underlying_type_t<::CF_CALLBACK_TYPE> {
		fetch_data = ::CF_CALLBACK_TYPE::CF_CALLBACK_TYPE_FETCH_DATA,
		validate_data = ::CF_CALLBACK_TYPE::CF_CALLBACK_TYPE_VALIDATE_DATA,									// unused
		cancel_fetching_data = ::CF_CALLBACK_TYPE::CF_CALLBACK_TYPE_CANCEL_FETCH_DATA,
		fetch_placeholders = ::CF_CALLBACK_TYPE::CF_CALLBACK_TYPE_FETCH_PLACEHOLDERS,
		cancel_fetching_placeholders = ::CF_CALLBACK_TYPE::CF_CALLBACK_TYPE_CANCEL_FETCH_PLACEHOLDERS,		// not implemented yet
		notify_file_open_completion = ::CF_CALLBACK_TYPE::CF_CALLBACK_TYPE_NOTIFY_FILE_OPEN_COMPLETION,		// unused
		notify_file_close_completion = ::CF_CALLBACK_TYPE::CF_CALLBACK_TYPE_NOTIFY_FILE_CLOSE_COMPLETION,	// unused
		notify_dehydration = ::CF_CALLBACK_TYPE::CF_CALLBACK_TYPE_NOTIFY_DEHYDRATE,							// unused
		notify_dehydration_completion = ::CF_CALLBACK_TYPE::CF_CALLBACK_TYPE_NOTIFY_DEHYDRATE_COMPLETION,	// unused
		notify_deletion = ::CF_CALLBACK_TYPE::CF_CALLBACK_TYPE_NOTIFY_DELETE,								// unused
		notify_deletion_completion = ::CF_CALLBACK_TYPE::CF_CALLBACK_TYPE_NOTIFY_DELETE_COMPLETION,			// unused
		notify_renaming = ::CF_CALLBACK_TYPE::CF_CALLBACK_TYPE_NOTIFY_RENAME,								// unused
		notify_renaming_completion = ::CF_CALLBACK_TYPE::CF_CALLBACK_TYPE_NOTIFY_RENAME_COMPLETION			// unused
	};

	class callback_duplication_exception : public std::runtime_error {
	public:
		callback_duplication_exception(cloud_provider_callback_type type, const std::string& message) : 
			std::runtime_error(message), m_type(type) {}
		callback_duplication_exception(cloud_provider_callback_type type, const char* message) : 
			std::runtime_error(message), m_type(type) {}

		inline cloud_provider_callback_type get_type() const noexcept { return this->m_type; }
	private:
		cloud_provider_callback_type m_type;
	};

	namespace internal {
		template <cloud_provider_callback_type T>
		struct typed_callback_aliases {
			using callback_parameters = callback_parameters;
			using operation_info = operation_info;
		};
		DECLARE_TYPED_CALLBACK_SIGNITURE_ALIASES(fetch_data, models::chunked_callback_generator<fetch_data_operation_info>, fetch_data_callback_parameters);
		DECLARE_TYPED_CALLBACK_SIGNITURE_ALIASES(fetch_placeholders, fetch_placeholders_operation_info, callback_parameters);
		DECLARE_TYPED_CALLBACK_SIGNITURE_ALIASES(cancel_fetching_data, void, cancel_fetch_data_callback_parameters);

		using nt_cloud_provider_callback_t = void(*)(const ::CF_CALLBACK_INFO*, const ::CF_CALLBACK_PARAMETERS*);
	}

	using nt_cloud_provider_callback_t = std::function<void(const ::CF_CALLBACK_INFO*, const ::CF_CALLBACK_PARAMETERS*)>;

	template <cloud_provider_callback_type T>
	using typed_cloud_provider_callback_t = std::function<typename internal::typed_callback_aliases<T>::operation_info(const typename internal::typed_callback_aliases<T>::callback_parameters&)>;

	class cloud_provider_callback {
	private:
		cloud_provider_callback_type m_type;
	protected:
		virtual void internal_nt_callback(const ::CF_CALLBACK_INFO* info, const ::CF_CALLBACK_PARAMETERS* parameters) const = 0;
	public:
		cloud_provider_callback(cloud_provider_callback_type type) : m_type(type) {}
		cloud_provider_callback(const cloud_provider_callback&) = default;
		cloud_provider_callback(cloud_provider_callback&&) = default;
		virtual ~cloud_provider_callback() noexcept = default;

		inline cloud_provider_callback_type get_type() const noexcept {
			return this->m_type;
		}
		inline const nt_cloud_provider_callback_t get_nt_callback() const noexcept {
			return [this](const ::CF_CALLBACK_INFO* info, const ::CF_CALLBACK_PARAMETERS* parameters) -> void { this->internal_nt_callback(info, parameters); };
		}
	};

	template <cloud_provider_callback_type T>
	class LINUXPLORER_SHELL_API specialized_cloud_provider_callback : public cloud_provider_callback {
	private:
		typed_cloud_provider_callback_t<T> m_callback = nullptr;
		virtual void internal_nt_callback(const ::CF_CALLBACK_INFO* info, const ::CF_CALLBACK_PARAMETERS* parameters) const override;
	public:
		specialized_cloud_provider_callback(typed_cloud_provider_callback_t<T> callback) : cloud_provider_callback(T), m_callback(callback) {}
		specialized_cloud_provider_callback(const specialized_cloud_provider_callback<T>&) = default;
		specialized_cloud_provider_callback(specialized_cloud_provider_callback<T>&&) = default;
		virtual ~specialized_cloud_provider_callback() noexcept = default;
	};

	using fetch_data_callback = specialized_cloud_provider_callback<cloud_provider_callback_type::fetch_data>;
	using fetch_placeholders_callback = specialized_cloud_provider_callback<cloud_provider_callback_type::fetch_placeholders>;
	using cancel_fetch_data_callback = specialized_cloud_provider_callback<cloud_provider_callback_type::cancel_fetching_data>;

	class callback_abort_exception : public std::runtime_error {
	private:
		::NTSTATUS m_code;
	public:
		callback_abort_exception(::NTSTATUS nts, const std::string& message = "") : std::runtime_error(message), m_code(nts) {}

		::NTSTATUS code() const noexcept {
			return this->m_code;
		}
	};
}

#endif // LINUXPLORER_CLOUD_PROVIDER_CALLBACK_HPP_