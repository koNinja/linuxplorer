#ifndef LINUXPLORER_CLOUD_PROVIDER_CALLBACK_HPP_
#define LINUXPLORER_CLOUD_PROVIDER_CALLBACK_HPP_

#include <shell/shellfwd.hpp>
#include <shell/cloud_provider_exception.hpp>
#include <shell/functional/callback_parameters.hpp>
#include <shell/models/chunked_callback_generator.hpp>
#include <windows.h>
#include <cfapi.h>

namespace linuxplorer::shell::functional {
	enum class cloud_provider_callback_type : std::underlying_type_t<::CF_CALLBACK_TYPE> {
		fetch_data = ::CF_CALLBACK_TYPE::CF_CALLBACK_TYPE_FETCH_DATA,
		validate_data = ::CF_CALLBACK_TYPE::CF_CALLBACK_TYPE_VALIDATE_DATA,									// unused
		cancel_fetching_data = ::CF_CALLBACK_TYPE::CF_CALLBACK_TYPE_CANCEL_FETCH_DATA,						// not implemented yet
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

	class callback_duplicated_exception : public cloud_provider_runtime_exception {
	public:
		callback_duplicated_exception(cloud_provider_callback_type type, const char* message) : cloud_provider_runtime_exception(message), m_type(type) {}
		callback_duplicated_exception(cloud_provider_callback_type type, const std::string& message) : cloud_provider_runtime_exception(message), m_type(type) {}

		inline cloud_provider_callback_type get_type() const noexcept {
			return this->m_type;
		}
	private:
		cloud_provider_callback_type m_type;
	};

	namespace internal {
		template <cloud_provider_callback_type T>
		struct typed_callback_aliases {
			using callback_parameters = callback_parameters;
			using operation_info = operation_info;
		};

		template <>
		struct typed_callback_aliases<cloud_provider_callback_type::fetch_data> {
			using callback_parameters = fetch_data_callback_parameters;
			using operation_info = models::chunked_callback_generator<fetch_data_operation_info>;
		};

		template <>
		struct typed_callback_aliases<cloud_provider_callback_type::fetch_placeholders> {
			using callback_parameters = callback_parameters;
			using operation_info = fetch_placeholders_operation_info;
		};
	}

	using nt_cloud_provider_callback_t = void(*)(const ::CF_CALLBACK_INFO*, const ::CF_CALLBACK_PARAMETERS*);

	template <cloud_provider_callback_type T>
	using typed_cloud_provider_callback_t = typename internal::typed_callback_aliases<T>::operation_info(*)(const typename internal::typed_callback_aliases<T>::callback_parameters&);

	class cloud_provider_callback {
	private:
		cloud_provider_callback_type m_type;
	public:
		inline cloud_provider_callback(cloud_provider_callback_type type) : m_type(type) {}
		cloud_provider_callback(const cloud_provider_callback&) = delete;
		cloud_provider_callback(cloud_provider_callback&&) = delete;
		virtual ~cloud_provider_callback() noexcept = default;

		inline cloud_provider_callback_type get_type() const noexcept {
			return this->m_type;
		}
		virtual const nt_cloud_provider_callback_t get_nt_callback() const noexcept = 0;
	};

	template <cloud_provider_callback_type T>
	class LINUXPLORER_SHELL_API specialized_cloud_provider_callback : public cloud_provider_callback {
	public:
		using this_t = specialized_cloud_provider_callback<T>;

		inline static constexpr cloud_provider_callback_type callback_type = T;

		specialized_cloud_provider_callback(typed_cloud_provider_callback_t<T> callback);
		specialized_cloud_provider_callback(const specialized_cloud_provider_callback<T>&) = delete;
		specialized_cloud_provider_callback(specialized_cloud_provider_callback<T>&&) = delete;
		virtual ~specialized_cloud_provider_callback() noexcept = default;

		virtual const nt_cloud_provider_callback_t get_nt_callback() const noexcept override;

		static void clear_callback() noexcept;
	private:
		inline static typed_cloud_provider_callback_t<T> s_callback = nullptr;

		static void internal_nt_callback(const ::CF_CALLBACK_INFO* info, const ::CF_CALLBACK_PARAMETERS* parameters);
	};

	using fetch_data_callback = specialized_cloud_provider_callback<cloud_provider_callback_type::fetch_data>;
	using fetch_placeholders_callback = specialized_cloud_provider_callback<cloud_provider_callback_type::fetch_placeholders>;

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