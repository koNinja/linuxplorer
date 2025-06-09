#ifndef LINUXPLORER_CLOUD_PROVIDER_CALLBACK_HPP_
#define LINUXPLORER_CLOUD_PROVIDER_CALLBACK_HPP_

#include <shell/shellfwd.hpp>
#include <windows.h>
#include <cfapi.h>

namespace linuxplorer::shell {
	enum class cloud_provider_callback_type {
		fetch_data,
		validate_data,
		cancel_fetching_data,
		fetch_placeholders,
		cancel_fetching_placeholders,
		notify_file_open_completion,
		notify_file_close_completion,
		notify_dehydration,
		notify_dehydration_completion,
		notify_deletion,
		notify_deletion_completion,
		notify_renaming,
		notify_renaming_completion
	};

	using cloud_provider_callback_t = void(*)(const ::CF_CALLBACK_INFO*, const ::CF_CALLBACK_PARAMETERS*);

	class LINUXPLORER_SHELL_API cloud_provider_callback {
		cloud_provider_callback_type m_type;
		cloud_provider_callback_t m_callback;
	public:
		cloud_provider_callback(cloud_provider_callback_type type, cloud_provider_callback_t callback);
		virtual ~cloud_provider_callback() noexcept;

		cloud_provider_callback_type get_type() const noexcept;
		const cloud_provider_callback_t get_callback() const noexcept;
	};
}

#endif // CLOUD_PROVIDER_CALLBACK_H