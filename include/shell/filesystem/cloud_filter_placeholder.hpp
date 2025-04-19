#ifndef CLOUD_FILTER_PLACEHOLDER_H
#define CLOUD_FILTER_PLACEHOLDER_H

#include <shell/cloud_provider_session.hpp>
#include <string>

namespace linuxplorer::shell::filesystem {
	enum class placeholder_type {
		file,
		directory
	};

	class cloud_filter_placeholder {
		std::wstring m_relative_path;
		::HANDLE m_handle;
		placeholder_type m_type;
		
		cloud_filter_placeholder() noexcept;
		cloud_filter_placeholder(const cloud_filter_placeholder&) = delete;

		static cloud_filter_placeholder internal_create(const cloud_provider_session& session, std::wstring_view relative_path, ::CF_PLACEHOLDER_CREATE_INFO& create_info);
	public:
		cloud_filter_placeholder(cloud_filter_placeholder&& right);
		cloud_filter_placeholder& operator=(cloud_filter_placeholder&& right);
		static cloud_filter_placeholder create(const cloud_provider_session& session, std::wstring_view relative_path, const ::CF_FS_METADATA& metadata);
		static cloud_filter_placeholder create_directory(const cloud_provider_session& session, std::wstring_view relative_path, ::FILE_BASIC_INFO& metadata);
		static cloud_filter_placeholder open(const cloud_provider_session& session, std::wstring_view relative_path);

		static void remove(const cloud_provider_session& session, cloud_filter_placeholder&& placeholder);

		virtual ~cloud_filter_placeholder() noexcept;

		void hydrate() const;
		void dehydrate() const;
	};
}

#endif // CLOUD_FILTER_PLACEHOLDER_H