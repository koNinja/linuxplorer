#ifndef LINUXPLORER_CLOUD_FILTER_PLACEHOLDER_HPP_
#define LINUXPLORER_CLOUD_FILTER_PLACEHOLDER_HPP_

#include <shell/shellfwd.hpp>
#include <shell/cloud_provider_session.hpp>
#include <shell/filesystem/placeholder_info.hpp>
#include <string>
#include <span>

namespace linuxplorer::shell::filesystem {
	enum class placeholder_type {
		file,
		directory
	};

	class LINUXPLORER_SHELL_API cloud_filter_placeholder {
	private:
		void internal_primary_fetch();
		void internal_primary_flush() const;

		std::wstring m_absolute_path;
		::HANDLE m_handle;
		placeholder_type m_type;
		std::uint64_t m_id;
		::CF_IN_SYNC_STATE m_in_sync_marked;
		::CF_PIN_STATE m_pin_state;
	protected:
		virtual void internal_secondary_fetch();
		virtual void internal_secondary_flush() const;

		void close_handle();
		void open_handle();
	public:
		cloud_filter_placeholder(const cloud_provider_session& session, std::wstring_view relative_path);
		cloud_filter_placeholder(const cloud_filter_placeholder&) = delete;
		cloud_filter_placeholder(cloud_filter_placeholder&& rhs);

		static cloud_filter_placeholder create(const cloud_provider_session& session, const placeholder_creation_info& metadata);
		static cloud_filter_placeholder transform(const cloud_provider_session& session, std::wstring_view relative_path, std::span<const std::byte> identity);
		static void revert(const cloud_provider_session& session, cloud_filter_placeholder&& placeholder);
		static bool is_placeholder(const cloud_provider_session& session, std::wstring_view relative_path);

		virtual ~cloud_filter_placeholder();

		void fetch();
		void flush();

		std::wstring_view get_path() const noexcept;
		std::uint64_t get_id() const noexcept;
		::HANDLE get_handle() const noexcept;
		placeholder_type get_type() const noexcept;
		bool is_marked_in_sync() const noexcept;
		void set_marked_in_sync(bool synchronized) noexcept;
		::CF_PIN_STATE get_pin_state() const noexcept;
		void set_pin_state(::CF_PIN_STATE state) noexcept;
	};

	class LINUXPLORER_SHELL_API file_placeholder : public cloud_filter_placeholder {
	private:
		void internal_dehydrate(std::size_t offset, std::size_t length);
	public:
		file_placeholder(const cloud_provider_session& session, std::wstring_view relative_path);
		file_placeholder(const file_placeholder&) = delete;
		file_placeholder(file_placeholder&& rhs);
		file_placeholder(cloud_filter_placeholder&& rhs);

		virtual ~file_placeholder();

		virtual void hydrate() const;
		virtual void hydrate(std::size_t offset, std::size_t length) const;
		virtual void dehydrate();
		virtual void dehydrate(std::size_t offset, std::size_t length);
	};

	class LINUXPLORER_SHELL_API directory_placeholder : public cloud_filter_placeholder {
	private:
		bool m_enumeration_enabled;
	protected:
		virtual void internal_secondary_flush() const override;
	public:
		directory_placeholder(const cloud_provider_session& session, std::wstring_view relative_path);
		directory_placeholder(const directory_placeholder&) = delete;
		directory_placeholder(directory_placeholder&& rhs);
		directory_placeholder(cloud_filter_placeholder&& rhs);

		virtual ~directory_placeholder();

		void set_enumeration_enabled(bool enabled);
	};
}

#endif // LINUXPLORER_CLOUD_FILTER_PLACEHOLDER_HPP_