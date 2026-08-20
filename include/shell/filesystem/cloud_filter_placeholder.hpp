#ifndef LINUXPLORER_CLOUD_FILTER_PLACEHOLDER_HPP_
#define LINUXPLORER_CLOUD_FILTER_PLACEHOLDER_HPP_

#include <shell/shellfwd.hpp>
#include <shell/cloud_provider_session.hpp>
#include <shell/filesystem/placeholder_info.hpp>
#include <string>
#include <filesystem>
#include <span>

namespace linuxplorer::shell::filesystem {
	enum class placeholder_type {
		file,
		directory
	};

	enum class placeholder_pin_state {
		unspecified = ::CF_PIN_STATE::CF_PIN_STATE_UNSPECIFIED,
		pinned = ::CF_PIN_STATE::CF_PIN_STATE_PINNED,
		unpinned = ::CF_PIN_STATE::CF_PIN_STATE_UNPINNED,
		excluded = ::CF_PIN_STATE::CF_PIN_STATE_EXCLUDED,
		inherited = ::CF_PIN_STATE::CF_PIN_STATE_INHERIT
	};

	class placeholder_type_inconsistency_exception : cloud_provider_runtime_exception {
	public:
		explicit placeholder_type_inconsistency_exception(const char* message) : cloud_provider_runtime_exception(message) {}
		explicit placeholder_type_inconsistency_exception(const std::string& message) : cloud_provider_runtime_exception(message) {}
		virtual ~placeholder_type_inconsistency_exception() noexcept = default;
	};

	class LINUXPLORER_SHELL_API cloud_filter_placeholder {
	private:
		void internal_primary_fetch();
		void internal_primary_flush() const;

		std::filesystem::path m_absolute_path;
		::HANDLE m_handle;
		placeholder_type m_type;
		std::uint64_t m_id;
		::CF_IN_SYNC_STATE m_in_sync_marked;
		placeholder_pin_state m_pin_state;

		file_times m_file_times;

		std::vector<std::byte> m_identity;
	protected:
		virtual void internal_secondary_fetch();
		virtual void internal_secondary_flush() const;

		void close_handle();
		void open_handle();
	public:
		cloud_filter_placeholder(const std::filesystem::path& absolute_path);
		[[deprecated("This constructor may reduce availability due to the strict requirement of the 1st argument.")]]
		cloud_filter_placeholder(const cloud_provider_session& session, const std::filesystem::path& relative_path);
		cloud_filter_placeholder(const cloud_filter_placeholder&) = delete;
		cloud_filter_placeholder(cloud_filter_placeholder&& rhs) noexcept;

		[[deprecated("This method may reduce availability due to the strict requirement of the 1st argument.")]]
		static cloud_filter_placeholder create(const cloud_provider_session& session, const placeholder_creation_info& metadata);
		static cloud_filter_placeholder create(const std::filesystem::path& syncroot_path, const placeholder_creation_info& metadata);

		[[deprecated("This method may reduce availability due to the strict requirement of the 1st argument.")]]
		static cloud_filter_placeholder transform(const cloud_provider_session& session, const std::filesystem::path& relative_path, std::span<const std::byte> identity);
		static cloud_filter_placeholder transform(const std::filesystem::path& absolute_path, std::span<const std::byte> identity);

		[[deprecated("This method may reduce availability due to the strict requirement of the 1st argument.")]]
		static void revert(const cloud_provider_session& session, cloud_filter_placeholder&& placeholder);
		static void revert(cloud_filter_placeholder&& placeholder);
		
		[[deprecated("This method may reduce availability due to the strict requirement of the 1st argument.")]]
		static bool is_placeholder(const cloud_provider_session& session, const std::filesystem::path& relative_path);
		static bool is_placeholder(const std::filesystem::path& absolute_path);

		virtual ~cloud_filter_placeholder();

		void fetch();
		void flush();

		const std::filesystem::path& get_path() const noexcept;
		std::uint64_t get_id() const noexcept;
		::HANDLE get_handle() const noexcept;
		placeholder_type get_type() const noexcept;
		bool is_marked_in_sync() const noexcept;
		void set_marked_in_sync(bool synchronized) noexcept;
		placeholder_pin_state get_pin_state() const noexcept;
		void set_pin_state(placeholder_pin_state state) noexcept;

		const file_times& get_file_times() const noexcept;
		void set_file_times(const file_times& file_times) noexcept;

		std::span<const std::byte> get_identity() const noexcept;
		void set_identity(const std::vector<std::byte>& identity) noexcept;
	};

	class LINUXPLORER_SHELL_API file_placeholder : public cloud_filter_placeholder {
	private:
		std::size_t m_file_size;
	protected:
		virtual void internal_dehydrate_unsafe(std::size_t offset, std::optional<std::size_t> length);
		virtual void internal_secondary_fetch() override;
		virtual void internal_secondary_flush() const override;
	public:
		file_placeholder(const std::filesystem::path& absolute_path);
		[[deprecated("This constructor may reduce availability due to the strict requirement of the 1st argument.")]]
		file_placeholder(const cloud_provider_session& session, const std::filesystem::path& relative_path);
		file_placeholder(const file_placeholder&) = delete;
		file_placeholder(file_placeholder&& rhs) noexcept;
		file_placeholder(cloud_filter_placeholder&& rhs);

		virtual ~file_placeholder();

		virtual void hydrate() const;
		virtual void hydrate(std::size_t offset, std::streamsize length) const;
		virtual void dehydrate_unsafe();
		virtual void dehydrate_unsafe(std::size_t offset, std::size_t length);

		std::size_t get_file_size() const noexcept;
		void set_file_size(std::size_t file_size) noexcept;
	};

	class LINUXPLORER_SHELL_API directory_placeholder : public cloud_filter_placeholder {
	private:
		bool m_enumeration_enabled;
	protected:
		virtual void internal_secondary_flush() const override;
	public:
		directory_placeholder(const std::filesystem::path& absolute_path);
		[[deprecated("This constructor may reduce availability due to the strict requirement of the 1st argument.")]]
		directory_placeholder(const cloud_provider_session& session, const std::filesystem::path& relative_path);
		directory_placeholder(const directory_placeholder&) = delete;
		directory_placeholder(directory_placeholder&& rhs) noexcept;
		directory_placeholder(cloud_filter_placeholder&& rhs);

		virtual ~directory_placeholder();

		void set_enumeration_enabled(bool enabled);
	};
}

#endif // LINUXPLORER_CLOUD_FILTER_PLACEHOLDER_HPP_