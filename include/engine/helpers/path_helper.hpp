#ifndef LINUXPLORER_ENGINE_PATH_HELPER_HPP_
#define LINUXPLORER_ENGINE_PATH_HELPER_HPP_

#include <engine/enginefwd.hpp>
#include <filesystem>

namespace linuxplorer::engine::helpers {
	enum class style_conversion_class {
		relative_format,
		absolute_format
	};

	class LINUXPLORER_ENGINE_API path_helper {
	public:
		static bool is_under(const std::filesystem::path& path, const std::filesystem::path& base);
		static bool contains_invalid_ntfs_character(const std::filesystem::path& path);
		static std::filesystem::path tolower(const std::filesystem::path& path);
	private:
		std::filesystem::path m_syncroot;
		std::filesystem::path m_linux_root;
	public:
		path_helper(const std::filesystem::path& syncroot, const std::filesystem::path& linux_root = L"/");

		const std::filesystem::path& get_syncroot() const noexcept;

		std::filesystem::path to_relative_from_syncroot(const std::filesystem::path& absolute_path) const;
		std::filesystem::path to_absolute(const std::filesystem::path& relative_path_from_syncroot) const;

		std::filesystem::path to_linux_style(const std::filesystem::path& path, style_conversion_class conversion_class) const;
		std::filesystem::path to_win_style(style_conversion_class conversion_class, const std::filesystem::path& linux_style_path) const;

	};
}

#endif // LINUXPLORER_ENGINE_PATH_HELPER_HPP_