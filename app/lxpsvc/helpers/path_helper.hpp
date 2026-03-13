#ifndef LINUXPLORER_LXPSVC_PATH_HELPER_HPP_
#define LINUXPLORER_LXPSVC_PATH_HELPER_HPP_

#include <filesystem>

namespace linuxplorer::app::lxpsvc::helpers {
	enum class style_conversion_class {
		relative_format,
		absolute_format
	};

	class path_helper {
	public:
		static bool is_under(const std::filesystem::path& path, const std::filesystem::path& base);
	private:
		std::filesystem::path m_syncroot;
		std::filesystem::path m_linux_root;
	public:
		path_helper(const std::filesystem::path& syncroot, const std::filesystem::path& linux_root = L"/");

		const std::filesystem::path& get_syncroot() const noexcept;

		std::filesystem::path to_relative_from_syncroot(const std::filesystem::path& absolute_path) const;
		std::filesystem::path to_absolute(const std::filesystem::path& relative_path_from_syncroot) const;

		std::filesystem::path to_linux_style(const std::filesystem::path& path, style_conversion_class conversion_class) const;
		std::filesystem::path to_win_style(const std::filesystem::path& linux_style_path, style_conversion_class conversion_class) const;
	};
}

#endif // LINUXPLORER_LXPSVC_PATH_HELPER_HPP_