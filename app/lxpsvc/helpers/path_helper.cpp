#include "path_helper.hpp"

#include <string>
#include <cwctype>
#include <algorithm>

namespace linuxplorer::app::lxpsvc::helpers {
	path_helper::path_helper(const std::filesystem::path& syncroot, const std::filesystem::path& linux_root) : m_syncroot(syncroot), m_linux_root(linux_root) {}

	std::filesystem::path path_helper::to_relative_from_syncroot(const std::filesystem::path& absolute_path) const {
		return std::filesystem::relative(absolute_path, this->m_syncroot);
	}

	std::filesystem::path path_helper::to_absolute(const std::filesystem::path& relative_path_from_syncroot) const {
		return this->m_syncroot / relative_path_from_syncroot;
	}

	std::filesystem::path path_helper::to_linux_style(const std::filesystem::path& path, style_conversion_class conversion_class) const {
		std::filesystem::path result;
		std::wstring relative_path_str;

		switch (conversion_class) {
		case style_conversion_class::relative_format:
		{
			relative_path_str = path.wstring();
			break;
		}
		case style_conversion_class::absolute_format:
		{
			relative_path_str = this->to_relative_from_syncroot(path);
			break;
		}
		default:
			break;
		}

		std::transform(relative_path_str.begin(), relative_path_str.end(), relative_path_str.begin(), [](wchar_t ch) {
			return ch == L'\\' ? L'/' : ch;
		});

		if (this->m_linux_root.wstring().ends_with(L'/')) {
			result =  this->m_linux_root.wstring() + relative_path_str;
		}
		else {
			result =  this->m_linux_root.wstring() + L"/" + relative_path_str;
		}

		return result;
	}

	std::filesystem::path path_helper::to_win_style(const std::filesystem::path& linux_style_path, style_conversion_class conversion_class) const {
		std::filesystem::path result;

		if (linux_style_path.empty()) return result;

		std::wstring relative_path_str(linux_style_path.wstring().begin() + 1, linux_style_path.wstring().end());
		std::transform(relative_path_str.begin(), relative_path_str.end(), relative_path_str.begin(), [](wchar_t ch) {
			return ch == L'/' ? L'\\' : ch;
		});

		switch (conversion_class) {
		case style_conversion_class::relative_format:
		{
			result = relative_path_str;
			break;
		}
		case style_conversion_class::absolute_format:
		{
			result = this->to_absolute(relative_path_str);
			break;
		}
		default:
			break;
		}

		return result;
	}

	bool path_helper::is_under(const std::filesystem::path& path, const std::filesystem::path& base) {
		auto normalize = [](const std::filesystem::path& path)
		{
			auto p = std::filesystem::weakly_canonical(path).lexically_normal();

			std::wstring s = p.native();
			std::transform(s.begin(), s.end(), s.begin(),
				[](wchar_t c){ return std::towlower(c); });

			return std::filesystem::path(s);
		};

		std::filesystem::path p = normalize(path);
		std::filesystem::path b = normalize(base);

		if (p == b) return false;

		if (p.root_name() != b.root_name()) return false;

		std::filesystem::path rel = p.lexically_relative(b);

		if (rel.empty()) return false;

		if (*rel.begin() == "..") return false;

		return true;
	}

	const std::filesystem::path& path_helper::get_syncroot() const noexcept {
		return this->m_syncroot;
	}
}