#ifndef LINUXPLORER_STARTUP_CONFIG_HPP_
#define LINUXPLORER_STARTUP_CONFIG_HPP_

#include <util/config/configfwd.hpp>
#include <util/config/app_settings.hpp>

namespace linuxplorer::util::config {
	class startup_inconsistency_exception : config_exception {
	public:
		startup_inconsistency_exception(const char* what) : config_exception(what) {}
		startup_inconsistency_exception(const std::string& what) : config_exception(what) {}
	};

	class LINUXPLORER_CONFIG_API startup_config : public app_configuration<bool, bool> {
	public:
		using data_type = bool;
		using json_data_type = bool;
		startup_config();

	private:
		bool m_enabled;

		static std::wstring get_startup_file_path();
		static long create_link_without_co_initialization(const std::wstring& src, const std::wstring& link) noexcept;
	protected:
		virtual void xload(const json_data_type& data) override;
		virtual json_data_type xsave() const override;
		virtual data_type xget() const override;
		virtual void xset(const data_type& data) override;

		virtual inline constexpr std::string_view get_json_key_name() const noexcept override {
			return "startup";
		}
	};
}

#endif // LINUXPLORER_STARTUP_CONFIG_HPP_