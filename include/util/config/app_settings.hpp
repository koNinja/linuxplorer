#ifndef LINUXPLORER_APP_SETTINGS_HPP_
#define LINUXPLORER_APP_SETTINGS_HPP_

#include <util/config/configfwd.hpp>
#include <util/config/config_exception.hpp>
#include <shared_mutex>
#include <fstream>
#include <nlohmann/json.hpp>

namespace linuxplorer::util::config {
	class LINUXPLORER_CONFIG_API configuration_manager {
	private:
		inline static std::optional<nlohmann::json> s_config_json;
	public:
		configuration_manager() = delete;

		template <class T>
		static T get_value(std::string_view name) {
			try {
				if (!s_config_json) {
					std::ifstream ifs;
					ifs.exceptions(std::ios_base::badbit | std::ios_base::failbit);
					ifs.open(get_config_path());
					s_config_json = nlohmann::json::parse(ifs);
				}

				return (*s_config_json)[name].get<T>();
			}
			catch (const std::ios_base::failure& e) {
				std::stringstream error;
				error << "File stream failed: " << e.code().message();
				throw config_io_exception(error.str());
			}
			catch (const nlohmann::json::exception& e) {
				std::stringstream error;
				error << "JSON manipulation failed: " << e.what();
				throw config_json_exception(std::current_exception(), error.str());
			}
		}

		template <class T>
		static void set_value(std::string_view name, const T& value) {
			try {
				if (!s_config_json) {
					std::ifstream ifs;
					ifs.exceptions(std::ios_base::badbit | std::ios_base::failbit);
					ifs.open(get_config_path());
					s_config_json = nlohmann::json::parse(ifs);
				}

				(*s_config_json)[name] = value;

				auto text = s_config_json->dump(4);

				std::ofstream ofs(get_config_path());
				ofs << text << std::endl;
			}
			catch (const std::ios_base::failure& e) {
				std::stringstream error;
				error << "File stream failed: " << e.code().message();
				throw config_io_exception(error.str());
			}
			catch (const nlohmann::json::exception& e) {
				std::stringstream error;
				error << "JSON manipulation failed: " << e.what();
				throw config_json_exception(std::current_exception(), error.str());
			}
		}

		static bool has_value(std::string_view name) {
			try {
				if (!s_config_json) {
					std::ifstream ifs;
					ifs.exceptions(std::ios_base::badbit | std::ios_base::failbit);
					ifs.open(get_config_path());
					s_config_json = nlohmann::json::parse(ifs);
				}

				return s_config_json->contains(name);
			}
			catch (const std::ios_base::failure& e) {
				std::stringstream error;
				error << "File stream failed: " << e.code().message();
				throw config_io_exception(error.str());
			}
			catch (const nlohmann::json::exception& e) {
				std::stringstream error;
				error << "JSON manipulation failed: " << e.what();
				throw config_json_exception(std::current_exception(), error.str());
			}
		}

		static void initialize();

		static std::wstring get_root_path();
		static std::wstring get_config_path();
		static std::wstring get_log_path();
		static std::wstring get_install_path();
	};

	template <class T, class S>
	class app_configuration {
	public:
		using data_type = T;
		using json_data_type = S;
		app_configuration() {}
	public:
		virtual void load() {
			try {
				auto default_value_opt = this->get_default_value();
				if (default_value_opt.has_value() && !configuration_manager::has_value(this->get_json_key_name())) {
					configuration_manager::set_value(this->get_json_key_name(), *default_value_opt);
				}

				auto raw_value = configuration_manager::get_value<S>(this->get_json_key_name());
				this->xload(raw_value);
			}
			catch (const nlohmann::json::exception& e) {
				std::stringstream error;
				error << "JSON manipulation failed: " << e.what();
				throw config_json_exception(std::current_exception(), error.str());
			}
		}
		virtual void save() const {
			try {
				auto value_to_write = this->xsave();
				configuration_manager::set_value(this->get_json_key_name(), value_to_write);
			}
			catch (const nlohmann::json::exception& e) {
				std::stringstream error;
				error << "JSON manipulation failed: " << e.what();
				throw config_json_exception(std::current_exception(), error.str());
			}
		}
		virtual data_type get() const {
			return this->xget();
		}
		virtual void set(const data_type& data) {
			this->xset(data);
		}

	protected:
		virtual void xload(const json_data_type& data) = 0;
		virtual json_data_type xsave() const = 0;
		virtual data_type xget() const = 0;
		virtual void xset(const data_type& data) = 0;

		virtual constexpr std::string_view get_json_key_name() const noexcept = 0;
		virtual std::optional<json_data_type> get_default_value() const noexcept { return std::nullopt; }
	};

	template <class T, class S>
	class app_mtconfig : public app_configuration<T, S> {
	public:
		using data_type = T;
		using json_data_type = S;
		app_mtconfig() {}
	private:
		using base_t = app_configuration<T, S>;
		mutable std::shared_mutex m_mtx;
	public:
		void load() override {
			auto lock = std::lock_guard(this->m_mtx);
			base_t::load();
		}
		void save() const override {
			auto lock = std::shared_lock(this->m_mtx);
			base_t::save();
		}
		data_type get() const override {
			auto lock = std::shared_lock(this->m_mtx);
			return base_t::get();
		}
		void set(const data_type& data) override {
			auto lock = std::lock_guard(this->m_mtx);
			base_t::set(data);
		}
	};
}
#endif // LINUXPLORER_APP_SETTINGS_HPP_