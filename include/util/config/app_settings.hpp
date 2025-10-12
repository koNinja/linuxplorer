#ifndef LINUXPLORER_APP_SETTINGS_HPP_
#define LINUXPLORER_APP_SETTINGS_HPP_

#include <util/config/configfwd.hpp>
#include <shared_mutex>
#include <fstream>
#include <nlohmann/json.hpp>

namespace linuxplorer::util::config {
	class config_exception : public std::runtime_error {
	public:
		explicit config_exception(const char* what) : std::runtime_error(what) {}
		explicit config_exception(const std::string& what) : std::runtime_error(what) {}
		virtual ~config_exception() noexcept = default;
	};

	class config_io_exception : public config_exception {
	public:
		explicit config_io_exception(const char* what) : config_exception(what) {}
		explicit config_io_exception(const std::string& what) : config_exception(what) {}
		virtual ~config_io_exception() noexcept = default;
	};

	class config_json_exception : public config_io_exception {
	private:
		std::exception_ptr m_exptr;
	public:
		explicit config_json_exception(const char* what) : config_io_exception(what) {}
		explicit config_json_exception(const std::string& what) : config_io_exception(what) {}
		explicit config_json_exception(std::exception_ptr inner, const char* what) : config_io_exception(what), m_exptr(inner) {}
		explicit config_json_exception(std::exception_ptr inner, const std::string& what) : config_io_exception(what), m_exptr(inner) {}
		virtual ~config_json_exception() noexcept = default;

		std::exception_ptr inner_exception() const noexcept { return this->m_exptr; }
	};

	class config_system_error : public config_exception {
	private:
		std::error_code m_errc;
	public:
		explicit config_system_error(const std::error_code& errc, const char* what) : m_errc(errc), config_exception(what) {}
		explicit config_system_error(const std::error_code& errc, const std::string& what) : m_errc(errc), config_exception(what) {}
		virtual ~config_system_error() noexcept = default;

		const std::error_code& code() const noexcept { return this->m_errc; }
	};

	class LINUXPLORER_CONFIG_API configuration_manager {
	public:
		configuration_manager() = delete;

		template <class T>
		static T get_value(std::string_view name) {
			try {
				std::ifstream ifs;
				ifs.exceptions(std::ios_base::badbit | std::ios_base::failbit);
				ifs.open(get_config_path());

				auto json = nlohmann::json::parse(ifs);
				return json[name].get<T>();
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
				std::ifstream ifs;
				ifs.exceptions(std::ios_base::badbit | std::ios_base::failbit);
				ifs.open(get_config_path());

				auto json = nlohmann::json::parse(ifs);
				json[name] = value;

				auto text = json.dump(4);

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
				std::ifstream ifs;
				ifs.exceptions(std::ios_base::badbit | std::ios_base::failbit);
				ifs.open(get_config_path());

				auto json = nlohmann::json::parse(ifs);
				return json.contains(name);
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

		static std::string get_config_path();
		static std::string get_install_path();
		static std::string get_log_path();
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