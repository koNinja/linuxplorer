#ifndef APP_SETTINGS_HPP
#define APP_SETTINGS_HPP

#include <shared_mutex>
#include <fstream>
#include <nlohmann/json.hpp>

namespace linuxplorer::util::config {
	std::string get_config_path();
	std::string get_install_path();
	
	class config_exception : public std::runtime_error {
	public:
		config_exception(const char* what) : std::runtime_error(what) {}
		config_exception(const std::string& what) : std::runtime_error(what) {}
	};

	class config_io_exception : public config_exception {
	public:
		config_io_exception(const char* what) : config_exception(what) {}
		config_io_exception(const std::string& what) : config_exception(what) {}
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
				auto raw_value = this->extract();
				this->xload(raw_value);
			}
			catch (const nlohmann::json::exception& e) {
				std::stringstream error;
				error << "JSON manipulation failed: " << e.what();
				throw config_exception(error.str());
			}
		}
		virtual void save() const {
			try {
				auto value_to_write = this->xsave();
				this->embed(value_to_write);
			}
			catch (const nlohmann::json::exception& e) {
				std::stringstream error;
				error << "JSON manipulation failed: " << e.what();
				throw config_exception(error.str());
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
	private:
		json_data_type extract() const {
			try {
				std::ifstream ifs;
				ifs.exceptions(std::ios_base::badbit | std::ios_base::failbit);
				ifs.open(get_config_path());

				auto json = nlohmann::json::parse(ifs);
				std::string_view name = get_json_key_name();
				return json[name].get<S>();
			}
			catch (const std::ios_base::failure& e) {
				std::stringstream error;
				error << "File stream failed: " << e.code().message();
				throw config_io_exception(error.str());
			}
			catch (const nlohmann::json::exception& e) {
				std::stringstream error;
				error << "JSON manipulation failed: " << e.what();
				throw config_io_exception(error.str());
			}
		}

		void embed(json_data_type& value) const {
			try {
				std::ifstream ifs;
				ifs.exceptions(std::ios_base::badbit | std::ios_base::failbit);
				ifs.open(get_config_path());

				auto json = nlohmann::json::parse(ifs);
				std::string_view name = this->get_json_key_name();
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
				throw config_io_exception(error.str());
			}
		}
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
#endif // APP_SETTINGS_HPP