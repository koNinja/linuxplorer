#ifndef APP_SETTINGS_HPP
#define APP_SETTINGS_HPP

#include <shared_mutex>

namespace linuxplorer::util::config {
	std::wstring get_config_path();
	
	class config_exception : public std::runtime_error {
	public:
		config_exception(const char* what) : std::runtime_error(what) {}
		config_exception(const std::string& what) : std::runtime_error(what) {}
	};

	template <class T>
	class app_configuration {
	public:
		using data_type = T;
		app_configuration() {}
	public:
		virtual void load() = 0;
		virtual void save() const = 0;
		virtual data_type get() const = 0;
		virtual void set(data_type& data) = 0;
	};

	template <class T>
	class app_mtconfig : public app_configuration<T> {
	public:
		using data_type = T;
		app_mtconfig() {}
	private:
		mutable std::shared_mutex m_mtx;
	protected:
		virtual void xload() = 0;
		virtual void xsave() const = 0;
		virtual data_type xget() const = 0;
		virtual void xset(const data_type& data) = 0;
	public:
		void load() override {
			auto lock = std::lock_guard(this->m_mtx);
			this->xload();
		}
		void save() const override {
			auto lock = std::shared_lock(this->m_mtx);
			this->xsave();
		}
		data_type get() const override {
			auto lock = std::shared_lock(this->m_mtx);
			return this->xget();
		}
		void set(data_type& data) override {
			auto lock = std::lock_guard(this->m_mtx);
			this->xset(data);
		}
	};
}
#endif // APP_SETTINGS_HPP