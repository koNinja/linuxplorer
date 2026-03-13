#ifndef LINUXPLORER_APP_LXPSVC_REQUEST_RESULT_ADAPTER_HPP_
#define LINUXPLORER_APP_LXPSVC_REQUEST_RESULT_ADAPTER_HPP_

#include <deque>
#include <mutex>
#include <exception>
#include <utility>

namespace linuxplorer::app::lxpsvc::models::requests {
	enum class request_result {
		success,
		transient_failure,
		permanent_failure,
		cancelled
	};

	template <class T>
	class result_adapter {
	private:
		std::deque<T> m_results;
		std::mutex m_mutex;
		std::exception_ptr m_exptr;
		std::condition_variable m_cv;
	public:
		T wait_head() {
			while (true) {
				std::unique_lock lock(this->m_mutex);
				if (this->m_exptr) {
					std::rethrow_exception(this->m_exptr);
				}
				else if (!this->m_results.empty()) {
					auto result = this->m_results.front();
					this->m_results.pop_front();
					return result;
				}
				else {
					this->m_cv.wait(lock, [this] { return !this->m_results.empty() || this->m_exptr != nullptr; });
				}
			}
		}

		template <class V>
		void set_value(V&& value) {
			std::unique_lock lock(this->m_mutex);
			this->m_results.push_back(std::forward<V>(value));
			this->m_cv.notify_all();
		}

		template <class X>
		void set_exception(X&& exception) {
			std::unique_lock lock(this->m_mutex);
			this->m_exptr = std::make_exception_ptr(std::forward<X>(exception));
			this->m_cv.notify_all();
		}
	};

	template <>
	class result_adapter<void> {
	private:
		std::mutex m_mutex;
		std::atomic<std::uint64_t> m_count = 0;
		std::exception_ptr m_exptr;
	public:
		void wait_head() {
			while (true) {
				{
					std::unique_lock lock(this->m_mutex);
					if (this->m_exptr) {
						std::rethrow_exception(this->m_exptr);
					}
				}
				
				std::uint64_t current_count;
				while ((current_count = this->m_count.load(std::memory_order::acquire)) == 0) {
					this->m_count.wait(0, std::memory_order::acquire);
				}

				if (this->m_count.compare_exchange_strong(current_count, current_count - 1, std::memory_order::acq_rel, std::memory_order::acquire)) {
					return;
				}
			}
		}

		void set_value() {
			this->m_count.fetch_add(1, std::memory_order::acq_rel);
			this->m_count.notify_all();
		}
		
		template <class X>
		void set_exception(X&& exception) {
			{
				std::unique_lock lock(this->m_mutex);
				this->m_exptr = std::make_exception_ptr(std::forward<X>(exception));
			}
			this->m_count.notify_all();
		}
	};
}

#endif // LINUXPLORER_APP_LXPSVC_REQUEST_RESULT_ADAPTER_HPP_