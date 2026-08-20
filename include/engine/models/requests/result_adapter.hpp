#ifndef LINUXPLORER_ENGINE_RESULT_ADAPTER_HPP_
#define LINUXPLORER_ENGINE_RESULT_ADAPTER_HPP_

#include <deque>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <exception>
#include <utility>
#include <optional>

namespace linuxplorer::engine::models::requests {
	enum class request_result {
		success,
		transient_failure,
		permanent_failure,
		cancelled
	};

	template <class T>
	class result_adapter {
	private:
		std::mutex m_mutex;
		std::deque<T> m_results;
		bool m_done = false;
		std::exception_ptr m_exptr = nullptr;
		std::condition_variable m_cv;
	public:
		result_adapter() {}

		std::optional<T> wait_head() {
			std::unique_lock lock(this->m_mutex);

			this->m_cv.wait(lock, [this] { return !this->m_results.empty() || this->m_exptr != nullptr || this->m_done; });

			if (this->m_exptr) std::rethrow_exception(this->m_exptr);

			if (this->m_done && this->m_results.empty()) return std::nullopt;

			T result = std::move(this->m_results.front());
			this->m_results.pop_front();

			return result;
		}

		template <class V>
		void set_value(V&& value) {
			{
				std::unique_lock lock(this->m_mutex);
				if (this->m_done) return;
				this->m_results.push_back(std::forward<V>(value));
			}
			this->m_cv.notify_one();
		}

		template <class X>
		void set_exception(X&& exception) {
			{
				std::unique_lock lock(this->m_mutex);
				if (this->m_done) return;
				if (!this->m_exptr) this->m_exptr = std::make_exception_ptr(std::forward<X>(exception));
			}
			this->m_cv.notify_all();
		}

		void set_exception(std::exception_ptr exptr) {
			{
				std::unique_lock lock(this->m_mutex);
				if (this->m_done) return;
				if (!this->m_exptr) this->m_exptr = exptr;
			}
			this->m_cv.notify_all();
		}

		void finalize() {
			{
				std::unique_lock lock(this->m_mutex);
				if (this->m_done) return;
				this->m_done = true;
			}
			this->m_cv.notify_all();
		}

		bool done() noexcept {
			std::unique_lock lock(this->m_mutex);
			return this->m_done;
		}
	};

	template <>
	class result_adapter<void> {
	private:
		std::mutex m_mutex;
		bool m_done;
		std::uint64_t m_count;
		std::condition_variable m_cv;
		std::exception_ptr m_exptr;
	public:
		result_adapter() : m_count(0), m_done(false) {}

		bool wait_head() {
			std::unique_lock lock(this->m_mutex);

			this->m_cv.wait(lock, [this] { return this->m_count > 0 || this->m_exptr != nullptr || this->m_done; });

			if (this->m_exptr) {
				std::rethrow_exception(this->m_exptr);
			}

			if (this->m_done && this->m_count == 0) {
				return false;
			}
			
			this->m_count--;
			return true;
		}

		void set_value() {
			{
				std::unique_lock lock(this->m_mutex);
				if (this->m_done) return;
				this->m_count++;
			}
			this->m_cv.notify_one();
		}
		
		template <class X>
		void set_exception(X&& exception) {
			{
				std::unique_lock lock(this->m_mutex);
				if (this->m_done) return;
				if (!this->m_exptr) this->m_exptr = std::make_exception_ptr(std::forward<X>(exception));
			}
			this->m_cv.notify_all();
		}

		void set_exception(std::exception_ptr exptr) {
			{
				std::unique_lock lock(this->m_mutex);
				if (this->m_done) return;
				if (!this->m_exptr) this->m_exptr = exptr;
			}
			this->m_cv.notify_all();
		}

		void finalize() {
			{
				std::unique_lock lock(this->m_mutex);
				if (this->m_done) return;
				this->m_done = true;
			}
			this->m_cv.notify_all();
		}

		bool done() noexcept {
			std::unique_lock lock(this->m_mutex);
			return this->m_done;
		}
	};
}

#endif // LINUXPLORER_ENGINE_RESULT_ADAPTER_HPP_