#ifndef LINUXPLORER_ENGINE_RESULT_DRAIN_HPP_
#define LINUXPLORER_ENGINE_RESULT_DRAIN_HPP_

#include <optional>
#include <mutex>
#include <atomic>

namespace linuxplorer::engine::models::requests {
	template <class T>
	class result_drain {
	private:
		std::optional<T> m_result;
		std::mutex m_mutex;
		std::atomic<bool> m_done;
	public:
		result_drain() : m_done(false), m_result(std::nullopt) {}

		template <class V>
		void set_value(V&& value) {
			if (this->done()) return;

			{
				std::unique_lock lock(this->m_mutex);
				this->m_result.emplace(std::forward<V>(value));
			}

			this->m_done.store(true, std::memory_order::release);
		}

		T* try_get_value() {
			if (!this->done()) return nullptr;
			std::unique_lock lock(this->m_mutex);
			return this->m_result.has_value() ? &this->m_result.value() : nullptr;
		}

		bool done() const noexcept {
			return this->m_done.load(std::memory_order::acquire);
		}
	};
}

#endif // LINUXPLORER_ENGINE_RESULT_DRAIN_HPP_