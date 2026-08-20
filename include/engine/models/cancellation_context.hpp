#ifndef LINUXPLORER_ENGINE_CANCELLATION_CONTEXT_HPP_
#define LINUXPLORER_ENGINE_CANCELLATION_CONTEXT_HPP_

#include <stop_token>

namespace linuxplorer::engine::models {
	class cancellation_context {
	private:
		std::stop_source m_stop_source;
	public:
		std::stop_token get_stop_token() const noexcept {
			return this->m_stop_source.get_token();
		}

		bool request_cancel() noexcept {
			return this->m_stop_source.request_stop();
		}

		bool is_cancellable() const noexcept {
			return this->m_stop_source.stop_possible();
		}

		bool has_cancel_requested() const noexcept {
			return this->m_stop_source.stop_requested();
		}
	};
}

#endif // LINUXPLORER_ENGINE_CANCELLATION_CONTEXT_HPP_