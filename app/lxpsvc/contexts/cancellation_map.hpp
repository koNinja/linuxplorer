#ifndef LINUXPLORER_LXPSVC_CANCELLATION_MAP_HPP_
#define LINUXPLORER_LXPSVC_CANCELLATION_MAP_HPP_

#include "../models/operations/io_operations.hpp"
#include <unordered_map>

namespace linuxplorer::lxpsvc::contexts {
	class cancellation_map {
	private:
		std::unordered_map<models::operations::io_operation::identifier_type, std::weak_ptr<std::stop_source>> m_stop_sources;
		std::mutex m_mutex;

		void cleanup_expired_cancellations() {
			for (auto itr = this->m_stop_sources.begin(); itr != this->m_stop_sources.end();) {
				auto& [id, weak_source_ptr] = *itr;

				if (weak_source_ptr.expired()) itr = this->m_stop_sources.erase(itr);
				else itr++;
			}
		}
	public:
		cancellation_map() {}

		void register_cancellation(models::operations::io_operation::identifier_type id, std::weak_ptr<std::stop_source> weak_stop_source) {
			constexpr std::uint32_t registration_limit_before_cleanup = 30;
			static std::uint32_t count_for_cleanup = 0;

			std::unique_lock lock(this->m_mutex);
			this->m_stop_sources[id] = weak_stop_source;

			if (++count_for_cleanup >= registration_limit_before_cleanup) {
				count_for_cleanup = 0;
				this->cleanup_expired_cancellations();
			}
		}

		bool try_cancel_operation(models::operations::io_operation::identifier_type id) const noexcept {
			if (!this->m_stop_sources.contains(id)) return false;
			if (this->m_stop_sources.at(id).expired()) return false;

			auto ptr = this->m_stop_sources.at(id).lock();
			return ptr->stop_possible() ? ptr->request_stop() : false;
		}
	};

	class io_operation_factory {
	private:
		cancellation_map& m_cancellation_map;
	public:
		io_operation_factory(cancellation_map& cancellation_map) : m_cancellation_map(cancellation_map) {}

		template <class O, class... Args>
		requires models::operations::is_operation_v<O>
		std::unique_ptr<O> create_with_cancellation(Args&&... args) {
			auto operation =  std::make_unique<O>(std::forward<Args>(args)...);	
			this->m_cancellation_map.register_cancellation(operation->get_id(), operation->get_stop_source());
			return operation;
		}
	};
}

#endif // LINUXPLORER_LXPSVC_CANCELLATION_MAP_HPP_