#ifndef LINUXPLORER_LXPSVC_LRU_CACHE_HPP_
#define LINUXPLORER_LXPSVC_LRU_CACHE_HPP_

#include <cstddef>
#include <list>
#include <unordered_map>

namespace linuxplorer::lxpsvc::models {
	template <class Key, class Value>
	class lru_cache {
	private:
		const std::size_t m_capacity;
		std::list<std::pair<Key, Value>> m_items;
		std::unordered_map<Key, typename std::list<std::pair<Key, Value>>::iterator> m_itr_map;
	public:
		lru_cache(std::size_t capacity) : m_capacity(capacity) {}
		lru_cache(const lru_cache& lhs) = delete;
		lru_cache(lru_cache&& rhs) = default;

		lru_cache& operator=(const lru_cache& lhs) = delete;
		lru_cache& operator=(lru_cache&& rhs) = default;

		const Value* peek_if(const Key& key) const {
			auto map_itr = this->m_itr_map.find(key);
			if (map_itr == this->m_itr_map.end()) return nullptr;

			auto list_itr = map_itr->second;

			return &list_itr->second;
		}

		Value* get(const Key& key) {
			auto map_itr = this->m_itr_map.find(key);
			if (map_itr == this->m_itr_map.end()) return nullptr;

			auto list_itr = map_itr->second;
			this->m_items.splice(this->m_items.begin(), this->m_items, list_itr);

			return &list_itr->second;
		}

		template <class K, class V>
		void put(K&& key, V&& value) {
			if (this->m_capacity == 0) return;

			auto map_itr = this->m_itr_map.find(key);

			if (map_itr != this->m_itr_map.end()) {
				auto list_itr = map_itr->second;
				list_itr->second = std::forward<V>(value);
				this->m_items.splice(this->m_items.begin(), this->m_items, list_itr);
			}
			else {
				this->m_items.emplace_front(std::forward<K>(key), std::forward<V>(value));
				this->m_itr_map.emplace(this->m_items.front().first, this->m_items.begin());
			}

			if (this->m_items.size() > this->m_capacity) {
				auto& [old_key, _] = this->m_items.back();
				this->m_itr_map.erase(old_key);
				this->m_items.pop_back();
			}
		}

		bool try_erase(const Key& key) {
			if (!this->m_itr_map.contains(key)) {
				return false;
			}

			auto list_itr = this->m_itr_map[key];
			if (this->m_items.erase(list_itr) == this->m_items.end()) {
				return false;
			}

			this->m_itr_map.erase(key);

			return true;
		}

		std::size_t size() const noexcept {
			return this->m_items.size();
		}

		std::size_t capacity() const noexcept {
			return this->m_capacity;
		}

		bool empty() const noexcept {
			return this->m_items.empty();
		}

		void clear() {
			this->m_items.clear();
			this->m_itr_map.clear();
		}

		bool contains(const Key& key) const {
			return this->m_itr_map.find(key) != this->m_itr_map.end();
		}
	};
}

#endif // LINUXPLORER_LXPSVC_LRU_CACHE_HPP_