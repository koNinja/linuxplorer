#ifndef LINUXPLORER_CHUNKED_CALLBACK_GENERATOR_HPP_
#define LINUXPLORER_CHUNKED_CALLBACK_GENERATOR_HPP_

#include <shell/shellfwd.hpp>

#include <coroutine>
#include <exception>
#include <iterator>
#include <optional>

namespace linuxplorer::shell::models {
	template <class T>
	struct chunked_callback_generator {
		struct promise_type;
		
		using handle_type = std::coroutine_handle<promise_type>;

		struct promise_type {
			std::optional<T> m_value;
			std::exception_ptr m_exptr;

			auto get_return_object() { 
				return chunked_callback_generator{handle_type::from_promise(*this)};
			}
			std::suspend_always initial_suspend() { 
				return {}; 
			}
			std::suspend_always final_suspend() noexcept { 
				return {}; 
			}

			std::suspend_always yield_value(const T& value) {
				this->m_value = value;
				return {};
			}

			void return_void() {}
			
			void unhandled_exception() {
				this->m_exptr = std::current_exception();
			}

			void rethrow_if_exception() {
				if (this->m_exptr) {
					std::rethrow_exception(this->m_exptr);
				}
			}
		};

		struct iterator {
			using value_type = T;
            using reference = const T&;
            using pointer = const T*;
			using iterator_category = std::input_iterator_tag;
            using difference_type = std::ptrdiff_t;

			std::coroutine_handle<promise_type> m_coro;

            iterator() = default;
            explicit iterator(std::coroutine_handle<promise_type> coro) noexcept : m_coro(coro) {}
			explicit iterator(iterator&& rhs) noexcept : m_coro(std::move(rhs)) {}

            iterator& operator++() {
                this->m_coro.resume();
                if (this->m_coro.done()) {
					auto coro = std::move(this->m_coro);
					coro.promise().rethrow_if_exception();
					this->m_coro = nullptr;
                }

                return *this;
            }

            void operator++(int) {
                ++*this;
            }

            bool operator==(const iterator& lhs) const noexcept {
                return this->m_coro == lhs.m_coro;
            }

            bool operator!=(const iterator& lhs) const noexcept {
                return !(*this == lhs);
            }

            reference operator*() const noexcept {
                return *this->m_coro.promise().m_value;
            }

            pointer operator->() const noexcept {
                return &(*this->m_coro.promise().m_value);
            }
		};

		iterator begin() {
            if (this->m_coro) {
                this->m_coro.resume();
                if (this->m_coro.done()) {
					this->m_coro.promise().rethrow_if_exception();
					return {};
                }
            }

            return iterator{this->m_coro};
        }

        iterator end() noexcept {
            return {};
        }

		handle_type m_coro;

		explicit chunked_callback_generator(promise_type& p) noexcept : m_coro(handle_type::from_promise(p)) {}
		explicit chunked_callback_generator(handle_type h) : m_coro(h) {}
		chunked_callback_generator(chunked_callback_generator&& rhs) noexcept : m_coro(std::move(rhs.m_coro)) {}
		~chunked_callback_generator() { 
			if(this->m_coro) this->m_coro.destroy();
		}

		bool next() {
			this->m_coro.resume();
			return !this->m_coro.done(); 
		}

		T value() { 
			return *this->m_coro.promise().m_value;
		}
	};
}

#endif // LINUXPLORER_CHUNKED_CALLBACK_GENERATPR_HPP_
