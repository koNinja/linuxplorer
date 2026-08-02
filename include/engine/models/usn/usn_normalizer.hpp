#ifndef LINUXPLORER_ENGINE_USN_NORMALIZER_HPP_
#define LINUXPLORER_ENGINE_USN_NORMALIZER_HPP_

#include <engine/enginefwd.hpp>
#include <cstdint>
#include <array>

namespace linuxplorer::engine::models::usn {
	class operation_recognizer {
	public:
		enum class usn_symbol {
			created = 0,
			modified,
			renamed,
			attr_changed
		};

		enum class state {
			initial = 0,
			creation,
			modification,
			import,
			attribute,
			dead
		};
	private:
		inline static constexpr std::uint32_t s_symbol_count = static_cast<std::uint32_t>(usn_symbol::attr_changed) + 1;
		inline static constexpr std::uint32_t s_state_count = static_cast<std::uint32_t>(state::dead) + 1;

		state m_state;

		// s_transition_table[current_state][input_symbol] returns a next state to be transitioned
		inline static const std::array<std::array<state, s_symbol_count>, s_state_count> s_transition_table{ {
			{ state::creation, state::modification, state::import, state::attribute },	// when the current state is 'initial'
			{ state::creation, state::import, state::import, state::creation },			// 'creation'
			{ state::import, state::modification, state::import, state::modification },
			{ state::import, state::import, state::import, state::import },
			{ state::dead, state::modification, state::import, state::attribute },
			{ state::dead, state::dead, state::dead, state::dead }
		}};
	public:
		operation_recognizer() : m_state(state::initial) {}

		void transition(usn_symbol input) noexcept {
			this->m_state = s_transition_table[static_cast<std::uint32_t>(this->m_state)][static_cast<std::uint32_t>(input)];
		}

		inline state get_operation_type() const noexcept {
			return this->m_state;
		}
	};
}

#endif // LINUXPLORER_ENGINE_USN_NORMALIZER_HPP_