#ifndef LINUXPLORER_ENGINE_IO_OPERATIONS_HPP_
#define LINUXPLORER_ENGINE_IO_OPERATIONS_HPP_

#include <engine/enginefwd.hpp>
#include <engine/models/cancellation_context.hpp>
#include <engine/models/requests/remote/remote_requests.hpp>
#include <engine/models/requests/local/local_requests.hpp>
#include <engine/models/requests/result_adapter.hpp>
#include <engine/models/requests/result_drain.hpp>
#include <engine/helpers/path_helper.hpp>

#include <cstddef>
#include <cstdint>
#include <variant>
#include <filesystem>
#include <vector>

#define DECLARE_STATE_TRAITS(operation_name, ...)						\
	struct operation_name##_state_traits {								\
	public:																\
		enum class state_type { __VA_ARGS__, done };					\
		inline static constexpr state_type done = state_type::done;		\
	}

namespace linuxplorer::engine::models::operations {
	class invalid_state_exception : public std::logic_error {
	public:
		using std::logic_error::logic_error;
	};

	class not_implemented_exception : public std::logic_error {
	public:
		using std::logic_error::logic_error;
	};

	template <class... T>
	requires requests::are_request_v<T...>
	using generic_request_variant_t = std::variant<T...>;	

	enum class operation_priority {
		lower,
		normal,
		higher,
		immediate
	};

	enum class operation_result {
		pending,
		succeeded,
		failed,
		cancelled
	};

	class io_operation {
	public:
		using identifier_type = std::uint64_t;
	private:
		inline static constexpr std::uint32_t s_max_attempts = 3;
		inline static std::atomic<identifier_type> s_id_prefix = 0;
	public:
		static std::uint32_t get_max_attempts() noexcept {
			return s_max_attempts;
		}
	protected:
		using request_variant_t = generic_request_variant_t<
			requests::remote::creation_request,
			requests::remote::modification_request,
			requests::remote::deletion_request,
			requests::remote::renaming_request,
			requests::remote::hydration_request,
			requests::remote::population_request,
			requests::local::attribute_request,
			requests::local::transform_request,
			requests::local::dehydration_request,
			requests::local::hydration_triggering_request,
			requests::remote::enumeration_request,
			requests::local::directory_update_request
		>;
	private:
		const identifier_type m_id;
		operation_priority m_priority;
		std::filesystem::path m_absolute_path;
		helpers::path_helper m_path_helper;
		operation_result m_result;
		std::shared_ptr<cancellation_context> m_cancellation;

		std::uint32_t m_attempts;
	public:
		io_operation(
			operation_priority priority,
			const std::filesystem::path& syncroot,
			const std::filesystem::path& relative_path,
			std::shared_ptr<cancellation_context> cancellation_context = nullptr
		) :
			m_id(s_id_prefix.fetch_add(1, std::memory_order::relaxed)),
			m_priority(priority),
			m_result(operation_result::pending),
			m_absolute_path(syncroot / relative_path),
			m_path_helper(syncroot),
			m_attempts(0),
			m_cancellation(cancellation_context)
		{
		}

		io_operation(const io_operation& lhs) = delete;
		io_operation(io_operation&& rhs) = default;

		std::uint64_t get_id() const noexcept {
			return this->m_id;
		}

		const std::filesystem::path& get_absolute_path() const noexcept {
			return this->m_absolute_path;
		}

		operation_priority get_priority() const noexcept {
			return this->m_priority;
		}

		operation_result get_result() const noexcept {
			return this->m_result;
		}

		virtual request_variant_t fetch() const = 0;
		virtual bool done() const noexcept = 0;
		bool is_necessary() const {
			if (this->get_result() != operation_result::pending || this->done()) {
				return false;
			}
			else {
				return this->should_execute();
			}
		}

		void transition(requests::request_result result) noexcept {
			if (this->m_result != operation_result::pending) return;

			switch (result) {
			case requests::request_result::success:
				this->transition_on_success();
				this->m_attempts = 0;
				if (this->done()) this->m_result = operation_result::succeeded;
				break;
			case requests::request_result::transient_failure:
				if (++this->m_attempts <= s_max_attempts) {
					this->transition_on_transient_failure();
					break;
				}
				else [[fallthrough]];
			case requests::request_result::permanent_failure:
				this->permanently_fail();
				break;
			case requests::request_result::cancelled:
				this->transition_on_cancelled();
				this->m_result = operation_result::cancelled;
				break;
			default:
				break;
			}
		}

		std::stop_token get_stop_token() const noexcept {
			return this->m_cancellation ? this->m_cancellation->get_stop_token() : std::stop_token();
		}

		std::uint32_t get_current_attempts() const noexcept {
			return this->m_attempts;
		}

		virtual ~io_operation() = default;
	protected:
		const helpers::path_helper& get_path_helper() const noexcept {
			return this->m_path_helper;
		}

		void permanently_fail() noexcept {
			this->transition_on_permanent_failure();
			this->m_result = operation_result::failed;
		}

		virtual void transition_on_success() noexcept = 0;
		virtual void transition_on_transient_failure() noexcept = 0;
		virtual void transition_on_permanent_failure() noexcept = 0;
		virtual void transition_on_cancelled() noexcept = 0;

		virtual bool should_execute() const {
			return true;
		}
	};

	template <class T>
	concept is_operation_v = std::is_base_of_v<io_operation, T>;

	template <class state_traits>
	class stateful_io_operation : public io_operation {
	protected:
		using traits_type = state_traits;
		using state_type = typename traits_type::state_type;
	private:
		std::atomic<state_type> m_state;
	protected:
		void set_state(state_type new_state, std::memory_order order = std::memory_order::seq_cst) noexcept {
			this->m_state.store(new_state, order);
		}
		bool weakly_compare_and_swap_state(state_type& expected, state_type desired, std::memory_order order = std::memory_order::seq_cst) noexcept {
			return this->m_state.compare_exchange_weak(expected, desired, order);
		}
		bool strongly_compare_and_swap_state(state_type& expected, state_type desired, std::memory_order order = std::memory_order::seq_cst) noexcept {
			return this->m_state.compare_exchange_strong(expected, desired, order);
		}

		virtual void transition_on_transient_failure() noexcept override {}
		virtual void transition_on_permanent_failure() noexcept override {
			this->m_state.store(traits_type::done);
		}
		virtual void transition_on_cancelled() noexcept override {
			this->m_state.store(traits_type::done);
		}

		void finalize(std::memory_order order = std::memory_order::seq_cst) noexcept {
			this->m_state.store(traits_type::done, order);
		}
	public:
		using io_operation::io_operation;
		virtual ~stateful_io_operation() = default;

		state_type get_state(std::memory_order order = std::memory_order::seq_cst) const noexcept {
			return this->m_state.load(order);
		}

		virtual bool done() const noexcept override {
			return this->m_state.load() == traits_type::done;
		}
	};

	namespace internal {
		DECLARE_STATE_TRAITS(creation_operation, creating, transforming, committing);
		DECLARE_STATE_TRAITS(modification_operation, uploading, committing);
		DECLARE_STATE_TRAITS(deletion_operation, deleting);
		DECLARE_STATE_TRAITS(renaming_operation, renaming, deleting, committing);
		DECLARE_STATE_TRAITS(import_operation, 
			creating,
			transforming,
			uploading,
			committing,
			creating_child,
			transforming_child,
			uploading_child,
			committing_child
		);
		DECLARE_STATE_TRAITS(hydration_operation, downloading);
		DECLARE_STATE_TRAITS(population_operation, enumerating, cleaning_up, metadata_comitting);
		DECLARE_STATE_TRAITS(attribute_operation, applying, committing);
		DECLARE_STATE_TRAITS(directory_update_operation, enumerating, entry_comitting, committing);
	}

	class LINUXPLORER_ENGINE_API creation_operation : public stateful_io_operation<internal::creation_operation_state_traits> {
	private:
		std::filesystem::file_type m_type;
		std::vector<std::byte> m_identity;
	protected:
		virtual void transition_on_success() noexcept override;
	public:
		creation_operation(const std::filesystem::path& syncroot, const std::filesystem::path& relative_path, std::shared_ptr<cancellation_context> cancellation_context = nullptr);

		virtual request_variant_t fetch() const override;
		virtual bool should_execute() const override;

		virtual ~creation_operation() = default;
	};

	class LINUXPLORER_ENGINE_API modification_operation : public stateful_io_operation<internal::modification_operation_state_traits> {
	private:
		inline static constexpr std::size_t s_unit_chunk_length = 2097152;	// 2MiB

		mutable std::optional<std::vector<range<std::size_t>>> m_ranges;
		void acquire_modified_ranges_if_consted() const;

		std::size_t m_current_range_index;
		models::requests::remote::modification_type m_type;
	protected:
		virtual void transition_on_success() noexcept override;
	public:
		modification_operation(const std::filesystem::path& syncroot, const std::filesystem::path& relative_path, models::requests::remote::modification_type type, std::shared_ptr<cancellation_context> cancellation_context = nullptr);

		virtual request_variant_t fetch() const override;
		virtual bool should_execute() const override;

		virtual ~modification_operation() = default;
	};

	class LINUXPLORER_ENGINE_API deletion_operation : public stateful_io_operation<internal::deletion_operation_state_traits> {
	private:
		mutable std::shared_ptr<requests::result_adapter<void>> m_adapter;
	protected:
		virtual void transition_on_success() noexcept override;
		virtual void transition_on_permanent_failure() noexcept override;
		virtual void transition_on_cancelled() noexcept override;
	public:
		deletion_operation(const std::filesystem::path& syncroot, const std::filesystem::path& relative_path, std::shared_ptr<cancellation_context> cancellation_context = nullptr);

		virtual request_variant_t fetch() const override;

		std::weak_ptr<requests::result_adapter<void>> get_adapter() noexcept;

		virtual ~deletion_operation() = default;
	};

	/*
		Note: This class represents renaming within the syncroot or moving out of the syncroot tree, 
			and it's used by only CF_CALLBACK_TYPE_ACK_RENAME callback.
	*/
	class LINUXPLORER_ENGINE_API renaming_operation : public stateful_io_operation<internal::renaming_operation_state_traits> {
	private:
		mutable std::shared_ptr<requests::result_adapter<void>> m_adapter;

		std::filesystem::path m_absolute_new_path;
	protected:
		virtual void transition_on_success() noexcept override;
		virtual void transition_on_permanent_failure() noexcept override;
		virtual void transition_on_cancelled() noexcept override;
	public:
		renaming_operation(const std::filesystem::path& syncroot, const std::filesystem::path& relative_path, const std::filesystem::path& absolute_new_path, std::shared_ptr<cancellation_context> cancellation_context = nullptr);

		virtual request_variant_t fetch() const override;

		std::weak_ptr<requests::result_adapter<void>> get_adapter() noexcept;

		virtual ~renaming_operation() = default;
	};

	/*
		Note: This class represents moving into the syncroot tree, and it's used by only filesystem_watcher.
	*/
	class LINUXPLORER_ENGINE_API import_operation : public stateful_io_operation<internal::import_operation_state_traits> {
	private:
		inline static constexpr std::size_t s_unit_chunk_length = 2097152;	// 2MiB

		const std::filesystem::recursive_directory_iterator m_rditr_end = std::filesystem::recursive_directory_iterator{};
		std::filesystem::recursive_directory_iterator m_rditr;

		std::size_t m_current_file_size;
		std::size_t m_remaining_current_file_size;
		inline std::size_t calculate_chunk_length() const noexcept {
			return std::min(s_unit_chunk_length, this->m_remaining_current_file_size);
		}
	protected:
		virtual void transition_on_success() noexcept override;
	public:
		import_operation(const std::filesystem::path& syncroot, const std::filesystem::path& relative_path, std::shared_ptr<cancellation_context> cancellation_context = nullptr);

		virtual request_variant_t fetch() const override;
		virtual bool should_execute() const override;

		virtual ~import_operation() = default;
	};

	class LINUXPLORER_ENGINE_API hydration_operation : public stateful_io_operation<internal::hydration_operation_state_traits> {
	public:
		using result_t = requests::remote::hydration_request::result_t;
	private:
		inline static constexpr std::size_t s_unit_chunk_length = 2097152;	// 2MiB

		range<std::size_t> m_range;
		std::size_t m_remaining_length;
		inline range<std::size_t> calculate_range_to_download() const noexcept {
			auto relative_offset = this->m_range.get_length() - this->m_remaining_length;
			auto length = std::min(s_unit_chunk_length, this->m_remaining_length);

			return range(this->m_range.get_offset() + relative_offset, length);
		}

		mutable std::shared_ptr<requests::result_adapter<result_t>> m_adapter;
	protected:
		virtual void transition_on_success() noexcept override;
		virtual void transition_on_permanent_failure() noexcept override;
		virtual void transition_on_cancelled() noexcept override;
	public:
		hydration_operation(const std::filesystem::path& syncroot, const std::filesystem::path& relative_path, const range<std::size_t>& range, std::shared_ptr<cancellation_context> cancellation_context = nullptr);

		virtual request_variant_t fetch() const override;

		std::weak_ptr<requests::result_adapter<result_t>> get_adapter() noexcept;

		virtual ~hydration_operation() = default;
	};

	class LINUXPLORER_ENGINE_API population_operation : public stateful_io_operation<internal::population_operation_state_traits> {
	public:
		using result_t = requests::remote::population_request::result_t;
	private:
		mutable std::shared_ptr<requests::result_adapter<result_t>> m_adapter;
	protected:
		virtual void transition_on_success() noexcept override;
		virtual void transition_on_permanent_failure() noexcept override;
		virtual void transition_on_cancelled() noexcept override;
	public:
		population_operation(const std::filesystem::path& syncroot, const std::filesystem::path& relative_path, std::shared_ptr<cancellation_context> cancellation_context = nullptr);

		virtual request_variant_t fetch() const override;

		std::weak_ptr<requests::result_adapter<result_t>> get_adapter() noexcept;

		virtual ~population_operation() = default;
	};

	class LINUXPLORER_ENGINE_API attribute_operation : public stateful_io_operation<internal::attribute_operation_state_traits> {
	public:
		enum class operation_reason {
			pinned,
			unpinned
		};
	private:
		operation_reason m_reason;
	protected:
		virtual void transition_on_success() noexcept override;
	public:
		attribute_operation(const std::filesystem::path& syncroot, const std::filesystem::path& relative_path, std::shared_ptr<cancellation_context> cancellation_context = nullptr);

		virtual request_variant_t fetch() const override;
		virtual bool should_execute() const override;

		virtual ~attribute_operation() = default;
	};

	class LINUXPLORER_ENGINE_API directory_update_operation : public stateful_io_operation<internal::directory_update_operation_state_traits> {
	private:
		mutable std::unique_ptr<requests::result_drain<requests::remote::enumeration_request::result_t>> m_enumerated_entries;
	protected:
		virtual void transition_on_success() noexcept override;
	public:
		directory_update_operation(const std::filesystem::path& syncroot, const std::filesystem::path& relative_path, std::shared_ptr<cancellation_context> cancellation_context = nullptr);

		virtual request_variant_t fetch() const override;

		virtual ~directory_update_operation() = default;
	};
}

#undef DECLARE_STATE_TRAITS
#endif // LINUXPLORER_ENGINE_IO_OPERATIONS_HPP_