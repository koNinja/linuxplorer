#ifndef LINUXPLORER_LXPSVC_IO_OPERATIONS_HPP_
#define LINUXPLORER_LXPSVC_IO_OPERATIONS_HPP_

#include "../requests/remote_requests.hpp"
#include "../requests/local_requests.hpp"
#include "../requests/result_adapter.hpp"
#include "../../helpers/path_helper.hpp"

#include <cstddef>
#include <cstdint>
#include <variant>
#include <filesystem>
#include <vector>

namespace linuxplorer::app::lxpsvc::models::operations {
	class invalid_state_exception : public std::logic_error {
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
		immediate,
		interruptive
	};

	enum class operation_result {
		pending,
		succeeded,
		failed,
		cancelled,
		ignored
	};

	class io_operation {
	private:
		inline static std::atomic<std::uint64_t> s_id_prefix = 0;
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
			requests::local::hydration_triggering_request
		>;
	private:
		const std::uint64_t m_id;
		operation_priority m_priority;
		std::filesystem::path m_absolute_path;
		helpers::path_helper m_path_helper;
		operation_result m_result;
		std::uint64_t m_request_index;
	public:
		io_operation(operation_priority priority, const std::filesystem::path& syncroot, const std::filesystem::path& relative_path) :
			m_id(s_id_prefix.fetch_add(1, std::memory_order::relaxed)),
			m_priority(priority),
			m_path_helper(syncroot),
			m_result(operation_result::pending),
			m_request_index(0)
		{
			this->m_absolute_path = this->m_path_helper.to_absolute(relative_path);
		}

		std::uint64_t get_id() const noexcept {
			return this->m_id;
		}

		std::uint64_t get_request_index() const noexcept {
			return this->m_request_index;
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

		void transition(requests::request_result result) noexcept {
			if (this->m_result != operation_result::pending) return;

			switch (result) {
			case requests::request_result::success:
				this->m_request_index++;
				this->transition_on_success();
				if (this->done()) this->m_result = operation_result::succeeded;
				break;
			case requests::request_result::transient_failure:
				this->transition_on_transient_failure();
				break;
			case requests::request_result::permanent_failure:
				this->transition_on_permanent_failure();
				this->m_result = operation_result::failed;
				break;
			case requests::request_result::cancelled:
				this->transition_on_cancelled();
				this->m_result = operation_result::cancelled;
				break;
			default:
				break;
			}
		}

		virtual ~io_operation() = default;
	protected:
		const helpers::path_helper& get_path_helper() const noexcept {
			return this->m_path_helper;
		}

		virtual void transition_on_success() noexcept = 0;
		virtual void transition_on_transient_failure() noexcept {}
		virtual void transition_on_permanent_failure() noexcept = 0;
		virtual void transition_on_cancelled() noexcept = 0;

		void mark_as_ignored() noexcept {
			this->m_result = operation_result::ignored;
		}
	};

	class creation_operation : public io_operation {
	private:
		enum class state_t {
			creating,
			transforming,
			committing,
			done
		} m_state;

		std::filesystem::file_type m_type;
		std::vector<std::byte> m_identity;
	protected:
		virtual void transition_on_success() noexcept override;
		virtual void transition_on_permanent_failure() noexcept override;
		virtual void transition_on_cancelled() noexcept override;
	public:
		creation_operation(const std::filesystem::path& syncroot, const std::filesystem::path& relative_path);

		virtual request_variant_t fetch() const override;
		virtual bool done() const noexcept override;

		virtual ~creation_operation() = default;
	};

	class modification_operation : public io_operation {
	private:
		enum class state_t {
			uploading,
			committing,
			done
		} m_state;

		std::vector<range<std::size_t>> m_ranges;
		std::size_t m_current_range_index;
	protected:
		virtual void transition_on_success() noexcept override;
		virtual void transition_on_permanent_failure() noexcept override;
		virtual void transition_on_cancelled() noexcept override;
	public:
		modification_operation(const std::filesystem::path& syncroot, const std::filesystem::path& relative_path);

		virtual request_variant_t fetch() const override;
		virtual bool done() const noexcept override;

		virtual ~modification_operation() = default;
	};

	class deletion_operation : public io_operation {
	private:
		enum class state_t {
			deleting,
			done
		} m_state;

		mutable requests::result_adapter<void> m_adapter;
	protected:
		virtual void transition_on_success() noexcept override;
		virtual void transition_on_permanent_failure() noexcept override;
		virtual void transition_on_cancelled() noexcept override;
	public:
		deletion_operation(const std::filesystem::path& syncroot, const std::filesystem::path& relative_path);

		virtual request_variant_t fetch() const override;
		virtual bool done() const noexcept override;

		void wait_head() const;

		virtual ~deletion_operation() = default;
	};

	/*
		Note: This class represents renaming within the syncroot or moving out of the syncroot tree, 
			and it's used by only CF_CALLBACK_TYPE_ACK_RENAME callback.
	*/
	class renaming_operation : public io_operation {
	private:
		enum class state_t {
			renaming,
			deleting,
			committing,
			done
		} m_state;

		mutable requests::result_adapter<void> m_adapter;

		std::filesystem::path m_absolute_new_path;
	protected:
		virtual void transition_on_success() noexcept override;
		virtual void transition_on_permanent_failure() noexcept override;
		virtual void transition_on_cancelled() noexcept override;
	public:
		renaming_operation(const std::filesystem::path& syncroot, const std::filesystem::path& relative_old_path, const std::filesystem::path& absolute_new_path);

		virtual request_variant_t fetch() const override;
		virtual bool done() const noexcept override;

		void wait_head() const;

		virtual ~renaming_operation() = default;
	};

	/*
		Note: This class represents moveing into the syncroot tree, and it's used by only filesystem_watcher.
	*/
	class import_operation : public io_operation {
	private:
		enum class state_t {
			creating,
			transforming,
			uploading,
			committing,
			creating_child,
			transforming_child,
			uploading_child,
			committing_child,
			done
		} m_state;

		const std::filesystem::recursive_directory_iterator m_rditr_end = std::filesystem::recursive_directory_iterator{};
		std::filesystem::recursive_directory_iterator m_rditr;

		std::size_t m_current_file_size;
		std::size_t m_remaining_current_file_size;
		inline std::size_t calculate_chunk_length() const noexcept {
			constexpr std::size_t unit_chunk_length = 262144;	// 256KiB
			return std::min(unit_chunk_length, this->m_remaining_current_file_size);
		}
	protected:
		virtual void transition_on_success() noexcept override;
		virtual void transition_on_permanent_failure() noexcept override;
		virtual void transition_on_cancelled() noexcept override;
	public:
		import_operation(const std::filesystem::path& syncroot, const std::filesystem::path& relative_path);

		virtual request_variant_t fetch() const override;
		virtual bool done() const noexcept override;

		virtual ~import_operation() = default;
	};

	class hydration_operation : public io_operation {
	public:
		using result_t = requests::remote::hydration_request::result_t;
	private:
		enum class state_t {
			downloading,
			done
		} m_state;

		range<std::size_t> m_range;
		std::size_t m_remaining_length;
		inline range<std::size_t> calculate_range_to_download() const noexcept {
			constexpr std::size_t unit_chunk_length = 2097152;	// 2 MiB
			auto relative_offset = this->m_range.get_length() - this->m_remaining_length;
			auto length = std::min(unit_chunk_length, this->m_remaining_length);

			return range(this->m_range.get_offset() + relative_offset, length);
		}

		mutable requests::result_adapter<result_t> m_adapter;
	protected:
		virtual void transition_on_success() noexcept override;
		virtual void transition_on_permanent_failure() noexcept override;
		virtual void transition_on_cancelled() noexcept override;
	public:
		hydration_operation(const std::filesystem::path& syncroot, const std::filesystem::path& relative_path, const range<std::size_t>& range);

		virtual request_variant_t fetch() const override;
		virtual bool done() const noexcept override;

		virtual ~hydration_operation() = default;
	};

	class population_operation : public io_operation {
	public:
		using result_t = requests::remote::population_request::result_t;
	private:
		enum class state_t {
			enumerating,
			done
		} m_state;

		mutable requests::result_adapter<result_t> m_adapter;
	protected:
		virtual void transition_on_success() noexcept override;
		virtual void transition_on_permanent_failure() noexcept override;
		virtual void transition_on_cancelled() noexcept override;
	public:
		population_operation(const std::filesystem::path& syncroot, const std::filesystem::path& relative_path);

		virtual request_variant_t fetch() const override;
		virtual bool done() const noexcept override;

		virtual ~population_operation() = default;
	};

	class attribute_operation : public io_operation {
	public:
		enum class operation_reason {
			pinned,
			unpinned
		};
	private:
		enum class state_t {
			applying,
			committing,
			done
		} m_state;

		operation_reason m_reason;
	protected:
		virtual void transition_on_success() noexcept override;
		virtual void transition_on_permanent_failure() noexcept override;
		virtual void transition_on_cancelled() noexcept override;
	public:
		attribute_operation(const std::filesystem::path& syncroot, const std::filesystem::path& relative_path);

		virtual request_variant_t fetch() const override;
		virtual bool done() const noexcept override;

		virtual ~attribute_operation() = default;
	};
}

#endif // LINUXPLORER_LXPSVC_IO_OPERATIONS_HPP_