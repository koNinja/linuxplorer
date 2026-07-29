#include "io_operations.hpp"

#include <shell/filesystem/cloud_filter_placeholder.hpp>
#include <ranges>

namespace linuxplorer::lxpsvc::models::operations {
	creation_operation::creation_operation(const std::filesystem::path& syncroot, const std::filesystem::path& relative_path, std::shared_ptr<cancellation_context> cancellation_context)
		: stateful_io_operation<internal::creation_operation_state_traits>(operation_priority::lower, syncroot, relative_path, cancellation_context), m_identity(1)
	{
		this->set_state(state_type::creating);
		this->m_identity[0] = std::byte{0};
		this->m_type = std::filesystem::status(this->get_absolute_path()).type();
	}

	creation_operation::request_variant_t creation_operation::fetch() const {
		switch (this->get_state()) {	
		case state_type::creating:
			return requests::remote::creation_request(
				this->get_path_helper().to_linux_style(this->get_absolute_path(), helpers::style_conversion_class::absolute_format),
				this->m_type
			);
		case state_type::transforming:
			return requests::local::transform_request(this->get_absolute_path(), this->m_identity);
		case state_type::committing:
			return requests::local::attribute_request(
				this->get_absolute_path(),
				requests::local::attribute_request::change_domain::mark_in_sync
			);
		default:
			throw invalid_state_exception("The state machine has already been completed.");
		}
	}

	void creation_operation::transition_on_success() noexcept {
		switch (this->get_state()) {
		case state_type::creating:
			this->set_state(state_type::transforming);
			break;
		case state_type::transforming:
			this->set_state(this->m_type == std::filesystem::file_type::directory ? creation_operation::state_type::committing : creation_operation::state_type::done);
			break;
		case state_type::committing:
			this->finalize();
			break;
		default:
			break;
		}
	}

	bool creation_operation::should_execute() const {
		if (shell::filesystem::cloud_filter_placeholder::is_placeholder(this->get_absolute_path())) {
			return false;
		}

		return true;
	}

	modification_operation::modification_operation(const std::filesystem::path& syncroot, const std::filesystem::path& relative_path, models::requests::remote::modification_type type, std::shared_ptr<cancellation_context> cancellation_context) :
		stateful_io_operation<internal::modification_operation_state_traits>(operation_priority::lower, syncroot, relative_path, cancellation_context),
		m_current_range_index(0), m_type(type)
	{
		if (std::filesystem::is_directory(this->get_absolute_path())) {
			this->set_state(state_type::committing);
			return;
		}
	}

	void modification_operation::acquire_modified_ranges_if_consted() const {
		if (this->m_ranges.has_value()) return;

		std::vector<range<std::size_t>> modified_ranges;
		switch (this->m_type) {
		case models::requests::remote::modification_type::appended: [[fallthrough]];
		case models::requests::remote::modification_type::overwritten:
		{
			shell::filesystem::cloud_filter_placeholder placeholder(this->get_absolute_path());

			constexpr std::size_t ranges_count = 64;
			::CF_FILE_RANGE fragmented_modified_ranges[ranges_count];
			::DWORD bytes_read_ranges;
			::HRESULT hr = ::CfGetPlaceholderRangeInfo(
				placeholder.get_handle(),
				::CF_PLACEHOLDER_RANGE_INFO_CLASS::CF_PLACEHOLDER_RANGE_INFO_MODIFIED,
				::LARGE_INTEGER { .QuadPart = 0 },
				::LARGE_INTEGER { .QuadPart = CF_EOF },
				fragmented_modified_ranges,
				sizeof(::CF_FILE_RANGE) * ranges_count,
				&bytes_read_ranges
			);

			std::size_t valid_range_count = bytes_read_ranges / sizeof(::CF_FILE_RANGE);
			if (FAILED(hr)) {
				auto file_size = std::filesystem::file_size(placeholder.get_path());

				// Transfer all the data to the server
				valid_range_count = 1;
				fragmented_modified_ranges[0].StartingOffset.QuadPart = 0;
				fragmented_modified_ranges[0].Length.QuadPart = file_size;
			}

			for (int i = 0; i < valid_range_count; i++) {
				modified_ranges.emplace_back(
					fragmented_modified_ranges[i].StartingOffset.QuadPart,
					fragmented_modified_ranges[i].Length.QuadPart
				);
			}
			break;
		}
		case models::requests::remote::modification_type::truncated: [[fallthrough]];
		default:
		{
			modified_ranges.emplace_back(0, std::filesystem::file_size(this->get_absolute_path()));
			break;
		}
		}
		
		std::vector<range<std::size_t>> normalized_modified_ranges;
		for (const auto& modified_range : modified_ranges) {
			std::streamsize bytes_remaining = modified_range.get_length();
			std::size_t relative_offset = 0;
			do {
				std::size_t length = std::min(s_unit_chunk_length, static_cast<std::size_t>(bytes_remaining));

				normalized_modified_ranges.emplace_back(modified_range.get_offset() + relative_offset, length);

				bytes_remaining -= length;
				relative_offset += length;
			} while (bytes_remaining > 0);
		}

		this->m_ranges = std::move(normalized_modified_ranges);
	}

	modification_operation::request_variant_t modification_operation::fetch() const {
		this->acquire_modified_ranges_if_consted();

		switch (this->get_state()) {	
		case state_type::uploading:
			return requests::remote::modification_request(
				this->get_path_helper().to_linux_style(this->get_absolute_path(), helpers::style_conversion_class::absolute_format),
				this->m_ranges->at(this->m_current_range_index),
				this->m_type
			);
		case state_type::committing:
			return requests::local::attribute_request(this->get_absolute_path(), requests::local::attribute_request::change_domain::mark_in_sync);
		default:
			throw invalid_state_exception("The state machine has already been completed.");
		}
	}

	void modification_operation::transition_on_success() noexcept {
		switch (this->get_state()) {
		case state_type::uploading:
		{
			if ((this->m_current_range_index + 1) >= this->m_ranges->size()) {
				this->set_state(state_type::committing);
			}
			else {
				this->m_current_range_index++;
			}

			break;
		}
		case state_type::committing:
			this->finalize();
			break;
		default:
			break;
		}
	}

	bool modification_operation::should_execute() const {
		if (!shell::filesystem::cloud_filter_placeholder::is_placeholder(this->get_absolute_path())) {
			return false;
		}
		
		if (!std::filesystem::is_regular_file(this->get_absolute_path())) {
			return false;
		}

		shell::filesystem::file_placeholder placeholder(this->get_absolute_path());

		if (placeholder.is_marked_in_sync()) {
			return false;
		}
		
		this->acquire_modified_ranges_if_consted();

		return true;
	}

	deletion_operation::deletion_operation(const std::filesystem::path& syncroot, const std::filesystem::path& relative_path, std::shared_ptr<cancellation_context> cancellation_context) :
		stateful_io_operation<internal::deletion_operation_state_traits>(operation_priority::higher, syncroot, relative_path, cancellation_context)
	{
		this->set_state(state_type::deleting);
		this->m_adapter = std::make_shared<requests::result_adapter<void>>();
	}

	deletion_operation::request_variant_t deletion_operation::fetch() const {
		switch (this->get_state()) {
		case state_type::deleting:
		{
			return requests::remote::deletion_request(
				this->get_path_helper().to_linux_style(this->get_absolute_path(), helpers::style_conversion_class::absolute_format),
				*this->m_adapter
			);
		}
		default:
			throw invalid_state_exception("The state machine has already been completed.");
		}
	}

	void deletion_operation::transition_on_success() noexcept {
		switch (this->get_state()) {
		case state_type::deleting:
			this->finalize();
			this->m_adapter->finalize();
			break;
		default:
			break;
		}
	}

	void deletion_operation::transition_on_permanent_failure() noexcept {
		this->m_adapter->set_exception(shell::functional::callback_abort_exception(ERROR_CLOUD_FILE_UNSUCCESSFUL));
		this->finalize();
	}

	void deletion_operation::transition_on_cancelled() noexcept {
		this->m_adapter->set_exception(shell::functional::callback_abort_exception(ERROR_CLOUD_FILE_REQUEST_CANCELED));
		this->finalize();
	}

	std::weak_ptr<requests::result_adapter<void>> deletion_operation::get_adapter() noexcept {
		return this->m_adapter;
	}

	renaming_operation::renaming_operation(const std::filesystem::path& syncroot, const std::filesystem::path& relative_old_path, const std::filesystem::path& absolute_new_path, std::shared_ptr<cancellation_context> cancellation_context) :
		stateful_io_operation<internal::renaming_operation_state_traits>(operation_priority::higher, syncroot, relative_old_path, cancellation_context), 
		m_absolute_new_path(absolute_new_path)
	{
		this->m_adapter = std::make_shared<requests::result_adapter<void>>();

		if (this->get_path_helper().is_under(this->m_absolute_new_path, this->get_path_helper().get_syncroot())) {
			this->set_state(state_type::renaming);
		}
		else {
			this->set_state(state_type::deleting);
		}
	}

	renaming_operation::request_variant_t renaming_operation::fetch() const {
		switch (this->get_state()) {
		case state_type::renaming:
		{
			return requests::remote::renaming_request(
				this->get_path_helper().to_linux_style(this->get_absolute_path(), helpers::style_conversion_class::absolute_format),
				this->get_path_helper().to_linux_style(this->m_absolute_new_path, helpers::style_conversion_class::absolute_format),
				*this->m_adapter
			);
		}
		case state_type::deleting:
		{
			return requests::remote::deletion_request(
				this->get_path_helper().to_linux_style(this->get_absolute_path(), helpers::style_conversion_class::absolute_format),
				*this->m_adapter
			);
		}
		case state_type::committing:
		{
			return requests::local::attribute_request(
				this->get_absolute_path(),
				requests::local::attribute_request::change_domain::mark_in_sync
			);
		}
		default:
			throw invalid_state_exception("The state machine has already been completed.");
		}
	}

	void renaming_operation::transition_on_success() noexcept {
		switch (this->get_state()) {
		case state_type::renaming:
			this->set_state(state_type::committing);
			this->m_adapter->finalize();
			break;
		case state_type::deleting: [[fallthrough]];
		case state_type::committing:
			this->finalize();
			this->m_adapter->finalize();
			break;
		default:
			break;
		}
	}

	void renaming_operation::transition_on_permanent_failure() noexcept {
		this->m_adapter->set_exception(shell::functional::callback_abort_exception(ERROR_CLOUD_FILE_UNSUCCESSFUL));
		this->finalize();
	}

	void renaming_operation::transition_on_cancelled() noexcept {
		this->m_adapter->set_exception(shell::functional::callback_abort_exception(ERROR_CLOUD_FILE_REQUEST_CANCELED));
		this->finalize();
	}

	std::weak_ptr<requests::result_adapter<void>> renaming_operation::get_adapter() noexcept {
		return this->m_adapter;
	}

	import_operation::import_operation(const std::filesystem::path& syncroot, const std::filesystem::path& relative_path, std::shared_ptr<cancellation_context> cancellation_context) :
		stateful_io_operation<internal::import_operation_state_traits>(operation_priority::lower, syncroot, relative_path, cancellation_context)
	{
		if (shell::filesystem::cloud_filter_placeholder::is_placeholder(this->get_absolute_path())) {
			this->finalize();
			return;
		}

		this->set_state(state_type::creating);

		auto stat = std::filesystem::status(this->get_absolute_path());
		if (stat.type() == std::filesystem::file_type::directory) {
			this->m_rditr = std::filesystem::recursive_directory_iterator(this->get_absolute_path());
		}
		else {
			this->m_rditr = this->m_rditr_end;
		}
	}

	import_operation::request_variant_t import_operation::fetch() const {
		switch (this->get_state()) {
		case state_type::creating:
			return requests::remote::creation_request(
				this->get_path_helper().to_linux_style(this->get_absolute_path(), helpers::style_conversion_class::absolute_format),
				std::filesystem::status(this->get_absolute_path()).type()
			);
		case state_type::transforming:
			return requests::local::transform_request(
				this->get_absolute_path(),
				{ std::byte{0} } // dummy FileIdentity blob
			);
		case state_type::uploading:
		{
			std::size_t offset = this->m_current_file_size - this->m_remaining_current_file_size;
			std::size_t length = this->calculate_chunk_length();

			return requests::remote::modification_request(
				this->get_path_helper().to_linux_style(this->get_absolute_path(), helpers::style_conversion_class::absolute_format),
				range(offset, length),
				requests::remote::modification_type::appended
			);
		}
		case state_type::committing:
			return requests::local::attribute_request(
				this->get_absolute_path(),
				requests::local::attribute_request::change_domain::mark_in_sync
			);
		case state_type::creating_child:
			return requests::remote::creation_request(
				this->get_path_helper().to_linux_style(this->m_rditr->path(), helpers::style_conversion_class::absolute_format),
				this->m_rditr->status().type()
			);
		case state_type::transforming_child:
			return requests::local::transform_request(
				this->m_rditr->path(),
				{ std::byte{0} }
			);
		case state_type::uploading_child:
		{
			std::size_t offset = this->m_current_file_size - this->m_remaining_current_file_size;
			std::size_t length = this->calculate_chunk_length();

			return requests::remote::modification_request(
				this->get_path_helper().to_linux_style(this->m_rditr->path(), helpers::style_conversion_class::absolute_format),
				range(offset, length),
				requests::remote::modification_type::appended
			);
		}
		case state_type::committing_child:
			return requests::local::attribute_request(
				this->m_rditr->path(),
				requests::local::attribute_request::change_domain::mark_in_sync
			);
		default:
			throw invalid_state_exception("The state machine has already been completed.");
		}
	}

	void import_operation::transition_on_success() noexcept {
		switch (this->get_state()) {
		case state_type::creating:
		{
			this->set_state(state_type::transforming);
			break;
		}
		case state_type::transforming:
		{
			std::error_code ec;

			auto stat = std::filesystem::status(this->get_absolute_path(), ec);

			if (ec || stat.type() != std::filesystem::file_type::regular) {
				// when unable to upload
				this->set_state(state_type::committing);
			}
			else {
				this->set_state(state_type::uploading);
				this->m_current_file_size = this->m_remaining_current_file_size = std::filesystem::file_size(this->get_absolute_path(), ec);
				if (ec || this->m_current_file_size == 0) {
					this->set_state(state_type::committing);
				}
			}
			break;
		}
		case state_type::uploading:
		{
			std::size_t length = this->calculate_chunk_length();
			this->m_remaining_current_file_size -= length;

			if (this->m_remaining_current_file_size == 0) {
				this->set_state(state_type::committing);
			}
			break;
		}
		case state_type::committing:
		{
			if (this->m_rditr == this->m_rditr_end) {
				this->finalize();
			}
			else {
				this->set_state(state_type::creating_child);
			}
			break;
		}
		case state_type::creating_child:
		{
			this->set_state(state_type::transforming_child);
			break;
		}
		case state_type::transforming_child:
		{
			std::error_code ec;

			auto stat = this->m_rditr->status(ec);

			if (ec || stat.type() != std::filesystem::file_type::regular) {
				// when unable to upload
				this->set_state(state_type::committing_child);
			}
			else {
				this->set_state(state_type::uploading_child);
				this->m_current_file_size = this->m_remaining_current_file_size = this->m_rditr->file_size(ec);
				if (ec || this->m_current_file_size == 0) {
					this->set_state(state_type::committing_child);
				}
			}
			break;
		}
		case state_type::uploading_child:
		{
			std::size_t length = this->calculate_chunk_length();
			this->m_remaining_current_file_size -= length;

			if (this->m_remaining_current_file_size == 0) {
				this->set_state(state_type::committing_child);
			}
			break;
		}
		case state_type::committing_child:
		{
			if (this->m_rditr == this->m_rditr_end || ++this->m_rditr == this->m_rditr_end) {
				this->finalize();
			}
			else {
				this->set_state(state_type::creating_child);
			}
			break;
		}
		case state_type::done:
			break;
		default:
			break;
		}
	}

	bool import_operation::should_execute() const {
		if (shell::filesystem::cloud_filter_placeholder::is_placeholder(this->get_absolute_path())) {
			return false;
		}

		return true;
	}

	hydration_operation::hydration_operation(const std::filesystem::path& syncroot, const std::filesystem::path& relative_path, const range<std::size_t>& range, std::shared_ptr<cancellation_context> cancellation_context) :
		stateful_io_operation<internal::hydration_operation_state_traits>(operation_priority::normal, syncroot, relative_path, cancellation_context),
		m_range(range), m_remaining_length(range.get_length())
	{
		this->set_state(state_type::downloading);
		this->m_adapter = std::make_shared<requests::result_adapter<result_t>>();
	}

	hydration_operation::request_variant_t hydration_operation::fetch() const {
		switch (this->get_state()) {
		case state_type::downloading:
		{
			auto range = this->calculate_range_to_download();
			return requests::remote::hydration_request(
				this->get_path_helper().to_linux_style(this->get_absolute_path(), helpers::style_conversion_class::absolute_format),
				range,
				*this->m_adapter
			);
		}
		default:
			throw invalid_state_exception("The state machine has already been completed.");
		}
	}

	void hydration_operation::transition_on_success() noexcept {
		switch (this->get_state()) {
		case state_type::downloading:
		{
			auto range = this->calculate_range_to_download();
			this->m_remaining_length -= range.get_length();

			if (this->m_remaining_length == 0) {
				this->finalize();
				this->m_adapter->finalize();
			}

			break;
		}
		default:
			break;
		}
	}

	void hydration_operation::transition_on_permanent_failure() noexcept {
		this->m_adapter->set_exception(shell::functional::callback_abort_exception(ERROR_CLOUD_FILE_UNSUCCESSFUL));
		this->finalize();
	}

	void hydration_operation::transition_on_cancelled() noexcept {
		this->m_adapter->set_exception(shell::functional::callback_abort_exception(ERROR_CLOUD_FILE_REQUEST_CANCELED));
		this->finalize();
	}

	std::weak_ptr<requests::result_adapter<hydration_operation::result_t>> hydration_operation::get_adapter() noexcept {
		return this->m_adapter;
	}

	population_operation::population_operation(const std::filesystem::path& syncroot, const std::filesystem::path& relative_path, std::shared_ptr<cancellation_context> cancellation_context) :
		stateful_io_operation<internal::population_operation_state_traits>(operation_priority::higher, syncroot, relative_path, cancellation_context)
	{
		this->set_state(state_type::enumerating);
		this->m_adapter = std::make_shared<requests::result_adapter<result_t>>();
	}

	population_operation::request_variant_t population_operation::fetch() const {
		switch (this->get_state()) {
		case state_type::enumerating:
			return requests::remote::population_request(
				this->get_path_helper().to_linux_style(this->get_absolute_path(), helpers::style_conversion_class::absolute_format),
				*this->m_adapter
			);
		default:
			throw invalid_state_exception("The state machine has already been completed.");
		}
	}

	void population_operation::transition_on_success() noexcept {
		switch (this->get_state()) {
		case state_type::enumerating:
		{
			this->finalize();
			this->m_adapter->finalize();
			break;
		}
		default:
			break;
		}
	}

	void population_operation::transition_on_permanent_failure() noexcept {
		this->m_adapter->set_exception(shell::functional::callback_abort_exception(ERROR_CLOUD_FILE_UNSUCCESSFUL));
		this->finalize();
	}

	void population_operation::transition_on_cancelled() noexcept {
		this->m_adapter->set_exception(shell::functional::callback_abort_exception(ERROR_CLOUD_FILE_REQUEST_CANCELED));
		this->finalize();
	}

	std::weak_ptr<requests::result_adapter<population_operation::result_t>> population_operation::get_adapter() noexcept {
		return this->m_adapter;
	}

	attribute_operation::attribute_operation(const std::filesystem::path& syncroot, const std::filesystem::path& relative_path, std::shared_ptr<cancellation_context> cancellation_context) :
		stateful_io_operation<internal::attribute_operation_state_traits>(operation_priority::immediate, syncroot, relative_path, cancellation_context)
	{
		if (!shell::filesystem::cloud_filter_placeholder::is_placeholder(this->get_absolute_path())) {
			this->finalize();
			return;
		}

		shell::filesystem::cloud_filter_placeholder placeholder(this->get_absolute_path());
		if (placeholder.get_type() != shell::filesystem::placeholder_type::file) {
			this->finalize();
			return;
		}

		this->set_state(state_type::applying);
		
		switch (placeholder.get_pin_state()) {
		case shell::filesystem::placeholder_pin_state::pinned:
		{
			this->m_reason = operation_reason::pinned;
			break;
		}
		case shell::filesystem::placeholder_pin_state::unpinned:
		{
			this->m_reason = operation_reason::unpinned;
			break;
		}
		default:
			this->finalize();
			return;
		};
	}

	attribute_operation::request_variant_t attribute_operation::fetch() const {
		switch (this->get_state()) {
		case state_type::applying:
		{
			switch (this->m_reason) {
				case operation_reason::pinned:
					return requests::local::hydration_triggering_request(this->get_absolute_path());
				case operation_reason::unpinned:
					return requests::local::dehydration_request(this->get_absolute_path());
				default:
					throw not_implemented_exception("The reason for attribute change is not supported.");
			}
			break;
		}
		case state_type::committing:
			if (this->m_reason == operation_reason::unpinned) {
				return requests::local::attribute_request(
					this->get_absolute_path(),
					requests::local::attribute_request::change_domain::mark_in_sync
				);
			}
			else [[fallthrough]];
		default:
			throw invalid_state_exception("The state machine has already been completed.");
		}
	}

	void attribute_operation::transition_on_success() noexcept {
		switch (this->get_state()) {
		case state_type::applying:
			switch (this->m_reason) {
			case operation_reason::unpinned:
				this->set_state(state_type::committing);
				break;
			case operation_reason::pinned: [[fallthrough]];
			default:
				this->finalize();
				break;
			}
			break;
		case state_type::committing:
			this->finalize();
			break;
		case state_type::done:
			break;
		default:
			break;
		}
	}

	bool attribute_operation::should_execute() const {
		switch (this->m_reason) {
		case operation_reason::pinned:
		{
			shell::filesystem::cloud_filter_placeholder placeholder(this->get_absolute_path());

			::LARGE_INTEGER catalog_file_size{ .QuadPart = 0 };
			::GetFileSizeEx(placeholder.get_handle(), &catalog_file_size);

			::CF_FILE_RANGE range_to_verify;
			::DWORD bytes_returned;
			::HRESULT hr = ::CfGetPlaceholderRangeInfo(
				placeholder.get_handle(),
				::CF_PLACEHOLDER_RANGE_INFO_CLASS::CF_PLACEHOLDER_RANGE_INFO_VALIDATED,
				{ .QuadPart = 0 }, { .QuadPart = CF_EOF },
				&range_to_verify,
				sizeof(range_to_verify),
				&bytes_returned
			);
			if (hr == HRESULT_FROM_WIN32(ERROR_MORE_DATA)) {
				return true;
			}
			else if (bytes_returned < sizeof(::CF_FILE_RANGE)) {
				return true;
			}
			else if (range_to_verify.Length.QuadPart < catalog_file_size.QuadPart && bytes_returned >= sizeof(::CF_FILE_RANGE)) {
				return true;
			}
			else {
				return false;
			}
		}
		case operation_reason::unpinned:
		{
			shell::filesystem::cloud_filter_placeholder placeholder(this->get_absolute_path());

			::CF_FILE_RANGE range_to_verify;
			::DWORD bytes_returned;
			::HRESULT hr = ::CfGetPlaceholderRangeInfo(
				placeholder.get_handle(),
				::CF_PLACEHOLDER_RANGE_INFO_CLASS::CF_PLACEHOLDER_RANGE_INFO_ONDISK,
				// In this app, partial dehydration is not supported, so the range to verify is always the entire file
				{ .QuadPart = 0 }, { .QuadPart = CF_EOF },
				&range_to_verify,
				sizeof(range_to_verify),
				&bytes_returned
			);
			if (hr == HRESULT_FROM_WIN32(ERROR_MORE_DATA)) {
				return true;
			}
			else if (range_to_verify.Length.QuadPart > 0 && bytes_returned >= sizeof(::CF_FILE_RANGE)) {
				return true;
			}
			else {
				return false;
			}
			break;
		}
		default:
			return false;
		}
	}

	directory_update_operation::directory_update_operation(const std::filesystem::path& syncroot, const std::filesystem::path& relative_path, std::shared_ptr<cancellation_context> cancellation_context) :
		stateful_io_operation(operation_priority::lower, syncroot, relative_path, cancellation_context)
	{
		this->set_state(state_type::enumerating);
		this->m_enumerated_entries = std::make_unique<requests::result_drain<requests::remote::enumeration_request::result_t>>();
	}

	directory_update_operation::request_variant_t directory_update_operation::fetch() const {
		switch (this->get_state()) {
		case state_type::enumerating:
			return requests::remote::enumeration_request(
				this->get_path_helper().to_linux_style(this->get_absolute_path(), helpers::style_conversion_class::absolute_format),
				*this->m_enumerated_entries
			);
		case state_type::entry_comitting:	
			return requests::local::directory_update_request(
				this->get_absolute_path(),
				*this->m_enumerated_entries->try_get_value()
			);
		case state_type::committing:
			return requests::local::attribute_request(
				this->get_absolute_path(),
				requests::local::attribute_request::change_domain::mark_in_sync
			);
		default:
			throw invalid_state_exception("The state machine has already been completed.");
		}
	}

	void directory_update_operation::transition_on_success() noexcept {
		switch (this->get_state()) {
		case state_type::enumerating:
			if (this->m_enumerated_entries->try_get_value() == nullptr) {
				this->permanently_fail();
			}
			else {
				this->set_state(state_type::entry_comitting);
			}
			break;
		case state_type::entry_comitting:
			this->set_state(state_type::committing);
			break;
		case state_type::committing:
			this->finalize();
			break;
		default:
			break;
		}
	}
}