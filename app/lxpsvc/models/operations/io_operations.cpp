#include "io_operations.hpp"

#include <shell/filesystem/cloud_filter_placeholder.hpp>

namespace linuxplorer::app::lxpsvc::models::operations {
	creation_operation::creation_operation(const std::filesystem::path& syncroot, const std::filesystem::path& relative_path)
		: io_operation(operation_priority::lower, syncroot, relative_path), m_state(state_t::creating), m_identity(1)
	{
		this->m_identity[0] = std::byte{0};
		this->m_type = std::filesystem::status(this->get_absolute_path()).type();
	}

	creation_operation::request_variant_t creation_operation::fetch() const {
		switch (this->m_state) {	
		case state_t::creating:
			return requests::remote::creation_request(
				this->get_path_helper().to_linux_style(this->get_absolute_path(), helpers::style_conversion_class::absolute_format),
				this->m_type
			);
		case state_t::transforming:
			return requests::local::transform_request(this->get_absolute_path(), this->m_identity);
		case state_t::committing:
			return requests::local::attribute_request(
				this->get_absolute_path(),
				requests::local::attribute_request::change_domain::mark_in_sync
			);
		default:
			throw invalid_state_exception("The state machine has already been completed.");
		}
	}

	void creation_operation::transition_on_success() noexcept {
		switch (this->m_state) {
		case state_t::creating:
			this->m_state = state_t::transforming;
			break;
		case state_t::transforming:
			this->m_state = this->m_type == std::filesystem::file_type::directory ? creation_operation::state_t::committing : creation_operation::state_t::done;
			break;
		case state_t::committing:
			this->m_state = state_t::done;
			break;
		default:
			break;
		}
	}

	bool creation_operation::done() const noexcept {
		return this->m_state == state_t::done;
	}

	void creation_operation::transition_on_permanent_failure() noexcept {
		this->m_state = state_t::done;
	}

	void creation_operation::transition_on_cancelled() noexcept {
		this->m_state = state_t::done;
	}

	modification_operation::modification_operation(const std::filesystem::path& syncroot, const std::filesystem::path& relative_path) :
		io_operation(operation_priority::lower, syncroot, relative_path),
		m_current_range_index(0)
	{
		bool is_directory = std::filesystem::status(this->get_absolute_path()).type() == std::filesystem::file_type::directory;

		if (shell::filesystem::cloud_filter_placeholder::is_placeholder(this->get_absolute_path().wstring())) {
			this->m_state = state_t::done;
			this->mark_as_ignored();
			return;
		}

		if (is_directory) {
			this->m_state = state_t::committing;
			return;
		}

		shell::filesystem::file_placeholder placeholder(relative_path.wstring());
		if (placeholder.is_marked_in_sync()) {
			this->m_state = state_t::done;
			this->mark_as_ignored();
			return;
		}
	
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
			::LARGE_INTEGER file_size;
			if (!::GetFileSizeEx(placeholder.get_handle(), &file_size)) {
				throw std::system_error(std::error_code(::GetLastError(), std::system_category()), "Failed to get size of the modified file.");
			}

			// Transfer all the data to the server
			valid_range_count = 1;
			fragmented_modified_ranges[0].StartingOffset.QuadPart = 0;
			fragmented_modified_ranges[0].Length.QuadPart = file_size.QuadPart;
		}

		constexpr std::size_t unit_chunk_length = 262144;	// 256KiB
		
		for (int i = 0; i < valid_range_count; i++) {
			std::streamsize bytes_remaining = fragmented_modified_ranges[i].Length.QuadPart;
			std::size_t relative_offset = 0;
			do {
				std::size_t length = std::min(unit_chunk_length, static_cast<std::size_t>(bytes_remaining));

				this->m_ranges.emplace_back(fragmented_modified_ranges[i].StartingOffset.QuadPart + relative_offset, length);

				bytes_remaining -= length;
				relative_offset += length;
			} while (bytes_remaining > 0);
		}

		this->m_state = state_t::uploading;

		return;
	}

	modification_operation::request_variant_t modification_operation::fetch() const {
		switch (this->m_state) {	
		case state_t::uploading:
			return requests::remote::modification_request(
				this->get_path_helper().to_linux_style(this->get_absolute_path(), helpers::style_conversion_class::absolute_format),
				this->m_ranges[this->m_current_range_index]
			);
		case state_t::committing:
			return requests::local::attribute_request(this->get_absolute_path(), requests::local::attribute_request::change_domain::mark_in_sync);
		default:
			throw invalid_state_exception("The state machine has already been completed.");
		}
	}

	void modification_operation::transition_on_success() noexcept {
		switch (this->m_state) {
		case state_t::uploading:
		{
			if ((this->m_current_range_index + 1) >= this->m_ranges.size()) {
				this->m_state = state_t::committing;
			}
			else {
				this->m_current_range_index++;
			}

			break;
		}
		case state_t::committing:
			this->m_state = state_t::done;
			break;
		default:
			break;
		}
	}

	bool modification_operation::done() const noexcept {
		return this->m_state == state_t::done;
	}

	void modification_operation::transition_on_permanent_failure() noexcept {
		this->m_state = state_t::done;
	}

	void modification_operation::transition_on_cancelled() noexcept {
		this->m_state = state_t::done;
	}

	deletion_operation::deletion_operation(const std::filesystem::path& syncroot, const std::filesystem::path& relative_path) : 
		io_operation(operation_priority::higher, syncroot, relative_path), m_state(state_t::deleting)
	{}

	deletion_operation::request_variant_t deletion_operation::fetch() const {
		switch (this->m_state) {
		case state_t::deleting:
		{
			return requests::remote::deletion_request(
				this->get_path_helper().to_linux_style(this->get_absolute_path(), helpers::style_conversion_class::absolute_format),
				this->m_adapter
			);
		}
		default:
			throw invalid_state_exception("The state machine has already been completed.");
		}
	}

	void deletion_operation::transition_on_success() noexcept {
		switch (this->m_state) {
		case state_t::deleting:
			this->m_state = state_t::done;
			break;
		default:
			break;
		}
	}

	bool deletion_operation::done() const noexcept {
		return this->m_state == state_t::done;
	}

	void deletion_operation::transition_on_permanent_failure() noexcept {
		this->m_state = state_t::done;
	}

	void deletion_operation::transition_on_cancelled() noexcept {
		this->m_state = state_t::done;
	}

	void deletion_operation::wait_head() const {
		this->m_adapter.wait_head();
	}

	renaming_operation::renaming_operation(const std::filesystem::path& syncroot, const std::filesystem::path& relative_old_path, const std::filesystem::path& absolute_new_path) : 
		io_operation(operation_priority::higher, syncroot, relative_old_path), 
		m_absolute_new_path(absolute_new_path)
	{
		if (this->get_path_helper().is_under(this->m_absolute_new_path, this->get_path_helper().get_syncroot())) {
			this->m_state = state_t::renaming;
		}
		else {
			this->m_state = state_t::deleting;
		}
	}

	renaming_operation::request_variant_t renaming_operation::fetch() const {
		switch (this->m_state) {
		case state_t::renaming:
		{
			return requests::remote::renaming_request(
				this->get_path_helper().to_linux_style(this->get_absolute_path(), helpers::style_conversion_class::absolute_format),
				this->get_path_helper().to_linux_style(this->m_absolute_new_path, helpers::style_conversion_class::absolute_format),
				this->m_adapter
			);
		}
		case state_t::deleting:
		{
			return requests::remote::deletion_request(
				this->get_path_helper().to_linux_style(this->get_absolute_path(), helpers::style_conversion_class::absolute_format),
				this->m_adapter
			);
		}
		default:
			throw invalid_state_exception("The state machine has already been completed.");
		}
	}

	void renaming_operation::transition_on_success() noexcept {
		switch (this->m_state) {
		case state_t::renaming:
			[[fallthrough]];
		case state_t::deleting:
			this->m_state = state_t::committing;
			break;
		case state_t::committing:
			this->m_state = state_t::done;
			break;
		default:
			break;
		}
	}

	bool renaming_operation::done() const noexcept {
		return this->m_state == state_t::done;
	}

	void renaming_operation::transition_on_permanent_failure() noexcept {
		this->m_state = state_t::done;
	}

	void renaming_operation::transition_on_cancelled() noexcept {
		this->m_state = state_t::done;
	}

	void renaming_operation::wait_head() const {
		this->m_adapter.wait_head();
	}

	import_operation::import_operation(const std::filesystem::path& syncroot, const std::filesystem::path& relative_path) :
		io_operation(operation_priority::lower, syncroot, relative_path),
		m_state(state_t::creating)
	{
		auto stat = std::filesystem::status(this->get_absolute_path());
		if (stat.type() == std::filesystem::file_type::directory) {
			this->m_rditr = std::filesystem::recursive_directory_iterator(this->get_absolute_path());
		}
		else {
			this->m_rditr = this->m_rditr_end;
		}
	}

	import_operation::request_variant_t import_operation::fetch() const {
		switch (this->m_state) {
		case state_t::creating:
			return requests::remote::creation_request(
				this->get_path_helper().to_linux_style(this->get_absolute_path(), helpers::style_conversion_class::absolute_format),
				std::filesystem::status(this->get_absolute_path()).type()
			);
		case state_t::transforming:
			return requests::local::transform_request(
				this->get_absolute_path(),
				{ std::byte{0} } // dummy FileIdentity blob
			);
		case state_t::uploading:
		{
			std::size_t offset = this->m_current_file_size - this->m_remaining_current_file_size;
			std::size_t length = this->calculate_chunk_length();

			return requests::remote::modification_request(
				this->get_path_helper().to_linux_style(this->get_absolute_path(), helpers::style_conversion_class::absolute_format),
				range(offset, length)
			);
		}
		case state_t::committing:
			return requests::local::attribute_request(
				this->get_absolute_path(),
				requests::local::attribute_request::change_domain::mark_in_sync
			);
		case state_t::creating_child:
			return requests::remote::creation_request(
				this->get_path_helper().to_linux_style(this->m_rditr->path(), helpers::style_conversion_class::absolute_format),
				this->m_rditr->status().type()
			);
		case state_t::transforming_child:
			return requests::local::transform_request(
				this->m_rditr->path(),
				{ std::byte{0} }
			);
		case state_t::uploading_child:
		{
			std::size_t offset = this->m_current_file_size - this->m_remaining_current_file_size;
			std::size_t length = this->calculate_chunk_length();

			return requests::remote::modification_request(
				this->get_path_helper().to_linux_style(this->m_rditr->path(), helpers::style_conversion_class::absolute_format),
				range(offset, length)
			);
		}
		case state_t::committing_child:
			return requests::local::attribute_request(
				this->m_rditr->path(),
				requests::local::attribute_request::change_domain::mark_in_sync
			);
		default:
			throw invalid_state_exception("The state machine has already been completed.");
		}
	}

	void import_operation::transition_on_success() noexcept {
		switch (this->m_state) {
		case state_t::creating:
		{
			this->m_state = state_t::transforming;
			break;
		}
		case state_t::transforming:
		{
			std::error_code ec;

			auto stat = std::filesystem::status(this->get_absolute_path(), ec);

			if (ec || stat.type() != std::filesystem::file_type::regular) {
				// unable to upload
				this->m_state = state_t::committing;
			}
			else {
				this->m_state = state_t::uploading;
				this->m_current_file_size = this->m_remaining_current_file_size = std::filesystem::file_size(this->get_absolute_path(), ec);
				if (ec || this->m_current_file_size == 0) {
					this->m_state = state_t::committing;
				}
			}
			break;
		}
		case state_t::uploading:
		{
			std::size_t length = this->calculate_chunk_length();
			this->m_remaining_current_file_size -= length;

			if (this->m_remaining_current_file_size == 0) {
				this->m_state = state_t::committing;
			}
			break;
		}
		case state_t::committing:
		{
			if (this->m_rditr == this->m_rditr_end) {
				this->m_state = state_t::done;
			}
			else {
				this->m_state = state_t::creating_child;
			}
			break;
		}
		case state_t::creating_child:
		{
			this->m_state = state_t::transforming_child;
			break;
		}
		case state_t::transforming_child:
		{
			std::error_code ec;

			auto stat = this->m_rditr->status(ec);

			if (ec || stat.type() != std::filesystem::file_type::regular) {
				// unable to upload
				this->m_state = state_t::committing_child;
			}
			else {
				this->m_state = state_t::uploading_child;
				this->m_current_file_size = this->m_remaining_current_file_size = this->m_rditr->file_size(ec);
				if (ec || this->m_current_file_size == 0) {
					this->m_state = state_t::committing_child;
				}
			}
			break;
		}
		case state_t::uploading_child:
		{
			std::size_t length = this->calculate_chunk_length();
			this->m_remaining_current_file_size -= length;

			if (this->m_remaining_current_file_size == 0) {
				this->m_state = state_t::committing_child;
			}
			break;
		}
		case state_t::committing_child:
		{
			if (this->m_rditr == this->m_rditr_end || ++this->m_rditr == this->m_rditr_end) {
				this->m_state = state_t::done;
			}
			else {
				this->m_state = state_t::creating_child;
			}
			break;
		}
		case state_t::done:
			break;
		default:
			break;
		}
	}

	bool import_operation::done() const noexcept {
		return this->m_state == state_t::done;
	}

	void import_operation::transition_on_permanent_failure() noexcept {
		this->m_state = state_t::done;
	}

	void import_operation::transition_on_cancelled() noexcept {
		this->m_state = state_t::done;
	}

	hydration_operation::hydration_operation(const std::filesystem::path& syncroot, const std::filesystem::path& relative_path, const range<std::size_t>& range) :
		io_operation(operation_priority::normal, syncroot, relative_path),
		m_state(state_t::downloading),
		m_range(range), m_remaining_length(range.get_length())
	{}

	hydration_operation::request_variant_t hydration_operation::fetch() const {
		switch (this->m_state) {
		case state_t::downloading:
		{
			auto range = this->calculate_range_to_download();
			return requests::remote::hydration_request(
				this->get_path_helper().to_linux_style(this->get_absolute_path(), helpers::style_conversion_class::absolute_format),
				range,
				this->m_adapter
			);
		}
		default:
			throw invalid_state_exception("The state machine has already been completed.");
		}
	}

	void hydration_operation::transition_on_success() noexcept {
		switch (this->m_state) {
		case state_t::downloading:
		{
			auto range = this->calculate_range_to_download();
			this->m_remaining_length -= range.get_length();

			if (this->m_remaining_length == 0) {
				this->m_state = state_t::done;
			}

			break;
		}
		case state_t::done:
			break;
		default:
			break;
		}
	}

	bool hydration_operation::done() const noexcept {
		return this->m_state == state_t::done;
	}

	void hydration_operation::transition_on_permanent_failure() noexcept {
		this->m_state = state_t::done;
	}

	void hydration_operation::transition_on_cancelled() noexcept {
		this->m_state = state_t::done;
	}

	population_operation::population_operation(const std::filesystem::path& syncroot, const std::filesystem::path& relative_path) :
		io_operation(operation_priority::higher, syncroot, relative_path),
		m_state(state_t::enumerating)
	{}

	population_operation::request_variant_t population_operation::fetch() const {
		switch (this->m_state) {
		case state_t::enumerating:
			return requests::remote::population_request(
				this->get_path_helper().to_linux_style(this->get_absolute_path(), helpers::style_conversion_class::absolute_format),
				this->m_adapter
			);
		default:
			throw invalid_state_exception("The state machine has already been completed.");
		}
	}

	void population_operation::transition_on_success() noexcept {
		switch (this->m_state) {
		case state_t::enumerating:
		{
			this->m_state = state_t::done;
			break;
		}
		case state_t::done:
			break;
		default:
			break;
		}
	}

	bool population_operation::done() const noexcept {
		return this->m_state == state_t::done;
	}

	void population_operation::transition_on_permanent_failure() noexcept {
		this->m_state = state_t::done;
	}

	void population_operation::transition_on_cancelled() noexcept {
		this->m_state = state_t::done;
	}

	attribute_operation::attribute_operation(const std::filesystem::path& syncroot, const std::filesystem::path& relative_path) :
		io_operation(operation_priority::immediate, syncroot, relative_path),
		m_state(state_t::applying)
	{
		if (!shell::filesystem::cloud_filter_placeholder::is_placeholder(this->get_absolute_path().wstring())) {
			this->m_state = state_t::done;
			this->mark_as_ignored();
			return;
		}

		shell::filesystem::cloud_filter_placeholder placeholder(this->get_absolute_path().wstring());
		
		switch (placeholder.get_pin_state()) {
		case ::CF_PIN_STATE::CF_PIN_STATE_PINNED:
			this->m_reason = operation_reason::pinned;
			break;
		case ::CF_PIN_STATE::CF_PIN_STATE_UNPINNED:
			this->m_reason = operation_reason::unpinned;
			break;
		default:
			this->m_state = state_t::done;
			this->mark_as_ignored();
			return;
		};

		if (placeholder.get_type() != shell::filesystem::placeholder_type::file) {
			this->m_state = state_t::done;
			this->mark_as_ignored();
			return;
		}
	}

	attribute_operation::request_variant_t attribute_operation::fetch() const {
		switch (this->m_state) {
		case state_t::applying:
		{
			switch (this->m_reason) {
				case operation_reason::pinned:
					return requests::local::hydration_triggering_request(this->get_absolute_path());
				case operation_reason::unpinned:
					return requests::local::dehydration_request(this->get_absolute_path());
				default:
					break;
			}
			break;
		}
		case state_t::committing:
			return requests::local::attribute_request(
				this->get_absolute_path(),
				requests::local::attribute_request::change_domain::mark_in_sync
			);
		default:
			throw invalid_state_exception("The state machine has already been completed.");
		}
	}

	void attribute_operation::transition_on_success() noexcept {
		switch (this->m_state) {
		case state_t::applying:
			this->m_state = state_t::committing;
			break;
		case state_t::committing:
			this->m_state = state_t::done;
			break;
		case state_t::done:
			break;
		default:
			break;
		}
	}

	bool attribute_operation::done() const noexcept {
		return this->m_state == state_t::done;
	};

	void attribute_operation::transition_on_permanent_failure() noexcept {
		this->m_state = state_t::done;
	}

	void attribute_operation::transition_on_cancelled() noexcept {
		this->m_state = state_t::done;
	}
}