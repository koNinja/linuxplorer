#include <ssh/sftp/io/sftpstream.hpp>
#include <ssh/ssh_exception.hpp>
#include <util/charset/multibyte_wide_compat_helper.hpp>

namespace linuxplorer::ssh::sftp::io {
	sftpbuf::sftpbuf(sftpbuf&& rhs) noexcept : m_sftp(std::move(rhs.m_sftp)), m_handle(std::move(rhs.m_handle)) {
		this->m_in_seek = rhs.m_in_seek;
		this->m_out_seek = rhs.m_out_seek;
		this->m_inbufsize = rhs.m_inbufsize;
		this->m_outbufsize = rhs.m_outbufsize;
		this->m_inbuf = std::move(rhs.m_inbuf);
		this->m_outbuf = std::move(rhs.m_outbuf);
	}

	sftpbuf::sftpbuf(const sftp_session& sftp, sftp_handle&& handle, std::ios_base::openmode used_buffer, std::streamsize buffer_size) : m_sftp(sftp), m_handle(std::move(handle)) {
		this->m_inbuf = nullptr;
		this->m_outbuf = nullptr;
		this->m_inbufsize = 0;
		this->m_outbufsize = 0;
		this->m_in_seek = 0;
		this->m_out_seek = 0;

		if (buffer_size <= 0) throw ssh_invalid_operation_exception("Invalid buffer size.");

		if (used_buffer & std::ios_base::in) {
			this->m_inbufsize = buffer_size;
			this->m_inbuf = std::make_unique<sftpbuf::char_type[]>(this->m_inbufsize);
		}
		if (used_buffer & std::ios_base::out) {
			this->m_outbufsize = buffer_size;
			this->m_outbuf = std::make_unique<sftpbuf::char_type[]>(this->m_outbufsize);
		}

		::libssh2_sftp_seek64(this->m_handle.get_handle(), 0);

		this->setg(this->m_inbuf.get(), this->m_inbuf.get(), this->m_inbuf.get());
		this->setp(this->m_outbuf.get(), this->m_outbuf.get(), this->m_outbuf.get() + this->m_outbufsize);
	}

	std::streamsize sftpbuf::xsgetn(sftpbuf::char_type* out, std::streamsize length) {
		std::streamsize bytes_copied = 0;
		while (length > bytes_copied) {
			std::streamsize bytes_required_to_copy = length - bytes_copied;
			std::streamsize bytes_readable_from_buffer = this->egptr() - this->gptr();

			if (bytes_readable_from_buffer <= 0) {
				if (sftpbuf::traits_type::eq_int_type(this->underflow(), sftpbuf::traits_type::eof())) break;
				else continue;
			}

			std::streamsize actual_bytes_to_copy = std::min(bytes_readable_from_buffer, bytes_required_to_copy);

			sftpbuf::traits_type::copy(out + bytes_copied, this->gptr(), static_cast<std::size_t>(actual_bytes_to_copy));
			this->gbump(static_cast<int>(actual_bytes_to_copy));

			bytes_copied += actual_bytes_to_copy;
		}

		return bytes_copied;
	}

	sftpbuf::int_type sftpbuf::underflow() {
		if (!this->m_inbuf) {
			return sftpbuf::traits_type::eof();
		}

		auto bytes_read = ::libssh2_sftp_read(this->m_handle.get_handle(), this->m_inbuf.get(), this->m_inbufsize);
		if (bytes_read < 0) {
			throw ssh_libssh2_sftp_exception(std::error_code(bytes_read, libssh2_sftp_category()), "Failed to read data.");
		}
		
		if (bytes_read == 0) {
			this->setg(this->m_inbuf.get(), this->m_inbuf.get(), this->m_inbuf.get());
			return sftpbuf::traits_type::eof();
		}
		else {
			this->setg(this->m_inbuf.get(), this->m_inbuf.get(), this->m_inbuf.get() + bytes_read);
			this->m_in_seek += bytes_read;
			return sftpbuf::traits_type::to_int_type(*this->gptr());
		}
	}

	std::streamsize sftpbuf::xsputn(const sftpbuf::char_type* in, std::streamsize length) {
		std::streamsize bytes_written = 0;
		while (length > bytes_written) {
			std::streamsize bytes_required_to_write = length - bytes_written;
			std::streamsize bytes_writable_to_buffer = this->epptr() - this->pptr();
			if (bytes_writable_to_buffer <= 0) {
				if (sftpbuf::traits_type::eq_int_type(this->overflow(), sftpbuf::traits_type::eof())) break;
				else continue;
			}

			std::streamsize actual_bytes_to_write = std::min(bytes_writable_to_buffer, bytes_required_to_write);

			sftpbuf::traits_type::copy(this->pptr(), in + bytes_written, actual_bytes_to_write);
			this->pbump(static_cast<int>(actual_bytes_to_write));

			bytes_written += actual_bytes_to_write;
		}

		return bytes_written;
	}

	sftpbuf::int_type sftpbuf::overflow(sftpbuf::int_type ch) {
		if (!this->m_outbuf) {
			return sftpbuf::traits_type::eof();
		}

		std::streamsize total_bytes_written = 0;
		std::streamsize bytes_written = 0;
		std::streamsize bytes_to_write = this->pptr() - this->pbase();
		do {
			bytes_written = ::libssh2_sftp_write(this->m_handle.get_handle(), this->m_outbuf.get() + total_bytes_written, bytes_to_write);
			if (bytes_written < 0) {
				throw ssh_libssh2_exception(std::error_code(bytes_written, libssh2_sftp_category()), "Failed to write data.");
			}

			bytes_to_write -= bytes_written;
			total_bytes_written += bytes_written;
		} while (bytes_written > 0 && bytes_to_write > 0);
		
		this->m_out_seek += total_bytes_written;
		this->setp(this->m_outbuf.get(), this->m_outbuf.get(), this->m_outbuf.get() + this->m_outbufsize);
		
		if (!sftpbuf::traits_type::eq_int_type(ch, sftpbuf::traits_type::eof())) {
			sftpbuf::char_type c = sftpbuf::traits_type::to_char_type(ch);
			*this->pptr() = c;
			this->pbump(1);
			return sftpbuf::traits_type::to_int_type(ch);
		}

		return sftpbuf::traits_type::not_eof(ch);
	}

	int sftpbuf::sync() {
		if (this->m_outbuf && this->overflow() == traits_type::eof()) {
			return -1;
		}
		return 0;
	}

	sftpbuf::pos_type sftpbuf::seekoff(sftpbuf::off_type off, std::ios_base::seekdir dir, std::ios_base::openmode which) {
		sftpbuf::pos_type abs_in_pos = 0;
		sftpbuf::pos_type abs_out_pos = 0;

		switch (dir) {
		case std::ios_base::beg:
		{
			if (which & std::ios_base::in) abs_in_pos = off;
			if (which & std::ios_base::out) abs_out_pos = off;
			break;
		}
		case std::ios_base::cur:
		{
			if (which & std::ios_base::in) abs_in_pos = this->m_in_seek + off;
			if (which & std::ios_base::out) abs_out_pos = this->m_out_seek + off;
			break;
		}
		case std::ios_base::end:
		{
			::LIBSSH2_SFTP_ATTRIBUTES attr;
			int rc = ::libssh2_sftp_fstat_ex(this->m_handle.get_handle(), &attr, 0);
			if (rc < 0) {
				throw ssh_libssh2_sftp_exception(std::error_code(rc, libssh2_sftp_category()), "Failed to get attributes on an SFTP file handle.");
			}
			
			if (which & std::ios_base::in) abs_in_pos = attr.filesize + off;
			if (which & std::ios_base::out) abs_out_pos = attr.filesize + off;
			break;
		}
		default:
			throw std::invalid_argument("Invalid seeking direction type.");
		}

		if (which & std::ios_base::in) {
			this->seekpos(abs_in_pos, std::ios_base::in);
			return abs_in_pos;
		}
		else if (which & std::ios_base::out) {
			this->seekpos(abs_out_pos, std::ios_base::out);
			return abs_out_pos;
		}
		else {
			return 0;
		}
	}

	sftpbuf::pos_type sftpbuf::seekpos(sftpbuf::pos_type pos, std::ios_base::openmode which) {
		if (which & std::ios_base::in) {
			this->m_in_seek = pos;
			this->setg(this->m_inbuf.get(), this->m_inbuf.get(), this->m_inbuf.get());
		}

		if (which & std::ios_base::out) {
			this->m_out_seek = pos;
			this->setp(this->m_outbuf.get(), this->m_outbuf.get(), this->m_outbuf.get() + this->m_outbufsize);
		}

		::libssh2_sftp_seek64(this->m_handle.get_handle(), pos);

		return pos;
	}

	isftpstream::isftpstream(isftpstream&& right) : std::basic_istream<char>(nullptr) {
		this->m_buffer = std::move(right.m_buffer);
		this->init(this->m_buffer.get());
	}

	isftpstream::isftpstream(const sftp_session& session, std::wstring_view s, std::ios_base::openmode mode) : std::basic_istream<char>(nullptr)
	{
		unsigned long flags = 0;

		if (mode & std::ios_base::trunc) {
			flags |= LIBSSH2_FXF_TRUNC;
		}
		if (mode & std::ios_base::in) {
			flags |= LIBSSH2_FXF_READ;
		}
		if (mode & std::ios_base::out) {
			flags |= LIBSSH2_FXF_WRITE;
		}
		
		auto sftp = session.get_session();

		auto path = util::charset::multibyte_wide_compat_helper::convert_wide_to_multibyte(s);

		auto handle = ::libssh2_sftp_open_ex(sftp, path.c_str(), path.length() * sizeof(char), flags, LIBSSH2_FXF_READ, LIBSSH2_SFTP_OPENFILE);
		if (!handle) {
			throw ssh_libssh2_sftp_exception(std::error_code(session.get_last_errno(), libssh2_sftp_category()), "Failed to open file.");
		}

		this->m_buffer = std::make_unique<sftpbuf>(session, std::move(sftp_handle(session, handle)), std::ios_base::in, sftpbuf_default_buffer_size);
		
		if (mode & std::ios_base::app) {
			this->m_buffer->pubseekoff(0, std::ios_base::end, std::ios_base::out);
		}
		if (mode & std::ios_base::ate) {
			this->m_buffer->pubseekoff(0, std::ios_base::end);
		}

		this->init(this->m_buffer.get());
	}

	osftpstream::osftpstream(const sftp_session& session, std::wstring_view s, std::ios_base::openmode mode, long permissions_created) : std::basic_ostream<char>(nullptr)
	{
		unsigned long flags = LIBSSH2_FXF_CREAT;

		if (mode & std::ios_base::trunc) {
			flags |= LIBSSH2_FXF_TRUNC;
		}
		if (mode & std::ios_base::in) {
			flags |= LIBSSH2_FXF_READ;
		}
		if (mode & std::ios_base::out) {
			flags |= LIBSSH2_FXF_WRITE;
		}
		
		auto sftp = session.get_session();

		auto path = util::charset::multibyte_wide_compat_helper::convert_wide_to_multibyte(s);

		auto handle = ::libssh2_sftp_open_ex(sftp, path.c_str(), path.length() * sizeof(char), flags, permissions_created, LIBSSH2_SFTP_OPENFILE);
		if (!handle) {
			throw ssh_libssh2_sftp_exception(std::error_code(session.get_last_errno(), libssh2_sftp_category()), "Failed to open file.");
		}

		this->m_buffer = std::make_unique<sftpbuf>(session,  std::move(sftp_handle(session, handle)), std::ios_base::out, sftpbuf_default_buffer_size);

		if (mode & std::ios_base::app) {
			this->m_buffer->pubseekoff(0, std::ios_base::end, std::ios_base::out);
		}
		if (mode & std::ios_base::ate) {
			this->m_buffer->pubseekoff(0, std::ios_base::end);
		}

		this->init(this->m_buffer.get());
	}

	osftpstream::osftpstream(osftpstream&& right) : std::basic_ostream<char>(nullptr) {
		this->m_buffer = std::move(right.m_buffer);
		this->init(this->m_buffer.get());
	}
}