#define NOMINMAX

#include <ssh/sftp/sftpstream.hpp>
#include <ssh/ssh_exception.hpp>

namespace linuxplorer::ssh::sftp {
	sftpbuf::sftpbuf(::LIBSSH2_SFTP* sftp, ::LIBSSH2_SFTP_HANDLE* handle, sftpbuf_used_buffer used_buffer, std::streamsize buffer_size) {
		this->m_sftp = sftp;
		this->m_handle = handle;
		this->m_inbuf = nullptr;
		this->m_outbuf = nullptr;
		this->m_inbufsize = 0;
		this->m_outbufsize = 0;
		this->m_in_seek = 0;
		this->m_out_seek = 0;

		if (buffer_size < 0) throw std::invalid_argument("Invalid buffer size.");

		switch (used_buffer) {
		case sftpbuf_used_buffer::inout:
		case sftpbuf_used_buffer::in:
			this->m_inbufsize = buffer_size;
			this->m_inbuf = std::make_unique<sftpbuf::char_type[]>(this->m_inbufsize);
			if (used_buffer != linuxplorer::ssh::sftp::sftpbuf_used_buffer::inout) break;

		case sftpbuf_used_buffer::out:
			this->m_outbufsize = buffer_size;
			this->m_outbuf = std::make_unique<sftpbuf::char_type[]>(this->m_outbufsize);
			break;

		default:
			break;
		}

		::libssh2_sftp_seek64(this->m_handle, 0);

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

		::libssh2_sftp_seek64(this->m_handle, this->m_in_seek);
		auto bytes_read = libssh2_sftp_read(this->m_handle, this->m_inbuf.get(), this->m_inbufsize);
		if (bytes_read < 0) {
			throw ssh_libssh2_sftp_exception(bytes_read, "Failed to read data.");
		}
		
		sftpbuf::int_type result = 0;
		if (bytes_read == 0) {
			result = sftpbuf::traits_type::eof();
			this->setg(this->m_inbuf.get(), this->m_inbuf.get(), this->m_inbuf.get());
		}
		else {
			this->setg(this->m_inbuf.get(), this->m_inbuf.get(), this->m_inbuf.get() + bytes_read);
			this->m_in_seek += bytes_read;
			result = *this->gptr();
		}
		
		return result;
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

		sftpbuf::int_type result = sftpbuf::traits_type::not_eof(ch);
		::libssh2_sftp_seek64(this->m_handle, this->m_out_seek);

		auto bytes_written = ::libssh2_sftp_write(this->m_handle, this->m_outbuf.get(), this->pptr() - this->pbase());
		if (bytes_written < 0) {
			throw ssh_libssh2_exception(bytes_written, "Failed to write data.");
		}

		this->m_out_seek += bytes_written;
		this->setp(this->m_outbuf.get(), this->m_outbuf.get(), this->m_outbuf.get() + this->m_outbufsize);

		if (!sftpbuf::traits_type::eq_int_type(ch, sftpbuf::traits_type::eof())) {
			sftpbuf::char_type c = sftpbuf::traits_type::to_char_type(ch);

			auto bytes_append = ::libssh2_sftp_write(this->m_handle, &c, 1);
			if (bytes_append < 0) {
				throw ssh_libssh2_exception(bytes_append, "Failed to append the parameter data.");
			}

			this->m_out_seek += 1;

			result = ch;
		}

		return result;
	}
	

	int sftpbuf::sync() {
		auto o = this->overflow();
		auto u = this->underflow();

		return -(sftpbuf::traits_type::eq_int_type(o, sftpbuf::traits_type::eof()) || sftpbuf::traits_type::eq_int_type(o, sftpbuf::traits_type::eof()));
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
			int rc = libssh2_sftp_fstat(this->m_handle, &attr);
			if (rc < 0) {
				throw ssh_libssh2_sftp_exception(rc, "Failed to get attributes on an SFTP file handle.");
			}
			
			if (which & std::ios_base::in) abs_in_pos = attr.filesize - off;
			if (which & std::ios_base::out) abs_out_pos = attr.filesize - off;
			break;
		}
		default:
			throw std::invalid_argument("Invalid seeking direction type.");
		}

		if (which & std::ios_base::in) this->seekpos(abs_in_pos, std::ios_base::in);
		if (which & std::ios_base::out) this->seekpos(abs_out_pos, std::ios_base::out);

		return abs_in_pos + abs_out_pos;
	}

	sftpbuf::pos_type sftpbuf::seekpos(sftpbuf::pos_type pos, std::ios_base::openmode which) {
		if (which & std::ios_base::in) {
			this->m_in_seek = pos;
		}

		if (which & std::ios_base::out) {
			this->m_out_seek = pos;
		}

		return pos;
	}
}