#ifndef SFTPSTREAM_HPP
#define SFTPSTREAM_HPP

#include <streambuf>
#include <iosfwd>
#include <libssh2_sftp.h>

namespace linuxplorer::ssh::sftp {
	constexpr std::streamsize sftpbuf_default_buffer_size = 0x1000;

	enum class sftpbuf_used_buffer {
		in,
		out,
		inout
	};

	class sftpbuf : public std::streambuf {
		using base = std::streambuf;

		std::unique_ptr<char_type[]> m_inbuf;
		std::unique_ptr<char_type[]> m_outbuf;
		std::streamsize m_inbufsize;
		std::streamsize m_outbufsize;

		pos_type m_in_seek;
		pos_type m_out_seek;
	protected:
		::LIBSSH2_SFTP* m_sftp;
		::LIBSSH2_SFTP_HANDLE* m_handle;

		virtual std::streamsize xsgetn(char_type* out, std::streamsize length) override;
		virtual int_type underflow() override;

		virtual std::streamsize xsputn(const char_type* in, std::streamsize length) override;
		virtual int_type overflow(int_type ch = traits_type::eof()) override;
		virtual int sync() override;

		virtual pos_type seekoff(off_type off, std::ios_base::seekdir dir, std::ios_base::openmode which = std::ios_base::in | std::ios_base::out) override;
		virtual pos_type seekpos(pos_type pos, std::ios_base::openmode which = std::ios_base::in | std::ios_base::out) override;
	public:
		sftpbuf(::LIBSSH2_SFTP* sftp, ::LIBSSH2_SFTP_HANDLE* handle, sftpbuf_used_buffer used_buffer = sftpbuf_used_buffer::inout, std::streamsize buffer_size = sftpbuf_default_buffer_size);
	};

	
}

#endif // SFTPSTREAM_HPP