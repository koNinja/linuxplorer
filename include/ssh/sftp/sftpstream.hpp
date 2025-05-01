#ifndef SFTPSTREAM_HPP
#define SFTPSTREAM_HPP

#include <streambuf>
#include <iosfwd>
#include <iostream>
#include <libssh2_sftp.h>

namespace linuxplorer::ssh::sftp {
	constexpr std::streamsize sftpbuf_default_buffer_size = 0x1000;

	class sftpbuf : public std::basic_streambuf<char> {
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
		sftpbuf(::LIBSSH2_SFTP* sftp, ::LIBSSH2_SFTP_HANDLE* handle, std::ios_base::openmode used_buffer = std::ios_base::in | std::ios_base::out, std::streamsize buffer_size = sftpbuf_default_buffer_size);	
		sftpbuf(sftpbuf&& right);
	};

	class isftpstream : public std::basic_istream<char> {
	protected:
		::LIBSSH2_SFTP_HANDLE* m_handle;
		std::unique_ptr<sftpbuf> m_buffer;
	public:
		explicit isftpstream(::LIBSSH2_SFTP* sftp, std::string_view s, std::ios_base::openmode mode = std::ios_base::in, long sftp_posix_permissions_created = LIBSSH2_SFTP_S_IFREG | LIBSSH2_SFTP_S_IRUSR | LIBSSH2_SFTP_S_IWUSR | LIBSSH2_SFTP_S_IXUSR);
		explicit isftpstream(const isftpstream&) = delete;
		explicit isftpstream(isftpstream&& right);

		virtual ~isftpstream();
	};
}

#endif // SFTPSTREAM_HPP