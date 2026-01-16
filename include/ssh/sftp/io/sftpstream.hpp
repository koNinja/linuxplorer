#ifndef LINUXPLORER_SFTPSTREAM_HPP_
#define LINUXPLORER_SFTPSTREAM_HPP_

#include <ssh/sshfwd.hpp>
#include <ssh/sftp/sftp_session.hpp>
#include <streambuf>
#include <iosfwd>

namespace linuxplorer::ssh::sftp::io {
	constexpr std::streamsize sftpbuf_default_buffer_size = 262144;	// 256 KiB

	class LINUXPLORER_SSH_API sftpbuf : public std::basic_streambuf<char> {
		std::unique_ptr<char_type[]> m_inbuf;
		std::unique_ptr<char_type[]> m_outbuf;
		std::streamsize m_inbufsize;
		std::streamsize m_outbufsize;

		pos_type m_in_seek;
		pos_type m_out_seek;
	protected:
		sftp_session m_sftp;
		sftp_handle m_handle;

		virtual std::streamsize xsgetn(char_type* out, std::streamsize length) override;
		virtual int_type underflow() override;

		virtual std::streamsize xsputn(const char_type* in, std::streamsize length) override;
		virtual int_type overflow(int_type ch = traits_type::eof()) override;
		virtual int sync() override;

		virtual pos_type seekoff(off_type off, std::ios_base::seekdir dir, std::ios_base::openmode which = std::ios_base::in | std::ios_base::out) override;
		virtual pos_type seekpos(pos_type pos, std::ios_base::openmode which = std::ios_base::in | std::ios_base::out) override;
	public:
		sftpbuf(const sftp_session& sftp, sftp_handle&& handle, std::ios_base::openmode used_buffer = std::ios_base::in | std::ios_base::out, std::streamsize buffer_size = sftpbuf_default_buffer_size);	
		sftpbuf(sftpbuf&& rhs) noexcept;

		virtual ~sftpbuf() = default;
	};

	constexpr long sftp_default_permissions_created = LIBSSH2_SFTP_S_IFREG | LIBSSH2_SFTP_S_IRUSR | LIBSSH2_SFTP_S_IWUSR | LIBSSH2_SFTP_S_IRGRP | LIBSSH2_SFTP_S_IROTH;

	class LINUXPLORER_SSH_API isftpstream : public std::basic_istream<char> {
	protected:
		std::unique_ptr<sftpbuf> m_buffer;
	public:
		explicit isftpstream(const sftp_session& session, std::wstring_view s, std::ios_base::openmode mode = std::ios_base::in);
		explicit isftpstream(const isftpstream&) = delete;
		explicit isftpstream(isftpstream&& rhs);

		virtual ~isftpstream() = default;
	};

	class LINUXPLORER_SSH_API osftpstream : public std::basic_ostream<char> {
	protected:
		std::unique_ptr<sftpbuf> m_buffer;
	public:
		explicit osftpstream(const sftp_session& session, std::wstring_view s, std::ios_base::openmode mode = std::ios_base::out, long permissions_created = sftp_default_permissions_created);
		explicit osftpstream(const osftpstream&) = delete;
		explicit osftpstream(osftpstream&& rhs);

		virtual ~osftpstream() = default;
	};
}

#endif // LINUXPLORER_SFTPSTREAM_HPP_