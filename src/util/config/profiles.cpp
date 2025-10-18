#include <util/config/profiles.hpp>

#include <util/charset/multibyte_wide_compat_helper.hpp>
#include <nlohmann/json.hpp>
#include <nlohmann/byte_container_with_subtype.hpp>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <windows.h>
#include <dpapi.h>

/*
	The 'credential' value in 'config.json' contains AES-encrypted credentials and the necessary data for decryption.
	It is saved as a byte sequence in base64.
	The format of the byte sequence of the credentials is described below.

	After base64 decoding, the byte sequence has the following structure (array of unsigned char):
	[4 byte: encrypted key length]
	[1 byte: IV length]
	[N bytes: DPAPI-encrypted AES key]
	[M bytes: AES IV]
	[remaining bytes: AES-encrypted credential JSON data]
	
	Details:
	- encrypted key length: bytes of encrypted-key
	- encrypted key: the DPAPI-encrypted-key required to decrypt encrypted-credential-data
	- IV - initialization vector
	- encrypted credential data: the AES-encrypted credential data. It is a plain JSON text data.

	Sample of credential data:
	{
		"addr": "xxx.xxx.xxx.xxx",
		"user": "<username>",
		"password": "<password>"
	}
*/

namespace linuxplorer::util::config {
	const char* openssl_category::name() const noexcept {
		return "openssl_category";
	}
	std::string openssl_category::message(int errc) const {
		constexpr std::size_t static_buffer_length = 1024;
		char buf[static_buffer_length];

		::ERR_error_string_n(errc, buf, static_buffer_length);
		return buf;
	}

	credential::~credential() noexcept {
		::RtlSecureZeroMemory(this->m_host.data(), this->m_host.size() * sizeof(decltype(this->m_host)::value_type));
		::RtlSecureZeroMemory(this->m_username.data(), this->m_username.size() * sizeof(decltype(this->m_username)::value_type));
		::RtlSecureZeroMemory(this->m_password.data(), this->m_password.size() * sizeof(decltype(this->m_password)::value_type));
	}

	profile_config::profile_config() {}

	void profile_config::hlocal_delete_t::operator()(void* ptr) {
		::LocalFree(ptr);
	}

	void profile_config::decode_from_base64(std::string_view base64_data, std::unique_ptr<std::byte[]>& decoded, std::size_t& decoded_length) {
		std::size_t base64_data_length = base64_data.size() * sizeof(char);

		std::size_t padding = 0;
		if (base64_data[base64_data_length / sizeof(char) - 1] == '=') // last char is '='
			padding++;
		if (base64_data[base64_data_length / sizeof(char) - 2] == '=') // last second char is '='
			padding++;
		
		std::size_t decode_length = (base64_data_length * 3) / 4 - padding;
		decoded = std::make_unique<std::byte[]>(decode_length);
		::BIO* bio = ::BIO_new_mem_buf(base64_data.data(), base64_data_length);
		::BIO* b64_filter = ::BIO_new_ex(nullptr, ::BIO_f_base64());
		bio = ::BIO_push(b64_filter, bio);

		::BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // Don't use newlines to flush buffer
		std::size_t bytes_read = ::BIO_read(bio, decoded.get(), decode_length);
		
		if (bytes_read == 0 || bytes_read != decode_length) {
			throw cryptographic_exception(std::error_code(::ERR_peek_last_error(), openssl_category()), "Failed to read the BIO data fully.");
		}
		::BIO_free_all(bio);

		decoded_length = decode_length;
	}

	void profile_config::divide_decoded_raw_cred_into_elements(
		const std::byte* decoded_raw_cred,
		std::size_t decoded_raw_cred_length,
		const std::byte** encrypted_key_head,
		std::size_t* encrypted_key_length,
		const std::byte** iv_head,
		std::size_t* iv_length,
		const std::byte** encrypted_cred_data_head,
		std::size_t* encrypted_cred_data_length
	) {
		const std::byte* ret_encrypted_key_head;
		std::size_t ret_encrypted_key_length = 0;
		const std::byte* ret_iv_head;
		std::size_t ret_iv_length;
		const std::byte* ret_encrypted_cred_data_head;
		std::size_t ret_encrypted_cred_data_length;

		std::size_t pos = 0;;

		for (int i = 0; i < 4; i++, pos++) {
			ret_encrypted_key_length |= static_cast<std::size_t>(decoded_raw_cred[i]) << ((3 - i) * 4);
		}

		ret_iv_length = std::to_integer<std::size_t>(*(decoded_raw_cred + pos));
		pos++;

		ret_encrypted_key_head = decoded_raw_cred + pos;
		pos += ret_encrypted_key_length;

		ret_iv_head = decoded_raw_cred + pos;
		pos += ret_iv_length;

		ret_encrypted_cred_data_head = decoded_raw_cred + pos;
		ret_encrypted_cred_data_length = decoded_raw_cred_length - pos;

		if (encrypted_key_head) {
			*encrypted_key_head = ret_encrypted_key_head;
		}
		if (encrypted_key_length) {
			*encrypted_key_length = ret_encrypted_key_length;
		}
		if (iv_head) {
			*iv_head = ret_iv_head;
		}
		if (iv_length) {
			*iv_length = ret_iv_length;
		}
		if (encrypted_cred_data_head) {
			*encrypted_cred_data_head = ret_encrypted_cred_data_head;
		}
		if (encrypted_cred_data_length) {
			*encrypted_cred_data_length = ret_encrypted_cred_data_length;
		}
	}

	void profile_config::decrypt_key(const std::byte* encrypted_key, std::size_t encrypted_key_length, unique_hlocal_ptr_t<std::byte>& decrypted_key, std::size_t& decrypted_key_length) {
		::DATA_BLOB encrypted_blob, decrypted_blob;
		encrypted_blob.pbData = to_byte_ptr(const_cast<std::byte*>(encrypted_key));
		encrypted_blob.cbData = encrypted_key_length;

		bool succeeded = ::CryptUnprotectData(&encrypted_blob, nullptr, nullptr, nullptr, nullptr, 0, &decrypted_blob);
		if (!succeeded) {
			std::error_code ec(::GetLastError(), std::system_category());
			throw config_system_error(ec, "Failed to decrypt the AES-encrypted-key.");
		}

		decrypted_key.reset(to_byte_ptr(decrypted_blob.pbData));
		decrypted_key_length = decrypted_blob.cbData;
	}

	void profile_config::decrypt_cred_data(
		const std::byte* encrypted_cred_data,
		std::size_t encrypted_cred_data_length,
		const std::byte* key,
		std::size_t /* key_length */,
		const std::byte* iv,
		std::size_t /* iv_length */,
		std::unique_ptr<std::byte[]>& decrypted_cred_data,
		std::size_t& decrypted_cred_data_length
	) {
		using unique_chipher_ctx_ptr_t = std::unique_ptr<::EVP_CIPHER_CTX, decltype([](::EVP_CIPHER_CTX* ptr) -> void { ::EVP_CIPHER_CTX_free(ptr); })>;

		unique_chipher_ctx_ptr_t ctx(::EVP_CIPHER_CTX_new());
		if (!ctx) {
			throw cryptographic_exception(std::error_code(::ERR_peek_last_error(), openssl_category()), "Failed to initialize the OpenSSL cipher context.");
		}

		const ::EVP_CIPHER* cipher_suite;
		if constexpr (profile_config::bytes_key_length == 32) {
			cipher_suite = ::EVP_aes_256_cbc();
		}
		else if constexpr (profile_config::bytes_key_length == 24) {
			cipher_suite = ::EVP_aes_192_cbc();
		}
		else if constexpr (profile_config::bytes_key_length == 16) {
			cipher_suite = ::EVP_aes_128_cbc();
		}
		else {
			static_assert(
				profile_config::bytes_key_length == 32 || profile_config::bytes_key_length == 24 || profile_config::bytes_key_length == 16,
				"Invalid AES key length in bytes."
			);
		}

		if (!cipher_suite) {
			throw cryptographic_exception(std::error_code(::ERR_peek_last_error(), openssl_category()),  "Failed to get cipher suite.");
		}

		int rc = ::EVP_DecryptInit(ctx.get(), cipher_suite, to_byte_ptr(key), to_byte_ptr(iv));
		if (rc == 0) {
			throw cryptographic_exception(std::error_code(::ERR_peek_last_error(), openssl_category()), "Failed to initialize the OpenSSL cipher context.");
		}

		decrypted_cred_data = std::make_unique<std::byte[]>(encrypted_cred_data_length);
		int decrypted_cred_multiple_length;

		rc = ::EVP_DecryptUpdate(ctx.get(), to_byte_ptr(decrypted_cred_data.get()), &decrypted_cred_multiple_length, to_byte_ptr(encrypted_cred_data), encrypted_cred_data_length);
		if (rc == 0) {
			throw cryptographic_exception(std::error_code(::ERR_peek_last_error(), openssl_category()), "Failed to decrypt certification data.");
		}

		int decrypted_cred_remaining_length;
		rc = ::EVP_DecryptFinal_ex(ctx.get(), to_byte_ptr(decrypted_cred_data.get() + decrypted_cred_multiple_length), &decrypted_cred_remaining_length);
		if (rc == 0) {
			throw cryptographic_exception(std::error_code(::ERR_peek_last_error(), openssl_category()), "Padding process was failed.");
		}

		decrypted_cred_data_length = decrypted_cred_multiple_length + decrypted_cred_remaining_length;
	}

	credential profile_config::deserialize_cred_info_from_bin_to_obj(const std::byte* cred_data, std::size_t /* cred_data_length */) {
		std::string text_json = reinterpret_cast<const char*>(to_byte_ptr(cred_data));

		using charset_helper = util::charset::multibyte_wide_compat_helper;
		auto json = nlohmann::json::parse(text_json);
		auto host = charset_helper::convert_multibyte_to_wide(json["addr"].get<std::string>());
		auto user = charset_helper::convert_multibyte_to_wide(json["user"].get<std::string>());
		auto passwd = charset_helper::convert_multibyte_to_wide(json["password"].get<std::string>());

		return credential(host, user, passwd);
	}

	void profile_config::serialize_cred_info_from_obj_to_bin(const credential& data, std::unique_ptr<std::byte[]>& bin, std::size_t& bin_length) {
		using charset_helper = util::charset::multibyte_wide_compat_helper;

		nlohmann::json json = {
			{ "addr", charset_helper::convert_wide_to_multibyte(data.get_host()) },
			{ "user", charset_helper::convert_wide_to_multibyte(data.get_username()) },
			{ "password", charset_helper::convert_wide_to_multibyte(data.get_password()) }
		};
		
		auto text = json.dump();

		bin_length = text.size();
		bin = std::make_unique<std::byte[]>(bin_length);

		std::transform(text.begin(), text.end(), bin.get(), [](char ch) { return static_cast<std::byte>(ch); });
	}

	void profile_config::encrypt_cred_data(
		const std::byte* cred_data,
		std::size_t cred_data_length,
		std::unique_ptr<std::byte[]>& key,
		std::size_t& key_length,
		std::unique_ptr<std::byte[]>& iv,
		std::size_t& iv_length,
		std::unique_ptr<std::byte[]>& encrypted_cred_data,
		std::size_t& encrypted_cred_data_length
	) {
		using unique_chipher_ctx_ptr_t = std::unique_ptr<::EVP_CIPHER_CTX, decltype([](::EVP_CIPHER_CTX* ptr) -> void { ::EVP_CIPHER_CTX_free(ptr); })>;

		unique_chipher_ctx_ptr_t ctx(::EVP_CIPHER_CTX_new());
		if (!ctx) {
			throw cryptographic_exception(std::error_code(::ERR_peek_last_error(), openssl_category()), "Failed to initialize the OpenSSL cipher context.");
		}

		const ::EVP_CIPHER* cipher_suite;
		if constexpr (profile_config::bytes_key_length == 32) {
			cipher_suite = ::EVP_aes_256_cbc();
		}
		else if constexpr (profile_config::bytes_key_length == 24) {
			cipher_suite = ::EVP_aes_192_cbc();
		}
		else if constexpr (profile_config::bytes_key_length == 16) {
			cipher_suite = ::EVP_aes_128_cbc();
		}
		else {
			static_assert(
				profile_config::bytes_key_length == 32 || profile_config::bytes_key_length == 192 || profile_config::bytes_key_length == 128,
				"Invalid AES key length in bytes."
			);
		}

		if (!cipher_suite) {
			throw cryptographic_exception(std::error_code(::ERR_peek_last_error(), openssl_category()), "Failed to get cipher suite.");
		}

		key = std::make_unique<std::byte[]>(bytes_key_length);
		key_length = bytes_key_length;
		iv = std::make_unique<std::byte[]>(bytes_iv_length);
		iv_length = bytes_iv_length;

		if (::RAND_bytes(to_byte_ptr(key.get()), key_length) != 1) {
			throw cryptographic_exception(std::error_code(::ERR_peek_last_error(), openssl_category()), "Failed to generate an AES key.");
		}
		if (::RAND_bytes(to_byte_ptr(iv.get()), iv_length) != 1) {
			throw cryptographic_exception(std::error_code(::ERR_peek_last_error(), openssl_category()), "Failed to generate an AES IV (aka. initialization vector).");
		}

		int rc = ::EVP_EncryptInit(ctx.get(), cipher_suite, to_byte_ptr(key.get()), to_byte_ptr(iv.get()));
		if (rc == 0) {
			throw cryptographic_exception(std::error_code(::ERR_peek_last_error(), openssl_category()), "Failed to construct the OpenSSL cipher context.");
		}

		encrypted_cred_data_length = cred_data_length + (profile_config::bytes_aes_block_length - cred_data_length % profile_config::bytes_aes_block_length);
		encrypted_cred_data = std::make_unique<std::byte[]>(encrypted_cred_data_length);

		int bytes_written = 0;
		rc = ::EVP_EncryptUpdate(ctx.get(), to_byte_ptr(encrypted_cred_data.get()), &bytes_written, to_byte_ptr(cred_data), cred_data_length);
		if (rc == 0) {
			throw cryptographic_exception(std::error_code(::ERR_peek_last_error(), openssl_category()), "Failed to encrypt data.");
		}

		rc = ::EVP_EncryptFinal_ex(ctx.get(), to_byte_ptr(encrypted_cred_data.get() + bytes_written), &bytes_written);
		if (rc == 0) {
			throw cryptographic_exception(std::error_code(::ERR_peek_last_error(), openssl_category()), "Padding process was failed.");
		}
	}

	void profile_config::encrypt_key(const std::byte* key, std::size_t key_length, unique_hlocal_ptr_t<std::byte>& encrypted_key, std::size_t& encrypted_key_length) {
		::DATA_BLOB blob, encrypted_blob;

		blob.cbData = key_length;
		blob.pbData = to_byte_ptr(const_cast<std::byte*>(key));

		bool succeeded = ::CryptProtectData(
			&blob,
			nullptr,
			nullptr,
			nullptr,
			nullptr,
			0,
			&encrypted_blob
		);
		if (!succeeded) {
			std::error_code ec(::GetLastError(), std::system_category());
			throw config_system_error(ec, "Failed to encrypt the AES key.");
		}

		encrypted_key.reset(to_byte_ptr(encrypted_blob.pbData));
		encrypted_key_length = encrypted_blob.cbData;
	}

	void profile_config::concatenate_cred_data(
		const std::byte* encrypted_key,
		std::size_t encrypted_key_length,
		const std::byte* iv,
		std::size_t iv_length,
		const std::byte* encrypted_cred_data,
		std::size_t encrypted_cred_data_length,
		std::unique_ptr<std::byte[]>& result,
		std::size_t& result_length
	) {
		result_length = 4 + 1 + encrypted_key_length + iv_length + encrypted_cred_data_length;
		result = std::make_unique<std::byte[]>(result_length);

		std::size_t offset = 0;

		for (int i = 0; i < 4; i++, offset++) {
			result[i] = static_cast<std::byte>((encrypted_key_length >> (3 - i) * 4) & 0xF);
		}
		result[offset] = static_cast<std::byte>(iv_length);
		offset++;

		std::copy_n(encrypted_key, encrypted_key_length, result.get() + offset);
		offset += encrypted_key_length;

		std::copy_n(iv, iv_length, result.get() + offset);
		offset += iv_length;

		std::copy_n(encrypted_cred_data, encrypted_cred_data_length, result.get() + offset);
		offset += encrypted_cred_data_length;
	}

	void profile_config::encode_to_base64(const std::byte* plain, std::size_t plain_length, std::string& encoded) {
		::BIO *bio = ::BIO_new(::BIO_s_mem());
		::BIO *b64 = ::BIO_new(::BIO_f_base64());

		bio = ::BIO_push(b64, bio);

		::BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
		int bytes_written = ::BIO_write(bio, plain, plain_length);
		if (bytes_written < 0) {
			throw cryptographic_exception(std::error_code(::ERR_peek_last_error(), openssl_category()), "Failed to write the BIO data.");
		}
		::BIO_ctrl(bio, BIO_CTRL_FLUSH, 0, nullptr);
		
		char* buffer = nullptr;
		int buffer_length = ::BIO_ctrl(bio, BIO_CTRL_INFO, 0, &buffer);
		if (buffer_length < 0) {
			throw cryptographic_exception(std::error_code(::ERR_peek_last_error(), openssl_category()), "Failed to set a pointer to the start of the memory BIO data.");
		}

		encoded.assign(buffer, buffer_length / sizeof(char));

		::BIO_ctrl(bio, BIO_CTRL_SET_CLOSE, BIO_NOCLOSE, nullptr);
		::BIO_free_all(bio);
	}

	void profile_config::xload(const profile_config::json_data_type& data) {
		using chcvt = util::charset::multibyte_wide_compat_helper;

		std::vector<profile> profiles;

		// each profiles
		for (const auto& raw_profile : data) {
			auto raw_name = raw_profile["name"].get<std::string>();
			auto raw_syncroot = raw_profile["syncroot"].get<std::string>();
			auto port = raw_profile["port"].get<std::uint16_t>();
			auto raw_cred = raw_profile["credential"].get<std::string>();

			std::size_t raw_cred_length = raw_cred.size();
			std::unique_ptr<std::byte[]> decoded_raw_cred;
			std::size_t decoded_raw_cred_length;

			if (raw_cred_length <= 0) {
				throw config_json_exception("Invalid configuration data.");
			}

			profile_config::decode_from_base64(raw_cred, decoded_raw_cred, decoded_raw_cred_length);

			const std::byte *encrypted_key_head, *iv_head, *encrypted_cred_data_head;
			std::size_t encrypted_key_length, iv_length, encrypted_cred_data_length;
			profile_config::divide_decoded_raw_cred_into_elements(
				decoded_raw_cred.get(),
				decoded_raw_cred_length,
				&encrypted_key_head,
				&encrypted_key_length,
				&iv_head,
				&iv_length,
				&encrypted_cred_data_head,
				&encrypted_cred_data_length
			);

			unique_hlocal_ptr_t<std::byte> decrypted_key;
			std::size_t decrypted_key_length;
			profile_config::decrypt_key(encrypted_key_head, encrypted_key_length, decrypted_key, decrypted_key_length);

			std::unique_ptr<std::byte[]> decrypted_cred_data;
			std::size_t decrypted_cred_data_length;
			profile_config::decrypt_cred_data(
				encrypted_cred_data_head,
				encrypted_cred_data_length,
				decrypted_key.get(),
				decrypted_key_length,
				iv_head,
				iv_length,
				decrypted_cred_data,
				decrypted_cred_data_length
			);

			auto cred = profile_config::deserialize_cred_info_from_bin_to_obj(decrypted_cred_data.get(), decrypted_cred_data_length);

			::RtlSecureZeroMemory(decrypted_key.get(), decrypted_key_length);
			::RtlSecureZeroMemory(decrypted_cred_data.get(), decrypted_cred_data_length);

			profiles.emplace_back(chcvt::convert_multibyte_to_wide(raw_name), chcvt::convert_multibyte_to_wide(raw_syncroot), port, std::move(cred));
		}

		this->m_data = std::move(profiles);
	}

	profile_config::json_data_type profile_config::xsave() const {
		using chcvt = util::charset::multibyte_wide_compat_helper;

		profile_config::json_data_type result;
		
		for (const auto& profile : this->m_data) {
			std::unique_ptr<std::byte[]> serialized_cred_info;
			std::size_t serialized_cred_info_length;

			profile_config::serialize_cred_info_from_obj_to_bin(profile.get_credential(), serialized_cred_info, serialized_cred_info_length);

			std::unique_ptr<std::byte[]> key, iv, encrypted_cred_data;
			std::size_t key_length, iv_length, encrypted_cred_data_length;
			profile_config::encrypt_cred_data(
				serialized_cred_info.get(),
				serialized_cred_info_length,
				key,
				key_length,
				iv,
				iv_length,
				encrypted_cred_data,
				encrypted_cred_data_length
			);

			unique_hlocal_ptr_t<std::byte> encrypted_key;
			std::size_t encrypted_key_length;
			profile_config::encrypt_key(key.get(), key_length, encrypted_key, encrypted_key_length);

			::RtlSecureZeroMemory(key.get(), key_length);

			std::unique_ptr<std::byte[]> normalized_cred_data;
			std::size_t normalized_cred_data_length;
			profile_config::concatenate_cred_data(
				encrypted_key.get(),
				encrypted_key_length,
				iv.get(),
				iv_length,
				encrypted_cred_data.get(),
				encrypted_cred_data_length,
				normalized_cred_data,
				normalized_cred_data_length
			);

			std::string cred_data_to_write;
			profile_config::encode_to_base64(normalized_cred_data.get(), normalized_cred_data_length, cred_data_to_write);

			auto raw_name = chcvt::convert_wide_to_multibyte(profile.get_name());
			auto raw_syncroot = chcvt::convert_wide_to_multibyte(profile.get_syncroot());
			nlohmann::json raw_profile = {
				{ "name", raw_name },
				{ "syncroot", raw_syncroot },
				{ "port", profile.get_port() },
				{ "credential", cred_data_to_write }
			};

			result.push_back(raw_profile);
		}
		
		return std::move(result);
	}

	profile_config::data_type profile_config::xget() const {
		return std::ref(this->m_data);
	}

	void profile_config::xset(const profile_config::data_type& data) {
		this->m_data = data.get();
	}

	void profile_manager::internal_try_fetch() {
		if (!s_profiles.has_value()) fetch();
	}

	const std::vector<profile>& profile_manager::enumerate() {
		internal_try_fetch();
		std::shared_lock lock(s_mutex);
		return s_profiles.value();
	}
	
	void profile_manager::add(const profile& profile) {
		internal_try_fetch();
		std::unique_lock lock(s_mutex);
		for (const auto& p : *s_profiles) {
			if (profile.get_name() == p.get_name()) throw profile_name_exception(std::wstring(p.get_name()), "The profile with the same name is already registered.");
		}
		s_profiles->push_back(profile);
	}

	void profile_manager::remove(std::wstring_view name) {
		internal_try_fetch();
		std::unique_lock lock(s_mutex);
		auto xitr = std::remove_if(s_profiles->begin(), s_profiles->end(), [name](const profile& p) -> bool { return p.get_name() == name; });
		if (xitr == s_profiles->end()) throw profile_name_exception(std::wstring(name), "The profile with the specified name hasn't been registered yet.");
		s_profiles->erase(xitr, s_profiles->end());
	}

	profile& profile_manager::get(std::wstring_view name) {
		internal_try_fetch();
		std::shared_lock lock(s_mutex);
		auto itr = std::find_if(s_profiles->begin(), s_profiles->end(), [name](const profile& p) -> bool { return p.get_name() == name; });
		if (itr == s_profiles->end()) throw profile_name_exception(std::wstring(name), "The profile with the specified name hasn't been registered yet.");
		return *itr;
	}

	void profile_manager::flush() {
		internal_try_fetch();
		std::shared_lock lock(s_mutex);
		s_config.set(std::ref(*s_profiles));
		s_config.save();
	}

	void profile_manager::fetch() {
		std::unique_lock lock(s_mutex);
		s_config.load();
		s_profiles = std::move(s_config.get().get());
	}
}